"""IT/OT bridge session emitter.

See ``it_ot_bridge/__init__.py`` for the design contract: matched-pair
telemetry across IT and OT sides with a shared ``bridge_session_uid``,
three normal session kinds + three anomalous overlays.

Module layout:
    constants                   schedule + correlation key shape
    BridgeSession + AnomalyWindow dataclasses
    RNG / UID helpers
    record emitters (per source: zeek conn, linux auth_log, ot_hosts auth)
    per-kind session builders (jump_to_ews, historian_bi_read, ews_config_backup,
        jump_host_bypass, unexpected_corp_to_ot, historian_external_replication)
    public entry: generate_for_topologies()
"""

from __future__ import annotations

import hashlib
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator, Literal

from blue_bench_generators.it_baseline.topology import Host, Topology
from blue_bench_generators.ot_protocols.topology import Device, OTNetwork

log = logging.getLogger(__name__)


# --- constants -------------------------------------------------------------


# Normal session counts per *weekday*. Weekend defaults to zero. Anchor
# session start jitter inside the 07:00-19:00 window so traffic clusters
# during the business day -- bridge sessions are operator-driven, not
# automated polling.
_SHIFT_START_H: int = 7
_SHIFT_END_H: int = 19


SessionKind = Literal[
    # Normal patterns.
    "jump_to_ews",
    "historian_bi_read",
    "ews_config_backup",
    # Anomalous patterns (anomaly-window only, never in baseline).
    "jump_host_bypass",
    "unexpected_corp_to_ot",
    "historian_external_replication",
]


# Per-weekday baseline session count, scaled with tier. ``ews_config_backup``
# is a fixed once-per-weekday pattern, not Poisson-drawn.
_NORMAL_KINDS: tuple[SessionKind, ...] = (
    "jump_to_ews",
    "historian_bi_read",
    "ews_config_backup",
)


_ANOMALOUS_KINDS: tuple[SessionKind, ...] = (
    "jump_host_bypass",
    "unexpected_corp_to_ot",
    "historian_external_replication",
)


_PER_DAY_BASELINE: dict[str, dict[SessionKind, int]] = {
    "S": {
        "jump_to_ews": 3,
        "historian_bi_read": 6,
        "ews_config_backup": 1,  # interpreted as "1 if weekday else 0"
    },
    "M": {
        "jump_to_ews": 4,
        "historian_bi_read": 9,
        "ews_config_backup": 1,
    },
    "L": {
        "jump_to_ews": 6,
        "historian_bi_read": 12,
        "ews_config_backup": 1,
    },
}


# Corporate file-share host name (synthetic). Bridge config backups
# target this host; if the IT topology happens not to have a
# ``file-server`` role we synthesise a plausible IP in the server VLAN.
# Fallback corporate file-share used by ews_config_backup when the IT
# topology has no ``file-server`` role. IT topology allocates the
# server VLAN upward from .10 (L tier reaches .22), so we anchor the
# fallback at .200 to stay above the assignment ceiling even at L
# tier scaling. Same protection pattern as the OT-host RDP source IP
# range bumped in PR #5.
_CORP_FILESHARE_HOST_FALLBACK: tuple[str, str] = (
    "fs-corp-01.corp.example.invalid",
    "10.20.0.200",
)


# Fallback DMZ jump-host used when the IT topology has no jump-host
# role (S/M tiers; only L populates one). DMZ VLAN gateway is
# 10.30.0.1; we anchor the fallback at .200 (well above the topology
# allocator's .10-onward assignment range) so the synthesised jump-host
# cannot collide with another DMZ host.
_JUMP_HOST_FALLBACK_FQDN: str = "jump-bridge-01.corp.example.invalid"
_JUMP_HOST_FALLBACK_IP: str = "10.30.0.200"


# Documentation/external IP range (RFC5737 TEST-NET-3). Used by the
# ``historian_external_replication`` anomaly so the dst IP is obviously
# external and never collides with topology subnets. Matches the
# convention used by it_baseline.sysmon for outbound test traffic.
_EXTERNAL_TEST_NET_3_PREFIX: str = "198.51.100"


AnomalyKind = SessionKind  # alias -- anomaly kinds are session kinds


@dataclass(frozen=True)
class BridgeSession:
    """A single IT/OT bridge session.

    Attributes:
        kind: session pattern (normal or anomalous).
        start: session start (naive UTC). All emitted records land in
            ``[start, start + duration)``.
        bridge_session_uid: 13-char "B"-prefixed correlation key tying
            together every record emitted for the session.
        it_host: IT-side originator (corp workstation or jump-host).
        ot_target: OT-side target device (EWS, historian, etc.).
        user: user identity driving the session (None for anomalies
            where attribution is intentionally absent).
    """

    kind: SessionKind
    start: datetime
    bridge_session_uid: str
    it_host: Host | None
    ot_target: Device | None
    user: str | None


@dataclass(frozen=True)
class AnomalyWindow:
    """Time-bounded anomaly overlay.

    Attributes:
        kind: which anomaly to emit (must be one of the three anomalous
            session kinds).
        start: window start (naive UTC). The anomaly emits at
            ``start`` exactly; the window's ``end`` is used only for
            corpus-boundary validation.
        end: window end (exclusive, naive UTC).
        target_device: OT-side target. ``None`` selects the first
            eligible device deterministically.
    """

    kind: AnomalyKind
    start: datetime
    end: datetime
    target_device: str | None = None


# --- RNG / UID helpers -----------------------------------------------------


def _session_rng(seed: int, kind: SessionKind, session_idx: int) -> random.Random:
    payload = f"{seed}|{kind}|{session_idx}".encode()
    digest = hashlib.blake2b(payload, digest_size=8).digest()
    return random.Random(int.from_bytes(digest, "little"))


def _session_uid(seed: int, kind: SessionKind, session_idx: int) -> str:
    """Stable 13-character bridge session UID.

    ``B`` prefix distinguishes bridge correlation keys from OT-protocol
    ``C`` and OT-host ``H`` UIDs at a glance.
    """
    payload = f"{seed}|bridge|{kind}|{session_idx}".encode()
    return "B" + hashlib.blake2b(payload, digest_size=6).hexdigest()


def _zeek_uid(session_uid: str, leg: str) -> str:
    """Per-connection Zeek UID derived from the session UID.

    Real Zeek's ``uid`` is per-TCP-connection, not per-session. A
    jump-to-EWS session has two TCP legs (corp->jump, jump->EWS), each
    needing its own ``uid``. Both still carry the same
    ``bridge_session_uid`` for cross-stream correlation.
    """
    payload = f"{session_uid}|{leg}".encode()
    return "C" + hashlib.blake2b(payload, digest_size=6).hexdigest()


def _zeek_ts(ts: datetime) -> str:
    return f"{ts.timestamp():.6f}"


def _iso_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def _ephemeral_port(rng: random.Random) -> int:
    return 49152 + rng.randrange(0, 65535 - 49152 + 1)


def _on_shift(ts: datetime) -> bool:
    if ts.weekday() > 4:
        return False
    return _SHIFT_START_H <= ts.hour < _SHIFT_END_H


# --- IT/OT picker helpers --------------------------------------------------


def _pick_jump_host(topology: Topology) -> tuple[str, str]:
    """Return ``(fqdn, ip)`` for the bridge jump-host.

    Falls back to a synthesised DMZ host (``jump-bridge-01``, .10) when
    the IT topology has no ``jump-host`` role -- S/M tier populations
    in the current builder have zero jump-hosts; only L does. The
    fallback IP is reserved below the topology builder's host
    assignment range so it can't collide with another DMZ device.
    """
    for h in topology.hosts:
        if h.role == "jump-host":
            return h.fqdn, h.ip
    return _JUMP_HOST_FALLBACK_FQDN, _JUMP_HOST_FALLBACK_IP


def _pick_corp_workstation(topology: Topology, rng: random.Random) -> Host | None:
    candidates = [h for h in topology.hosts if h.role in ("workstation", "admin-workstation")]
    if not candidates:
        return None
    return candidates[rng.randrange(len(candidates))]


def _pick_corp_bi_host(topology: Topology, rng: random.Random) -> Host | None:
    """A corp-side host that plausibly runs a BI tool reading the historian.

    Prefer servers (database-server, file-server) on the server VLAN;
    fall back to admin-workstations.
    """
    candidates = [h for h in topology.hosts if h.role in ("database-server", "file-server")]
    if not candidates:
        candidates = [h for h in topology.hosts if h.role == "admin-workstation"]
    if not candidates:
        return None
    return candidates[rng.randrange(len(candidates))]


def _pick_corp_file_share(topology: Topology) -> tuple[str, str]:
    """Return (fqdn, ip) for the corp file share used by config backups."""
    for h in topology.hosts:
        if h.role == "file-server":
            return h.fqdn, h.ip
    return _CORP_FILESHARE_HOST_FALLBACK


def _pick_ews(network: OTNetwork) -> Device | None:
    for d in network.devices:
        if d.role == "engineering-workstation":
            return d
    return None


def _pick_historian(network: OTNetwork) -> Device | None:
    for d in network.devices:
        if d.role == "historian":
            return d
    return None


def _pick_ot_controller(network: OTNetwork, rng: random.Random) -> Device | None:
    controllers = [d for d in network.devices if d.role in ("controller", "safety-controller")]
    if not controllers:
        return None
    return controllers[rng.randrange(len(controllers))]


def _resolve_target_device(
    network: OTNetwork,
    eligible_roles: tuple[str, ...],
    target_name: str | None,
    kind: AnomalyKind,
    rng: random.Random | None = None,
) -> Device | None:
    """Resolve an anomaly's target device by role + optional explicit name.

    Mirrors ``ot_hosts._pick_anomaly_device`` policy: returns ``None``
    when the network has no devices of the eligible role at all
    (S/M may have no jump-host, no safety-controller, etc.) -- callers
    skip silently. An explicit ``target_name`` that doesn't match any
    eligible device is a caller bug and raises with the sorted
    eligible-name list, uniform with the cross-boundary-window and
    on-shift-start raises across the generator suite.
    """
    eligible = [d for d in network.devices if d.role in eligible_roles]
    if not eligible:
        return None
    if target_name is not None:
        for d in eligible:
            if d.name == target_name:
                return d
        eligible_names = sorted(d.name for d in eligible)
        raise ValueError(
            f"anomaly {kind!r} target_device {target_name!r} is not an "
            f"eligible {list(eligible_roles)!r} device in this network; "
            f"eligible: {eligible_names}"
        )
    if rng is not None:
        return eligible[rng.randrange(len(eligible))]
    return eligible[0]


def _pick_user(topology: Topology, rng: random.Random) -> str:
    """A real corp username from the topology, or a synthetic fallback."""
    if topology.users:
        return topology.users[rng.randrange(len(topology.users))].username
    return "corpuser"


# --- record emitters -------------------------------------------------------


def _emit_zeek_conn(
    *,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    service: str,
    ts: datetime,
    bridge_session_uid: str,
    leg: str,
    bytes_orig: int = 4096,
    bytes_resp: int = 16384,
    source_dir: str = "zeek",
) -> dict:
    return {
        "_source": source_dir,
        "_log": "conn",
        "ts": _zeek_ts(ts),
        "uid": _zeek_uid(bridge_session_uid, leg),
        "id.orig_h": src_ip,
        "id.orig_p": str(src_port),
        "id.resp_h": dst_ip,
        "id.resp_p": str(dst_port),
        "proto": "tcp",
        "service": service,
        "orig_bytes": str(bytes_orig),
        "resp_bytes": str(bytes_resp),
        "conn_state": "SF",
        "history": "ShADadFf",
        "bridge_session_uid": bridge_session_uid,
    }


# SSH key fingerprint alphabet matches linux_logs.py:357 -- 32 chars
# (no I/O confusion). Bridge fingerprints derive deterministically from
# bridge_session_uid so they are SHAPE-INDISTINGUISHABLE from natural
# sshd records: 43 characters from the same alphabet. A detector
# trained on natural fingerprint length will not get a free shortcut
# on bridge records.
_SSH_FP_ALPHABET: str = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"


def _bridge_ssh_thumbprint(bridge_session_uid: str) -> str:
    """Deterministic 43-char SSH thumb derived from the session UID.

    blake2b(32 bytes) gives 256 bits of derivation entropy; we render
    them into the 32-char ssh-fp alphabet (5 bits/char) to fill 43
    characters. Pure function of ``bridge_session_uid`` -- no RNG, no
    process-salt dependency, no length divergence from natural records.
    """
    digest = hashlib.blake2b(
        bridge_session_uid.encode("utf-8"), digest_size=32
    ).digest()
    # Treat the digest as a base-2 stream; emit 43 base-32 chars.
    bits = int.from_bytes(digest, "big")
    out: list[str] = []
    for _ in range(43):
        out.append(_SSH_FP_ALPHABET[bits & 0x1F])
        bits >>= 5
    return "".join(out)


def _emit_linux_auth_accepted(
    *,
    host_fqdn: str,
    ts: datetime,
    user: str,
    src_ip: str,
    src_port: int,
    bridge_session_uid: str,
    pid: int = 4321,
) -> dict:
    # Append ``session=<uid>`` to the message tail so cross-stream
    # consumers can correlate bridge records in auth.log even after
    # _write_syslog_text drops every key except the formatted message.
    # The session= suffix is the documented carve-out for linux/auth.log
    # (see __init__.py module header) since the dict-level
    # bridge_session_uid does not survive the syslog text writer.
    thumb = _bridge_ssh_thumbprint(bridge_session_uid)
    msg = (
        f"Accepted publickey for {user} from {src_ip} port {src_port} "
        f"ssh2: ED25519 SHA256:{thumb} session={bridge_session_uid}"
    )
    return {
        "_source": "linux",
        "_log": "auth_log",
        # Second precision -- matches the natural sshd record format
        # (linux_logs uses second-precision ISO strings for auth.log).
        "timestamp": ts.replace(microsecond=0).isoformat(),
        "hostname": host_fqdn,
        "facility": "auth",
        "process": "sshd",
        "pid": pid,
        "message": msg,
        "bridge_session_uid": bridge_session_uid,
    }


def _emit_ot_host_auth(
    *,
    host_fqdn: str,
    host_role: str,
    ts: datetime,
    user: str,
    method: str,
    src_ip: str,
    bridge_session_uid: str,
    seed: int,
) -> dict:
    # ``seed`` is included in the UID key explicitly, matching the
    # natural ``ot_hosts._uid`` pattern. Functionally redundant with
    # bridge_session_uid's transitive seed-dependence, but pattern
    # uniformity matters more here than the byte saved.
    return {
        "_source": "ot_hosts",
        "_log": "ot_auth",
        "timestamp": _iso_ts(ts),
        "uid": "H" + hashlib.blake2b(
            f"{seed}|bridge|ot_auth|{bridge_session_uid}".encode(),
            digest_size=6,
        ).hexdigest(),
        "host": host_fqdn,
        "host_role": host_role,
        "user": user,
        "auth_method": method,
        "status": "success",
        "source_ip": src_ip,
        "message": f"{method} login success for {user} from {src_ip}",
        "bridge_session_uid": bridge_session_uid,
    }


# --- per-kind session builders --------------------------------------------


def _build_jump_to_ews(
    *,
    topology: Topology,
    network: OTNetwork,
    ts: datetime,
    session_uid: str,
    rng: random.Random,
    seed: int,
) -> list[dict]:
    """Corp user -> jump-host (SSH) -> EWS (RDP).

    Matched-pair records:
      1. zeek conn      corp_ws -> jump-host (SSH)
      2. linux auth_log Accepted publickey on jump-host
      3. zeek conn      jump-host -> EWS (RDP)
      4. ot_hosts auth  EWS receives RDP login from jump-host
    """
    corp_ws = _pick_corp_workstation(topology, rng)
    jump_fqdn, jump_ip = _pick_jump_host(topology)
    ews = _pick_ews(network)
    if corp_ws is None or ews is None:
        return []
    user = _pick_user(topology, rng)
    leg1_port = _ephemeral_port(rng)
    leg2_port = _ephemeral_port(rng)
    handoff_ts = ts + timedelta(seconds=3)
    return [
        _emit_zeek_conn(
            src_ip=corp_ws.ip, src_port=leg1_port,
            dst_ip=jump_ip, dst_port=22, service="ssh",
            ts=ts, bridge_session_uid=session_uid, leg="corp_to_jump",
        ),
        _emit_linux_auth_accepted(
            host_fqdn=jump_fqdn, ts=ts + timedelta(milliseconds=500),
            user=user, src_ip=corp_ws.ip, src_port=leg1_port,
            bridge_session_uid=session_uid,
        ),
        _emit_zeek_conn(
            src_ip=jump_ip, src_port=leg2_port,
            dst_ip=ews.ip, dst_port=3389, service="rdp",
            ts=handoff_ts, bridge_session_uid=session_uid, leg="jump_to_ews",
        ),
        _emit_ot_host_auth(
            host_fqdn=ews.fqdn, host_role=ews.role,
            ts=handoff_ts + timedelta(milliseconds=400),
            user=user, method="rdp", src_ip=jump_ip,
            bridge_session_uid=session_uid, seed=seed,
        ),
    ]


def _build_historian_bi_read(
    *,
    topology: Topology,
    network: OTNetwork,
    ts: datetime,
    session_uid: str,
    rng: random.Random,
    seed: int,
) -> list[dict]:
    """Corp BI host -> historian (HTTPS).

    Matched-pair: IT-side zeek conn (outbound from corp) + OT-side ot
    zeek conn (inbound to historian). Both carry the same
    ``bridge_session_uid``.
    """
    bi_host = _pick_corp_bi_host(topology, rng)
    historian = _pick_historian(network)
    if bi_host is None or historian is None:
        return []
    src_port = _ephemeral_port(rng)
    return [
        _emit_zeek_conn(
            src_ip=bi_host.ip, src_port=src_port,
            dst_ip=historian.ip, dst_port=443, service="ssl",
            ts=ts, bridge_session_uid=session_uid, leg="bi_outbound",
            bytes_orig=2048, bytes_resp=65536,
            source_dir="zeek",
        ),
        _emit_zeek_conn(
            src_ip=bi_host.ip, src_port=src_port,
            dst_ip=historian.ip, dst_port=443, service="ssl",
            ts=ts + timedelta(milliseconds=100),
            bridge_session_uid=session_uid, leg="bi_inbound_ot",
            bytes_orig=2048, bytes_resp=65536,
            source_dir="ot",
        ),
    ]


def _build_ews_config_backup(
    *,
    topology: Topology,
    network: OTNetwork,
    ts: datetime,
    session_uid: str,
    rng: random.Random,
    seed: int,
) -> list[dict]:
    """EWS -> corp file share (SMB).

    Matched-pair: OT-side outbound + IT-side inbound zeek conn records.
    """
    ews = _pick_ews(network)
    if ews is None:
        return []
    fs_fqdn, fs_ip = _pick_corp_file_share(topology)
    src_port = _ephemeral_port(rng)
    return [
        _emit_zeek_conn(
            src_ip=ews.ip, src_port=src_port,
            dst_ip=fs_ip, dst_port=445, service="smb",
            ts=ts, bridge_session_uid=session_uid, leg="backup_outbound_ot",
            bytes_orig=8 * 1024 * 1024, bytes_resp=4096,
            source_dir="ot",
        ),
        _emit_zeek_conn(
            src_ip=ews.ip, src_port=src_port,
            dst_ip=fs_ip, dst_port=445, service="smb",
            ts=ts + timedelta(milliseconds=120),
            bridge_session_uid=session_uid, leg="backup_inbound_corp",
            bytes_orig=8 * 1024 * 1024, bytes_resp=4096,
            source_dir="zeek",
        ),
    ]


def _build_jump_host_bypass(
    *,
    topology: Topology,
    network: OTNetwork,
    ts: datetime,
    session_uid: str,
    rng: random.Random,
    seed: int,
    target_device: str | None,
) -> list[dict]:
    """Corp workstation -> EWS direct, bypassing the jump-host.

    Signature: a zeek conn corp->EWS exists AND an ot_hosts ot_auth on
    EWS exists, but there is NO linux/auth.log on the jump-host. This
    must be testably disjoint from baseline ``jump_to_ews`` where the
    jump-host auth record is always present.
    """
    corp_ws = _pick_corp_workstation(topology, rng)
    ews = _resolve_target_device(
        network, ("engineering-workstation",), target_device,
        "jump_host_bypass", rng=None,  # deterministic-first when unspecified
    )
    if corp_ws is None or ews is None:
        return []
    user = _pick_user(topology, rng)
    src_port = _ephemeral_port(rng)
    return [
        _emit_zeek_conn(
            src_ip=corp_ws.ip, src_port=src_port,
            dst_ip=ews.ip, dst_port=3389, service="rdp",
            ts=ts, bridge_session_uid=session_uid, leg="bypass_corp_to_ews",
        ),
        _emit_ot_host_auth(
            host_fqdn=ews.fqdn, host_role=ews.role,
            ts=ts + timedelta(milliseconds=400),
            user=user, method="rdp", src_ip=corp_ws.ip,
            bridge_session_uid=session_uid, seed=seed,
        ),
    ]


def _build_unexpected_corp_to_ot(
    *,
    topology: Topology,
    network: OTNetwork,
    ts: datetime,
    session_uid: str,
    rng: random.Random,
    seed: int,
    target_device: str | None,
) -> list[dict]:
    """Corp workstation -> OT controller directly.

    Signature: a zeek conn from a corp-VLAN source IP to a control-VLAN
    controller IP. Baseline traffic NEVER originates from corp into the
    OT control or field VLANs.
    """
    corp_ws = _pick_corp_workstation(topology, rng)
    target = _resolve_target_device(
        network, ("controller", "safety-controller"), target_device,
        "unexpected_corp_to_ot", rng=rng,
    )
    if corp_ws is None or target is None:
        return []
    src_port = _ephemeral_port(rng)
    return [
        _emit_zeek_conn(
            src_ip=corp_ws.ip, src_port=src_port,
            dst_ip=target.ip, dst_port=502, service="modbus",
            ts=ts, bridge_session_uid=session_uid, leg="corp_direct_to_ot",
            source_dir="zeek",
        ),
        _emit_zeek_conn(
            src_ip=corp_ws.ip, src_port=src_port,
            dst_ip=target.ip, dst_port=502, service="modbus",
            ts=ts + timedelta(milliseconds=100),
            bridge_session_uid=session_uid, leg="corp_direct_to_ot_ot_side",
            source_dir="ot",
        ),
    ]


def _build_historian_external_replication(
    *,
    topology: Topology,
    network: OTNetwork,
    ts: datetime,
    session_uid: str,
    rng: random.Random,
    seed: int,
    target_device: str | None,
) -> list[dict]:
    """Historian -> RFC5737 external destination.

    Signature: outbound TLS from the historian to a documentation-range
    external IP (198.51.100.x). Baseline historian traffic never leaves
    the topology subnets.
    """
    historian = _resolve_target_device(
        network, ("historian",), target_device,
        "historian_external_replication", rng=None,
    )
    if historian is None:
        return []
    src_port = _ephemeral_port(rng)
    ext_ip = f"{_EXTERNAL_TEST_NET_3_PREFIX}.{rng.randrange(2, 254)}"
    return [
        _emit_zeek_conn(
            src_ip=historian.ip, src_port=src_port,
            dst_ip=ext_ip, dst_port=443, service="ssl",
            ts=ts, bridge_session_uid=session_uid,
            leg="historian_outbound_external",
            bytes_orig=4 * 1024 * 1024, bytes_resp=1024,
            source_dir="ot",
        ),
    ]


_BUILDERS = {
    "jump_to_ews": _build_jump_to_ews,
    "historian_bi_read": _build_historian_bi_read,
    "ews_config_backup": _build_ews_config_backup,
}


_ANOMALY_BUILDERS = {
    "jump_host_bypass": _build_jump_host_bypass,
    "unexpected_corp_to_ot": _build_unexpected_corp_to_ot,
    "historian_external_replication": _build_historian_external_replication,
}


# --- scheduling helpers ---------------------------------------------------


def _weekdays_in_window(start: datetime, end: datetime) -> list[datetime]:
    """Return naive-UTC midnights of each weekday inside ``[start, end)``.

    Caveat: when ``start`` falls mid-day, the cursor rolls forward to
    the next midnight, dropping that day's sessions entirely. The
    composer anchors at 00:00 (``DEFAULT_START``) so this is fine in
    practice, but a future caller passing ``--start 12:00`` would
    silently lose a weekday of bridge sessions.
    """
    days: list[datetime] = []
    cursor = start.replace(hour=0, minute=0, second=0, microsecond=0)
    if cursor < start:
        cursor = cursor + timedelta(days=1)
    while cursor < end:
        if cursor.weekday() <= 4:
            days.append(cursor)
        cursor = cursor + timedelta(days=1)
    return days


def _pick_shift_time(day_midnight: datetime, rng: random.Random) -> datetime:
    """Pick a deterministic time inside [shift_start, shift_end) on ``day``."""
    seconds_in_shift = (_SHIFT_END_H - _SHIFT_START_H) * 3600
    offset = rng.uniform(0.0, seconds_in_shift)
    return day_midnight + timedelta(hours=_SHIFT_START_H, seconds=offset)


def _baseline_per_day(tier: Literal["S", "M", "L"], kind: SessionKind) -> int:
    """Per-weekday session count for a normal kind. ``ews_config_backup``
    returns 1 (once per weekday); others return the tier-scaled count."""
    return _PER_DAY_BASELINE[tier].get(kind, 0)


def session_kind_counts(tier: Literal["S", "M", "L"]) -> dict[SessionKind, int]:
    """Public introspection: the per-weekday baseline counts for a tier.

    Used by tests and the manifest summary block. Anomaly counts are
    not included -- they come from caller-supplied AnomalyWindow tuples.
    """
    return dict(_PER_DAY_BASELINE[tier])


# --- public entry point ----------------------------------------------------


def generate_for_topologies(
    topology: Topology,
    network: OTNetwork,
    start: datetime,
    end: datetime,
    *,
    seed: int = 0,
    anomaly_windows: tuple[AnomalyWindow, ...] = (),
) -> Iterator[dict]:
    """Yield bridge events for an IT + OT network pair.

    Deterministic given ``(topology, network, start, end, seed,
    anomaly_windows)``. Events are pre-sorted by ``(timestamp,
    bridge_session_uid)`` so the composer's final per-source sort
    sees pre-ordered input.

    Each event carries a ``_source`` field naming the destination
    source directory; the composer strips it before writing.
    """
    if end <= start:
        log.info("it_ot_bridge: empty window, no events")
        return

    tier = getattr(topology, "tier", None)
    if tier not in ("S", "M", "L"):
        raise TypeError(
            f"it_ot_bridge: topology.tier must be S/M/L, got {tier!r}"
        )

    weekdays = _weekdays_in_window(start, end)
    events: list[dict] = []
    session_idx = 0

    # Normal sessions -- one Poisson-deterministic block per weekday
    # per kind, except ews_config_backup which fires exactly once per
    # weekday at a stable time.
    for kind in _NORMAL_KINDS:
        for day in weekdays:
            count = _baseline_per_day(tier, kind)
            if count <= 0:
                continue
            if kind == "ews_config_backup":
                # Fixed once-per-weekday at 18:30 local-ish (still in
                # the shift window). Deterministic, no jitter.
                session_idx += 1
                session_uid = _session_uid(seed, kind, session_idx)
                rng = _session_rng(seed, kind, session_idx)
                ts = day + timedelta(hours=18, minutes=30)
                if ts < start or ts >= end:
                    continue
                events.extend(_BUILDERS[kind](
                    topology=topology, network=network, ts=ts,
                    session_uid=session_uid, rng=rng, seed=seed,
                ))
                continue
            for _ in range(count):
                session_idx += 1
                session_uid = _session_uid(seed, kind, session_idx)
                rng = _session_rng(seed, kind, session_idx)
                ts = _pick_shift_time(day, rng)
                if ts < start or ts >= end:
                    continue
                events.extend(_BUILDERS[kind](
                    topology=topology, network=network, ts=ts,
                    session_uid=session_uid, rng=rng, seed=seed,
                ))

    # Anomalous sessions.
    for w in anomaly_windows:
        if w.end <= w.start:
            raise ValueError(
                f"bridge anomaly window {w.kind!r} has non-positive "
                f"duration: {w.start.isoformat()}..{w.end.isoformat()}"
            )
        # Cross-boundary -- raise loudly, same policy as ot_hosts.
        if w.end <= start or w.start >= end:
            continue
        if w.start < start or w.end > end:
            raise ValueError(
                f"bridge anomaly window {w.kind!r} {w.start.isoformat()}.."
                f"{w.end.isoformat()} straddles corpus window "
                f"{start.isoformat()}..{end.isoformat()}; must be fully "
                f"contained"
            )
        builder = _ANOMALY_BUILDERS.get(w.kind)
        if builder is None:
            raise ValueError(
                f"unknown bridge anomaly kind {w.kind!r}; expected one of "
                f"{tuple(_ANOMALY_BUILDERS)}"
            )
        session_idx += 1
        session_uid = _session_uid(seed, w.kind, session_idx)
        rng = _session_rng(seed, w.kind, session_idx)
        events.extend(builder(
            topology=topology, network=network, ts=w.start,
            session_uid=session_uid, rng=rng, seed=seed,
            target_device=w.target_device,
        ))

    events.sort(key=lambda e: (str(e.get("timestamp", e.get("ts", ""))), e["bridge_session_uid"]))
    for ev in events:
        yield ev
