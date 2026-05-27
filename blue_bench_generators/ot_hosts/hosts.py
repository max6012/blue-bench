"""OT host log emitter.

See ``ot_hosts/__init__.py`` for the high-level design contract: six
event families on a flat JSONL stream, operator-shift volume model,
three anomaly overlays, per-(host, hour) determinism.

Module layout: constants -> RNG / UID helpers -> per-family record
builders -> per-host hour walk -> anomaly overlays -> public entry point.
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Literal

from blue_bench_generators.ot_protocols.topology import Device, OTNetwork

log = logging.getLogger(__name__)


# --- constants -------------------------------------------------------------


# Weekday shift window in naive-UTC clock hours. The composer anchors
# corpora on a Monday at 00:00 UTC so a single S-tier (1 day) build
# exercises both off-hours (00-07, 19-24) and on-shift (07-19) regimes.
_SHIFT_START_H: int = 7
_SHIFT_END_H: int = 19

# Off-hours rate fraction of on-shift baseline. OT plants don't go
# silent at night -- night-shift operators acknowledge alarms, the
# historian keeps logging, but engineering / project / USB activity
# essentially stops. We apply ONE flat fraction here and then zero out
# project + USB families off-hours via ``_OFF_HOURS_FAMILY_ZERO``
# below; cleaner than per-family rate tables.
_OFF_HOURS_RATE_FRACTION: float = 0.08

# Families forced to zero outside shift (vs. just reduced by the
# _OFF_HOURS_RATE_FRACTION factor). These are activities tied to a
# present-and-active human engineer: project uploads/downloads,
# USB-device handling. Operator alarm-ack and historian audit
# continue (reduced) around the clock.
_OFF_HOURS_FAMILY_ZERO: frozenset[str] = frozenset(
    {"ews_project", "ot_usb"}
)


# Mean events per host per hour, on-shift. Tuned so an S-tier 1-day
# corpus emits a few hundred OT-host events total -- enough that schema
# tests have material to work with, not so many that the corpus bloats.
_HOURLY_RATES_ON_SHIFT: dict[str, dict[str, float]] = {
    "hmi": {
        "hmi_alarm": 6.0,         # alarms raised/acked across plant
        "hmi_operator": 3.0,      # setpoint / tag-write actions
        "ot_auth": 0.4,           # shift-change interactive logins
        "ot_usb": 0.05,           # rare; HMI consoles tend to be locked
    },
    "engineering-workstation": {
        "ews_project": 0.6,       # project up/download to controllers
        "ot_auth": 0.3,           # engineer logs in
        "ot_usb": 0.15,           # USB still used for vendor toolchains
    },
    "historian": {
        "historian_audit": 1.5,   # point definitions / retention edits
        "ot_auth": 0.1,
    },
    "ot-firewall": {
        # Firewall hosts only emit auth events here. Rule-change audit
        # would belong in a separate family if we modeled it.
        "ot_auth": 0.1,
    },
}


# Shared service-account labels. Realism point per the task spec:
# many OT environments rely on shared / kiosk accounts because the
# console is physical-access-controlled.
_SHARED_ACCOUNTS: tuple[str, ...] = (
    "ot-operator",
    "ot-engineer",
    "ot-supervisor",
    "scada-svc",
)


# Process unit / area labels for tag names. Vendor-neutral, plant-
# generic. Tags follow ``AREA{n}.UNIT{m}.{kind}{idx}`` -- a shape that
# any plant operator who has read DCS tag catalogues will recognise.
_AREA_COUNT: int = 4
_UNIT_COUNT: int = 6
_TAG_KINDS: tuple[str, ...] = (
    "FT",   # flow transmitter
    "PT",   # pressure transmitter
    "TT",   # temperature transmitter
    "LT",   # level transmitter
    "FV",   # flow valve (setpoint)
    "PV",   # pressure valve (setpoint)
    "PUMP", # pump on/off
    "MTR",  # motor speed
)


# Project-file synthetic naming. The "uploads/downloads" semantics are
# from the EWS->controller direction: upload = push project from EWS
# to controller; download = pull project from controller to EWS.
_PROJECT_TEMPLATES: tuple[str, ...] = (
    "plant_main",
    "safety_logic",
    "batch_recipe",
    "alarm_config",
    "scada_screens",
)


# USB device descriptors. Vendor-neutral product/vendor-id stubs.
_USB_DESCRIPTORS: tuple[tuple[str, str, str], ...] = (
    ("0x046d", "0xc52b", "Logitech-style HID"),
    ("0x0781", "0x5567", "USB mass storage"),
    ("0x0bda", "0x8153", "USB Ethernet adapter"),
    ("0x05ac", "0x0250", "Apple keyboard"),
)


# Alarm severities and actions, drawn uniformly.
_ALARM_SEVERITIES: tuple[str, ...] = ("info", "warning", "critical")
_ALARM_ACTIONS: tuple[str, ...] = ("raised", "acknowledged", "cleared")


# Operator setpoint / tag-write actions.
_OPERATOR_ACTIONS: tuple[str, ...] = ("setpoint_change", "tag_write", "manual_override")


# Historian audit actions.
_HISTORIAN_ACTIONS: tuple[str, ...] = (
    "point_create",
    "point_modify",
    "retention_change",
    "compression_change",
)


# Auth methods.
_AUTH_METHODS: tuple[str, ...] = ("interactive", "rdp", "ssh")


AnomalyKind = Literal[
    "off_hours_ews_login",
    "unexpected_project_download",
    "historian_tag_deletion",
]


@dataclass(frozen=True)
class AnomalyWindow:
    """Time-bounded OT-host anomaly overlay.

    Attributes:
        kind: which anomaly to emit.
        start: inclusive start (naive UTC).
        end: exclusive end (naive UTC).
        target_device: device name the anomaly targets. For
            ``off_hours_ews_login`` this is the EWS host that receives
            the off-hours login. For ``unexpected_project_download``
            this is the HMI that receives the project (the unusual
            target). For ``historian_tag_deletion`` this is the
            historian. ``None`` selects the first eligible device in
            deterministic order.
    """

    kind: AnomalyKind
    start: datetime
    end: datetime
    target_device: str | None = None


# --- RNG / UID helpers -----------------------------------------------------


def _host_hour_rng(seed: int, host_name: str, hour_epoch: int) -> random.Random:
    """Per-(host, hour) blake2b-derived RNG.

    Same pattern as ``ot_protocols.modbus._link_hour_rng``: process-
    independent (no bare ``hash()``), no XOR collisions, no module-
    level state.
    """
    payload = f"{seed}|{host_name}|{hour_epoch}".encode()
    digest = hashlib.blake2b(payload, digest_size=8).digest()
    return random.Random(int.from_bytes(digest, "little"))


def _uid(seed: int, *parts: object) -> str:
    """Stable 13-character UID for an OT-host event.

    ``H`` prefix distinguishes OT-host UIDs from the OT-protocol ``C``
    UIDs at a glance in grep output. Otherwise identical shape.
    """
    payload = "|".join([str(seed), *(str(p) for p in parts)]).encode()
    return "H" + hashlib.blake2b(payload, digest_size=6).hexdigest()


def _ts_iso(ts: datetime) -> str:
    """ISO-8601 with millisecond precision. Matches identity.py shape."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def _on_shift(ts: datetime) -> bool:
    """Weekday 07:00-19:00 = on-shift."""
    if ts.weekday() > 4:  # 5=Sat, 6=Sun
        return False
    return _SHIFT_START_H <= ts.hour < _SHIFT_END_H


def _hour_rate(role: str, family: str, ts: datetime) -> float:
    """Effective mean events/hour for ``role`` and ``family`` at ``ts``."""
    base = _HOURLY_RATES_ON_SHIFT.get(role, {}).get(family, 0.0)
    if base <= 0.0:
        return 0.0
    if _on_shift(ts):
        return base
    if family in _OFF_HOURS_FAMILY_ZERO:
        return 0.0
    return base * _OFF_HOURS_RATE_FRACTION


def _poisson_count(rng: random.Random, mean: float) -> int:
    """Knuth's Poisson sampler (same shape as the IT-baseline sysmon)."""
    if mean <= 0:
        return 0
    L = math.exp(-min(mean, 30.0))
    k = 0
    p = 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= L:
            return k - 1
        if k > 1000:
            return int(mean)


def _jitter_within_hour(rng: random.Random, hour_start: datetime, end: datetime) -> datetime:
    """Pick a deterministic timestamp inside ``[hour_start, hour_start+1h)``,
    clamped to ``end - 1us`` so events never spill outside the corpus
    window."""
    offset_seconds = rng.uniform(0.0, 3600.0)
    ts = hour_start + timedelta(seconds=offset_seconds)
    if ts >= end:
        return end - timedelta(microseconds=1)
    return ts


def _pick_account(rng: random.Random, role: str) -> str:
    """Role-biased shared account picker.

    HMI consoles bias toward ``ot-operator``; EWS toward ``ot-engineer``;
    historian toward ``scada-svc``; ot-firewall toward ``ot-supervisor``.
    The bias is real but not absolute -- supervisors do log into HMIs.
    """
    bias = {
        "hmi": "ot-operator",
        "engineering-workstation": "ot-engineer",
        "historian": "scada-svc",
        "ot-firewall": "ot-supervisor",
    }.get(role)
    if bias is not None and rng.random() < 0.75:
        return bias
    return _SHARED_ACCOUNTS[rng.randrange(len(_SHARED_ACCOUNTS))]


def _pick_tag(rng: random.Random) -> str:
    area = rng.randrange(1, _AREA_COUNT + 1)
    unit = rng.randrange(1, _UNIT_COUNT + 1)
    kind = _TAG_KINDS[rng.randrange(len(_TAG_KINDS))]
    idx = rng.randrange(1, 32)
    return f"AREA{area}.UNIT{unit}.{kind}{idx:02d}"


# --- per-family record builders --------------------------------------------


def _record_base(
    *,
    log_kind: str,
    host: Device,
    ts: datetime,
    seed: int,
    family_idx: int,
) -> dict:
    return {
        "_log": log_kind,
        "timestamp": _ts_iso(ts),
        "uid": _uid(seed, log_kind, host.name, ts.timestamp(), family_idx),
        "host": host.fqdn,
        "host_role": host.role,
    }


def _make_hmi_alarm(*, host: Device, ts: datetime, seed: int, idx: int, rng: random.Random) -> dict:
    rec = _record_base(log_kind="hmi_alarm", host=host, ts=ts, seed=seed, family_idx=idx)
    severity = _ALARM_SEVERITIES[rng.randrange(len(_ALARM_SEVERITIES))]
    action = _ALARM_ACTIONS[rng.randrange(len(_ALARM_ACTIONS))]
    tag = _pick_tag(rng)
    rec.update({
        "user": _pick_account(rng, host.role),
        "tag": tag,
        "severity": severity,
        "action": action,
        "message": f"alarm {action} on {tag} (severity={severity})",
    })
    return rec


def _make_hmi_operator(*, host: Device, ts: datetime, seed: int, idx: int, rng: random.Random) -> dict:
    rec = _record_base(log_kind="hmi_operator", host=host, ts=ts, seed=seed, family_idx=idx)
    action = _OPERATOR_ACTIONS[rng.randrange(len(_OPERATOR_ACTIONS))]
    tag = _pick_tag(rng)
    old_value = round(rng.uniform(0.0, 100.0), 2)
    new_value = round(rng.uniform(0.0, 100.0), 2)
    rec.update({
        "user": _pick_account(rng, host.role),
        "tag": tag,
        "action": action,
        "old_value": old_value,
        "new_value": new_value,
        "message": f"{action} {tag}: {old_value} -> {new_value}",
    })
    return rec


def _make_ews_project(
    *,
    host: Device,
    ts: datetime,
    seed: int,
    idx: int,
    rng: random.Random,
    network: OTNetwork,
    forced_action: str | None = None,
    forced_target: Device | None = None,
) -> dict:
    """EWS project upload/download event.

    Default target: a controller (the normal case). The
    ``unexpected_project_download`` anomaly forces the target to an HMI
    instead -- a configuration push to a console is what plant ops
    teams notice in post-incident review.
    """
    rec = _record_base(log_kind="ews_project", host=host, ts=ts, seed=seed, family_idx=idx)
    action = forced_action or ("upload" if rng.random() < 0.55 else "download")
    if forced_target is not None:
        target = forced_target
    else:
        controllers = [d for d in network.devices if d.role in ("controller", "safety-controller")]
        if not controllers:
            # A network with EWS hosts but no controllers is malformed
            # for this generator -- the baseline ews_project semantic
            # requires a real controller target. Fail loudly rather
            # than fabricate an ews->ews "project" record that no
            # downstream consumer can interpret.
            raise ValueError(
                f"_make_ews_project: network has engineering-workstation "
                f"{host.name!r} but no controllers; cannot construct a "
                f"baseline project target"
            )
        target = controllers[rng.randrange(len(controllers))]
    project = _PROJECT_TEMPLATES[rng.randrange(len(_PROJECT_TEMPLATES))]
    bytes_ = rng.randint(200_000, 12_000_000)
    rec.update({
        "user": _pick_account(rng, host.role),
        "action": action,
        "project": project,
        "target_device": target.name,
        "target_role": target.role,
        "bytes": bytes_,
        "message": f"project {action}: {project} {host.name}->{target.name} ({bytes_} bytes)",
    })
    return rec


def _make_historian_audit(
    *,
    host: Device,
    ts: datetime,
    seed: int,
    idx: int,
    rng: random.Random,
    forced_action: str | None = None,
) -> dict:
    rec = _record_base(log_kind="historian_audit", host=host, ts=ts, seed=seed, family_idx=idx)
    action = forced_action or _HISTORIAN_ACTIONS[rng.randrange(len(_HISTORIAN_ACTIONS))]
    tag = _pick_tag(rng)
    details = {
        "point_create": f"new point {tag} added",
        "point_modify": f"point {tag} attributes edited",
        "retention_change": f"retention policy for {tag} updated",
        "compression_change": f"compression deviation for {tag} updated",
        "point_delete": f"point {tag} removed",
    }.get(action, f"{action} on {tag}")
    rec.update({
        "user": _pick_account(rng, host.role),
        "tag": tag,
        "action": action,
        "details": details,
    })
    return rec


def _make_ot_auth(
    *,
    host: Device,
    ts: datetime,
    seed: int,
    idx: int,
    rng: random.Random,
    forced_status: str | None = None,
    forced_user: str | None = None,
) -> dict:
    rec = _record_base(log_kind="ot_auth", host=host, ts=ts, seed=seed, family_idx=idx)
    method = _AUTH_METHODS[rng.randrange(len(_AUTH_METHODS))]
    # Failures are uncommon on a kiosk-style console.
    status = forced_status or ("success" if rng.random() < 0.95 else "failure")
    user = forced_user or _pick_account(rng, host.role)
    # Source IPs: SSH/RDP come from the supervisory VLAN; interactive
    # logins come from the local console (host's own IP).
    if method in ("rdp", "ssh"):
        src_ip = f"10.40.0.{rng.randrange(10, 60)}"
    else:
        src_ip = host.ip
    rec.update({
        "user": user,
        "auth_method": method,
        "status": status,
        "source_ip": src_ip,
        "message": f"{method} login {status} for {user} from {src_ip}",
    })
    return rec


def _make_ot_usb(*, host: Device, ts: datetime, seed: int, idx: int, rng: random.Random) -> dict:
    rec = _record_base(log_kind="ot_usb", host=host, ts=ts, seed=seed, family_idx=idx)
    vendor_id, product_id, label = _USB_DESCRIPTORS[rng.randrange(len(_USB_DESCRIPTORS))]
    action = "insert" if rng.random() < 0.6 else "remove"
    rec.update({
        "user": _pick_account(rng, host.role),
        "action": action,
        "vendor_id": vendor_id,
        "product_id": product_id,
        "device_label": label,
        "message": f"USB {action}: {label} ({vendor_id}:{product_id})",
    })
    return rec


# Family -> builder. ``ews_project`` and ``historian_audit`` are wrapped
# because they need additional context (network, forced overrides).
def _emit_family(
    *,
    family: str,
    host: Device,
    ts: datetime,
    seed: int,
    idx: int,
    rng: random.Random,
    network: OTNetwork,
) -> dict:
    if family == "hmi_alarm":
        return _make_hmi_alarm(host=host, ts=ts, seed=seed, idx=idx, rng=rng)
    if family == "hmi_operator":
        return _make_hmi_operator(host=host, ts=ts, seed=seed, idx=idx, rng=rng)
    if family == "ews_project":
        return _make_ews_project(host=host, ts=ts, seed=seed, idx=idx, rng=rng, network=network)
    if family == "historian_audit":
        return _make_historian_audit(host=host, ts=ts, seed=seed, idx=idx, rng=rng)
    if family == "ot_auth":
        return _make_ot_auth(host=host, ts=ts, seed=seed, idx=idx, rng=rng)
    if family == "ot_usb":
        return _make_ot_usb(host=host, ts=ts, seed=seed, idx=idx, rng=rng)
    raise ValueError(f"unknown event family {family!r}")


# --- per-host hour walk ----------------------------------------------------


# Roles that emit OT host logs. Embedded RTOS roles (controller / safety
# / rtu) are excluded -- they have no host log surface.
_LOGGING_ROLES: frozenset[str] = frozenset(
    {"hmi", "engineering-workstation", "historian", "ot-firewall"}
)


def _generate_for_host(
    host: Device,
    network: OTNetwork,
    start: datetime,
    end: datetime,
    seed: int,
) -> list[dict]:
    if host.role not in _LOGGING_ROLES:
        return []
    if end <= start:
        return []

    events: list[dict] = []
    # Hour walk from the floor of ``start`` so the rate model aligns to
    # whole-hour buckets even when ``start`` is mid-hour.
    cursor = start.replace(minute=0, second=0, microsecond=0)
    families = tuple(_HOURLY_RATES_ON_SHIFT.get(host.role, {}).keys())
    while cursor < end:
        hour_epoch = int(cursor.timestamp())
        rng = _host_hour_rng(seed, host.name, hour_epoch)
        hour_end = cursor + timedelta(hours=1)
        # Sort families so a registry change doesn't reshuffle within-
        # hour emission order.
        for family in sorted(families):
            mean = _hour_rate(host.role, family, cursor)
            if mean <= 0.0:
                continue
            count = _poisson_count(rng, mean)
            for i in range(count):
                ts = _jitter_within_hour(rng, cursor, end)
                if ts < start:
                    # Hour bucket may start before window; clamp.
                    ts = start
                events.append(_emit_family(
                    family=family, host=host, ts=ts, seed=seed,
                    idx=hour_epoch * 1000 + i, rng=rng, network=network,
                ))
        cursor = hour_end
    return events


# --- anomaly overlays ------------------------------------------------------


def _pick_anomaly_device(
    network: OTNetwork, kind: AnomalyKind, target_name: str | None,
) -> Device | None:
    """Resolve an anomaly's target device.

    Each kind has a specific eligible role. ``target_name`` overrides
    the default-first behaviour; if it doesn't match an eligible
    device, the anomaly is silently skipped (callers should pick valid
    targets, but a broken caller shouldn't crash a corpus build).
    """
    eligible_role = {
        "off_hours_ews_login": "engineering-workstation",
        "unexpected_project_download": "hmi",
        "historian_tag_deletion": "historian",
    }[kind]
    eligible = [d for d in network.devices if d.role == eligible_role]
    if not eligible:
        return None
    if target_name is not None:
        for d in eligible:
            if d.name == target_name:
                return d
        return None
    return eligible[0]


def _emit_off_hours_ews_login(
    *, network: OTNetwork, window: AnomalyWindow, seed: int,
) -> list[dict]:
    ews = _pick_anomaly_device(network, "off_hours_ews_login", window.target_device)
    if ews is None:
        return []
    # ``window.start`` MUST be off-shift -- the whole point of the
    # anomaly is that the login lands outside operator hours and is
    # distinguishable from baseline. An on-shift start would emit a
    # record indistinguishable from a normal ``ot_auth`` event, which
    # would be a silent contract failure.
    if _on_shift(window.start):
        raise ValueError(
            f"off_hours_ews_login window.start {window.start.isoformat()} "
            f"is on-shift (weekday {window.start.weekday()}, hour "
            f"{window.start.hour}); pick a weekend or hour outside "
            f"{_SHIFT_START_H:02d}:00-{_SHIFT_END_H:02d}:00"
        )
    rng = _host_hour_rng(seed, ews.name, int(window.start.timestamp()))
    events: list[dict] = []
    events.append(_make_ot_auth(
        host=ews, ts=window.start, seed=seed, idx=900_000_001,
        rng=rng, forced_status="success",
        forced_user=_pick_account(rng, ews.role),
    ))
    follow_ts = min(window.start + timedelta(minutes=2), window.end - timedelta(microseconds=1))
    events.append(_make_ot_auth(
        host=ews, ts=follow_ts, seed=seed, idx=900_000_002,
        rng=rng, forced_status="success",
        forced_user=_pick_account(rng, ews.role),
    ))
    return events


def _emit_unexpected_project_download(
    *, network: OTNetwork, window: AnomalyWindow, seed: int,
) -> list[dict]:
    """Project download targeting an HMI rather than a controller.

    Source EWS = first EWS in topology (deterministic); target HMI =
    resolved from ``window.target_device``. The anomaly is the
    target_role being ``hmi`` -- which is what downstream detection
    code should be flagging on.
    """
    ews_list = [d for d in network.devices if d.role == "engineering-workstation"]
    target_hmi = _pick_anomaly_device(network, "unexpected_project_download", window.target_device)
    if not ews_list or target_hmi is None:
        return []
    ews = ews_list[0]
    rng = _host_hour_rng(seed, ews.name, int(window.start.timestamp()))
    return [_make_ews_project(
        host=ews, ts=window.start, seed=seed, idx=900_000_003, rng=rng,
        network=network, forced_action="download", forced_target=target_hmi,
    )]


def _emit_historian_tag_deletion(
    *, network: OTNetwork, window: AnomalyWindow, seed: int,
) -> list[dict]:
    historian = _pick_anomaly_device(network, "historian_tag_deletion", window.target_device)
    if historian is None:
        return []
    rng = _host_hour_rng(seed, historian.name, int(window.start.timestamp()))
    return [_make_historian_audit(
        host=historian, ts=window.start, seed=seed, idx=900_000_004, rng=rng,
        forced_action="point_delete",
    )]


_ANOMALY_EMITTERS = {
    "off_hours_ews_login": _emit_off_hours_ews_login,
    "unexpected_project_download": _emit_unexpected_project_download,
    "historian_tag_deletion": _emit_historian_tag_deletion,
}


def _emit_anomalies(
    network: OTNetwork,
    anomaly_windows: tuple[AnomalyWindow, ...],
    start: datetime,
    end: datetime,
    seed: int,
) -> list[dict]:
    events: list[dict] = []
    for w in anomaly_windows:
        # Skip anomalies whose window doesn't overlap the corpus window
        # at all -- emitting outside [start, end) would silently violate
        # the window-discipline invariant downstream tests check.
        if w.end <= start or w.start >= end:
            continue
        emitter = _ANOMALY_EMITTERS.get(w.kind)
        if emitter is None:
            raise ValueError(f"unknown anomaly kind {w.kind!r}")
        for ev in emitter(network=network, window=w, seed=seed):
            events.append(ev)
    return events


# --- public entry point ----------------------------------------------------


def generate_for_network(
    network: OTNetwork,
    start: datetime,
    end: datetime,
    *,
    seed: int = 0,
    anomaly_windows: tuple[AnomalyWindow, ...] = (),
) -> Iterator[dict]:
    """Yield OT-host event dicts for an OT network.

    Deterministic given ``(network, start, end, seed, anomaly_windows)``.
    Events are pre-sorted by ``(timestamp, _log, uid)`` so the composer's
    final sort is a no-op for this stream.

    Args:
        network: ``OTNetwork`` from ``ot_protocols.topology.build_ot_network``.
        start: window start (inclusive, naive UTC).
        end: window end (exclusive, naive UTC).
        seed: deterministic seed.
        anomaly_windows: tuple of ``AnomalyWindow`` overlays.
    """
    if end <= start:
        log.info("ot_hosts: empty window, no events")
        return

    logging_devices = [d for d in network.devices if d.role in _LOGGING_ROLES]
    log.info(
        "ot_hosts: generating events for %d hosts window=%s..%s seed=%d anomalies=%d",
        len(logging_devices), start.isoformat(), end.isoformat(), seed, len(anomaly_windows),
    )

    events: list[dict] = []
    for host in logging_devices:
        events.extend(_generate_for_host(host, network, start, end, seed))
    events.extend(_emit_anomalies(network, anomaly_windows, start, end, seed))

    events.sort(key=lambda e: (e["timestamp"], e["_log"], e["uid"]))
    for ev in events:
        yield ev
