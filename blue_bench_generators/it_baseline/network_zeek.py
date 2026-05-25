"""Benign-traffic Zeek-shaped event generator for the IT baseline corpus.

Consumes a ``Topology`` (host/VLAN/service layout) and an
``ActivityModel`` (per-host expected events/hour at a timestamp) and
yields Zeek-shaped event dicts -- conn / dns / http / ssl / files --
for *benign* enterprise traffic.

No C2, no malicious patterns. APT signal is injected separately by the
``c2`` generator; cybercrime foils are produced by ``cybercrime_foil``.
This module emits the everyday background only.

Field shape mirrors ``blue_bench_generators.c2.zeek_emit``: dict per
record, ``_log`` field naming the source log, ``ts`` field as a string
holding epoch seconds (Zeek convention).

Determinism: ``generate(topology, model, start, end, seed)`` is a pure
function of its inputs. Per-hour event counts are sampled with a
seeded ``random.Random`` keyed on (seed, host_index, hour_epoch,
event_class).

Traffic patterns emitted (all benign, vendor-neutral):

* corp-VLAN host -> ``dhcp-dns-server`` host  (DNS queries; udp/53)
* corp-VLAN workstation -> ``file-server``    (SMB; tcp/445)
* corp-VLAN workstation -> ``proxy-server``   (HTTP CONNECT / outbound;
  tcp/3128 with conn + http or ssl)
  -- proxy is required: at S tier (no proxy) outbound web traffic is
  not emitted. Real enterprises at this scale typically route through
  a managed gateway; absence-of-proxy means absence-of-outbound.
* server-VLAN host -> ``domain-controller``   (Kerberos tcp/88, LDAP
  tcp/389; constant low rate)
* ``domain-controller`` -> ``domain-controller``  (replication; constant
  low rate; only when 2+ DCs exist)

Disallowed traffic shapes (the test suite asserts these):

* No conn from corp VLAN to server VLAN on ports other than the
  allowed set {53, 88, 389, 445}.
* No workstation->workstation SMB (no east-west file-share peering;
  spec listed it as "rare" but the contract is "file-server is the
  only tcp/445 responder").
* No conn from corp VLAN directly to DMZ except via proxy (proxy is
  on tcp/3128).

Vendor-neutral: hostnames in DNS / HTTP / SSL records come from the
``.example.invalid`` benign pool. No exercise vocabulary.
"""

from __future__ import annotations

import hashlib
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from blue_bench_generators.it_baseline.behavior import ActivityModel
from blue_bench_generators.it_baseline.topology import Host, Topology

log = logging.getLogger(__name__)


# --- constants -------------------------------------------------------------


# Fraction of ``file_access`` events that produce a network-observable
# new SMB conn record. file_access at file-server is ~2000/hr; most are
# repeated ops on an already-open share. A small fraction creates a new
# tap-visible tcp/445 conn. This converts the per-op rate to a
# per-network-conn rate.
SMB_CONN_OBSERVABILITY_FRACTION: float = 0.03

# Fraction of ``http_request`` events that materialise as a separate
# ssl.log record (HTTPS) vs. an http.log record (cleartext via proxy).
# Most modern outbound web is HTTPS; we keep a small cleartext slice so
# both log types appear in the corpus.
HTTPS_FRACTION: float = 0.85

# Constant per-server rates for server->DC traffic. These are not
# driven by the activity model (none of its event classes maps cleanly
# to "server hits the DC for a Kerberos TGT"); a fixed low cadence
# reflects how often AD-joined servers refresh tickets / look up
# directory entries.
SERVER_TO_DC_KERBEROS_PER_HOUR: float = 4.0  # tcp/88
SERVER_TO_DC_LDAP_PER_HOUR: float = 6.0  # tcp/389

# DC<->DC replication cadence (per ordered DC pair, per hour).
DC_REPLICATION_PER_HOUR: float = 12.0

# Ports we allow corp-VLAN -> server-VLAN. Anything else from corp is
# either workstation->workstation (forbidden), workstation->DMZ-proxy
# (allowed via proxy port), or workstation->Internet (also via proxy).
CORP_TO_SERVER_ALLOWED_PORTS: frozenset[int] = frozenset({53, 88, 389, 445})

# Proxy port (matches the topology service definition).
PROXY_PORT: int = 3128

# Benign Internet hostnames for DNS / HTTP host / SSL SNI. Vendor-
# neutral, all under ``.example.invalid``. Mix of CDN/update/mail/news
# shapes so the corpus is not monotone.
BENIGN_DNS_POOL: tuple[str, ...] = (
    "corp-cdn.example.invalid",
    "internal-mail.example.invalid",
    "update.example.invalid",
    "news.example.invalid",
    "static.example.invalid",
    "api.example.invalid",
    "files.example.invalid",
    "ts.example.invalid",
    "stats.example.invalid",
    "cdn-edge.example.invalid",
)

# A small set of internal short names that workstations also resolve
# (file-server / DC / proxy by FQDN). The topology already names hosts
# under ``corp.example.invalid``; we reuse those names per-corpus
# rather than hard-coding them here.

# Browser-shaped User-Agent for benign HTTP.
_BENIGN_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


# --- internal helpers ------------------------------------------------------


@dataclass(frozen=True)
class _HourSlot:
    """A single (host, event_class, hour) materialisation slot.

    Carries the hour-start timestamp + the count of events drawn for
    that slot. Counts are produced by the seeded RNG; downstream
    emission spreads them across the hour deterministically.
    """

    host_index: int
    event_class: str
    hour_start: datetime
    count: int


def _hour_floor(ts: datetime) -> datetime:
    """Round down to the hour."""
    return ts.replace(minute=0, second=0, microsecond=0)


def _rng_for(seed: int, *parts: int | str) -> random.Random:
    """Derive a stable RNG from (seed, *parts).

    Uses sha256 of the concatenation so the produced stream is
    independent of any other (seed, parts) tuple -- avoids the
    well-known XOR-collision pitfalls of ``seed ^ host_index``.
    """
    payload = "|".join([str(seed), *(str(p) for p in parts)]).encode()
    digest = hashlib.sha256(payload).digest()
    # Use the first 8 bytes as a 64-bit seed for Random().
    return random.Random(int.from_bytes(digest[:8], "big"))


def _draw_count(rng: random.Random, expected: float) -> int:
    """Draw an integer count from an expected per-hour rate.

    ``int(expected)`` for the whole-event part plus a Bernoulli draw on
    the fractional remainder. Cheaper than a true Poisson and
    sufficient for "events expected per hour" semantics where we just
    need the per-hour total to track the rate.
    """
    if expected <= 0.0:
        return 0
    whole = int(expected)
    frac = expected - whole
    if frac > 0.0 and rng.random() < frac:
        whole += 1
    return whole


def _uid(seed: int, *parts: int | str) -> str:
    """Zeek-style UID. ``C`` prefix for conn-like, mirroring c2/zeek_emit."""
    payload = "|".join([str(seed), *(str(p) for p in parts)]).encode()
    return "C" + hashlib.sha256(payload).hexdigest()[:12]


def _fuid(seed: int, *parts: int | str) -> str:
    payload = "|".join([str(seed), *(str(p) for p in parts)]).encode()
    return "F" + hashlib.sha256(payload).hexdigest()[:12]


def _ts_str(ts: datetime) -> str:
    return f"{ts.timestamp():.6f}"


def _spread_in_hour(
    rng: random.Random, hour_start: datetime, count: int
) -> list[datetime]:
    """Deterministically scatter ``count`` timestamps inside the hour.

    Uniform across the hour; sorted ascending so the emitted stream is
    chronologically clean per (host, class).
    """
    if count <= 0:
        return []
    offsets = sorted(rng.random() for _ in range(count))
    return [
        hour_start + timedelta(seconds=int(off * 3600)) for off in offsets
    ]


def _hosts_by_role(topology: Topology) -> dict[str, list[Host]]:
    by_role: dict[str, list[Host]] = {}
    for h in topology.hosts:
        by_role.setdefault(h.role, []).append(h)
    return by_role


def _host_index(topology: Topology, host: Host) -> int:
    """Stable index of ``host`` in the topology's host tuple."""
    return topology.hosts.index(host)


def _src_port(rng: random.Random) -> int:
    """Pick a deterministic ephemeral source port."""
    return rng.randint(49152, 65535)


# --- record emitters -------------------------------------------------------


def _emit_dns_record(
    *,
    ts: datetime,
    src: Host,
    dst: Host,
    query: str,
    answer_ip: str,
    seed: int,
    sequence: int,
) -> dict:
    return {
        "_log": "dns",
        "ts": _ts_str(ts),
        "uid": _uid(seed, "dns", sequence),
        "id.orig_h": src.ip,
        "id.orig_p": str(_rng_for(seed, "dns-port", sequence).randint(49152, 65535)),
        "id.resp_h": dst.ip,
        "id.resp_p": "53",
        "proto": "udp",
        "query": query,
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "answers": answer_ip,
    }


def _emit_conn_record(
    *,
    ts: datetime,
    src: Host,
    dst: Host,
    dst_port: int,
    proto: str,
    service: str,
    seed: int,
    sequence: int,
    bytes_orig: int = 512,
    bytes_resp: int = 4096,
) -> dict:
    return {
        "_log": "conn",
        "ts": _ts_str(ts),
        "uid": _uid(seed, "conn", service, sequence),
        "id.orig_h": src.ip,
        "id.orig_p": str(_rng_for(seed, "conn-port", sequence, service).randint(49152, 65535)),
        "id.resp_h": dst.ip,
        "id.resp_p": str(dst_port),
        "proto": proto,
        "service": service,
        "orig_bytes": str(bytes_orig),
        "resp_bytes": str(bytes_resp),
        "conn_state": "SF",
        "history": "ShADadFf",
    }


def _emit_http_record(
    *,
    ts: datetime,
    src: Host,
    dst: Host,
    host_header: str,
    uri: str,
    seed: int,
    sequence: int,
) -> dict:
    return {
        "_log": "http",
        "ts": _ts_str(ts),
        "uid": _uid(seed, "http", sequence),
        "id.orig_h": src.ip,
        "id.orig_p": str(_rng_for(seed, "http-port", sequence).randint(49152, 65535)),
        "id.resp_h": dst.ip,
        "id.resp_p": str(PROXY_PORT),
        "method": "GET",
        "host": host_header,
        "uri": uri,
        "user_agent": _BENIGN_USER_AGENT,
        "status_code": "200",
        "request_body_len": "0",
        "response_body_len": "4096",
    }


def _emit_ssl_record(
    *,
    ts: datetime,
    src: Host,
    dst: Host,
    sni: str,
    seed: int,
    sequence: int,
) -> dict:
    return {
        "_log": "ssl",
        "ts": _ts_str(ts),
        "uid": _uid(seed, "ssl", sequence),
        "id.orig_h": src.ip,
        "id.orig_p": str(_rng_for(seed, "ssl-port", sequence).randint(49152, 65535)),
        "id.resp_h": dst.ip,
        "id.resp_p": str(PROXY_PORT),
        "version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "server_name": sni,
        "established": "T",
    }


def _emit_files_record(
    *,
    ts: datetime,
    src: Host,
    dst: Host,
    seed: int,
    sequence: int,
    size: int = 8192,
) -> dict:
    """SMB file-access files.log row.

    Emitted alongside SMB conn records to mirror the c2 generator's
    files-log shape. Source is "SMB" rather than "HTTP".
    """
    return {
        "_log": "files",
        "ts": _ts_str(ts),
        "fuid": _fuid(seed, "files", sequence),
        "tx_hosts": dst.ip,
        "rx_hosts": src.ip,
        "source": "SMB",
        "depth": "0",
        "analyzers": "SHA256",
        "mime_type": "application/octet-stream",
        "sha256": hashlib.sha256(
            f"benign-smb-{seed}-{sequence}".encode()
        ).hexdigest(),
        "seen_bytes": str(size),
        "total_bytes": str(size),
    }


# --- per-hour traffic shapes -----------------------------------------------


def _emit_dns_traffic(
    *,
    topology: Topology,
    model: ActivityModel,
    host: Host,
    hour_start: datetime,
    seed: int,
    sequence_base: int,
    dns_servers: list[Host],
) -> Iterator[dict]:
    if not dns_servers:
        return
    rate = model.rate(host, "dns_query", hour_start)
    if rate <= 0.0:
        return
    rng = _rng_for(seed, "dns", _host_index(topology, host), int(hour_start.timestamp()))
    count = _draw_count(rng, rate)
    if count <= 0:
        return
    timestamps = _spread_in_hour(rng, hour_start, count)
    host_idx = _host_index(topology, host)
    for i, ts in enumerate(timestamps):
        # Round-robin DNS server deterministically from host+sequence
        dns_server = dns_servers[(host_idx + i) % len(dns_servers)]
        query = BENIGN_DNS_POOL[(host_idx + i) % len(BENIGN_DNS_POOL)]
        # Synthetic answer IP in TEST-NET-3 (203.0.113.0/24) keeps the
        # corpus free of real Internet addresses.
        answer_ip = f"203.0.113.{((host_idx * 7 + i) % 250) + 1}"
        yield _emit_dns_record(
            ts=ts,
            src=host,
            dst=dns_server,
            query=query,
            answer_ip=answer_ip,
            seed=seed,
            sequence=sequence_base + i,
        )


def _emit_smb_traffic(
    *,
    topology: Topology,
    model: ActivityModel,
    host: Host,
    hour_start: datetime,
    seed: int,
    sequence_base: int,
    file_servers: list[Host],
) -> Iterator[dict]:
    """Workstation -> file-server SMB conn + files events.

    Only emitted from corp-VLAN workstations (workstation +
    admin-workstation). file_access rate from the activity model is
    multiplied by ``SMB_CONN_OBSERVABILITY_FRACTION`` to convert from
    per-op to per-new-conn.
    """
    if not file_servers:
        return
    if host.vlan != "corp":
        return
    if host.role not in ("workstation", "admin-workstation"):
        return
    raw_rate = model.rate(host, "file_access", hour_start)
    rate = raw_rate * SMB_CONN_OBSERVABILITY_FRACTION
    if rate <= 0.0:
        return
    rng = _rng_for(topology.seed ^ seed, "smb", _host_index(topology, host), int(hour_start.timestamp()))
    count = _draw_count(rng, rate)
    if count <= 0:
        return
    timestamps = _spread_in_hour(rng, hour_start, count)
    host_idx = _host_index(topology, host)
    for i, ts in enumerate(timestamps):
        fs = file_servers[(host_idx + i) % len(file_servers)]
        seq = sequence_base + i
        yield _emit_conn_record(
            ts=ts,
            src=host,
            dst=fs,
            dst_port=445,
            proto="tcp",
            service="smb",
            seed=seed,
            sequence=seq,
            bytes_orig=4096,
            bytes_resp=16384,
        )
        # Approximately every other SMB conn carries a files.log row
        # (mirroring the c2 generator's pairing of conn + files for
        # cleartext byte-visible payloads; SMB is cleartext on a tap).
        if i % 2 == 0:
            yield _emit_files_record(
                ts=ts,
                src=host,
                dst=fs,
                seed=seed,
                sequence=seq,
            )


def _emit_outbound_web_traffic(
    *,
    topology: Topology,
    model: ActivityModel,
    host: Host,
    hour_start: datetime,
    seed: int,
    sequence_base: int,
    proxy_servers: list[Host],
) -> Iterator[dict]:
    """Workstation -> proxy outbound web (conn + http or ssl).

    Routed via proxy in all tiers that have one. At S tier (no proxy)
    this generator emits nothing: no proxy means no outbound web shape
    we can faithfully attribute to a tap-visible enterprise gateway.
    """
    if not proxy_servers:
        return
    if host.vlan != "corp":
        return
    if host.role not in ("workstation", "admin-workstation"):
        return
    rate = model.rate(host, "http_request", hour_start)
    if rate <= 0.0:
        return
    rng = _rng_for(seed, "web", _host_index(topology, host), int(hour_start.timestamp()))
    count = _draw_count(rng, rate)
    if count <= 0:
        return
    timestamps = _spread_in_hour(rng, hour_start, count)
    host_idx = _host_index(topology, host)
    for i, ts in enumerate(timestamps):
        proxy = proxy_servers[(host_idx + i) % len(proxy_servers)]
        sni = BENIGN_DNS_POOL[(host_idx * 3 + i) % len(BENIGN_DNS_POOL)]
        seq = sequence_base + i
        # Always emit a conn record for the workstation->proxy hop.
        yield _emit_conn_record(
            ts=ts,
            src=host,
            dst=proxy,
            dst_port=PROXY_PORT,
            proto="tcp",
            service="http",
            seed=seed,
            sequence=seq,
            bytes_orig=512,
            bytes_resp=8192,
        )
        # HTTPS vs HTTP split: most modern web is HTTPS.
        is_https = rng.random() < HTTPS_FRACTION
        if is_https:
            yield _emit_ssl_record(
                ts=ts,
                src=host,
                dst=proxy,
                sni=sni,
                seed=seed,
                sequence=seq,
            )
        else:
            yield _emit_http_record(
                ts=ts,
                src=host,
                dst=proxy,
                host_header=sni,
                uri=f"/path/{seq % 100}",
                seed=seed,
                sequence=seq,
            )


def _emit_server_to_dc_traffic(
    *,
    topology: Topology,
    host: Host,
    hour_start: datetime,
    seed: int,
    sequence_base: int,
    dcs: list[Host],
) -> Iterator[dict]:
    """server-VLAN non-DC host -> DC Kerberos + LDAP, low constant cadence."""
    if not dcs:
        return
    if host.vlan != "server":
        return
    if host.role == "domain-controller":
        # DC<->DC is handled separately.
        return
    rng = _rng_for(seed, "srv-dc", _host_index(topology, host), int(hour_start.timestamp()))
    host_idx = _host_index(topology, host)
    # Kerberos tcp/88
    krb_count = _draw_count(rng, SERVER_TO_DC_KERBEROS_PER_HOUR)
    for i, ts in enumerate(_spread_in_hour(rng, hour_start, krb_count)):
        dc = dcs[(host_idx + i) % len(dcs)]
        yield _emit_conn_record(
            ts=ts,
            src=host,
            dst=dc,
            dst_port=88,
            proto="tcp",
            service="krb",
            seed=seed,
            sequence=sequence_base + i,
            bytes_orig=1024,
            bytes_resp=2048,
        )
    # LDAP tcp/389
    ldap_count = _draw_count(rng, SERVER_TO_DC_LDAP_PER_HOUR)
    for i, ts in enumerate(_spread_in_hour(rng, hour_start, ldap_count)):
        dc = dcs[(host_idx + i + 1) % len(dcs)]
        yield _emit_conn_record(
            ts=ts,
            src=host,
            dst=dc,
            dst_port=389,
            proto="tcp",
            service="ldap",
            seed=seed,
            sequence=sequence_base + 10000 + i,
            bytes_orig=2048,
            bytes_resp=4096,
        )


def _emit_dc_replication_traffic(
    *,
    topology: Topology,
    hour_start: datetime,
    seed: int,
    sequence_base: int,
    dcs: list[Host],
) -> Iterator[dict]:
    """DC <-> DC replication on tcp/389. Only when 2+ DCs."""
    if len(dcs) < 2:
        return
    rng = _rng_for(seed, "dc-repl", int(hour_start.timestamp()))
    seq = sequence_base
    # Each ordered pair replicates at the configured rate.
    for src in dcs:
        for dst in dcs:
            if src is dst:
                continue
            count = _draw_count(rng, DC_REPLICATION_PER_HOUR)
            for ts in _spread_in_hour(rng, hour_start, count):
                yield _emit_conn_record(
                    ts=ts,
                    src=src,
                    dst=dst,
                    dst_port=389,
                    proto="tcp",
                    service="ldap",
                    seed=seed,
                    sequence=seq,
                    bytes_orig=4096,
                    bytes_resp=4096,
                )
                seq += 1


# --- public API ------------------------------------------------------------


def generate(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Yield Zeek-shaped event dicts for benign enterprise traffic.

    Per hour in ``[start, end)``, per host, expected event counts are
    drawn from ``activity_model.rate(host, event_class, hour_start)``
    and materialised as conn / dns / http / ssl / files records.

    Args:
        topology: enterprise topology (hosts, VLANs, services).
        activity_model: per-(host, event_class, ts) expected-rate
            function.
        start: window start (inclusive).
        end: window end (exclusive).
        seed: RNG seed. Same (topology, model, start, end, seed) ALWAYS
            yields the same records.

    Yields:
        dicts shaped like ``conn.log`` / ``dns.log`` / ``http.log`` /
        ``ssl.log`` / ``files.log`` rows. Each dict has a ``_log`` key
        naming the source log and a ``ts`` key (epoch seconds string,
        Zeek convention).
    """
    if end <= start:
        log.warning(
            "network_zeek.generate called with end<=start (%s <= %s); no events emitted",
            end,
            start,
        )
        return

    by_role = _hosts_by_role(topology)
    dns_servers = by_role.get("dhcp-dns-server", [])
    file_servers = by_role.get("file-server", [])
    proxy_servers = by_role.get("proxy-server", [])
    dcs = by_role.get("domain-controller", [])

    log.info(
        "network_zeek.generate: tier=%s hosts=%d dns=%d files=%d proxies=%d dcs=%d",
        topology.tier,
        len(topology.hosts),
        len(dns_servers),
        len(file_servers),
        len(proxy_servers),
        len(dcs),
    )

    # Iterate by hour. Per-hour, per-host emission keeps memory bounded
    # and lets the seeded RNG be derived from (seed, host_index, hour).
    cursor = _hour_floor(start)
    # Start from the first hour fully or partially inside the window;
    # any event we emit will then be filtered to fall inside [start, end).
    if cursor < start:
        # cursor is already a floor(<=start); only equal when start is on
        # the hour boundary, so this branch is currently unreachable, but
        # left explicit for future contributors.
        pass

    one_hour = timedelta(hours=1)
    sequence_counter = 0

    while cursor < end:
        for host in topology.hosts:
            host_idx = _host_index(topology, host)
            # Use a wide-enough sequence stride per host+hour to avoid
            # UID collisions across event classes.
            base = sequence_counter
            sequence_counter += 100_000

            for ev in _emit_dns_traffic(
                topology=topology,
                model=activity_model,
                host=host,
                hour_start=cursor,
                seed=seed,
                sequence_base=base,
                dns_servers=dns_servers,
            ):
                if _in_window(ev, start, end):
                    yield ev

            for ev in _emit_smb_traffic(
                topology=topology,
                model=activity_model,
                host=host,
                hour_start=cursor,
                seed=seed,
                sequence_base=base + 20_000,
                file_servers=file_servers,
            ):
                if _in_window(ev, start, end):
                    yield ev

            for ev in _emit_outbound_web_traffic(
                topology=topology,
                model=activity_model,
                host=host,
                hour_start=cursor,
                seed=seed,
                sequence_base=base + 40_000,
                proxy_servers=proxy_servers,
            ):
                if _in_window(ev, start, end):
                    yield ev

            for ev in _emit_server_to_dc_traffic(
                topology=topology,
                host=host,
                hour_start=cursor,
                seed=seed,
                sequence_base=base + 60_000,
                dcs=dcs,
            ):
                if _in_window(ev, start, end):
                    yield ev

            _ = host_idx  # reserved for future per-host metrics

        # DC<->DC replication, once per hour, independent of per-host loop.
        for ev in _emit_dc_replication_traffic(
            topology=topology,
            hour_start=cursor,
            seed=seed,
            sequence_base=sequence_counter,
            dcs=dcs,
        ):
            if _in_window(ev, start, end):
                yield ev
        sequence_counter += 100_000

        cursor = cursor + one_hour


def _in_window(event: dict, start: datetime, end: datetime) -> bool:
    """Filter a record to [start, end) by its ``ts`` field."""
    ts_epoch = float(event["ts"])
    start_epoch = start.timestamp()
    end_epoch = end.timestamp()
    return start_epoch <= ts_epoch < end_epoch
