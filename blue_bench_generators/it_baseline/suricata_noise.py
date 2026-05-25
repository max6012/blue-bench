"""Suricata benign IDS-noise generator for the IT baseline corpus.

Emits ``eve.json``-shaped event dicts (``flow``, ``dns``, ``tls``,
``http``, plus the occasional low-severity ``alert``) that match what a
real Suricata install produces on **benign** enterprise traffic.

Critical design property: NO alerts on actually-malicious patterns. The
small low-severity rule pool covers things like a curl User-Agent, a
high-entropy SNI, or an internal port scan from an admin workstation --
realistic-but-uninteresting noise the analyst-LLM must filter past.
Alerts on cybercrime / APT families belong to the ``c2`` and
``cybercrime_foil`` generators, not here.

Volume is driven by the ``ActivityModel`` rates (``network_connection``,
``dns_query``, ``http_request``); per-hour event counts are quantised
from the per-hour rate via integer floor + Bernoulli on the fraction.
Timestamps are placed uniformly inside ``[hour, hour+1)`` and clipped to
the global ``[start, end)`` window.

Deterministic. Same ``(topology, activity_model, start, end, seed,
alert_ratio)`` always produces an identical event stream. RNG is seeded
via SHA-256 of a stable string -- never ``hash()`` (process-salt) and
never module-level ``random``.

Vendor-neutral; no exercise vocabulary anywhere.
"""

from __future__ import annotations

import hashlib
import logging
import random
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from blue_bench_generators.it_baseline.behavior import ActivityModel
from blue_bench_generators.it_baseline.topology import Host, Topology

log = logging.getLogger(__name__)


# --- benign rule pool ------------------------------------------------------
#
# Low-severity ET-Open-style families. NONE of these name a malware
# family, APT, or cybercrime tool. The tests assert this with a denylist
# against the c2 / cybercrime_foil signature vocabulary.

_BENIGN_RULE_SIGNATURES: tuple[str, ...] = (
    "ET INFO Suspicious User-Agent (curl)",
    "ET INFO HTTP/1.1 GET without Host Header",
    "ET POLICY Outbound TLS to High-Entropy SNI",
    "ET INFO Possible Port Scan from Internal Host",
    "ET INFO PE EXE or DLL Windows file download",
)


_BENIGN_DOMAINS: tuple[str, ...] = (
    "updates.example.com",
    "telemetry.example.net",
    "api.example.org",
    "cdn.example.com",
    "ntp.example.net",
    "ocsp.example.com",
    "mail.example.org",
    "intranet.corp.example.invalid",
    "vpn.example.com",
    "metrics.example.net",
)


_BENIGN_SNIS: tuple[str, ...] = (
    "updates.example.com",
    "telemetry.example.net",
    "api.example.org",
    "cdn.example.com",
    "auth.example.org",
    "metrics.example.net",
)


_BENIGN_HTTP_HOSTS: tuple[str, ...] = (
    "intranet.corp.example.invalid",
    "wiki.corp.example.invalid",
    "tickets.corp.example.invalid",
    "files.corp.example.invalid",
)


_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/7.88.1",
    "WindowsUpdateAgent/10.0",
    "Microsoft-Delivery-Optimization/10.0",
)


# Vendor-neutral external destinations from RFC5737 documentation
# blocks. NEVER use a real public IP.
_EXTERNAL_DESTS: tuple[str, ...] = (
    "203.0.113.10",
    "203.0.113.25",
    "203.0.113.40",
    "203.0.113.55",
    "198.51.100.20",
    "198.51.100.45",
    "192.0.2.80",
    "192.0.2.120",
)


# Where Suricata claims DNS goes. The dhcp-dns-server in topology lives
# at the bucket subnet first-host slot; we don't insist on a match here,
# we just need a stable resolver-shaped destination.
_RESOLVER_IP = "192.0.2.53"


# Ratio of cleartext HTTP vs TLS among http_request-class events. Most
# enterprise outbound is HTTPS; we keep cleartext small and roughly
# matching reality (intranet-only).
_HTTP_CLEARTEXT_FRACTION = 0.15


def _sha256_seed(*parts: str | int) -> int:
    """Stable 63-bit seed from arbitrary parts. Never uses ``hash()``."""
    joined = "\x1f".join(str(p) for p in parts)
    digest = hashlib.sha256(joined.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") & 0x7FFF_FFFF_FFFF_FFFF


def _rng_for(host: Host, hour_index: int, channel: str, seed: int) -> random.Random:
    """Per-host, per-hour, per-event-class RNG."""
    return random.Random(_sha256_seed(seed, host.name, hour_index, channel))


def _flow_id(seed: int, host_name: str, hour_index: int, channel: str, idx: int) -> int:
    return _sha256_seed(seed, host_name, hour_index, channel, idx)


def _bernoulli_count(rate: float, rng: random.Random) -> int:
    """Floor of rate + Bernoulli on the fractional part."""
    if rate <= 0.0:
        return 0
    whole = int(rate)
    frac = rate - whole
    if frac > 0.0 and rng.random() < frac:
        whole += 1
    return whole


def _eve_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _place_in_hour(
    count: int,
    hour_start: datetime,
    hour_end: datetime,
    rng: random.Random,
) -> list[datetime]:
    """Uniformly place ``count`` timestamps in [hour_start, hour_end)."""
    if count <= 0:
        return []
    span = (hour_end - hour_start).total_seconds()
    out = [
        hour_start + timedelta(seconds=rng.random() * span) for _ in range(count)
    ]
    out.sort()
    return out


def _pick_dest_ip(rng: random.Random, topology: Topology) -> str:
    """Half internal, half external. Internal pulled from topology."""
    if rng.random() < 0.5 and topology.hosts:
        h = rng.choice(topology.hosts)
        return h.ip
    return rng.choice(_EXTERNAL_DESTS)


def _make_flow(
    *,
    host: Host,
    ts: datetime,
    flow_id: int,
    dest_ip: str,
    dest_port: int,
    proto: str,
    rng: random.Random,
) -> dict:
    src_port = 30000 + rng.randrange(0, 35000)
    payload_to = 200 + rng.randrange(0, 5000)
    payload_from = 200 + rng.randrange(0, 5000)
    return {
        "_log": "eve",
        "timestamp": _eve_ts(ts),
        "flow_id": flow_id,
        "event_type": "flow",
        "src_ip": host.ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "flow": {
            "pkts_toserver": 5 + rng.randrange(0, 20),
            "pkts_toclient": 4 + rng.randrange(0, 20),
            "bytes_toserver": payload_to,
            "bytes_toclient": payload_from,
            "start": _eve_ts(ts),
            "end": _eve_ts(ts),
            "state": "established",
            "reason": "timeout",
        },
    }


def _make_dns(
    *, host: Host, ts: datetime, flow_id: int, rng: random.Random
) -> dict:
    rrname = rng.choice(_BENIGN_DOMAINS)
    src_port = 30000 + rng.randrange(0, 35000)
    return {
        "_log": "eve",
        "timestamp": _eve_ts(ts),
        "flow_id": flow_id,
        "event_type": "dns",
        "src_ip": host.ip,
        "src_port": src_port,
        "dest_ip": _RESOLVER_IP,
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "rrname": rrname,
            "rrtype": "A",
        },
    }


def _make_tls(
    *,
    host: Host,
    ts: datetime,
    flow_id: int,
    dest_ip: str,
    rng: random.Random,
) -> dict:
    src_port = 30000 + rng.randrange(0, 35000)
    sni = rng.choice(_BENIGN_SNIS)
    return {
        "_log": "eve",
        "timestamp": _eve_ts(ts),
        "flow_id": flow_id,
        "event_type": "tls",
        "src_ip": host.ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": 443,
        "proto": "TCP",
        "tls": {
            "sni": sni,
            "version": "TLS 1.3",
            "fingerprint_hint": "benign-baseline",
        },
    }


def _make_http(
    *,
    host: Host,
    ts: datetime,
    flow_id: int,
    dest_ip: str,
    rng: random.Random,
) -> dict:
    src_port = 30000 + rng.randrange(0, 35000)
    hostname = rng.choice(_BENIGN_HTTP_HOSTS)
    user_agent = rng.choice(_USER_AGENTS)
    method = rng.choice(("GET", "GET", "GET", "POST"))
    return {
        "_log": "eve",
        "timestamp": _eve_ts(ts),
        "flow_id": flow_id,
        "event_type": "http",
        "src_ip": host.ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": 80,
        "proto": "TCP",
        "http": {
            "hostname": hostname,
            "url": "/index.html",
            "http_user_agent": user_agent,
            "http_method": method,
            "protocol": "HTTP/1.1",
            "status": 200,
            "length": 200 + rng.randrange(0, 5000),
        },
    }


def _make_alert(
    *,
    host: Host,
    ts: datetime,
    flow_id: int,
    src_port: int,
    signature: str,
    dest_ip: str,
    dest_port: int,
    proto: str,
    rng: random.Random,
) -> dict:
    """Build an ``alert`` eve record. ``flow_id`` and ``src_port`` are
    threaded in from the anchor flow so the 5-tuple correlation key an
    analyst would use (alert.flow_id == flow.flow_id AND matching
    src_port) actually resolves to the flow record that exists in this
    same emit batch. ``rng`` is unused on the alert hot-path; kept in
    the signature for symmetry with the other ``_make_*`` helpers.
    """
    _ = rng
    return {
        "_log": "eve",
        "timestamp": _eve_ts(ts),
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": host.ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "sid": 0,  # benign-noise rules are not fabricated with real sids
            "rev": 1,
            "signature": signature,
            "category": "Misc activity",
            "severity": 3,
            "rule_name": signature,
        },
    }


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def generate(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int = 0,
    alert_ratio: float = 0.01,
) -> Iterable[dict]:
    """Yield eve.json-shaped dicts. Deterministic given inputs.

    Walks the corpus window in 1-hour buckets. For each (host, hour):
    derives expected counts from ``ActivityModel`` rates, samples them
    with a per-(host, hour, channel) RNG, places timestamps uniformly
    inside the bucket clipped to ``[start, end)``, and emits ``flow``,
    ``dns``, ``tls``, ``http`` records. Low-severity ``alert`` events
    are sampled at ``alert_ratio`` per flow, with a hard cap of one
    alert per ``(host, hour, signature)`` to prevent dedup throttling
    from producing dense bursts.

    Args:
        topology: the corpus topology.
        activity_model: rate source.
        start: window start, inclusive.
        end: window end, exclusive. If ``end <= start``, yields nothing.
        seed: deterministic stream seed.
        alert_ratio: alerts per flow. Default 0.01; the dedup cap means
            very flow-heavy fixtures may realise a slightly lower
            ratio, but tests allow +-50% on small windows.

    Yields:
        eve.json-shaped dicts in increasing-time order per (host, hour),
        across all hosts.
    """
    if end <= start:
        log.info("suricata_noise.generate: empty window, end <= start")
        return
    if alert_ratio < 0.0 or alert_ratio > 1.0:
        raise ValueError(
            f"alert_ratio must be in [0.0, 1.0]; got {alert_ratio!r}"
        )

    log.info(
        "suricata_noise.generate: tier=%s hosts=%d window=%s..%s seed=%d alert_ratio=%.4f",
        topology.tier,
        len(topology.hosts),
        start.isoformat(),
        end.isoformat(),
        seed,
        alert_ratio,
    )

    # Walk hour buckets. ``hour_index`` is a monotonic integer for the
    # bucket (used in RNG seeds). The bucket window is
    # [hour_start, hour_end), clipped to the overall [start, end).
    hour_start = _hour_floor(start)
    hour_index = 0
    while hour_start < end:
        next_hour = hour_start + timedelta(hours=1)
        clip_start = max(hour_start, start)
        clip_end = min(next_hour, end)
        if clip_end <= clip_start:
            hour_start = next_hour
            hour_index += 1
            continue
        # Hour-length scale factor to apply to rates (rates are per-hour
        # at multiplier 1.0; if the bucket is clipped to a fraction of
        # an hour at window edges, scale rates by that fraction).
        hour_scale = (clip_end - clip_start).total_seconds() / 3600.0

        for host in topology.hosts:
            yield from _emit_host_hour(
                host=host,
                activity_model=activity_model,
                hour_start=clip_start,
                hour_end=clip_end,
                hour_index=hour_index,
                hour_scale=hour_scale,
                seed=seed,
                alert_ratio=alert_ratio,
                topology=topology,
            )

        hour_start = next_hour
        hour_index += 1


def _emit_host_hour(
    *,
    host: Host,
    activity_model: ActivityModel,
    hour_start: datetime,
    hour_end: datetime,
    hour_index: int,
    hour_scale: float,
    seed: int,
    alert_ratio: float,
    topology: Topology,
) -> Iterator[dict]:
    # Rates per hour at the bucket start. Volume responds to time-of-day
    # because ActivityModel already encodes the multiplier.
    conn_rate = activity_model.rate(host, "network_connection", hour_start)
    dns_rate = activity_model.rate(host, "dns_query", hour_start)
    http_rate = activity_model.rate(host, "http_request", hour_start)

    # Scale-down knobs. Suricata is sampling at the tap; emit a fraction
    # of the activity-model rate so the per-corpus volume stays sane.
    # These are arbitrary v1 fractions: tunable later via config.
    flow_scale = 0.30
    dns_scale = 0.40
    tls_scale = 0.50
    http_scale = 0.50

    rng_flow = _rng_for(host, hour_index, "flow", seed)
    rng_dns = _rng_for(host, hour_index, "dns", seed)
    rng_tls = _rng_for(host, hour_index, "tls", seed)
    rng_http = _rng_for(host, hour_index, "http", seed)
    rng_alert = _rng_for(host, hour_index, "alert", seed)

    n_flows = _bernoulli_count(conn_rate * flow_scale * hour_scale, rng_flow)
    n_dns = _bernoulli_count(dns_rate * dns_scale * hour_scale, rng_dns)
    # http_request rate covers BOTH HTTP and HTTPS connections in the
    # activity model. Split into tls (majority) and cleartext http.
    n_https = _bernoulli_count(
        http_rate * tls_scale * (1.0 - _HTTP_CLEARTEXT_FRACTION) * hour_scale,
        rng_tls,
    )
    n_http = _bernoulli_count(
        http_rate * http_scale * _HTTP_CLEARTEXT_FRACTION * hour_scale,
        rng_http,
    )

    flow_times = _place_in_hour(n_flows, hour_start, hour_end, rng_flow)
    dns_times = _place_in_hour(n_dns, hour_start, hour_end, rng_dns)
    tls_times = _place_in_hour(n_https, hour_start, hour_end, rng_tls)
    http_times = _place_in_hour(n_http, hour_start, hour_end, rng_http)

    flow_records: list[dict] = []
    for idx, ts in enumerate(flow_times):
        dest_ip = _pick_dest_ip(rng_flow, topology)
        # Most flows are TCP. UDP minority.
        proto = "TCP" if rng_flow.random() < 0.85 else "UDP"
        # Vary dest port for non-app flows.
        dest_port = rng_flow.choice((445, 139, 3389, 22, 25, 587, 993, 8080, 8443))
        fid = _flow_id(seed, host.name, hour_index, "flow", idx)
        flow_records.append(
            _make_flow(
                host=host,
                ts=ts,
                flow_id=fid,
                dest_ip=dest_ip,
                dest_port=dest_port,
                proto=proto,
                rng=rng_flow,
            )
        )

    dns_records: list[dict] = []
    for idx, ts in enumerate(dns_times):
        fid = _flow_id(seed, host.name, hour_index, "dns", idx)
        dns_records.append(
            _make_dns(host=host, ts=ts, flow_id=fid, rng=rng_dns)
        )

    tls_records: list[dict] = []
    for idx, ts in enumerate(tls_times):
        dest_ip = _pick_dest_ip(rng_tls, topology)
        fid = _flow_id(seed, host.name, hour_index, "tls", idx)
        tls_records.append(
            _make_tls(
                host=host, ts=ts, flow_id=fid, dest_ip=dest_ip, rng=rng_tls
            )
        )

    http_records: list[dict] = []
    for idx, ts in enumerate(http_times):
        # Cleartext HTTP is intranet-only; pick an internal host.
        if topology.hosts:
            dest_ip = rng_http.choice(topology.hosts).ip
        else:
            dest_ip = "10.10.0.1"
        fid = _flow_id(seed, host.name, hour_index, "http", idx)
        http_records.append(
            _make_http(
                host=host, ts=ts, flow_id=fid, dest_ip=dest_ip, rng=rng_http
            )
        )

    # Alerts: sampled per-flow at alert_ratio, capped at one per
    # (host, hour, signature). Each fired alert pegs to a real flow's
    # 5-tuple (we take the flow's index in flow_records and re-emit
    # under the same dest/proto so alerts are anchored to real traffic).
    alerts_emitted: set[str] = set()
    alert_records: list[dict] = []
    for idx in range(n_flows):
        if rng_alert.random() >= alert_ratio:
            continue
        sig = rng_alert.choice(_BENIGN_RULE_SIGNATURES)
        if sig in alerts_emitted:
            continue
        alerts_emitted.add(sig)
        # Anchor to the corresponding flow record where possible. The
        # alert MUST inherit flow_id + src_port from the anchor (not
        # synthesise its own) so the 5-tuple correlation key analysts
        # use resolves to a flow record that exists in this batch.
        if idx < len(flow_records):
            anchor = flow_records[idx]
            ts_anchor = flow_times[idx]
            dest_ip = anchor["dest_ip"]
            dest_port = anchor["dest_port"]
            proto = anchor["proto"]
            fid = anchor["flow_id"]
            src_port = anchor["src_port"]
        else:
            # Defensive: shouldn't happen because n_flows == len(flow_records).
            # Falls back to a synthetic alert flow_id; downstream tests
            # exercise the primary anchor path.
            ts_anchor = hour_start
            dest_ip = _EXTERNAL_DESTS[0]
            dest_port = 443
            proto = "TCP"
            fid = _flow_id(seed, host.name, hour_index, "alert", idx)
            src_port = 30000 + (idx % 35000)
        alert_records.append(
            _make_alert(
                host=host,
                ts=ts_anchor,
                flow_id=fid,
                src_port=src_port,
                signature=sig,
                dest_ip=dest_ip,
                dest_port=dest_port,
                proto=proto,
                rng=rng_alert,
            )
        )

    # Yield in time-sorted order so downstream consumers see a stream
    # that loosely resembles a tail of eve.json. Sort by timestamp
    # field; ties broken by event_type so determinism survives.
    combined = flow_records + dns_records + tls_records + http_records + alert_records
    combined.sort(key=lambda r: (r["timestamp"], r["event_type"]))
    yield from combined
