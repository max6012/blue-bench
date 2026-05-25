"""Deterministic time + IP rewriter for parsed cybercrime-foil events.

Operates on structured event dicts produced by ``zeek_replay`` and
``suricata_replay``. Does NOT touch PCAP bytes.

Determinism: the RNG is seeded from the incident_id, so re-running with the
same incident_id produces an identical original-IP -> target-IP mapping
across invocations. This is required for re-buildable corpora.

Directionality (per advisor): we preserve the public/private distinction
from the original capture by definition — only RFC1918 (private) IPs get
mapped into the target subnet, and public IPs (the actual C2 / loader
infrastructure) are preserved as-is. Public IPs ARE the IOCs; rewriting
them would destroy the attribution signal.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import random
import re
from datetime import datetime, timezone
from typing import Iterable

log = logging.getLogger(__name__)


# Recognised timestamp field names across Zeek and Suricata.
# Zeek conn.log / dns.log etc. use "ts" (epoch seconds as string).
# Suricata eve.json uses "timestamp" (ISO 8601 with microseconds).
ZEEK_TS_FIELDS = ("ts",)
SURICATA_TS_FIELDS = ("timestamp",)

# Fields holding IPv4 addresses we should consider rewriting.
ZEEK_IP_FIELDS = (
    "id.orig_h",
    "id.resp_h",
    "tx_hosts",
    "rx_hosts",
)
SURICATA_IP_FIELDS = (
    "src_ip",
    "dest_ip",
)


def _seed_for(incident_id: str) -> int:
    """Stable integer seed derived from the incident_id."""
    digest = hashlib.sha256(incident_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp; tolerate ``Z`` and offset variants.

    Python 3.10's ``datetime.fromisoformat`` does NOT accept the
    ``+HHMM`` offset (no colon) shape -- only ``+HH:MM``. The matching
    writer in ``_set_event_ts`` emits Suricata-style ``+0000`` offsets
    by convention, so the writer's own output isn't round-trippable on
    3.10. Normalise both shapes before delegating to
    ``fromisoformat``. (3.11+ accepts the no-colon form; this code still
    works there.)
    """
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    elif len(ts) >= 5 and ts[-5] in "+-" and ts[-3] != ":":
        ts = ts[:-2] + ":" + ts[-2:]
    return datetime.fromisoformat(ts)


def _parse_event_ts(event: dict) -> datetime | None:
    """Best-effort timestamp parse across Zeek + Suricata shapes."""
    for f in ZEEK_TS_FIELDS:
        if f in event and event[f] not in (None, "-", ""):
            try:
                return datetime.fromtimestamp(float(event[f]), tz=timezone.utc)
            except (TypeError, ValueError):
                continue
    for f in SURICATA_TS_FIELDS:
        if f in event and event[f]:
            try:
                return _parse_iso(str(event[f]))
            except ValueError:
                continue
    return None


def _set_event_ts(event: dict, new_ts: datetime) -> None:
    """Write a timestamp back in the same format the field used."""
    for f in ZEEK_TS_FIELDS:
        if f in event and event[f] not in (None, "-", ""):
            event[f] = f"{new_ts.timestamp():.6f}"
            return
    for f in SURICATA_TS_FIELDS:
        if f in event and event[f]:
            # Suricata convention: ISO 8601 with microseconds, +0000 offset.
            event[f] = new_ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
            return


def _earliest_ts(events: Iterable[dict]) -> datetime | None:
    earliest: datetime | None = None
    for ev in events:
        ts = _parse_event_ts(ev)
        if ts is None:
            continue
        if earliest is None or ts < earliest:
            earliest = ts
    return earliest


# RFC1918 ranges only. Python's ``ipaddress.is_private`` is too broad — it
# also flags RFC5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) which the IR community commonly uses as STAND-IN PUBLIC
# IPs in PCAP captures and detection writeups. Those documentation ranges
# routinely appear in MTA captures as the C2 / loader infrastructure side
# — exactly the addresses we want to PRESERVE as IOCs, not rewrite.
_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def _is_private(addr: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(addr)
    except (ValueError, ipaddress.AddressValueError):
        return False
    return any(ip in net for net in _RFC1918)


def _looks_like_ipv6(addr: str) -> bool:
    """True if the token parses as IPv6 (regardless of scope).

    Used to surface IPv6 in MTA captures rather than silently passing
    through. v1 does NOT rewrite IPv6 -- those addresses survive the
    rewrite step unchanged, which may or may not be desired downstream.
    Emitting a one-time WARN per unique address makes the gap visible.
    """
    try:
        ipaddress.IPv6Address(addr)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def _build_ip_map(
    events: Iterable[dict],
    target_subnet: ipaddress.IPv4Network,
    rng: random.Random,
) -> dict[str, str]:
    """Collect every private IP in events, assign each a stable target IP.

    Target IPs are drawn (without replacement) from the host range of
    ``target_subnet`` excluding the .0 and .255 broadcast/network sentinels.
    The RNG determines draw order; same seed => same map.
    """
    private_ips: list[str] = []
    seen: set[str] = set()
    ipv6_warned: set[str] = set()
    for ev in events:
        for field in ZEEK_IP_FIELDS + SURICATA_IP_FIELDS:
            v = ev.get(field)
            if not v or v == "-":
                continue
            # Some Zeek fields are space-separated lists (tx_hosts, rx_hosts).
            for token in re.split(r"[\s,]+", str(v)):
                if not token:
                    continue
                if _is_private(token) and token not in seen:
                    seen.add(token)
                    private_ips.append(token)
                elif token not in ipv6_warned and _looks_like_ipv6(token):
                    log.warning(
                        "rewrite: IPv6 address %r passes through unchanged "
                        "(v1 only remaps IPv4 RFC1918 addresses)",
                        token,
                    )
                    ipv6_warned.add(token)
    # Stable ordering: sort before shuffling so the RNG draw order is
    # independent of dict-iteration order across Python versions.
    private_ips.sort()
    hosts = [str(h) for h in target_subnet.hosts()]
    if len(private_ips) > len(hosts):
        raise ValueError(
            f"target subnet {target_subnet} has {len(hosts)} usable hosts, "
            f"need {len(private_ips)}"
        )
    rng.shuffle(hosts)
    return {orig: hosts[i] for i, orig in enumerate(private_ips)}


def _rewrite_ip_field(value: str, ip_map: dict[str, str]) -> str:
    """Rewrite IPs in a field value (handles space/comma-separated lists)."""
    tokens = re.split(r"([\s,]+)", str(value))
    out: list[str] = []
    for tok in tokens:
        out.append(ip_map.get(tok, tok))
    return "".join(out)


def rewrite_events(
    events: list[dict],
    *,
    incident_id: str,
    target_epoch: datetime,
    target_subnet: str | ipaddress.IPv4Network,
) -> list[dict]:
    """Return a NEW list of events with timestamps and private IPs rewritten.

    Args:
        events: list of dicts as produced by ``zeek_replay.parse_all`` and/or
            ``suricata_replay.parse_eve``. Untouched on input — we deep-copy
            via dict construction.
        incident_id: drives the RNG seed for IP-map determinism.
        target_epoch: every event timestamp ``t`` is shifted to
            ``t + (target_epoch - earliest_ts_in_events)``.
        target_subnet: e.g. ``"10.42.0.0/16"``. Private IPs from the original
            capture are mapped into this subnet.

    Returns:
        Rewritten event list, same length and order as the input.
    """
    if not events:
        return []
    subnet = (
        target_subnet
        if isinstance(target_subnet, ipaddress.IPv4Network)
        else ipaddress.IPv4Network(target_subnet)
    )
    earliest = _earliest_ts(events)
    if earliest is None:
        raise ValueError("no parseable timestamps in events; cannot align epoch")
    delta = target_epoch - earliest
    rng = random.Random(_seed_for(incident_id))
    ip_map = _build_ip_map(events, subnet, rng)
    log.info(
        "rewrite incident=%s, %d events, ts shift=%s, IP remap entries=%d",
        incident_id,
        len(events),
        delta,
        len(ip_map),
    )

    rewritten: list[dict] = []
    for ev in events:
        new = dict(ev)  # shallow copy is enough; we replace primitives only
        ts = _parse_event_ts(new)
        if ts is not None:
            _set_event_ts(new, ts + delta)
        for field in ZEEK_IP_FIELDS + SURICATA_IP_FIELDS:
            if field in new and new[field] not in (None, "-", ""):
                new[field] = _rewrite_ip_field(str(new[field]), ip_map)
        rewritten.append(new)
    return rewritten


def build_ip_map_for_test(events: list[dict], incident_id: str, subnet: str) -> dict[str, str]:
    """Public helper for tests: deterministic IP map without rewrite."""
    rng = random.Random(_seed_for(incident_id))
    return _build_ip_map(events, ipaddress.IPv4Network(subnet), rng)
