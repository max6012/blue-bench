"""Suricata eve.json-format event emission for synthetic C2 beacons.

Per-profile emit policy:

    commodity  -- emits ``flow`` / ``http`` / ``tls`` / ``dns`` records
                  PLUS ``alert`` records. Alert ``signature`` strings name
                  Suricata rule families (e.g. ``ET MALWARE Cobalt Strike
                  Beacon (HTTP)``). ``sid`` is ALWAYS 0 -- we do not
                  fabricate signature IDs; the orchestrator + the live
                  Suricata install supply the real sids when the corpus
                  is replayed.

    stealth    -- emits flow / dns / tls events ONLY (no alerts). This
                  is the discriminating property: stealth C2 produces
                  passive telemetry but no Suricata triggers. The judge
                  must conclude "low-and-slow" from cadence + endpoint
                  shape, not from an alert.

eve.json convention: one event per line, ``event_type`` keys the record
shape. We carry the same set of fields downstream Suricata installs do
when ``alert`` is suppressed: ``flow``, ``http``, ``tls``, ``dns``.

PURE module: no IO, no subprocess.
"""

from __future__ import annotations

import hashlib
import logging
import random
from typing import Iterable

from blue_bench_generators.c2.beacon import BeaconEvent
from blue_bench_generators.c2.profiles import (
    C2Profile,
    emits_dns_log,
    emits_http_log,
    emits_ssl_log,
)

log = logging.getLogger(__name__)


def _eve_ts(beacon: BeaconEvent) -> str:
    return beacon.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _flow_id(beacon: BeaconEvent, seed: int) -> int:
    """Deterministic 64-bit integer Suricata flow_id."""
    h = hashlib.sha256(
        f"{seed}-flow-{beacon.sequence}-{beacon.timestamp.timestamp():.6f}".encode()
    ).digest()
    return int.from_bytes(h[:8], "big") & 0x7FFF_FFFF_FFFF_FFFF


def _common_5tuple(beacon: BeaconEvent) -> dict:
    return {
        "src_ip": beacon.src_ip,
        "src_port": beacon.src_port,
        "dest_ip": beacon.dst_ip,
        "dest_port": beacon.dst_port,
        "proto": beacon.transport_proto.upper(),
    }


def emit_flow_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """Always-on ``flow`` record. Both commodity and stealth emit these."""
    return {
        "_log": "eve",
        "timestamp": _eve_ts(beacon),
        "flow_id": _flow_id(beacon, seed),
        "event_type": "flow",
        **_common_5tuple(beacon),
        "flow": {
            "pkts_toserver": 8,
            "pkts_toclient": 6,
            "bytes_toserver": beacon.payload_size_bytes,
            "bytes_toclient": max(64, beacon.payload_size_bytes // 32),
            "start": _eve_ts(beacon),
            "end": _eve_ts(beacon),
            "state": "established",
            "reason": "timeout",
        },
    }


def emit_http_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """``http`` eve record. Emitted for ALL commodity profiles (both
    HTTP and HTTPS transports) under the commodity TLS-visibility
    hand-wave -- see ``zeek_emit.py`` module docstring. Stealth never
    emits http records.
    """
    return {
        "_log": "eve",
        "timestamp": _eve_ts(beacon),
        "flow_id": _flow_id(beacon, seed),
        "event_type": "http",
        **_common_5tuple(beacon),
        "http": {
            "hostname": profile.dns_query_pattern % {"seq": beacon.sequence},
            "url": profile.url_path_pattern % {"seq": beacon.sequence},
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "http_method": "POST" if beacon.payload_size_bytes > 256 else "GET",
            "protocol": "HTTP/1.1",
            "status": 200,
            "length": beacon.payload_size_bytes,
        },
    }


def emit_tls_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """``tls`` eve record. HTTPS profiles only."""
    sni = (
        profile.tls_sni_pattern % {"seq": beacon.sequence}
        if "%" in profile.tls_sni_pattern
        else profile.tls_sni_pattern
    )
    return {
        "_log": "eve",
        "timestamp": _eve_ts(beacon),
        "flow_id": _flow_id(beacon, seed),
        "event_type": "tls",
        **_common_5tuple(beacon),
        "tls": {
            "sni": sni,
            "version": "TLS 1.3",
            "fingerprint_hint": profile.tls_fingerprint_hint,
        },
    }


def emit_dns_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """``dns`` eve record. Both HTTPS-resolution and DNS-tunneled profiles."""
    # Mirror the zeek_emit dns logic for payload-encoded queries.
    if profile.transport == "dns" and "%(payload)s" in profile.dns_query_pattern:
        rng = random.Random(seed + beacon.sequence + 0xD15)
        label = rng.randbytes(max(1, beacon.payload_size_bytes // 2)).hex()
        chunks = [label[i:i + 63] for i in range(0, len(label), 63)]
        labelled = ".".join(chunks)[:240]
        rrname = profile.dns_query_pattern % {"payload": labelled}
    else:
        rrname = profile.dns_query_pattern % {"seq": beacon.sequence}
    return {
        "_log": "eve",
        "timestamp": _eve_ts(beacon),
        "flow_id": _flow_id(beacon, seed),
        "event_type": "dns",
        "src_ip": beacon.src_ip,
        "src_port": beacon.src_port,
        "dest_ip": "192.0.2.53",  # synthetic resolver, RFC5737
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "rrname": rrname,
            "rrtype": "A",
        },
    }


def emit_alert_records(
    beacon: BeaconEvent, profile: C2Profile, seed: int
) -> list[dict]:
    """Zero or more ``alert`` records, one per declared rule family.

    Commodity profiles produce alerts; stealth profiles return ``[]``.
    ``sid`` is always 0 (not fabricated). ``rule_name`` carries the
    family string.
    """
    if not profile.suricata_rule_families:
        return []
    out: list[dict] = []
    for family in profile.suricata_rule_families:
        out.append({
            "_log": "eve",
            "timestamp": _eve_ts(beacon),
            "flow_id": _flow_id(beacon, seed),
            "event_type": "alert",
            **_common_5tuple(beacon),
            "alert": {
                "action": "allowed",
                "gid": 1,
                "sid": 0,  # NOT a real signature ID; orchestrator supplies on replay
                "rev": 1,
                "signature": family,
                "category": "A Network Trojan was Detected",
                "severity": 1,
                "rule_name": family,
            },
        })
    return out


def emit_for_profile(
    *,
    beacons: Iterable[BeaconEvent],
    profile: C2Profile,
    seed: int,
) -> list[dict]:
    """Emit the full set of eve.json records for a beacon stream.

    Returns records in time + role order: flow, then protocol-specific
    (http / tls / dns), then alerts. Deterministic given a seed.
    """
    out: list[dict] = []
    for b in beacons:
        out.append(emit_flow_record(b, profile, seed))
        if emits_http_log(profile):
            out.append(emit_http_record(b, profile, seed))
        if emits_ssl_log(profile):
            out.append(emit_tls_record(b, profile, seed))
        if emits_dns_log(profile):
            out.append(emit_dns_record(b, profile, seed))
        out.extend(emit_alert_records(b, profile, seed))
    return out
