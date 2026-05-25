"""Zeek-format event emission for synthetic C2 beacons.

For each ``BeaconEvent`` we emit one record per applicable Zeek log:

    * ``conn``  -- always
    * ``dns``   -- when the profile resolves a hostname
                   (https/dns transport) or for dns-tunneled streams
    * ``http``  -- only when transport is cleartext http
    * ``ssl``   -- only when transport is https
    * ``files`` -- only when transport is http (the only case the
                   contents are observable to a tap)

The records use the same field shape that ``zeek_replay.parse_zeek_log_text``
produces in the cybercrime_foil module, with one addition: the
``_log`` key tags the source log so downstream rewriters / classifiers
know which Zeek log a record came from. ``parse_all`` in
``cybercrime_foil/zeek_replay.py`` injects this same key.

We don't try to be byte-identical to a live Zeek TSV; we emit DICTS
shaped like Zeek records. That's the same surface ``rewrite_events``
consumes, and the same surface tests in cybercrime_foil run against.
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
    emits_files_log,
    emits_http_log,
    emits_ssl_log,
)

log = logging.getLogger(__name__)


def _uid(prefix: str, beacon: BeaconEvent, seed: int) -> str:
    """Deterministic Zeek-style UID. ``C`` for conn-like, ``F`` for files."""
    h = hashlib.sha256(
        f"{seed}-{beacon.sequence}-{beacon.timestamp.timestamp():.6f}-{prefix}".encode()
    ).hexdigest()
    return f"{prefix}{h[:12]}"


def _ts_str(beacon: BeaconEvent) -> str:
    return f"{beacon.timestamp.timestamp():.6f}"


def emit_conn_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """One ``conn.log``-shaped record per beacon.

    Field shape mirrors a default Zeek conn.log; service is set per
    transport ("ssl" / "http" / "dns").
    """
    service = {"http": "http", "https": "ssl", "dns": "dns"}[profile.transport]
    return {
        "_log": "conn",
        "ts": _ts_str(beacon),
        "uid": _uid("C", beacon, seed),
        "id.orig_h": beacon.src_ip,
        "id.orig_p": str(beacon.src_port),
        "id.resp_h": beacon.dst_ip,
        "id.resp_p": str(beacon.dst_port),
        "proto": beacon.transport_proto,
        "service": service,
        # orig_bytes is the request side; resp_bytes is a small ACK.
        "orig_bytes": str(beacon.payload_size_bytes),
        "resp_bytes": str(max(64, beacon.payload_size_bytes // 32)),
        "conn_state": "SF",
        "history": "ShADadFf",
    }


def emit_dns_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """One ``dns.log``-shaped record per beacon, for profiles that resolve."""
    # For DNS-tunneled profiles, the "payload" is encoded in the
    # subdomain label. We synthesise a deterministic hex chunk whose
    # length matches the profile's payload size.
    query: str
    if profile.transport == "dns" and "%(payload)s" in profile.dns_query_pattern:
        # Hex-encode the payload size's worth of deterministic data.
        rng = random.Random(seed + beacon.sequence)
        label = rng.randbytes(max(1, beacon.payload_size_bytes // 2)).hex()
        # DNS labels are limited to 63 chars; chunk if needed.
        chunks = [label[i:i + 63] for i in range(0, len(label), 63)]
        labelled = ".".join(chunks)[:240]  # leave headroom under 253-byte limit
        query = profile.dns_query_pattern % {"payload": labelled}
    else:
        query = profile.dns_query_pattern % {"seq": beacon.sequence}
    return {
        "_log": "dns",
        "ts": _ts_str(beacon),
        "uid": _uid("C", beacon, seed),
        "id.orig_h": beacon.src_ip,
        "id.orig_p": str(beacon.src_port),
        "id.resp_h": _resolver_ip_for(beacon, seed),
        "id.resp_p": "53",
        "proto": "udp",
        "query": query,
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "answers": beacon.dst_ip,
    }


def _resolver_ip_for(beacon: BeaconEvent, seed: int) -> str:
    """Pick a deterministic resolver IP (not the C2 target).

    Uses a small synthetic pool inside RFC5737 documentation range so
    callers don't accidentally surface a real resolver IP.
    """
    rng = random.Random(seed ^ beacon.sequence)
    return f"192.0.2.{rng.randint(1, 254)}"


def emit_http_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """One ``http.log``-shaped record per beacon, http profiles only."""
    return {
        "_log": "http",
        "ts": _ts_str(beacon),
        "uid": _uid("C", beacon, seed),
        "id.orig_h": beacon.src_ip,
        "id.orig_p": str(beacon.src_port),
        "id.resp_h": beacon.dst_ip,
        "id.resp_p": str(beacon.dst_port),
        "method": "POST" if beacon.payload_size_bytes > 256 else "GET",
        "host": profile.dns_query_pattern % {"seq": beacon.sequence},
        "uri": profile.url_path_pattern % {"seq": beacon.sequence},
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "status_code": "200",
        "request_body_len": str(beacon.payload_size_bytes),
        "response_body_len": str(max(64, beacon.payload_size_bytes // 32)),
    }


def emit_ssl_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """One ``ssl.log``-shaped record per beacon.

    Emitted when ``emits_ssl_log(profile)`` is True (commodity-HTTPS and
    stealth-HTTPS). For HTTP-transport commodity profiles, this is NOT
    called -- the SSL log only exists when there's a TLS handshake.
    """
    sni = (
        profile.tls_sni_pattern % {"seq": beacon.sequence}
        if "%" in profile.tls_sni_pattern
        else profile.tls_sni_pattern
    )
    return {
        "_log": "ssl",
        "ts": _ts_str(beacon),
        "uid": _uid("C", beacon, seed),
        "id.orig_h": beacon.src_ip,
        "id.orig_p": str(beacon.src_port),
        "id.resp_h": beacon.dst_ip,
        "id.resp_p": str(beacon.dst_port),
        "version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "server_name": sni,
        "established": "T",
        "ja3_hint": profile.tls_fingerprint_hint,
    }


def emit_files_record(beacon: BeaconEvent, profile: C2Profile, seed: int) -> dict:
    """One ``files.log``-shaped record per beacon, when payload is observable."""
    return {
        "_log": "files",
        "ts": _ts_str(beacon),
        "fuid": _uid("F", beacon, seed),
        "tx_hosts": beacon.dst_ip,
        "rx_hosts": beacon.src_ip,
        "source": "HTTP",
        "depth": "0",
        "analyzers": "SHA256",
        "mime_type": "application/octet-stream",
        # SHA256 is over deterministic-random synthetic bytes; it does
        # NOT correspond to any real malicious file. Marked clearly.
        "sha256": hashlib.sha256(
            f"synthetic-{seed}-{beacon.sequence}".encode()
        ).hexdigest(),
        "seen_bytes": str(beacon.payload_size_bytes),
        "total_bytes": str(beacon.payload_size_bytes),
        "_note": "synthetic-random-payload-bytes; sha256 is not a real IOC",
    }


def emit_for_profile(
    *,
    beacons: Iterable[BeaconEvent],
    profile: C2Profile,
    seed: int,
) -> list[dict]:
    """Emit the full set of Zeek records for a beacon stream.

    Per-profile log selection:
        commodity http   -> conn, dns, http, files
        commodity https  -> conn, dns, ssl
        stealth   https  -> conn, dns, ssl
        stealth   dns    -> conn, dns
    """
    out: list[dict] = []
    for b in beacons:
        out.append(emit_conn_record(b, profile, seed))
        if emits_dns_log(profile):
            out.append(emit_dns_record(b, profile, seed))
        if emits_http_log(profile):
            out.append(emit_http_record(b, profile, seed))
        if emits_ssl_log(profile):
            out.append(emit_ssl_record(b, profile, seed))
        if emits_files_log(profile):
            out.append(emit_files_record(b, profile, seed))
    return out
