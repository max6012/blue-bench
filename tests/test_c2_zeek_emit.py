"""Zeek emitter -- per-profile log-coverage matrix."""

from __future__ import annotations

from datetime import datetime, timezone

from blue_bench_generators.c2 import profiles
from blue_bench_generators.c2.beacon import generate_beacons
from blue_bench_generators.c2.zeek_emit import emit_for_profile


START = datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc)
CALLBACKS = ["203.0.113.42", "203.0.113.99"]
TARGET = "10.42.0.5"


def _events_for(preset_name: str, duration_s: int = 3600, seed: int = 7) -> list[dict]:
    p = profiles.get_preset(preset_name)
    beacons = generate_beacons(
        profile=p,
        target_host_ip=TARGET,
        callback_targets=CALLBACKS,
        start_time=START,
        duration_seconds=duration_s,
        seed=seed,
    )
    assert beacons, f"no beacons generated for {preset_name}"
    return emit_for_profile(beacons=beacons, profile=p, seed=seed)


def _log_kinds(events: list[dict]) -> set[str]:
    return {ev["_log"] for ev in events}


def test_commodity_emits_all_five_log_types():
    """Spec: commodity emits to all five log types (full visibility).

    Commodity HTTPS gets conn + dns + http + ssl + files. Commodity HTTP
    does NOT have ssl (no TLS handshake on the wire). We assert the
    "all 5 where applicable" rule: HTTPS -> {conn, dns, http, ssl, files};
    HTTP -> {conn, dns, http, files}.
    """
    https_kinds = _log_kinds(_events_for("cobalt-strike-default"))
    assert https_kinds == {"conn", "dns", "http", "ssl", "files"}, https_kinds
    http_kinds = _log_kinds(_events_for("icedid-http"))
    assert http_kinds == {"conn", "dns", "http", "files"}, http_kinds


def test_stealth_https_emits_only_conn_and_ssl():
    """Spec: stealth-HTTPS -> conn + ssl only (TLS-encrypted, no HTTP)."""
    kinds = _log_kinds(_events_for("lotl-https-cloudfront", duration_s=86400 * 7))
    assert kinds == {"conn", "ssl"}, kinds
    assert "dns" not in kinds
    assert "http" not in kinds
    assert "files" not in kinds


def test_stealth_dns_emits_only_conn_and_dns():
    """Spec: stealth-DNS -> dns + conn only (small queries, no HTTP)."""
    kinds = _log_kinds(_events_for("lotl-dns-tunneled", duration_s=86400 * 7))
    assert kinds == {"conn", "dns"}, kinds
    assert "http" not in kinds
    assert "files" not in kinds
    assert "ssl" not in kinds


def test_zeek_records_carry_required_fields():
    events = _events_for("cobalt-strike-default")
    for ev in events:
        assert "ts" in ev
        assert "_log" in ev
        if ev["_log"] == "conn":
            for k in ("uid", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "proto"):
                assert k in ev
        if ev["_log"] == "ssl":
            assert "server_name" in ev
            assert ev["server_name"].endswith(".example.invalid"), ev["server_name"]


def test_dns_tunneled_query_carries_payload_encoded_subdomain():
    events = _events_for("lotl-dns-tunneled", duration_s=86400 * 14)
    dns_events = [e for e in events if e["_log"] == "dns"]
    assert dns_events
    for ev in dns_events:
        query = ev["query"]
        assert query.endswith(".tunnel-host.example.invalid"), query
        # Subdomain section must have at least some encoded content
        # (not just the tunnel-host suffix).
        prefix = query.rsplit(".tunnel-host.example.invalid", 1)[0]
        assert len(prefix) > 0


def test_zeek_emit_is_deterministic_with_seed():
    a = _events_for("cobalt-strike-default", seed=42)
    b = _events_for("cobalt-strike-default", seed=42)
    assert a == b


def test_files_record_has_sha256_marked_synthetic():
    events = _events_for("icedid-http")
    files_events = [e for e in events if e["_log"] == "files"]
    assert files_events
    for ev in files_events:
        assert len(ev["sha256"]) == 64
        assert ev.get("_note", "").startswith("synthetic")
