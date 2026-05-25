"""Suricata emitter -- alert presence per profile + event field shapes."""

from __future__ import annotations

from datetime import datetime, timezone

from blue_bench_generators.c2 import profiles
from blue_bench_generators.c2.beacon import generate_beacons
from blue_bench_generators.c2.suricata_emit import emit_for_profile


START = datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc)
CALLBACKS = ["203.0.113.42", "203.0.113.99"]
TARGET = "10.42.0.5"


def _events_for(preset_name: str, duration_s: int = 3600, seed: int = 11) -> list[dict]:
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


def _event_types(events: list[dict]) -> set[str]:
    return {ev.get("event_type") for ev in events}


def test_commodity_profile_emits_alerts():
    events = _events_for("cobalt-strike-default")
    alerts = [e for e in events if e.get("event_type") == "alert"]
    assert alerts, "commodity profile MUST produce at least one alert"
    # Every alert carries sid=0 (we never fabricate sids).
    for a in alerts:
        assert a["alert"]["sid"] == 0
        assert a["alert"]["signature"].startswith("ET ")
        assert "rule_name" in a["alert"]


def test_commodity_alert_signatures_match_profile_rule_families():
    p = profiles.get_preset("cobalt-strike-default")
    events = _events_for("cobalt-strike-default")
    alerts = [e for e in events if e.get("event_type") == "alert"]
    signatures = {a["alert"]["signature"] for a in alerts}
    assert set(p.suricata_rule_families).issubset(signatures), (
        f"emitted={signatures}, declared={p.suricata_rule_families}"
    )


def test_stealth_profiles_emit_zero_alerts():
    for preset_name in (
        "lotl-https-cloudfront",
        "lotl-https-azure",
        "lotl-dns-tunneled",
        "lotl-domain-fronted",
    ):
        events = _events_for(preset_name, duration_s=86400 * 14)
        alerts = [e for e in events if e.get("event_type") == "alert"]
        assert alerts == [], (
            f"stealth {preset_name} produced {len(alerts)} alerts; "
            f"must be zero"
        )


def test_stealth_https_emits_flow_and_tls_only():
    """Stealth-HTTPS: conn (flow) + ssl (tls) only -- no dns event type."""
    events = _events_for("lotl-https-cloudfront", duration_s=86400 * 7)
    types = _event_types(events)
    assert types == {"flow", "tls"}, types


def test_stealth_dns_emits_flow_and_dns_only():
    events = _events_for("lotl-dns-tunneled", duration_s=86400 * 7)
    types = _event_types(events)
    assert types == {"flow", "dns"}, types


def test_commodity_https_emits_flow_dns_http_tls_alert():
    """Spec: commodity emits all five log types -- HTTPS commodity carries
    flow + dns + http + tls + alert in eve.json."""
    events = _events_for("cobalt-strike-default")
    types = _event_types(events)
    assert types == {"flow", "dns", "http", "tls", "alert"}, types


def test_commodity_http_emits_flow_dns_http_alert_no_tls():
    """Commodity HTTP carries flow + dns + http + alert. No tls -- no
    TLS handshake on the wire."""
    events = _events_for("icedid-http")
    types = _event_types(events)
    assert types == {"flow", "dns", "http", "alert"}, types


def test_flow_record_carries_5tuple():
    events = _events_for("cobalt-strike-default")
    flows = [e for e in events if e.get("event_type") == "flow"]
    assert flows
    for f in flows:
        for k in ("src_ip", "src_port", "dest_ip", "dest_port", "proto"):
            assert k in f
        assert "flow" in f
        assert f["flow"]["bytes_toserver"] > 0


def test_tls_record_sni_matches_profile_pattern():
    events = _events_for("cobalt-strike-default")
    tls = [e for e in events if e.get("event_type") == "tls"]
    assert tls
    for e in tls:
        sni = e["tls"]["sni"]
        assert sni.endswith(".example.invalid"), sni


def test_suricata_emit_is_deterministic():
    a = _events_for("cobalt-strike-default", seed=99)
    b = _events_for("cobalt-strike-default", seed=99)
    assert a == b
