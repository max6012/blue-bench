"""End-to-end bundle emission for C2 profiles + schema validator coverage."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from blue_bench_generators.c2 import profiles
from blue_bench_generators.c2.beacon import generate_beacons
from blue_bench_generators.c2.bundle import (
    CorpusBinding,
    SchemaValidationError,
    build_ground_truth,
    load_events_ndjson,
    load_ground_truth,
    write_bundle,
)
from blue_bench_generators.c2.suricata_emit import (
    emit_for_profile as suricata_emit,
)
from blue_bench_generators.c2.zeek_emit import emit_for_profile as zeek_emit
from blue_bench_generators.cybercrime_foil.bundle import validate_bundle


START = datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc)
CALLBACKS = ["203.0.113.42", "203.0.113.99"]
TARGET = "10.42.0.5"


def _binding() -> CorpusBinding:
    return CorpusBinding(
        tier="M",
        build_hash="9" * 64,
        baseline_generator_config="generators/it_baseline/configs/m_tier_v1.yaml",
    )


def _emit_full(preset_name: str, duration_s: int = 3600, seed: int = 5) -> tuple:
    p = profiles.get_preset(preset_name)
    beacons = generate_beacons(
        profile=p,
        target_host_ip=TARGET,
        callback_targets=CALLBACKS,
        start_time=START,
        duration_seconds=duration_s,
        seed=seed,
    )
    assert beacons
    events = zeek_emit(beacons=beacons, profile=p, seed=seed) + suricata_emit(
        beacons=beacons, profile=p, seed=seed
    )
    return p, beacons, events


def test_commodity_bundle_round_trips(tmp_path: Path):
    p, beacons, events = _emit_full("cobalt-strike-default")
    nd, ym = write_bundle(
        incident_id="c2-commodity-test",
        profile=p,
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
        bundle_dir=tmp_path,
    )
    assert nd.is_file()
    assert ym.is_file()
    # NDJSON loads, has expected event_ids in order.
    nd_events = load_events_ndjson(nd)
    assert len(nd_events) == len(events)
    for i, ev in enumerate(nd_events, start=1):
        assert ev["event_id"] == f"evt-c2-commodity-test-{i:04d}"
    # YAML loads and revalidates.
    gt = load_ground_truth(ym)
    validate_bundle(gt)
    assert gt["source_class"] == "cybercrime"
    assert gt["segment_class"] == "IT"
    assert gt["confidence"] == "high"
    assert gt["source"]["kind"] == "synthetic-c2"


def test_stealth_bundle_round_trips(tmp_path: Path):
    p, beacons, events = _emit_full(
        "lotl-https-cloudfront", duration_s=86400 * 7
    )
    nd, ym = write_bundle(
        incident_id="c2-stealth-test",
        profile=p,
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
        bundle_dir=tmp_path,
    )
    gt = load_ground_truth(ym)
    validate_bundle(gt)
    assert gt["source_class"] == "apt"
    assert gt["confidence"] == "medium"


def test_all_11_rules_run_on_a_generated_commodity_bundle():
    """Exercise the validator against an in-memory commodity bundle."""
    p, beacons, events = _emit_full("cobalt-strike-default")
    gt = build_ground_truth(
        incident_id="c2-rule-coverage",
        profile=p,
        events_ndjson_filename="c2-rule-coverage.events.ndjson",
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
    )
    validate_bundle(gt)  # all rules pass


def test_all_11_rules_run_on_a_generated_stealth_bundle():
    p, beacons, events = _emit_full("lotl-dns-tunneled", duration_s=86400 * 7)
    gt = build_ground_truth(
        incident_id="c2-stealth-rule-coverage",
        profile=p,
        events_ndjson_filename="c2-stealth-rule-coverage.events.ndjson",
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
    )
    validate_bundle(gt)


def test_rule_4_fires_if_ttps_emptied():
    p, beacons, events = _emit_full("cobalt-strike-default")
    gt = build_ground_truth(
        incident_id="c2-rule4",
        profile=p,
        events_ndjson_filename="c2-rule4.events.ndjson",
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
    )
    gt["ttps"] = []
    import pytest
    with pytest.raises(SchemaValidationError, match="rule 4"):
        validate_bundle(gt)


def test_rule_11_required_must_be_subset_of_ttps():
    p, beacons, events = _emit_full("cobalt-strike-default")
    gt = build_ground_truth(
        incident_id="c2-rule11",
        profile=p,
        events_ndjson_filename="c2-rule11.events.ndjson",
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
    )
    # Inject a non-subset value.
    gt["expected_findings"]["ttp_attribution"]["required"] = ["T9999.001"]
    import pytest
    with pytest.raises(SchemaValidationError, match="rule 11"):
        validate_bundle(gt)


def test_bundle_attribution_required_is_subset_of_ttps():
    """Rule 11 invariant must hold for both profile families by default."""
    for preset in ("cobalt-strike-default", "lotl-https-cloudfront", "lotl-dns-tunneled"):
        p, beacons, events = _emit_full(preset, duration_s=86400 * 7)
        gt = build_ground_truth(
            incident_id=f"c2-{preset}",
            profile=p,
            events_ndjson_filename="x.ndjson",
            emitted_events=events,
            corpus=_binding(),
            injection_start=beacons[0].timestamp,
            injection_end=beacons[-1].timestamp,
        )
        required = set(gt["expected_findings"]["ttp_attribution"]["required"])
        ttps = set(gt["ttps"])
        assert required.issubset(ttps)


def test_event_pointers_line_up_with_ndjson(tmp_path: Path):
    p, beacons, events = _emit_full("cobalt-strike-default")
    nd, ym = write_bundle(
        incident_id="c2-pointers",
        profile=p,
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
        bundle_dir=tmp_path,
    )
    gt = load_ground_truth(ym)
    for i, ev_ptr in enumerate(gt["events"], start=1):
        assert "fixture_line" in ev_ptr["where"]
        assert "doc_id" not in ev_ptr["where"]
        fl = ev_ptr["where"]["fixture_line"]
        assert fl["path"] == nd.name
        assert fl["line"] == i


def test_two_writes_with_same_seed_produce_identical_bundles(tmp_path: Path):
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"

    def emit(into: Path) -> tuple[bytes, str]:
        p, beacons, events = _emit_full("cobalt-strike-default", seed=4242)
        nd, ym = write_bundle(
            incident_id="c2-determinism",
            profile=p,
            emitted_events=events,
            corpus=_binding(),
            injection_start=beacons[0].timestamp,
            injection_end=beacons[-1].timestamp,
            bundle_dir=into,
        )
        return nd.read_bytes(), ym.read_text(encoding="utf-8")

    nd_a, ym_a = emit(a_dir)
    nd_b, ym_b = emit(b_dir)
    assert nd_a == nd_b
    assert yaml.safe_load(ym_a) == yaml.safe_load(ym_b)


def test_confidence_per_profile_kind():
    p_c, beacons_c, events_c = _emit_full("cobalt-strike-default")
    p_s, beacons_s, events_s = _emit_full("lotl-https-cloudfront", duration_s=86400 * 7)
    gt_c = build_ground_truth(
        incident_id="c2-conf-c",
        profile=p_c,
        events_ndjson_filename="x",
        emitted_events=events_c,
        corpus=_binding(),
        injection_start=beacons_c[0].timestamp,
        injection_end=beacons_c[-1].timestamp,
    )
    gt_s = build_ground_truth(
        incident_id="c2-conf-s",
        profile=p_s,
        events_ndjson_filename="x",
        emitted_events=events_s,
        corpus=_binding(),
        injection_start=beacons_s[0].timestamp,
        injection_end=beacons_s[-1].timestamp,
    )
    assert gt_c["confidence"] == "high"
    assert gt_c["source_class"] == "cybercrime"
    assert gt_s["confidence"] == "medium"
    assert gt_s["source_class"] == "apt"


def test_scoring_attribution_weight_differs_by_class():
    p_c, beacons_c, events_c = _emit_full("cobalt-strike-default")
    p_s, beacons_s, events_s = _emit_full("lotl-https-cloudfront", duration_s=86400 * 7)
    gt_c = build_ground_truth(
        incident_id="c2-w-c",
        profile=p_c,
        events_ndjson_filename="x",
        emitted_events=events_c,
        corpus=_binding(),
        injection_start=beacons_c[0].timestamp,
        injection_end=beacons_c[-1].timestamp,
    )
    gt_s = build_ground_truth(
        incident_id="c2-w-s",
        profile=p_s,
        events_ndjson_filename="x",
        emitted_events=events_s,
        corpus=_binding(),
        injection_start=beacons_s[0].timestamp,
        injection_end=beacons_s[-1].timestamp,
    )
    assert gt_c["scoring"]["attribution"]["weight"] == 0.5
    assert gt_s["scoring"]["attribution"]["weight"] == 0.4


# --- IOC population (added 2026-05-25 after the schema 'synthetic-c2' enum
# patch and the resolution that synthetic generators should populate IOCs
# rather than ship empty fields) ---


def _gt_for(preset_name: str, duration_s: int = 3600, seed: int = 5) -> dict:
    p, beacons, events = _emit_full(preset_name, duration_s=duration_s, seed=seed)
    return build_ground_truth(
        incident_id=f"c2-iocs-{preset_name}",
        profile=p,
        events_ndjson_filename="x",
        emitted_events=events,
        corpus=_binding(),
        injection_start=beacons[0].timestamp,
        injection_end=beacons[-1].timestamp,
    )


def test_commodity_https_bundle_populates_iocs():
    gt = _gt_for("cobalt-strike-default")
    iocs = gt["expected_findings"]["iocs"]
    # Callback IPs surface as ipv4 IOCs.
    assert set(iocs["ipv4"]) >= set(CALLBACKS)
    # The TLS SNI we generated must appear as a domain IOC.
    assert iocs["domains"]
    # Cobalt Strike default profile uses HTTPS transport -> URLs are https://.
    assert iocs["urls"]
    assert all(u.startswith("https://") for u in iocs["urls"])
    # No host-side IOC types (process / file / registry) for network-only synthetic.
    assert iocs["sha256"] == []
    assert iocs["process_names"] == []


def test_commodity_http_bundle_emits_http_scheme_urls():
    # IcedID HTTP preset uses cleartext HTTP -> URLs are http://, not https://.
    gt = _gt_for("icedid-http")
    iocs = gt["expected_findings"]["iocs"]
    assert iocs["urls"], "commodity HTTP profile should emit URLs"
    assert all(u.startswith("http://") for u in iocs["urls"])
    assert all(not u.startswith("https://") for u in iocs["urls"])


def test_stealth_dns_bundle_populates_iocs_from_answers_not_resolver():
    # Stealth DNS-tunnel profile: ipv4 IOC must come from the Zeek `answers`
    # field (the actual C2 IP), NOT the DNS resolver IP (which is benign
    # infrastructure and lives in 192.0.2.0/24 TEST-NET-1).
    gt = _gt_for("lotl-dns-tunneled", duration_s=86400 * 14, seed=11)
    iocs = gt["expected_findings"]["iocs"]
    # Callbacks surface as IOCs.
    assert set(iocs["ipv4"]) >= set(CALLBACKS)
    # The resolver IPs (192.0.2.x) must NOT be in the IOC set.
    resolver_ips = {ip for ip in iocs["ipv4"] if ip.startswith("192.0.2.")}
    assert not resolver_ips, (
        f"DNS resolver IPs leaked into IOC set: {resolver_ips} - "
        "these are benign infrastructure, not C2 endpoints"
    )
    # Domain IOCs from the rrname tunneling pattern.
    assert iocs["domains"]
    # DNS-tunneled profiles have no HTTP -> no URL IOCs.
    assert iocs["urls"] == []


def test_iocs_are_sorted_and_deduplicated():
    gt = _gt_for("cobalt-strike-default", seed=7)
    iocs = gt["expected_findings"]["iocs"]
    # Sorted.
    assert iocs["ipv4"] == sorted(iocs["ipv4"])
    assert iocs["domains"] == sorted(iocs["domains"])
    assert iocs["urls"] == sorted(iocs["urls"])
    # Deduplicated (no entry appears twice despite many beacons hitting
    # the same callback IP).
    assert len(iocs["ipv4"]) == len(set(iocs["ipv4"]))
    assert len(iocs["domains"]) == len(set(iocs["domains"]))


def test_iocs_deterministic_across_runs():
    a = _gt_for("cobalt-strike-default", seed=13)["expected_findings"]["iocs"]
    b = _gt_for("cobalt-strike-default", seed=13)["expected_findings"]["iocs"]
    assert a == b
