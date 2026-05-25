"""Bundle emission + schema-validator tests.

Uses the canonical example incident ``mta-2022-12-20-icedid-cs`` (entry #5
in the catalogue, the one the worked-example YAML targets) so the emitted
bundle's shape is comparable to ``ground-truth-example.yaml``.

These tests run without Zeek/Suricata installed — replay outputs are mocked
via plain dict fixtures and parsed Zeek-log strings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from blue_bench_generators.cybercrime_foil import catalogue
from blue_bench_generators.cybercrime_foil.bundle import (
    CorpusBinding,
    SchemaValidationError,
    build_ground_truth,
    load_events_ndjson,
    load_ground_truth,
    validate_bundle,
    write_bundle,
)
from blue_bench_generators.cybercrime_foil.rewrite import rewrite_events
from blue_bench_generators.cybercrime_foil.zeek_replay import parse_zeek_log_text


INCIDENT_ID = "mta-2022-12-20-icedid-cs"


# Minimal Zeek conn.log fixture text. Mirrors the real header convention
# Zeek emits — six private/public IP pairs over a short window, all TLS.
ZEEK_CONN_LOG = "\t".join([
    "#separator \\x09",
    "",
]) + "\n" + (
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n"
    "1671558720.001\tC0001\t10.0.0.5\t49152\t203.0.113.42\t443\ttcp\tssl\n"
    "1671558740.002\tC0002\t10.0.0.5\t49153\t198.51.100.17\t80\ttcp\thttp\n"
    "1671558790.003\tC0003\t10.0.0.6\t49154\t203.0.113.42\t443\ttcp\tssl\n"
    "1671558820.004\tC0004\t10.0.0.5\t49155\t203.0.113.42\t443\ttcp\tssl\n"
    "1671558900.005\tC0005\t10.0.0.7\t49156\t203.0.113.99\t443\ttcp\tssl\n"
)


def _mock_events() -> list[dict]:
    return parse_zeek_log_text(ZEEK_CONN_LOG, "conn")


def _binding() -> CorpusBinding:
    return CorpusBinding(
        tier="M",
        build_hash="1" * 64,
        baseline_generator_config="generators/it_baseline/configs/m_tier_v1.yaml",
    )


def test_mock_events_parse():
    events = _mock_events()
    assert len(events) == 5
    assert events[0]["_log"] == "conn"
    assert events[0]["id.orig_h"] == "10.0.0.5"


def test_build_ground_truth_passes_all_11_rules(tmp_path: Path):
    entry = catalogue.get(INCIDENT_ID)
    events = _mock_events()
    rewritten = rewrite_events(
        events,
        incident_id=INCIDENT_ID,
        target_epoch=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        target_subnet="10.42.0.0/16",
    )
    gt = build_ground_truth(
        entry=entry,
        events_ndjson_filename=f"{INCIDENT_ID}.events.ndjson",
        rewritten_events=rewritten,
        corpus=_binding(),
        injection_start=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        injection_end=datetime(2026, 6, 10, 14, 35, 0, tzinfo=timezone.utc),
    )
    validate_bundle(gt)  # should not raise


def test_write_bundle_round_trips(tmp_path: Path):
    entry = catalogue.get(INCIDENT_ID)
    rewritten = rewrite_events(
        _mock_events(),
        incident_id=INCIDENT_ID,
        target_epoch=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        target_subnet="10.42.0.0/16",
    )
    ndjson_path, yaml_path = write_bundle(
        entry=entry,
        rewritten_events=rewritten,
        corpus=_binding(),
        injection_start=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        injection_end=datetime(2026, 6, 10, 14, 35, 0, tzinfo=timezone.utc),
        bundle_dir=tmp_path,
    )
    assert ndjson_path.is_file()
    assert yaml_path.is_file()
    # NDJSON: one line per event, each with event_id matching the YAML pointer.
    ndjson_events = list(load_events_ndjson(ndjson_path))
    assert len(ndjson_events) == len(rewritten)
    expected_ids = [f"evt-{INCIDENT_ID}-{i:04d}" for i in range(1, len(rewritten) + 1)]
    assert [e["event_id"] for e in ndjson_events] == expected_ids
    # YAML loads and revalidates.
    gt = load_ground_truth(yaml_path)
    validate_bundle(gt)


def test_yaml_event_pointers_line_up_with_ndjson(tmp_path: Path):
    entry = catalogue.get(INCIDENT_ID)
    rewritten = rewrite_events(
        _mock_events(),
        incident_id=INCIDENT_ID,
        target_epoch=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        target_subnet="10.42.0.0/16",
    )
    ndjson_path, yaml_path = write_bundle(
        entry=entry,
        rewritten_events=rewritten,
        corpus=_binding(),
        injection_start=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        injection_end=datetime(2026, 6, 10, 14, 35, 0, tzinfo=timezone.utc),
        bundle_dir=tmp_path,
    )
    gt = load_ground_truth(yaml_path)
    for i, ev_ptr in enumerate(gt["events"], start=1):
        # Rule 7 requires exactly one of doc_id / fixture_line — we use the
        # latter because the corpus is fixture-flavoured at this stage.
        assert "fixture_line" in ev_ptr["where"]
        assert "doc_id" not in ev_ptr["where"]
        fl = ev_ptr["where"]["fixture_line"]
        assert fl["path"] == ndjson_path.name
        assert fl["line"] == i


# --- per-rule failure tests ---


def _good_gt() -> dict:
    entry = catalogue.get(INCIDENT_ID)
    rewritten = rewrite_events(
        _mock_events(),
        incident_id=INCIDENT_ID,
        target_epoch=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        target_subnet="10.42.0.0/16",
    )
    return build_ground_truth(
        entry=entry,
        events_ndjson_filename=f"{INCIDENT_ID}.events.ndjson",
        rewritten_events=rewritten,
        corpus=_binding(),
        injection_start=datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc),
        injection_end=datetime(2026, 6, 10, 14, 35, 0, tzinfo=timezone.utc),
    )


def test_rule_1_unknown_schema_version():
    gt = _good_gt()
    gt["schema_version"] = "9.9"
    with pytest.raises(SchemaValidationError, match="rule 1"):
        validate_bundle(gt)


def test_rule_2_invalid_source_class():
    gt = _good_gt()
    gt["source_class"] = "mystery"
    with pytest.raises(SchemaValidationError, match="rule 2"):
        validate_bundle(gt)


def test_rule_3_invalid_segment_class():
    gt = _good_gt()
    gt["segment_class"] = "DMZ"
    with pytest.raises(SchemaValidationError, match="rule 3"):
        validate_bundle(gt)


def test_rule_4_empty_ttps_for_cybercrime():
    gt = _good_gt()
    gt["ttps"] = []
    with pytest.raises(SchemaValidationError, match="rule 4"):
        validate_bundle(gt)


def test_rule_5_invalid_ttp_id():
    gt = _good_gt()
    gt["ttps"] = list(gt["ttps"]) + ["not-a-ttp"]
    with pytest.raises(SchemaValidationError, match="rule 5"):
        validate_bundle(gt)


def test_rule_6_empty_events():
    gt = _good_gt()
    gt["events"] = []
    with pytest.raises(SchemaValidationError, match="rule 6"):
        validate_bundle(gt)


def test_rule_7_zero_where_keys():
    gt = _good_gt()
    gt["events"][0]["where"] = {}
    with pytest.raises(SchemaValidationError, match="rule 7"):
        validate_bundle(gt)


def test_rule_7_both_where_keys():
    gt = _good_gt()
    gt["events"][0]["where"] = {"doc_id": "x", "fixture_line": {"path": "p", "line": 1}}
    with pytest.raises(SchemaValidationError, match="rule 7"):
        validate_bundle(gt)


def test_rule_8_only_checked_when_expected_passed():
    gt = _good_gt()
    # No expected_build_hash -> rule 8 is intentionally skipped at emit time.
    validate_bundle(gt)
    # With a wrong expected hash, rule 8 fires.
    with pytest.raises(SchemaValidationError, match="rule 8"):
        validate_bundle(gt, expected_build_hash="2" * 64)
    # With the matching hash, all good.
    validate_bundle(gt, expected_build_hash=gt["corpus"]["build_hash"])


def test_rule_9_duration_mismatch():
    gt = _good_gt()
    gt["time_window"]["duration_seconds"] = 999999
    with pytest.raises(SchemaValidationError, match="rule 9"):
        validate_bundle(gt)


def test_rule_10_thresholds_inverted():
    gt = _good_gt()
    gt["scoring"]["detection"]["found_threshold"] = 0.1
    gt["scoring"]["detection"]["partial_threshold"] = 0.9
    with pytest.raises(SchemaValidationError, match="rule 10"):
        validate_bundle(gt)


def test_rule_11_attribution_required_not_subset():
    gt = _good_gt()
    gt["expected_findings"]["ttp_attribution"]["required"] = ["T9999.001"]  # not in ttps
    with pytest.raises(SchemaValidationError, match="rule 11"):
        validate_bundle(gt)


# --- determinism end-to-end ---


def test_two_writes_produce_identical_ndjson_and_yaml(tmp_path: Path):
    entry = catalogue.get(INCIDENT_ID)
    epoch = datetime(2026, 6, 10, 14, 32, 0, tzinfo=timezone.utc)
    end = datetime(2026, 6, 10, 14, 35, 0, tzinfo=timezone.utc)

    def emit(into: Path) -> tuple[bytes, str]:
        rewritten = rewrite_events(
            _mock_events(),
            incident_id=INCIDENT_ID,
            target_epoch=epoch,
            target_subnet="10.42.0.0/16",
        )
        nd, ym = write_bundle(
            entry=entry,
            rewritten_events=rewritten,
            corpus=_binding(),
            injection_start=epoch,
            injection_end=end,
            bundle_dir=into,
        )
        return nd.read_bytes(), ym.read_text(encoding="utf-8")

    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    nd_a, ym_a = emit(a_dir)
    nd_b, ym_b = emit(b_dir)
    assert nd_a == nd_b
    # YAML compare via parsed dicts to be insensitive to PyYAML's
    # serialization quirks across versions.
    assert yaml.safe_load(ym_a) == yaml.safe_load(ym_b)


def test_example_incident_yaml_shape_matches_schema_example():
    """Sanity: the emitted bundle has the same top-level keys as the
    canonical example file. The example carries fabricated values, so we
    compare the schema-required shape, not the values."""
    gt = _good_gt()
    required_top_keys = {
        "schema_version",
        "incident_id",
        "source_class",
        "segment_class",
        "source",
        "corpus",
        "time_window",
        "ttps",
        "ttps_optional",
        "confidence",
        "events",
        "expected_findings",
        "scoring",
        "notes",
    }
    assert required_top_keys.issubset(set(gt.keys()))
    assert gt["incident_id"] == INCIDENT_ID
    assert gt["source_class"] == "cybercrime"
    assert gt["segment_class"] == "IT"
    assert gt["confidence"] == "high"  # entry attribution_fidelity is H
