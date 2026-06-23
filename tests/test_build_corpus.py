"""Unit tests for the corpus build orchestrator (blue_bench_generators/merge/__main__).

Covers the pure helpers — corpus build_hash (exclusions + determinism), the
ground-truth stamping/validation, and the scenario->HostRemap resolution. The
full build() drives eforge + the heavy generators and is exercised live in
EF-P5, not in CI.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from blue_bench_generators.merge import __main__ as build


def _write(p: Path, text: str = "x\n") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_corpus_hash_excludes_ground_truth_and_ef_meta(tmp_path: Path):
    _write(tmp_path / "data" / "h" / "a.json", '{"x":1}\n')
    _write(tmp_path / "ot" / "modbus.ndjson", '{"f":3}\n')
    _write(tmp_path / "GROUND_TRUTH.json", '{"generated_at":"now"}')   # excluded (EF meta)
    _write(tmp_path / "ground-truth" / "x.ground-truth.yaml", "k: v\n")  # excluded (dir)
    h1 = build._corpus_build_hash(tmp_path)
    # mutating an excluded file does NOT change the hash
    _write(tmp_path / "GROUND_TRUTH.json", '{"generated_at":"later"}')
    _write(tmp_path / "ground-truth" / "x.ground-truth.yaml", "k: different\n")
    assert build._corpus_build_hash(tmp_path) == h1
    # mutating a telemetry file DOES change it
    _write(tmp_path / "ot" / "modbus.ndjson", '{"f":4}\n')
    assert build._corpus_build_hash(tmp_path) != h1


def test_stamp_ground_truth_binds_hash_and_validates(tmp_path: Path):
    gt = {
        "schema_version": "1.0", "incident_id": "x", "source_class": "cybercrime",
        "segment_class": "IT", "ttps": ["T1059.001"], "confidence": "high",
        "corpus": {"tier": "S", "build_hash": "0" * 64, "baseline_generator_config": "cfg"},
        "time_window": {"injection_start": "2026-03-02T05:00:00Z",
                        "injection_end": "2026-03-02T07:00:00Z", "duration_seconds": 7200},
        "events": [{"id": "e1", "where": {"doc_id": "abc"}, "role": "execution",
                    "ttp_links": ["T1059.001"]}],
        "expected_findings": {"ttp_attribution": {"required": ["T1059.001"], "accepted_alternates": {}}},
        "scoring": {"detection": {"found_threshold": 0.8, "partial_threshold": 0.3},
                    "attribution": {"weight": 0.5}, "discrimination": {"required": True}},
    }
    gt_dir = tmp_path / "ground-truth"
    gt_dir.mkdir()
    (gt_dir / "x.ground-truth.yaml").write_text(yaml.safe_dump(gt))
    stamped = build._stamp_ground_truth(tmp_path, "a" * 64)
    assert stamped == ["x.ground-truth.yaml"]
    out = yaml.safe_load((gt_dir / "x.ground-truth.yaml").read_text())
    assert out["corpus"]["build_hash"] == "a" * 64   # bound to the corpus


def test_remap_resolves_target_host_from_scenario():
    scenario = Path(__file__).resolve().parents[1] / "scenarios" / "heavy-telemetry" / "bb-benign-s.yaml"
    remap = build._remap_for_host(scenario, "S", "wkst-03")
    assert remap.to_fqdn == "wkst-03.corp.example.invalid"
    assert remap.to_ip == "10.10.0.13" and remap.to_name == "WKST-03"
    assert remap.from_fqdn == "ws-fin-014.corp.example"   # capture identity preserved


def test_default_adversary_mapping_tiers():
    # foil fits all tiers; APT (10-day dwell) only L
    assert [a[0] for a in build._DEFAULT_ADVERSARIES["S"]] == ["cybercrime-bb-001"]
    assert [a[0] for a in build._DEFAULT_ADVERSARIES["L"]] == ["apt-bb-001", "cybercrime-bb-001"]


def test_run_corpus_gates_single_class_returns_none(tmp_path: Path):
    # one class injected -> no discrimination test -> None (gates skipped)
    inj = tmp_path / "injected"
    inj.mkdir()
    (inj / "x.sysmon.sysmon.ndjson").write_text('{"event_id":1,"Image":"x.exe"}\n')
    res = build._run_corpus_gates(tmp_path, [{"incident": "x", "source_class": "cybercrime"}])
    assert res is None


def test_run_corpus_gates_two_class_returns_verdict(tmp_path: Path):
    inj = tmp_path / "injected"
    inj.mkdir()
    # apt: sparse cadence; foil: dense — behavioral separates, surface matched
    apt_lines = "\n".join(
        '{"event_id":1,"Image":"powershell.exe","UtcTime":"2026-03-02 %02d:00:00.000"}' % (9 + i)
        for i in range(8))
    foil_lines = "\n".join(
        '{"event_id":1,"Image":"powershell.exe","UtcTime":"2026-03-02 09:%02d:00.000"}' % i
        for i in range(8))
    (inj / "apt-x.sysmon.sysmon.ndjson").write_text(apt_lines + "\n")
    (inj / "foil-x.sysmon.sysmon.ndjson").write_text(foil_lines + "\n")
    res = build._run_corpus_gates(tmp_path, [
        {"incident": "apt-x", "source_class": "apt"},
        {"incident": "foil-x", "source_class": "cybercrime"},
    ])
    assert res is not None and "all_passed" in res and len(res["gates"]) == 4
