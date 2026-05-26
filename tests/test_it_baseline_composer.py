"""Acceptance tests for the IT-baseline corpus composer (``t-mhcg``).

The composer is the tier-driven orchestrator that wires the seven per-source
generators (Zeek, Suricata, Sysmon, EVTX, Linux, identity, services) into a
unified corpus build with a ``corpus-manifest.yaml`` describing what was
produced. Two acceptance requirements drive these tests:

  1. ``build_corpus(tier="S", output_dir=tmp, seed=0)`` produces a usable
     corpus end-to-end: all seven source directories populated, manifest
     fields present, ``ts``-sorted output, Zeek TSV header parseable.
  2. Same ``(tier, seed)`` produces byte-identical files on re-run.

These tests use the S tier (1 day, ~11 hosts) for speed; M and L are
parameter changes only.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from blue_bench_generators.it_baseline.composer import (
    DEFAULT_START,
    TIER_DURATION_DAYS,
    build_corpus,
)


SOURCE_DIRS = {"zeek", "suricata", "sysmon", "evtx", "linux", "identity", "services"}


def _build_s(tmp_path: Path, *, seed: int = 0) -> dict:
    return build_corpus(tier="S", output_dir=tmp_path, seed=seed)


# --- end-to-end shape ------------------------------------------------------


def test_build_creates_all_seven_source_directories(tmp_path):
    _build_s(tmp_path)
    present = {p.name for p in tmp_path.iterdir() if p.is_dir()}
    assert SOURCE_DIRS.issubset(present), f"missing dirs: {SOURCE_DIRS - present}"


def test_build_writes_manifest_with_required_fields(tmp_path):
    manifest = _build_s(tmp_path)
    manifest_path = tmp_path / "corpus-manifest.yaml"
    assert manifest_path.exists(), "corpus-manifest.yaml not written"

    loaded = yaml.safe_load(manifest_path.read_text())
    # Manifest returned by build_corpus must match the file on disk.
    assert loaded == manifest

    for key in ("schema_version", "tier", "seed", "build_hash", "window", "topology", "totals", "sources"):
        assert key in manifest, f"manifest missing {key!r}"
    assert manifest["tier"] == "S"
    assert manifest["seed"] == 0
    assert len(manifest["build_hash"]) == 64  # sha256 hex
    assert manifest["window"]["duration_days"] == TIER_DURATION_DAYS["S"]
    assert manifest["topology"]["hosts"] >= 10  # S tier ~11 hosts
    assert manifest["totals"]["events"] > 0
    assert manifest["totals"]["bytes"] > 0


def test_manifest_sources_cover_all_seven_streams(tmp_path):
    manifest = _build_s(tmp_path)
    sources = {s["source"] for s in manifest["sources"]}
    assert sources == SOURCE_DIRS

    # Every source ran without crashing; some may emit zero events if the
    # 1-day S window doesn't activate them, but the spec is that all seven
    # generators are invoked. event_count of 0 is acceptable; a missing
    # source entry is not.
    for s in manifest["sources"]:
        assert isinstance(s["event_count"], int)
        assert isinstance(s["files"], list)


def test_zeek_tsv_files_are_parseable(tmp_path):
    """The output must conform to the schema scripts/seed_es.py parses."""
    _build_s(tmp_path)
    zeek_dir = tmp_path / "zeek"
    log_files = list(zeek_dir.glob("*.log"))
    assert log_files, "expected at least one zeek log file"

    for path in log_files:
        text = path.read_text()
        lines = text.splitlines()
        # Must start with the standard Zeek TSV preamble.
        assert lines[0] == "#separator \\x09", f"{path.name}: bad separator line"
        fields_line = next((l for l in lines if l.startswith("#fields")), None)
        assert fields_line is not None, f"{path.name}: no #fields header"
        fields = fields_line.split("\t")[1:]
        assert "ts" in fields, f"{path.name}: no ts column"

        # Each data line must have the same number of tab-separated cols
        # as the header. This is the property that the seed_es.py parser
        # depends on; if it ever breaks, ingestion fails silently.
        for line in lines:
            if line.startswith("#") or not line:
                continue
            parts = line.split("\t")
            assert len(parts) == len(fields), (
                f"{path.name}: data row has {len(parts)} cols, header has {len(fields)}"
            )


def test_suricata_eve_is_jsonl(tmp_path):
    _build_s(tmp_path)
    eve = tmp_path / "suricata" / "eve.json"
    if not eve.exists():
        # Some seeds may produce zero alerts on S tier — but the file
        # should be written even if empty.
        pytest.fail("suricata/eve.json must exist even when event count is 0")
    for line in eve.read_text().splitlines():
        if line.strip():
            obj = json.loads(line)
            assert isinstance(obj, dict)


def test_jsonl_streams_are_well_formed(tmp_path):
    """Every .jsonl file must parse as line-delimited JSON."""
    _build_s(tmp_path)
    for jsonl_path in tmp_path.rglob("*.jsonl"):
        for i, line in enumerate(jsonl_path.read_text().splitlines()):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                pytest.fail(f"{jsonl_path}: line {i + 1} not JSON: {e}")
            assert isinstance(obj, dict)


# --- determinism -----------------------------------------------------------


def test_same_seed_byte_identical_re_run(tmp_path):
    """Same (tier, seed) -> byte-identical corpus across rebuilds."""
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    m_a = build_corpus(tier="S", output_dir=out_a, seed=42)
    m_b = build_corpus(tier="S", output_dir=out_b, seed=42)

    assert m_a["build_hash"] == m_b["build_hash"]

    files_a = sorted(p.relative_to(out_a) for p in out_a.rglob("*") if p.is_file())
    files_b = sorted(p.relative_to(out_b) for p in out_b.rglob("*") if p.is_file())
    assert files_a == files_b, "file layout differs between runs"

    for rel in files_a:
        bytes_a = (out_a / rel).read_bytes()
        bytes_b = (out_b / rel).read_bytes()
        assert bytes_a == bytes_b, f"{rel} differs across deterministic re-run"


def test_different_seeds_change_build_hash(tmp_path):
    m_a = build_corpus(tier="S", output_dir=tmp_path / "a", seed=1)
    m_b = build_corpus(tier="S", output_dir=tmp_path / "b", seed=2)
    assert m_a["build_hash"] != m_b["build_hash"]


# --- window + tier ---------------------------------------------------------


def test_window_anchors_at_default_start(tmp_path):
    manifest = _build_s(tmp_path)
    assert manifest["window"]["start"] == DEFAULT_START.isoformat()
    expected_end = DEFAULT_START + timedelta(days=TIER_DURATION_DAYS["S"])
    assert manifest["window"]["end"] == expected_end.isoformat()


def test_duration_days_override(tmp_path):
    manifest = build_corpus(
        tier="S", output_dir=tmp_path, seed=0, duration_days=2
    )
    assert manifest["window"]["duration_days"] == 2


def test_rejects_unknown_tier(tmp_path):
    with pytest.raises(ValueError, match="unknown tier"):
        build_corpus(tier="XL", output_dir=tmp_path)  # type: ignore[arg-type]


# --- CLI driver ------------------------------------------------------------


def test_cli_build_smoke(tmp_path):
    """Acceptance: ``python -m blue_bench_generators.it_baseline build
    --tier S --output <dir>`` runs end-to-end."""
    out = tmp_path / "corpus"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "blue_bench_generators.it_baseline",
            "build",
            "--tier",
            "S",
            "--output",
            str(out),
            "--seed",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"CLI failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (out / "corpus-manifest.yaml").exists()
    assert (out / "zeek").is_dir()
    assert "build_hash=" in result.stdout
