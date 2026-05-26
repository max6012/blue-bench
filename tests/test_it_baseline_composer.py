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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from blue_bench_generators.it_baseline.composer import (
    DEFAULT_START,
    TIER_DURATION_DAYS,
    _zeek_value,
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


def test_log_routing_field_stripped_from_jsonl(tmp_path):
    """``_log`` is a generator-internal routing field. Real
    Suricata/Sysmon/auditd telemetry has no such field; leaving it in
    would surface a phantom column to MCP consumers."""
    _build_s(tmp_path)
    jsonl_paths = list(tmp_path.rglob("*.jsonl")) + [tmp_path / "suricata" / "eve.json"]
    for path in jsonl_paths:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            assert "_log" not in obj, (
                f"{path}: ``_log`` field leaked into JSONL output; "
                f"strip it in the writer before serialisation"
            )


def test_evtx_channel_field_preserved(tmp_path):
    """``channel`` IS a real EventLog field (unlike ``_log``) and must
    survive the strip pass for evtx. Check every row, not just the first
    -- a partial-strip regression that drops ``channel`` mid-stream would
    slip past a head-only assertion."""
    _build_s(tmp_path)
    security = tmp_path / "evtx" / "security.jsonl"
    if not security.exists():
        pytest.skip("no security channel events in this S run")
    for i, line in enumerate(security.read_text().splitlines()):
        if not line.strip():
            continue
        obj = json.loads(line)
        assert obj.get("channel") == "Security", (
            f"row {i + 1}: channel={obj.get('channel')!r}, expected 'Security'"
        )


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


def test_tz_aware_start_normalised_to_utc(tmp_path):
    """A tz-aware ``--start`` from the CLI is reduced to its UTC wall-clock
    so the per-source generators (which assume naive datetimes) don't
    trip on offset-naive-vs-aware comparisons. The window in the manifest
    is the naive UTC value, not the original tz-aware string."""
    aware = datetime(2026, 1, 5, 4, 0, 0, tzinfo=timezone(timedelta(hours=4)))
    manifest = build_corpus(
        tier="S", output_dir=tmp_path, seed=0, start=aware, duration_days=1
    )
    assert manifest["window"]["start"] == "2026-01-05T00:00:00"


# --- stale-file cleanup ----------------------------------------------------


def test_rebuild_into_same_dir_removes_orphans(tmp_path):
    """A re-build of a smaller tier over a larger one must not leave
    orphan files from the prior build inside the managed source dirs."""
    # First build: L would be slow; simulate with an artificial pre-existing
    # file inside one of the managed source dirs.
    _build_s(tmp_path)
    orphan = tmp_path / "services" / "proxy_access.jsonl"
    orphan.write_text('{"_log": "proxy_access", "stale": true}\n', encoding="utf-8")
    assert orphan.exists()

    # Rebuild: the orphan must be gone.
    _build_s(tmp_path)
    proxy_files_now = [p.name for p in (tmp_path / "services").iterdir()]
    assert "proxy_access.jsonl" not in proxy_files_now, (
        f"orphan from prior build survived: services/ now contains {proxy_files_now}"
    )


# --- Zeek value formatting -------------------------------------------------


def test_zeek_value_bool_encoding():
    """Canonical Zeek TSV uses ``T`` / ``F`` for bools (see
    ``data/raw/conn.log`` ``local_orig`` column)."""
    assert _zeek_value(True) == "T"
    assert _zeek_value(False) == "F"


def test_zeek_value_escapes_tsv_breakers():
    """Tabs / newlines / backslashes inside a string field would corrupt
    the row's column count or escape semantics for a strict parser."""
    assert "\t" not in _zeek_value("foo\tbar")
    assert "\n" not in _zeek_value("foo\nbar")
    assert _zeek_value("foo\\bar") == "foo\\\\bar"


def test_zeek_value_none_and_lists():
    assert _zeek_value(None) == "-"
    assert _zeek_value([]) == "(empty)"
    assert _zeek_value(["a", "b"]) == "a,b"


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


def test_cli_cross_process_determinism(tmp_path):
    """Two CLI invocations with the same ``(tier, seed)`` must produce the
    same ``build_hash``. PR #2 added cross-process determinism explicitly
    for the per-source generators (no hash-randomisation / no
    environment-leak); the composer must inherit that property since the
    CLI is the load-bearing entry point for the bake-off, not the
    in-process API."""
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    for out in (out_a, out_b):
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
                "7",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.returncode == 0, f"CLI failed: stderr={result.stderr!r}"
    manifest_a = yaml.safe_load((out_a / "corpus-manifest.yaml").read_text())
    manifest_b = yaml.safe_load((out_b / "corpus-manifest.yaml").read_text())
    assert manifest_a["build_hash"] == manifest_b["build_hash"], (
        f"cross-process determinism broken: {manifest_a['build_hash']} != {manifest_b['build_hash']}"
    )


# --- guard rails -----------------------------------------------------------


def test_refuses_to_overwrite_unmanaged_output_dir(tmp_path):
    """If --output points at a directory containing a ``zeek/`` (or any
    other managed subdir) without a ``corpus-manifest.yaml``, refuse. This
    prevents wiping files in a directory that just happened to share a
    subdir name (e.g. ``--output ~/Documents``)."""
    bogus = tmp_path / "looks-like-corpus-but-isnt"
    (bogus / "zeek").mkdir(parents=True)
    (bogus / "zeek" / "user-data.log").write_text("important\n")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        build_corpus(tier="S", output_dir=bogus, seed=0)

    # The user's file must be untouched.
    assert (bogus / "zeek" / "user-data.log").read_text() == "important\n"


def test_routing_missing_field_raises(tmp_path):
    """A generator that emits a record without its declared routing field
    is a contract violation -- the composer must surface it, not bucket
    the record into ``other.jsonl`` and continue silently."""
    from blue_bench_generators.it_baseline.composer import _write_jsonl_by_field

    bad_events = [{"_log": "ok"}, {"missing": True}]  # second one lacks _log
    with pytest.raises(ValueError, match="missing routing field"):
        _write_jsonl_by_field(bad_events, tmp_path, tmp_path, field="_log", suffix=".jsonl")


def test_json_strict_default_rejects_non_native_types(tmp_path):
    """``json.dumps`` would otherwise coerce ``datetime`` via ``str()`` to
    a non-ISO form (``2026-01-05 00:00:00``) -- failing in CI is better
    than failing in a downstream parser."""
    from blue_bench_generators.it_baseline.composer import _json_strict

    with pytest.raises(TypeError, match="non-serialisable"):
        _json_strict(datetime(2026, 1, 5))


def test_zeek_value_rejects_nested_dict():
    """A nested dict in a Zeek record would silently stringify via
    ``str(dict)`` and produce invalid TSV that the column-count check
    wouldn't catch."""
    from blue_bench_generators.it_baseline.composer import _zeek_value

    with pytest.raises(TypeError, match="nested dicts"):
        _zeek_value({"a": 1})


def test_files_use_lf_newlines(tmp_path):
    """``newline=""`` everywhere -- the determinism contract requires
    byte-identical files across OSes, and any CRLF would leak through
    platform translation otherwise. Spot-check one of each format kind."""
    _build_s(tmp_path)
    samples = [
        tmp_path / "corpus-manifest.yaml",
        tmp_path / "zeek" / "conn.log",
        tmp_path / "suricata" / "eve.json",
        tmp_path / "evtx" / "security.jsonl",
        tmp_path / "linux" / "auth.log",
    ]
    for path in samples:
        if not path.exists():
            continue
        raw = path.read_bytes()
        assert b"\r\n" not in raw, f"{path}: CRLF newline leaked into output"
