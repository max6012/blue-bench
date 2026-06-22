"""Unit tests for the corpus merger helpers (blue_bench_generators/merge/merger).

Covers the pure writer/hash/window logic with synthetic events — the full
``merge_corpus`` drives the real OT generators (~500k events) and is exercised
live in EF-P4b/P4c, not in CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from blue_bench_generators.merge import merger


def test_write_ndjson_by_log_groups_strips_internal_and_sorts(tmp_path: Path):
    events = [
        {"_log": "modbus", "_source": "ot", "ts": "2.0", "uid": "b", "func": "read"},
        {"_log": "modbus", "_source": "ot", "ts": "1.0", "uid": "a", "func": "write"},
        {"_log": "conn", "ts": "1.5", "uid": "c", "proto": "tcp"},
    ]
    n = merger._write_ndjson_by_log(events, tmp_path)
    assert n == 3
    assert (tmp_path / "modbus.ndjson").exists() and (tmp_path / "conn.ndjson").exists()
    rows = [json.loads(x) for x in (tmp_path / "modbus.ndjson").read_text().splitlines()]
    # sorted by ts -> uid 'a' (ts 1.0) before 'b' (ts 2.0)
    assert [r["uid"] for r in rows] == ["a", "b"]
    # internal _-fields stripped from the written docs
    assert all(not any(k.startswith("_") for k in r) for r in rows)


def test_write_ndjson_prefix_separates_bridge_sources(tmp_path: Path):
    evs = [{"_log": "conn", "_source": "zeek", "ts": "1.0", "uid": "z"}]
    merger._write_ndjson_by_log(evs, tmp_path, prefix="zeek.")
    assert (tmp_path / "zeek.conn.ndjson").exists()


def test_parse_window_reads_collection_window(tmp_path: Path):
    (tmp_path / "GROUND_TRUTH.json").write_text(json.dumps({
        "collection_window": {"start": "2026-03-02T05:00:00Z", "end": "2026-03-03T05:00:00Z"}
    }))
    start, end = merger._parse_window(tmp_path)
    assert start.year == 2026 and start.hour == 5 and start.tzinfo is None
    assert (end - start).days == 1


def test_content_hash_excludes_ef_metadata_and_is_deterministic(tmp_path: Path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "a.json").write_text('{"x":1}\n')
    (tmp_path / "GROUND_TRUTH.json").write_text('{"generated_at":"now"}')  # excluded
    h1, files1 = merger._content_hash(tmp_path)
    # changing only the excluded metadata file must NOT change the hash
    (tmp_path / "GROUND_TRUTH.json").write_text('{"generated_at":"later"}')
    h2, _ = merger._content_hash(tmp_path)
    assert h1 == h2
    assert all(f["path"] != "GROUND_TRUTH.json" for f in files1)
    # changing a telemetry file MUST change the hash
    (tmp_path / "data" / "a.json").write_text('{"x":2}\n')
    h3, _ = merger._content_hash(tmp_path)
    assert h3 != h1
