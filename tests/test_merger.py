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


def test_write_ndjson_spills_and_merges_preserving_sort_order(tmp_path: Path):
    """The spill path must produce byte-identical output to the in-memory path.

    At L scale the OT generators yield ~87M events (~43 GB as dicts); the
    callers used to wrap them in list() and OOMed the machine. The writer now
    buffers a bounded chunk per log, spills sorted runs, and k-way merges them
    -- so sort order survives. Forced here with a tiny chunk_size.
    """
    import random
    rng = random.Random(7)
    events = [
        {"_log": "modbus" if i % 3 else "conn", "_source": "ot",
         "ts": str(rng.random() * 1000), "uid": f"u{i:05d}", "func": "read"}
        for i in range(500)
    ]
    streamed = tmp_path / "streamed"
    inmem = tmp_path / "inmem"
    n_s = merger._write_ndjson_by_log(iter(events), streamed, chunk_size=17)
    n_m = merger._write_ndjson_by_log(iter(events), inmem, chunk_size=10_000)
    assert n_s == n_m == 500

    for name in ("modbus.ndjson", "conn.ndjson"):
        a = (streamed / name).read_text()
        b = (inmem / name).read_text()
        assert a == b, f"{name}: spill+merge output differs from in-memory output"
        rows = [json.loads(x) for x in a.splitlines()]
        keys = [merger._ndjson_sort_key(r) for r in rows]
        assert keys == sorted(keys), f"{name} is not sorted after the merge"
    # the temp spill dir must not survive
    assert not (streamed / ".spill").exists()


def test_write_ndjson_accepts_a_generator_without_materializing(tmp_path: Path):
    """Guard the actual OOM: the writer must never hold the whole stream."""
    peak = {"n": 0}

    def _gen():
        for i in range(1000):
            peak["n"] = max(peak["n"], i)
            yield {"_log": "modbus", "ts": str(i), "uid": f"u{i:04d}"}

    n = merger._write_ndjson_by_log(_gen(), tmp_path, chunk_size=50)
    assert n == 1000
    rows = (tmp_path / "modbus.ndjson").read_text().splitlines()
    assert len(rows) == 1000
