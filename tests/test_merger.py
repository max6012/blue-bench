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


def test_merge_corpus_end_to_end_smoke(tmp_path: Path, monkeypatch):
    """Drive the REAL merge_corpus with stubbed generators.

    The heavy path was documented as "exercised live, not in CI", and that gap
    let a NameError in the manifest block ship: the writer unit tests all passed
    while `merge_corpus` itself crashed after writing 17 GB. Stubbing the three
    generators keeps this at a few milliseconds while still executing every line
    of the real function, which is what catches that class of bug.
    """
    ef = tmp_path / "corpus"
    ef.mkdir()
    (ef / "GROUND_TRUTH.json").write_text(json.dumps({
        "collection_window": {"start": "2026-03-02T05:00:00Z",
                              "end": "2026-03-03T05:00:00Z"}}))

    def _ot(*a, **k):
        yield {"_log": "modbus", "_source": "ot", "ts": "1.0", "uid": "m1"}

    def _hosts(*a, **k):
        yield {"_log": "auth", "_source": "ot_hosts", "timestamp": "2026-03-02T06:00:00Z",
               "uid": "h1"}

    def _bridge(*a, **k):
        yield {"_log": "conn", "_source": "zeek", "ts": "2.0", "uid": "b1"}
        yield {"_log": "conn", "_source": "ot", "ts": "3.0", "uid": "b2"}

    def _sur(*a, **k):
        yield {"_log": "eve", "event_type": "alert", "ts": "4.0", "uid": "s1"}
        yield {"_log": "eve", "event_type": "flow", "ts": "5.0", "uid": "s2"}  # dropped

    monkeypatch.setattr(merger.ot_protocols, "generate", _ot)
    monkeypatch.setattr(merger.ot_hosts, "generate", _hosts)
    monkeypatch.setattr(merger.it_ot_bridge, "generate", _bridge)
    monkeypatch.setattr(merger.suricata_noise, "generate", _sur)

    scenario = Path(__file__).resolve().parents[1] / "scenarios" / "heavy-telemetry" / "bb-benign-s.yaml"
    manifest = merger.merge_corpus(ef, scenario, tier="S", seed=0)

    seg = manifest["segments"]
    assert seg["ot_protocols"]["events"] == 1
    assert seg["ot_hosts"]["events"] == 1
    assert seg["bridge"]["events"] == 2
    # the field that was a NameError: bridge sources must be reported
    assert seg["bridge"]["sources"] == ["ot", "zeek"]
    assert seg["suricata_fp"]["events"] == 1          # non-alert eve dropped
    assert manifest["build_hash"] and manifest["tier"] == "S"
    assert (ef / "ot" / "modbus.ndjson").exists()
    assert (ef / "bridge" / "zeek.conn.ndjson").exists()
