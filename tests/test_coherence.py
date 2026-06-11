"""Unit tests for the bridge-coherence gate (blue_bench_generators/merge/coherence).

Builds a tiny merged-corpus layout (a data/ host dir + a bridge NDJSON) and
checks that real IT endpoints pass while a ghost reference fails.
"""

from __future__ import annotations

import json
from pathlib import Path

from blue_bench_generators.merge.coherence import check_bridge_coherence

SCENARIO = (
    Path(__file__).resolve().parents[1]
    / "scenarios" / "heavy-telemetry" / "bb-benign-s.yaml"
)


def _make_corpus(tmp_path: Path, bridge_rows: list[dict]) -> Path:
    # a real corpus host dir EF would have written
    (tmp_path / "data" / "wkst-01.corp.example.invalid").mkdir(parents=True)
    bdir = tmp_path / "bridge"
    bdir.mkdir()
    with (bdir / "zeek.conn.ndjson").open("w") as f:
        for r in bridge_rows:
            f.write(json.dumps(r) + "\n")
    return tmp_path


def test_gate_passes_when_endpoints_are_real_hosts(tmp_path: Path):
    # 10.10.0.11 is wkst-01 in the scenario; a real corpus host
    corpus = _make_corpus(tmp_path, [{"src_ip": "10.10.0.11", "dst_ip": "10.40.0.11"}])
    res = check_bridge_coherence(corpus, SCENARIO, tier="S")
    assert res.bridge_events == 1
    assert res.it_refs == {"10.10.0.11"}      # 10.40.x is OT dest, not an IT ref
    assert res.ok and not res.vacuous


def test_gate_fails_on_ghost_it_endpoint(tmp_path: Path):
    # 10.30.0.99 is in corp space but not a declared host -> orphan
    corpus = _make_corpus(tmp_path, [{"src_ip": "10.30.0.99", "dst_ip": "10.40.0.11"}])
    res = check_bridge_coherence(corpus, SCENARIO, tier="S")
    assert not res.ok and "10.30.0.99" in res.orphans


def test_gate_vacuous_when_no_bridge_events(tmp_path: Path):
    corpus = _make_corpus(tmp_path, [])
    res = check_bridge_coherence(corpus, SCENARIO, tier="S")
    assert res.vacuous and res.ok and res.bridge_events == 0


def test_jump_host_endpoint_is_a_real_host(tmp_path: Path):
    # the jump host we added in P4a — its IP must register as a real corpus host
    corpus = _make_corpus(tmp_path, [{"src_ip": "10.30.0.10", "dst_ip": "10.40.0.11"}])
    res = check_bridge_coherence(corpus, SCENARIO, tier="S")
    assert res.ok and "10.30.0.10" in res.it_refs
