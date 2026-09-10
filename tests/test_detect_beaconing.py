"""detect_beaconing unit tests — fixture-driven, no live ES.

We mock ElasticTool._agg (candidate aggregation) and ElasticTool._query (the
per-pair timestamp fetch) from an in-memory corpus of (src,dest)->timestamps,
so the interval-CV math, the coverage envelope, the rarity-first budget, and
the /24 rotation lever are all deterministic.
"""
import ipaddress
import json

import pytest

from blue_bench_mcp.config import BeaconingConfig, ServerConfig
from blue_bench_mcp.tool_classes.elastic import ElasticTool, _dest_key, _to_epoch

BASE = 1_780_000_000  # arbitrary fixed epoch


def _regular(dest, n, interval=10800, start=0, jitter=1200):
    """A regular beacon: n callbacks ~interval apart, small deterministic jitter."""
    return [(BASE + start + i * interval + ((i % 5) - 2) * jitter // 2) for i in range(n)]


def _bursty(dest, n):
    """Irregular traffic: alternating tiny and huge gaps -> high interval CV."""
    ts, t = [], BASE
    for i in range(n):
        ts.append(t)
        t += 60 if i % 2 == 0 else 50_000
    return ts


# in-memory corpus: (src, dest) -> list[epoch seconds]
CORPUS: dict[tuple[str, str], list[int]] = {
    ("10.10.0.13", "146.190.62.150"): _regular("146.190.62.150", 80),   # the beacon (rarity 1)
}
# a benign chatty CDN contacted by MANY hosts, bursty
for h in range(20):
    CORPUS[(f"10.10.0.{20+h}", "13.107.6.173")] = _bursty("13.107.6.173", 200)
# a rotated beacon: 80 callbacks every 3h, round-robin across 5 IPs in
# 146.190.63.0/24. Each IP gets 16 callbacks (< min=20) -> invisible per-IP;
# the merged /24 is a clean 3h cadence of 80 -> surfaces under aggregation='/24'.
_rot: dict[str, list[int]] = {}
for i in range(80):
    last = 10 + (i % 5)
    ts = BASE + i * 10800 + ((i % 5) - 2) * 600
    _rot.setdefault(f"146.190.63.{last}", []).append(ts)
for d, ts in _rot.items():
    CORPUS[("10.10.0.13", d)] = sorted(ts)


def _make_tool(**bc_kwargs) -> ElasticTool:
    cfg = ServerConfig(beaconing=BeaconingConfig(**bc_kwargs))
    tool = ElasticTool(cfg)

    async def fake_agg(body, index=None):
        # Build nested dest->src buckets from the corpus (external filter: corpus
        # is all-external already). Honor an explicit dest_ip filter if present.
        dests: dict[str, dict[str, int]] = {}
        for (s, d), ts in CORPUS.items():
            dests.setdefault(d, {})[s] = len(ts)
        return {"aggregations": {"dest": {"buckets": [
            {"key": d, "doc_count": sum(srcs.values()),
             "src": {"buckets": [{"key": s, "doc_count": c} for s, c in srcs.items()]}}
            for d, srcs in dests.items()]}}}

    async def fake_query(body, index=None):
        must = body["query"]["bool"]["must"]
        src = next((m["term"]["id.orig_h"] for m in must if "term" in m and "id.orig_h" in m["term"]), None)
        dest = next((m["term"]["id.resp_h"] for m in must if "term" in m and "id.resp_h" in m["term"]), None)
        net = ipaddress.ip_network(dest, strict=False) if dest and "/" in dest else None
        hits = []
        for (s, d), ts in CORPUS.items():
            if s != src:
                continue
            if net is not None:
                if ipaddress.ip_address(d) not in net:
                    continue
            elif d != dest:
                continue
            hits += [{"@timestamp": str(t), "orig_bytes": "540", "id.resp_p": "443"} for t in ts]
        return hits

    tool._agg = fake_agg
    tool._query = fake_query
    return tool


# --- pure helpers ---------------------------------------------------------

def test_to_epoch_parses_zeek_and_iso():
    assert _to_epoch("1780000000.5") == pytest.approx(1780000000.5)
    assert _to_epoch("2026-06-08T03:00:00+00:00") == pytest.approx(1780000000, abs=5e6)
    assert _to_epoch(None) is None
    assert _to_epoch("not-a-time") is None


def test_dest_key_granularity():
    assert _dest_key("146.190.63.11", "ip") == "146.190.63.11"
    assert _dest_key("146.190.63.11", "/24") == "146.190.63.0/24"


# --- the analytic ---------------------------------------------------------

async def test_beacon_surfaces_and_bursty_filtered():
    tool = _make_tool()
    out = json.loads(await tool.detect_beaconing(aggregation="ip"))
    dests = [c["dest"] for c in out["candidates"]]
    assert "146.190.62.150" in dests            # the regular beacon surfaces
    assert "13.107.6.173" not in dests          # bursty benign is filtered by max_jitter
    beacon = next(c for c in out["candidates"] if c["dest"] == "146.190.62.150")
    assert beacon["distinct_src_hosts"] == 1
    assert beacon["interval_cv"] < 0.35
    assert beacon["connections"] == 80


async def test_coverage_envelope_is_present_and_bounded():
    tool = _make_tool()
    out = json.loads(await tool.detect_beaconing(aggregation="ip"))
    a = out["analysis"]
    assert a["pairs_analyzed"] > 0
    assert a["min_connections"] == 20
    assert any("rotated" in b.lower() for b in a["blind_spots"])   # per-IP names the rotation blind spot
    assert any("min_connections" in b for b in a["blind_spots"])


async def test_rotation_blind_under_ip_caught_under_24():
    tool = _make_tool()
    ip = json.loads(await tool.detect_beaconing(aggregation="ip"))
    slash24 = json.loads(await tool.detect_beaconing(aggregation="/24"))
    ip_dests = {c["dest"] for c in ip["candidates"]}
    s24_dests = {c["dest"] for c in slash24["candidates"]}
    # each rotated leg has 15 conns (< min 20) -> invisible per-IP
    assert not any(d.startswith("146.190.63.") for d in ip_dests)
    # merged into the /24 -> 60 conns, regular -> surfaces
    assert "146.190.63.0/24" in s24_dests


async def test_min_connections_tuning_changes_exclusions():
    lo = json.loads(await _make_tool().detect_beaconing(min_connections=5, aggregation="ip"))
    hi = json.loads(await _make_tool().detect_beaconing(min_connections=200, aggregation="ip"))
    assert hi["analysis"]["pairs_excluded_below_min_connections"] > \
        lo["analysis"]["pairs_excluded_below_min_connections"]


async def test_floor_is_enforced():
    # config floor 5; asking for 1 is clamped up to the floor.
    out = json.loads(await _make_tool(min_connections_floor=5).detect_beaconing(min_connections=1))
    assert out["analysis"]["min_connections"] == 5
