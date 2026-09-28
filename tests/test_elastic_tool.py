"""ElasticTool unit tests — uses live ES when available, otherwise skipped.

Live path exercises search_alerts, get_connections, count_by_field end-to-end
without needing seeded data: empty indices still return a well-formed response.
"""
import json
import re

import pytest

from blue_bench_mcp.config import ElasticConfig, LimitsConfig, ServerConfig, ZeekConfig
from blue_bench_mcp.tool_classes.elastic import ElasticTool


ES_URL = "http://localhost:9200"


def _es_reachable() -> bool:
    import httpx
    try:
        return httpx.get(f"{ES_URL}/_cluster/health", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


requires_es = pytest.mark.skipif(not _es_reachable(), reason="Elasticsearch not running")


@pytest.fixture
def tool():
    cfg = ServerConfig(
        elastic=ElasticConfig(url=ES_URL, index_pattern="bb-test-*"),
        zeek=ZeekConfig(index="bb-test-*", use_elastic=True),
        limits=LimitsConfig(max_results=50, max_result_chars=5000, query_timeout=5),
    )
    return ElasticTool(cfg)


@requires_es
async def test_count_by_field_empty_index(tool):
    # Index doesn't exist → ES returns 404; our tool surfaces a well-formed error.
    out = await tool.count_by_field(field="src_ip", timerange_minutes=60)
    # Either "Error:" (404) or "(no results" (empty).
    assert out.startswith("Error:") or "no results" in out.lower() or out.startswith("Top ")


@requires_es
async def test_search_alerts_shape(tool):
    out = await tool.search_alerts(src_ip="10.10.5.22", timerange_minutes=60)
    # Returns valid JSON or a well-formed error; shouldn't raise.
    assert isinstance(out, str)
    assert len(out) > 0


async def test_severity_is_int_typed():
    # Post-fix: severity is int, not str. With `from __future__ import annotations`
    # annotations are strings; compare as string.
    cfg = ServerConfig(elastic=ElasticConfig(url=ES_URL))
    t = ElasticTool(cfg)
    import inspect
    sig = inspect.signature(t.search_alerts)
    assert str(sig.parameters["severity"].annotation) == "int"
    assert sig.parameters["severity"].default == 0


def test_zeek_index_chosen_when_use_elastic_true():
    cfg = ServerConfig(
        elastic=ElasticConfig(url=ES_URL, index_pattern="logstash-*"),
        zeek=ZeekConfig(index="zeek-custom-*", use_elastic=True),
    )
    t = ElasticTool(cfg)
    # get_connections spans the Zeek IT index + the OT connection index so a
    # defender sees OT protocol traffic (Modbus/DNP3/…) with the same tool.
    assert t.zeek_index == "zeek-custom-*,ot-conn"


def test_zeek_index_falls_back_when_use_elastic_false():
    cfg = ServerConfig(
        elastic=ElasticConfig(url=ES_URL, index_pattern="logstash-*"),
        zeek=ZeekConfig(index="zeek-custom-*", use_elastic=False),
    )
    t = ElasticTool(cfg)
    assert t.zeek_index == "logstash-*"


# --- absolute since / until ---------------------------------------------------
# search_alerts / get_connections / count_by_field are the remaining list and
# aggregate tools the fan-out slices bind; the range semantics live in one
# helper, so these check each tool actually routes through it.

def _capture(tool: ElasticTool, attr: str = "_search") -> list[dict]:
    """Stub the ES call to capture the request body instead of hitting ES."""
    seen: list[dict] = []

    async def fake(body, index=None, **k):
        seen.append(body)
        return ([], 0) if attr == "_search" else {}

    setattr(tool, attr, fake)
    return seen


BAND = {"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z",
                                 "lte": "2026-08-27T00:00:00Z"}}}


async def test_search_alerts_absolute_band_replaces_the_lookback(tool):
    seen = _capture(tool)
    await tool.search_alerts(timerange_minutes=99, since="2026-08-26T00:00:00Z",
                             until="2026-08-27T00:00:00Z")
    import json
    assert BAND in seen[0]["query"]["bool"]["must"]
    assert "now-" not in json.dumps(seen[0])


async def test_get_connections_absolute_band_replaces_the_lookback(tool):
    seen = _capture(tool)
    await tool.get_connections(timerange_minutes=99, since="2026-08-26T00:00:00Z",
                               until="2026-08-27T00:00:00Z")
    import json
    assert BAND in seen[0]["query"]["bool"]["must"]
    assert "now-" not in json.dumps(seen[0])


async def test_get_connections_since_alone_runs_to_now(tool):
    seen = _capture(tool)
    await tool.get_connections(since="2026-08-26T00:00:00+00:00")
    assert {"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z", "lte": "now"}}} \
        in seen[0]["query"]["bool"]["must"]


async def test_count_by_field_absolute_band_and_header(tool):
    seen = _capture(tool, "_agg")

    async def plan(field, index):
        return {field: [index]}

    tool._agg_field_plan = plan
    out = await tool.count_by_field(field="src_ip", timerange_minutes=99,
                                    since="2026-08-26T00:00:00Z", until="2026-08-27T00:00:00Z")
    assert seen[0]["query"] == BAND
    # The header must not keep advertising the lookback it just ignored.
    assert "last 99m" not in out
    assert "2026-08-26T00:00:00Z to 2026-08-27T00:00:00Z" in out


async def test_search_alerts_bad_bound_is_refused_without_calling_es(tool):
    async def boom(*a, **k):
        raise AssertionError("ES was called for an unparseable since")

    tool._search = boom
    out = await tool.search_alerts(since="last tuesday")
    assert out.startswith("Error: since/until must be ISO-8601 UTC")


async def test_get_connections_reversed_band_is_refused_without_calling_es(tool):
    async def boom(*a, **k):
        raise AssertionError("ES was called for a reversed range")

    tool._search = boom
    out = await tool.get_connections(since="2026-08-27T00:00:00Z",
                                     until="2026-08-26T00:00:00Z")
    assert out.startswith("Error:") and "after" in out


async def test_count_by_field_bad_bound_is_refused_without_calling_es(tool):
    async def boom(*a, **k):
        raise AssertionError("ES was called for an unparseable until")

    tool._agg = boom
    out = await tool.count_by_field(field="src_ip", until="whenever")
    assert out.startswith("Error: since/until must be ISO-8601 UTC")


# --- host_ip: the either-end filter -------------------------------------------
# The tool classes have always had host_ip (an OR over both ends); the registered
# wrappers did not expose it, so a fan-out slice's host_ips could not bind on
# search_alerts / get_connections. These pin the wrapper surface and the OR.

def _registered_server():
    """A real server with the elastic wrappers registered, as the model sees it."""
    from mcp.server import MCPServer

    from blue_bench_mcp.tools import elastic as elastic_tools
    server = MCPServer("test")
    elastic_tools.register(server, ServerConfig(elastic=ElasticConfig(url=ES_URL)))
    return server


async def test_network_wrappers_expose_host_ip_first():
    tools = {t.name: t for t in await _registered_server().list_tools()}
    for name, extra in (("search_alerts", {"severity", "query_text"}),
                        ("get_connections", {"dest_port", "proto"})):
        props = tools[name].input_schema["properties"]
        assert set(props) == {"host_ip", "src_ip", "dest_ip",
                              "timerange_minutes", "since", "until"} | extra
        assert props["host_ip"]["default"] == ""
        # First in the signature: it is the filter a model should reach for by
        # default, and schema order is what the model reads.
        assert next(iter(props)) == "host_ip"


async def test_host_ip_reaches_the_tool_class(monkeypatch):
    seen: list[dict] = []

    async def echo(self, **kwargs):
        seen.append(kwargs)
        return "[]"

    monkeypatch.setattr(ElasticTool, "search_alerts", echo)
    monkeypatch.setattr(ElasticTool, "get_connections", echo)
    server = _registered_server()
    for name in ("search_alerts", "get_connections"):
        await server.call_tool(name, {"host_ip": "10.1.20.33"})
    assert [k["host_ip"] for k in seen] == ["10.1.20.33", "10.1.20.33"]


@requires_es
async def test_live_host_ip_matches_both_ends_and_beats_src_ip_alone():
    """The OR is doing work: host_ip must match strictly more than src_ip alone.

    Everything is derived from the live corpus — the band from a min/max agg on
    zeek-conn, the IP from a terms agg on id.orig_h — so the test carries no
    hard-coded corpus facts that a rebuild would falsify.
    """
    import httpx
    conn = "zeek-conn"
    band = httpx.post(f"{ES_URL}/{conn}/_search", json={
        "size": 0,
        "aggs": {"lo": {"min": {"field": "@timestamp"}},
                 "hi": {"max": {"field": "@timestamp"}}},
    }, timeout=30.0).json()["aggregations"]
    since = band["lo"]["value_as_string"]
    until = band["hi"]["value_as_string"]
    rng = {"range": {"@timestamp": {"gte": since, "lte": until}}}

    def _count(clause: dict) -> int:
        body = {"query": {"bool": {"must": [clause, rng]}}}
        return httpx.post(f"{ES_URL}/{conn}/_count", json=body, timeout=30.0).json()["count"]

    # id.orig_h is mapped `ip`, so a plain terms agg on the bare field works.
    buckets = httpx.post(f"{ES_URL}/{conn}/_search", json={
        "size": 0, "query": rng,
        "aggs": {"t": {"terms": {"field": "id.orig_h", "size": 10}}},
    }, timeout=30.0).json()["aggregations"]["t"]["buckets"]

    # A top talker is not automatically a responder: pick the first candidate
    # that actually appears at both ends, so the inequality below is real.
    either = {"bool": {"should": [{"term": {"id.orig_h": None}},
                                  {"term": {"id.resp_h": None}}],
                       "minimum_should_match": 1}}
    for b in buckets:
        ip = b["key"]
        either["bool"]["should"][0]["term"]["id.orig_h"] = ip
        either["bool"]["should"][1]["term"]["id.resp_h"] = ip
        if _count(either) > _count({"term": {"id.orig_h": ip}}):
            break
    else:
        pytest.skip("no top-talker IP in zeek-conn appears as a responder too")

    cfg = ServerConfig(elastic=ElasticConfig(url=ES_URL),
                       limits=LimitsConfig(max_results=20, max_result_chars=40000,
                                           query_timeout=30))
    t = ElasticTool(cfg)
    both = await t.get_connections(host_ip=ip, since=since, until=until)
    orig = await t.get_connections(src_ip=ip, since=since, until=until)
    assert not both.startswith("Error:"), both
    assert not orig.startswith("Error:"), orig

    # Every record really has the IP at one end or the other.
    records = json.loads(both.split("\n\n---")[0])
    assert records
    assert all(ip in (r.get("id.orig_h"), r.get("id.resp_h")) for r in records)

    # Compare true match counts, not page sizes: max_results caps both bodies.
    assert _match_total(both) > _match_total(orig)


def _match_total(out: str) -> int:
    """The true match count of a list-tool result.

    The footer only states it when ES matched more than one page (guardrails.
    result_footer), so fall back to counting the records actually returned.
    """
    m = re.search(r"matched ([\d,]+)", out)
    if m:
        return int(m.group(1).replace(",", ""))
    return len(json.loads(out.split("\n\n---")[0]))
