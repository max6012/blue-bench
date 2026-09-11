"""count_by_time (date_histogram survey tool) tests for ElasticTool.

Unit path: stub ElasticTool._agg to capture the request body and assert the
query shape (histogram key, interval, host / event_id filters), plus the
rendering of an empty result and the bad-interval refusal (which must not
reach ES at all).

Live path: when ES is reachable and windows-sysmon is populated, survey the
whole corpus at 1d and check the header total is the sum of the buckets.
"""
import json
import re

import pytest
from mcp.server import MCPServer

from blue_bench_mcp.config import (
    ElasticConfig,
    LimitsConfig,
    ServerConfig,
    SysmonConfig,
    ZeekConfig,
)
from blue_bench_mcp.tool_classes.elastic import ElasticTool
from blue_bench_mcp.tools import elastic as elastic_tools


ES_URL = "http://localhost:9200"
SYSMON_INDEX = "windows-sysmon"


def _es_reachable() -> bool:
    import httpx
    try:
        return httpx.get(f"{ES_URL}/_cluster/health", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


def _sysmon_populated() -> bool:
    import httpx
    try:
        r = httpx.get(f"{ES_URL}/{SYSMON_INDEX}/_count", timeout=2.0)
        return r.status_code == 200 and r.json().get("count", 0) > 0
    except (httpx.HTTPError, ValueError):
        return False


requires_sysmon = pytest.mark.skipif(
    not (_es_reachable() and _sysmon_populated()),
    reason="Elasticsearch / windows-sysmon not available",
)


def _cfg() -> ServerConfig:
    return ServerConfig(
        elastic=ElasticConfig(url=ES_URL, index_pattern="bb-test-*"),
        zeek=ZeekConfig(index="bb-test-*", use_elastic=True),
        sysmon=SysmonConfig(index=SYSMON_INDEX),
        limits=LimitsConfig(max_results=50, max_result_chars=20000, query_timeout=5),
    )


@pytest.fixture
def tool():
    return ElasticTool(_cfg())


def _stub_agg(tool: ElasticTool, buckets: list[dict]) -> dict:
    """Replace tool._agg with a capture stub; returns the dict the stub fills."""
    seen: dict = {}

    async def fake_agg(body, index=None):
        seen["body"] = body
        seen["index"] = index
        return {"aggregations": {"over_time": {"buckets": buckets}}}

    tool._agg = fake_agg
    return seen


# --- query shape ---------------------------------------------------------------

async def test_histogram_shape_and_default_index(tool):
    seen = _stub_agg(tool, [])
    await tool.count_by_time(interval="6h", timerange_minutes=120)
    body = seen["body"]
    assert seen["index"] == "bb-test-*"
    assert body["size"] == 0
    hist = body["aggs"]["over_time"]["date_histogram"]
    # ES 8: bare `interval` is rejected; fixed_interval is the accepted key.
    assert hist == {"field": "@timestamp", "fixed_interval": "6h", "min_doc_count": 1}
    assert "aggs" not in body["aggs"]["over_time"]  # no host sub-agg unless asked
    must = body["query"]["bool"]["must"]
    assert must == [{"range": {"@timestamp": {"gte": "now-120m", "lte": "now"}}}]


async def test_index_override_passes_comma_list(tool):
    seen = _stub_agg(tool, [])
    await tool.count_by_time(index="windows-security,linux-syslog")
    assert seen["index"] == "windows-security,linux-syslog"


async def test_host_filter_spans_sysmon_zeek_and_auth_fields(tool):
    seen = _stub_agg(tool, [])
    await tool.count_by_time(host="wkst-01.corp.example.invalid")
    must = seen["body"]["query"]["bool"]["must"]
    host_clause = must[0]["bool"]
    assert host_clause["minimum_should_match"] == 1
    assert host_clause["should"] == [
        {"term": {"Computer.keyword": "wkst-01.corp.example.invalid"}},
        {"term": {"id.orig_h": "wkst-01.corp.example.invalid"}},
        {"term": {"id.resp_h": "wkst-01.corp.example.invalid"}},
        # match_phrase, not match: an analyzed OR over the FQDN tokens would
        # match every sibling host in the domain (found on the live corpus).
        {"match_phrase": {"Computer": "wkst-01.corp.example.invalid"}},
        {"match_phrase": {"host": "wkst-01.corp.example.invalid"}},
    ]


async def test_event_id_matches_both_spellings(tool):
    seen = _stub_agg(tool, [])
    await tool.count_by_time(event_id=4624)
    must = seen["body"]["query"]["bool"]["must"]
    assert {"bool": {"should": [
        {"term": {"EventID": 4624}},
        {"term": {"event_id": 4624}},
    ], "minimum_should_match": 1}} in must


async def test_query_text_and_top_n_hosts(tool):
    seen = _stub_agg(tool, [])
    await tool.count_by_time(query_text="powershell", top_n_hosts=3)
    must = seen["body"]["query"]["bool"]["must"]
    assert {"query_string": {"query": "powershell"}} in must
    sub = seen["body"]["aggs"]["over_time"]["aggs"]
    assert sub == {"hosts": {"terms": {"field": "Computer.keyword", "size": 3}}}


async def test_bad_interval_is_refused_without_calling_es(tool):
    async def boom(body, index=None):
        raise AssertionError("ES was called for an invalid interval")

    tool._agg = boom
    out = await tool.count_by_time(interval="2h")
    assert out.startswith("Error:")
    assert "2h" in out
    assert "15m, 1h, 6h, 1d" in out


# --- absolute since / until ----------------------------------------------------

async def test_since_and_until_replace_the_lookback(tool):
    seen = _stub_agg(tool, [])
    await tool.count_by_time(timerange_minutes=120, since="2026-08-26T00:00:00Z",
                             until="2026-08-27T00:00:00Z")
    must = seen["body"]["query"]["bool"]["must"]
    assert must == [{"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z",
                                             "lte": "2026-08-27T00:00:00Z"}}}]
    assert "now-" not in json.dumps(seen["body"])


async def test_since_alone_runs_to_now(tool):
    seen = _stub_agg(tool, [])
    await tool.count_by_time(since="2026-08-26T00:00:00+00:00")
    must = seen["body"]["query"]["bool"]["must"]
    assert must == [{"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z", "lte": "now"}}}]


async def test_header_reports_the_absolute_band_not_the_ignored_lookback(tool):
    """timerange_minutes is ignored when a bound is given -- the header must not
    keep claiming it."""
    _stub_agg(tool, [])
    out = await tool.count_by_time(timerange_minutes=120, since="2026-08-26T00:00:00Z",
                                   until="2026-08-27T00:00:00Z")
    assert "last 120m" not in out
    assert "2026-08-26T00:00:00Z to 2026-08-27T00:00:00Z" in out.splitlines()[0]


async def test_bad_bound_is_refused_without_calling_es(tool):
    async def boom(body, index=None):
        raise AssertionError("ES was called for an unparseable since")

    tool._agg = boom
    out = await tool.count_by_time(since="last tuesday")
    assert out.startswith("Error: since/until must be ISO-8601 UTC")
    assert "2026-08-26T00:00:00Z" in out


async def test_since_after_until_is_refused_without_calling_es(tool):
    async def boom(body, index=None):
        raise AssertionError("ES was called for a reversed range")

    tool._agg = boom
    out = await tool.count_by_time(since="2026-08-27T00:00:00Z", until="2026-08-26T00:00:00Z")
    assert out.startswith("Error:")
    assert "after" in out


# --- rendering -------------------------------------------------------------------

async def test_empty_buckets_render_no_results_not_error(tool):
    _stub_agg(tool, [])
    out = await tool.count_by_time(interval="1d")
    lines = out.splitlines()
    assert not out.startswith("Error:")
    assert "0 docs in 0 buckets" in lines[0]
    assert lines[1].strip().startswith("(no results")


async def test_buckets_render_with_hosts_and_summed_total(tool):
    _stub_agg(tool, [
        {"key_as_string": "2026-09-01T00:00:00.000Z", "key": 1, "doc_count": 10,
         "hosts": {"buckets": [{"key": "dc-01", "doc_count": 6}, {"key": "wkst-01", "doc_count": 4}]}},
        {"key_as_string": "2026-09-02T00:00:00.000Z", "key": 2, "doc_count": 5,
         "hosts": {"buckets": []}},
    ])
    out = await tool.count_by_time(interval="1d", index="windows-sysmon", top_n_hosts=2, host="dc-01")
    lines = out.splitlines()
    assert "index windows-sysmon, interval 1d" in lines[0]
    assert "host=dc-01" in lines[0]
    assert "15 docs in 2 buckets" in lines[0]
    assert lines[1] == "  2026-09-01T00:00:00.000Z  10"
    assert lines[2] == "      dc-01: 6"
    assert lines[3] == "      wkst-01: 4"
    assert lines[4] == "  2026-09-02T00:00:00.000Z  5"
    assert len(lines) == 5


async def test_http_error_surfaces_as_error_not_empty(tool):
    import httpx

    async def fail(body, index=None):
        raise httpx.ConnectError("refused")

    tool._agg = fail
    out = await tool.count_by_time()
    assert out.startswith("Error: ES aggregation failed")


# --- MCP registration ------------------------------------------------------------

async def test_count_by_time_registered_on_server():
    server = MCPServer("test")
    elastic_tools.register(server, _cfg())
    tools = {t.name: t for t in await server.list_tools()}
    assert "count_by_time" in tools
    props = tools["count_by_time"].input_schema["properties"]
    assert set(props) == {"interval", "index", "timerange_minutes", "host",
                          "event_id", "query_text", "top_n_hosts", "since", "until"}
    assert props["timerange_minutes"]["default"] == 240
    assert props["interval"]["default"] == "1h"


# --- live corpus -------------------------------------------------------------------

@requires_sysmon
async def test_live_daily_histogram_over_sysmon_corpus(tool):
    out = await tool.count_by_time(interval="1d", index=SYSMON_INDEX, timerange_minutes=43200)
    assert not out.startswith("Error:"), out
    lines = out.splitlines()
    m = re.search(r": (\d+) docs in (\d+) buckets$", lines[0])
    assert m, lines[0]
    header_total, n_buckets = int(m.group(1)), int(m.group(2))
    bucket_lines = [l for l in lines[1:] if re.match(r"^  \d{4}-\d{2}-\d{2}T\S+  \d+$", l)]
    # The corpus spans ~18 days; UTC-midnight alignment makes that 18-20 buckets.
    assert 17 <= len(bucket_lines) <= 20, out
    assert len(bucket_lines) == n_buckets
    assert sum(int(l.split()[-1]) for l in bucket_lines) == header_total
