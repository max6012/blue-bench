"""count_by_field is scoped to one host when asked — by name, by address, or
both ORed — and the slice binding sets both from the slice.

Before this, count_by_field had no host argument at all: a worker told to
"survey first" got corpus-wide counts back under its slice footer and read
them as its host's baseline (caught by the Opus 5.5 smoke run, 2026-09-28).
"""
import asyncio

from blue_bench_client.fanout.schema import Slice, SliceFilters
from blue_bench_mcp.config import ElasticConfig, ServerConfig
from blue_bench_mcp.es_queries import host_ip_clauses
from blue_bench_mcp.fanout_bind import bind_args
from blue_bench_mcp.tool_classes.elastic import ElasticTool

HOST, IP = "wkst-05.corp.example.invalid", "10.10.0.15"


def _bodies(**kw):
    tool = ElasticTool(ServerConfig(elastic=ElasticConfig(url="http://es.invalid:9200")))
    seen = []

    async def fake_agg(body, index=None):
        seen.append(body)
        return {"aggregations": {"top_values": {"buckets": [{"key": 1, "doc_count": 3}]}}}

    tool._agg = fake_agg

    async def plan(field, index):
        return {field: [index]}

    tool._agg_field_plan = plan
    asyncio.run(tool.count_by_field("EventID", index="windows-sysmon",
                                    since="2026-09-12T00:00:00Z", until="2026-09-13T00:00:00Z", **kw))
    return seen[0]["query"]


def _should(q):
    return q["bool"]["filter"][0]["bool"]["should"]


def test_no_host_is_the_bare_time_range():
    q = _bodies()
    assert "bool" not in q or "filter" not in q.get("bool", {})


def test_host_matches_the_name_fields_exactly():
    fields = {next(iter(c[k])) for c in _should(_bodies(host=HOST)) for k in c}
    assert fields == {"Computer.keyword", "host.keyword"}


def test_host_and_ip_are_one_or_not_an_and():
    q = _bodies(host=HOST, host_ip=IP)
    assert q["bool"]["filter"][0]["bool"]["minimum_should_match"] == 1
    fields = {next(iter(c[k])) for c in _should(q) for k in c}
    assert {"Computer.keyword", "id.orig_h", "id.resp_h", "src_ip.keyword", "dest_ip.keyword"} <= fields


def test_a_hostname_never_reaches_the_ip_typed_fields():
    # A term on an ip-mapped field with a name is a 400 from ES, not an empty result.
    assert all("id.orig_h" not in c["term"] and "id.resp_h" not in c["term"]
               for c in host_ip_clauses("wkst-05"))


def test_the_slice_binds_both_host_and_host_ip():
    sl = Slice(id="s1", question="q", rationale="r", turn_budget=5,
               filters=SliceFilters(hosts=[HOST], host_ips=[IP], indices=["windows-sysmon"]))
    schema = {"properties": {k: {"type": "string"} for k in
                             ("field", "index", "since", "until", "host", "host_ip")}}
    bound, over = bind_args("count_by_field", {"field": "Image"}, sl, schema)
    assert bound["host"] == HOST and bound["host_ip"] == IP and bound["index"] == "windows-sysmon"
    assert "_unbindable" not in over


def _time_query(**kw):
    tool = ElasticTool(ServerConfig(elastic=ElasticConfig(url="http://es.invalid:9200")))
    seen = []

    async def fake_agg(body, index=None):
        seen.append(body)
        return {"hits": {"total": {"value": 0}}, "aggregations": {"over_time": {"buckets": []}}}

    tool._agg = fake_agg
    asyncio.run(tool.count_by_time(interval="1d", index="zeek-conn,windows-sysmon",
                                   since="2026-09-12T00:00:00Z", until="2026-09-13T00:00:00Z", **kw))
    return str(seen[0]["query"])


def test_count_by_time_never_puts_a_hostname_on_the_ip_fields():
    # ES fails the Zeek shards on that and returns the Sysmon half as if whole.
    q = _time_query(host=HOST)
    assert "id.orig_h" not in q and "id.resp_h" not in q


def test_count_by_time_ors_host_and_host_ip():
    q = _time_query(host=HOST, host_ip=IP)
    assert "Computer.keyword" in q and f"'id.orig_h': '{IP}'" in q


def test_the_slice_binds_count_by_time_host_ip_too():
    sl = Slice(id="s1", question="q", rationale="r", turn_budget=5,
               filters=SliceFilters(hosts=[HOST], host_ips=[IP]))
    schema = {"properties": {k: {"type": "string"} for k in ("interval", "host", "host_ip", "since", "until")}}
    bound, _ = bind_args("count_by_time", {}, sl, schema)
    assert bound["host"] == HOST and bound["host_ip"] == IP


def _es_up() -> bool:
    import httpx
    try:
        return httpx.get("http://localhost:9200/zeek-conn/_count", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


import pytest  # noqa: E402


@pytest.mark.skipif(not _es_up(), reason="needs live Elasticsearch")
def test_live_mixed_mapping_survey_is_complete():
    """dest_port is numeric in ot-conn and text in zeek-conn; the default
    alert/Zeek pattern mixes alert.signature text with nothing. Before the
    per-index field plan, both returned partial results (9 + 4 of the 22 in the
    Opus 5.5 ceiling run)."""
    from blue_bench_mcp import shard_check
    tool = ElasticTool(ServerConfig(elastic=ElasticConfig(url="http://localhost:9200")))

    async def go(field, index):
        tok = shard_check._FAILURES.set([])
        try:
            out = await tool.count_by_field(field, index=index, timerange_minutes=60 * 24 * 30, top_n=5)
            return out, list(shard_check._FAILURES.get())
        finally:
            shard_check._FAILURES.reset(tok)

    for field, index in (("dest_port", "zeek-conn,ot-conn"), ("alert.signature", ""),
                         ("IpAddress", "windows-security,linux-syslog")):
        out, failures = asyncio.run(go(field, index))
        assert failures == [], (field, failures)
        assert "no results" not in out, (field, out)
