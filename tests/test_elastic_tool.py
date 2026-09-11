"""ElasticTool unit tests — uses live ES when available, otherwise skipped.

Live path exercises search_alerts, get_connections, count_by_field end-to-end
without needing seeded data: empty indices still return a well-formed response.
"""
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
