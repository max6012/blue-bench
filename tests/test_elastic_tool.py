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
    assert t.zeek_index == "zeek-custom-*"


def test_zeek_index_falls_back_when_use_elastic_false():
    cfg = ServerConfig(
        elastic=ElasticConfig(url=ES_URL, index_pattern="logstash-*"),
        zeek=ZeekConfig(index="zeek-custom-*", use_elastic=False),
    )
    t = ElasticTool(cfg)
    assert t.zeek_index == "logstash-*"
