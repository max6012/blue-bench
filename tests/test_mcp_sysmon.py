"""Sysmon host-telemetry tool tests for ElasticTool.

Unit path: assert the ES query bodies built by the _build_* helpers, so the
filter logic is verified without a live ES (mirrors how get_connections is
structured around a bool/must query + @timestamp range).

Live path: when ES is reachable and windows-sysmon is populated, exercises
get_process_events end-to-end against real EvidenceForge Sysmon records.
"""
import json

import pytest

from blue_bench_mcp.config import (
    ElasticConfig,
    LimitsConfig,
    ServerConfig,
    SysmonConfig,
)
from blue_bench_mcp.tool_classes.elastic import ElasticTool


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


@pytest.fixture
def tool():
    cfg = ServerConfig(
        elastic=ElasticConfig(url=ES_URL),
        sysmon=SysmonConfig(index=SYSMON_INDEX),
        limits=LimitsConfig(max_results=50, max_result_chars=20000, query_timeout=5),
    )
    return ElasticTool(cfg)


# --- config / wiring ----------------------------------------------------------

def test_sysmon_index_default():
    t = ElasticTool(ServerConfig())
    assert t.sysmon_index == "windows-sysmon"


def test_sysmon_index_override():
    t = ElasticTool(ServerConfig(sysmon=SysmonConfig(index="sysmon-custom-*")))
    assert t.sysmon_index == "sysmon-custom-*"


# --- get_process_events query construction -----------------------------------

def test_process_events_empty_is_range_only(tool):
    body = tool._build_process_events_query("", "", "", "", 0, 240)
    must = body["query"]["bool"]["must"]
    assert len(must) == 1
    assert must[0] == {"range": {"@timestamp": {"gte": "now-240m", "lte": "now"}}}
    assert body["size"] == tool.max_results
    assert body["sort"] == [{"@timestamp": "desc"}]


def test_process_events_host_uses_keyword(tool):
    body = tool._build_process_events_query(
        "wkst-01.corp.example.invalid", "", "", "", 0, 240
    )
    must = body["query"]["bool"]["must"]
    assert {"term": {"Computer.keyword": "wkst-01.corp.example.invalid"}} in must


def test_process_events_image_and_parent_use_keyword(tool):
    body = tool._build_process_events_query(
        "", "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\services.exe", "", 0, 60
    )
    must = body["query"]["bool"]["must"]
    assert {"term": {"Image.keyword": "C:\\Windows\\System32\\svchost.exe"}} in must
    assert {"term": {"ParentImage.keyword": "C:\\Windows\\System32\\services.exe"}} in must


def test_process_events_event_id_is_numeric_term(tool):
    body = tool._build_process_events_query("", "", "", "", 1, 240)
    must = body["query"]["bool"]["must"]
    assert {"term": {"EventID": 1}} in must


def test_process_events_event_id_zero_omitted(tool):
    body = tool._build_process_events_query("", "", "", "", 0, 240)
    must = body["query"]["bool"]["must"]
    assert not any("EventID" in str(c) for c in must)


def test_process_events_command_line_is_case_insensitive_wildcard(tool):
    body = tool._build_process_events_query("", "", "", "powershell", 0, 240)
    must = body["query"]["bool"]["must"]
    assert {
        "wildcard": {
            "CommandLine.keyword": {"value": "*powershell*", "case_insensitive": True}
        }
    } in must


def test_process_events_all_filters_combine(tool):
    body = tool._build_process_events_query(
        "host.invalid", "C:\\img.exe", "C:\\parent.exe", "-enc", 1, 30
    )
    must = body["query"]["bool"]["must"]
    # 5 filters + the timestamp range.
    assert len(must) == 6


# --- get_process_tree query construction -------------------------------------

def test_tree_self_query_matches_guid_either_role(tool):
    body = tool._build_process_tree_self_query("{GUID-A}", "", 240)
    must = body["query"]["bool"]["must"]
    should = must[0]["bool"]["should"]
    assert {"term": {"ProcessGuid.keyword": "{GUID-A}"}} in should
    assert {"term": {"ParentProcessGuid.keyword": "{GUID-A}"}} in should
    assert must[0]["bool"]["minimum_should_match"] == 1


def test_tree_children_query_matches_parent_guid(tool):
    body = tool._build_process_tree_children_query("{GUID-A}", "", 240)
    must = body["query"]["bool"]["must"]
    assert {"term": {"ParentProcessGuid.keyword": "{GUID-A}"}} in must


def test_tree_host_scopes_both_queries(tool):
    self_b = tool._build_process_tree_self_query("{G}", "h.invalid", 240)
    child_b = tool._build_process_tree_children_query("{G}", "h.invalid", 240)
    assert {"term": {"Computer.keyword": "h.invalid"}} in self_b["query"]["bool"]["must"]
    assert {"term": {"Computer.keyword": "h.invalid"}} in child_b["query"]["bool"]["must"]


async def test_tree_requires_guid(tool):
    out = await tool.get_process_tree(process_guid="")
    assert out.startswith("Error:")
    assert "process_guid" in out


# --- live path ----------------------------------------------------------------

@requires_sysmon
async def test_process_events_live_process_create(tool):
    out = await tool.get_process_events(event_id=1, timerange_minutes=4000)
    assert isinstance(out, str)
    # Strip any truncation footer before parsing JSON.
    payload = out.split("\n\n---")[0]
    records = json.loads(payload)
    assert isinstance(records, list)
    assert len(records) > 0
    # Real Sysmon process-create records carry an Image and EventID 1.
    assert all(r.get("EventID") == 1 for r in records)
    assert any(r.get("Image") for r in records)
