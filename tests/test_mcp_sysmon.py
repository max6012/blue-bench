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
    """The event id must be a NUMERIC term (both fields are `long`-mapped).

    Asserts the intent rather than the literal clause shape: since issue #37 the
    filter is an OR across both spellings (`EventID` from the EVTX ingest path,
    `event_id` from the NDJSON path), because a single-field term matched ZERO of
    the injected adversary documents.
    """
    body = tool._build_process_events_query("", "", "", "", 1, 240)
    must = body["query"]["bool"]["must"]
    should = next(c["bool"]["should"] for c in must if "bool" in c)
    assert {"term": {"EventID": 1}} in should
    assert {"term": {"event_id": 1}} in should
    # numeric, not "1" -- a string term never matches a long-mapped field
    for clause in should:
        assert isinstance(next(iter(clause["term"].values())), int)


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
    if not records:
        import pytest
        # ES is reachable but has no process-create events inside the lookback
        # (e.g. the ingested corpus's timestamps have aged past the window).
        # Nothing to validate — skip rather than hard-fail on stale live data.
        pytest.skip("no sysmon EventID=1 records in the live lookback window")
    # Real Sysmon process-create records carry an Image and EventID 1.
    assert all(r.get("EventID") == 1 for r in records)
    assert any(r.get("Image") for r in records)


# --- absolute since / until ---------------------------------------------------
# A fan-out worker investigates ONE time band of an 18-day corpus. A lookback
# bounds only the leading edge, so adjacent slices overlapped; these pin both.

def test_process_events_absolute_band_replaces_the_lookback(tool):
    body = tool._build_process_events_query(
        "", "", "", "", 0, 240, since="2026-08-26T00:00:00Z", until="2026-08-27T00:00:00Z")
    must = body["query"]["bool"]["must"]
    assert must == [{"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z",
                                              "lte": "2026-08-27T00:00:00Z"}}}]
    assert "now-" not in json.dumps(body)


def test_process_events_since_alone_runs_to_now(tool):
    body = tool._build_process_events_query(
        "", "", "", "", 0, 240, since="2026-08-26T00:00:00+00:00")
    assert body["query"]["bool"]["must"] == [
        {"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z", "lte": "now"}}}]


def test_until_alone_leaves_the_lower_bound_open(tool):
    """The first slice of a partition has no lower edge -- gte must be absent,
    not a sentinel that quietly filters."""
    body = tool._build_process_events_query("", "", "", "", 0, 240, until="2026-08-27T00:00:00Z")
    assert body["query"]["bool"]["must"] == [
        {"range": {"@timestamp": {"lte": "2026-08-27T00:00:00Z"}}}]


def test_process_events_naive_timestamp_is_read_as_utc(tool):
    """The corpus is UTC throughout; a missing suffix is not worth a refusal."""
    body = tool._build_process_events_query("", "", "", "", 0, 240, since="2026-08-26T00:00:00")
    assert body["query"]["bool"]["must"][0]["range"]["@timestamp"]["gte"] == "2026-08-26T00:00:00Z"


def test_tree_queries_take_the_absolute_band(tool):
    self_b = tool._build_process_tree_self_query(
        "{G}", "", 240, since="2026-08-26T00:00:00Z", until="2026-08-27T00:00:00Z")
    child_b = tool._build_process_tree_children_query(
        "{G}", "", 240, since="2026-08-26T00:00:00Z", until="2026-08-27T00:00:00Z")
    band = {"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z",
                                     "lte": "2026-08-27T00:00:00Z"}}}
    assert band in self_b["query"]["bool"]["must"]
    assert band in child_b["query"]["bool"]["must"]
    assert "now-" not in json.dumps([self_b, child_b])


async def test_process_events_bad_bound_is_refused_without_calling_es(tool):
    async def boom(*a, **k):
        raise AssertionError("ES was called for an unparseable since")

    tool._search = boom
    out = await tool.get_process_events(since="last tuesday")
    assert out.startswith("Error: since/until must be ISO-8601 UTC")
    assert "2026-08-26T00:00:00Z" in out


async def test_process_events_reversed_band_is_refused_without_calling_es(tool):
    async def boom(*a, **k):
        raise AssertionError("ES was called for a reversed range")

    tool._search = boom
    out = await tool.get_process_events(since="2026-08-27T00:00:00Z",
                                        until="2026-08-26T00:00:00Z")
    assert out.startswith("Error:") and "after" in out


async def test_process_tree_bad_bound_is_refused_without_calling_es(tool):
    async def boom(*a, **k):
        raise AssertionError("ES was called for an unparseable until")

    tool._search = boom
    out = await tool.get_process_tree(process_guid="{G}", until="not-a-time")
    assert out.startswith("Error: since/until must be ISO-8601 UTC")


# --- the ES _id every record now carries --------------------------------------

class _IdResponse:
    def __init__(self, payload): self._payload = payload
    def raise_for_status(self): pass
    def json(self): return self._payload


class _IdClient:
    """Fake httpx.AsyncClient so the REAL _search runs and adds _id/_index."""

    def __init__(self, hits): self._hits = hits
    def __call__(self, *a, **k): return self
    async def __aenter__(self): return self
    async def __aexit__(self, *exc): return False

    async def post(self, url, json=None, **k):
        return _IdResponse({"hits": {
            "total": {"value": len(self._hits), "relation": "eq"},
            "hits": self._hits,
        }})


async def test_records_carry_the_es_id_and_index_first(tool, monkeypatch):
    """Ground truth is keyed on the ES _id, so a worker can only cite evidence
    the scorer can join if the record carries it -- and at the FRONT, because
    the pretty-printed body is cut from the tail."""
    from blue_bench_mcp.tool_classes import elastic as elastic_mod

    monkeypatch.setattr(elastic_mod.httpx, "AsyncClient", _IdClient([
        {"_index": "windows-sysmon", "_id": "04ffe11d253050e99406c007dcb74188",
         "_source": {"EventID": 1, "Computer": "wkst-03.corp.example.invalid"}},
        {"_index": "windows-sysmon", "_id": "141fcbc4c7ce7475d38ffe875761632f",
         "_source": {"EventID": 11, "Computer": "wkst-03.corp.example.invalid"}},
    ]))
    out = await tool.get_process_events(event_id=1)
    records = json.loads(out.split("\n\n---")[0])
    # Order is what the model sees: json.dumps preserves insertion order.
    assert [list(r)[:2] for r in records] == [["_id", "_index"]] * 2
    assert [r["_id"] for r in records] == [
        "04ffe11d253050e99406c007dcb74188", "141fcbc4c7ce7475d38ffe875761632f"]
    assert records[0]["EventID"] == 1


async def test_source_never_shadows_the_real_id(tool, monkeypatch):
    """ES reserves _id/_index inside _source, so a copy there means a broken
    ingest -- the metadata must win rather than be shadowed."""
    from blue_bench_mcp.tool_classes import elastic as elastic_mod

    monkeypatch.setattr(elastic_mod.httpx, "AsyncClient", _IdClient([
        {"_index": "windows-sysmon", "_id": "real",
         "_source": {"_id": "impostor", "EventID": 1}},
    ]))
    out = await tool.get_process_events()
    records = json.loads(out.split("\n\n---")[0])
    assert records[0]["_id"] == "real"


# --- live: absolute band + the ground-truth join ------------------------------

GROUND_TRUTH = "/private/tmp/bb-corpus-l/ground-truth/apt-bb-001.ground-truth.yaml"


def _ground_truth_doc_ids(limit: int) -> list[str]:
    import re as _re
    from pathlib import Path
    text = Path(GROUND_TRUTH).read_text()
    return _re.findall(r"doc_id:\s*(\S+)", text)[:limit]


def _fetch_by_id(doc_id: str) -> dict | None:
    import httpx
    r = httpx.get(f"{ES_URL}/_search", params={"q": f"_id:{doc_id}", "size": 1}, timeout=5.0)
    hits = r.json().get("hits", {}).get("hits", [])
    return hits[0] if hits else None


requires_ground_truth = pytest.mark.skipif(
    not (_es_reachable() and _sysmon_populated()
         and __import__("pathlib").Path(GROUND_TRUTH).exists()),
    reason="Elasticsearch / windows-sysmon / L-corpus ground truth not available",
)


@requires_sysmon
async def test_live_absolute_band_bounds_both_edges(tool):
    """Every returned @timestamp falls inside the band, trailing edge included."""
    since, until = "2026-08-26T00:00:00Z", "2026-08-27T00:00:00Z"
    out = await tool.get_process_events(
        host="wkst-03.corp.example.invalid", since=since, until=until)
    assert not out.startswith("Error:"), out
    records = json.loads(out.split("\n\n---")[0])
    if not records:
        pytest.skip("no wkst-03 sysmon records in the 2026-08-26 band")
    for r in records:
        assert since <= r["@timestamp"].replace("+00:00", "Z") <= until, r["@timestamp"]
        assert r["_id"], "every record must carry its ES _id"


@requires_ground_truth
async def test_live_ground_truth_doc_id_appears_in_the_band(tool):
    """The join the whole fan-out harness rests on: a ground-truth pointer's
    doc_id is the ES _id, and a worker querying that host+band must see it.

    The band around the target holds thousands of records and the response is
    capped at max_result_chars, so the query is narrowed by the target's own
    EventID -- otherwise which records survive the cut is a coin flip, not a
    property of the join.
    """
    targets = []
    for doc_id in _ground_truth_doc_ids(5):
        hit = _fetch_by_id(doc_id)
        if hit:
            targets.append((doc_id, hit["_index"], hit["_source"]))
    assert targets, "no ground-truth doc_id resolved in ES"

    sysmon = [t for t in targets if t[1] == SYSMON_INDEX]
    if not sysmon:
        pytest.skip("no sysmon-indexed ground-truth pointer among the first 5")
    doc_id, _index, src = sysmon[0]
    from datetime import datetime, timedelta
    ts = datetime.fromisoformat(src["@timestamp"].replace("Z", "+00:00"))
    since = (ts - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    until = (ts + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")

    out = await tool.get_process_events(
        host=src["Computer"], event_id=int(src["EventID"]), since=since, until=until)
    assert not out.startswith("Error:"), out
    records = json.loads(out.split("\n\n---")[0])
    assert doc_id in [r["_id"] for r in records], (
        f"{doc_id} not among {len(records)} records returned for "
        f"{src['Computer']} EventID={src['EventID']} {since}..{until}")
