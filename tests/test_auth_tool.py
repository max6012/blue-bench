"""AuthTool unit tests.

Offline: config defaults, signature, and the filter->ES-query-body mapping
(captured by stubbing _search — no ES needed). Live: real queries when ES is up.
"""
import inspect

import pytest

from blue_bench_mcp.config import ElasticConfig, LimitsConfig, ServerConfig
from blue_bench_mcp.tool_classes.auth import AuthTool


ES_URL = "http://localhost:9200"


def _es_reachable() -> bool:
    import httpx
    try:
        return httpx.get(f"{ES_URL}/_cluster/health", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


requires_es = pytest.mark.skipif(not _es_reachable(), reason="Elasticsearch not running")


def _tool() -> AuthTool:
    cfg = ServerConfig(
        elastic=ElasticConfig(url=ES_URL),
        limits=LimitsConfig(max_results=50, max_result_chars=5000, query_timeout=5),
    )
    return AuthTool(cfg)


def _capture(tool: AuthTool) -> list[dict]:
    """Stub _search to capture the request body instead of hitting ES."""
    seen: list[dict] = []

    async def fake_search(body: dict) -> tuple[list, int]:
        seen.append(body)
        return [], 0

    tool._search = fake_search  # type: ignore[method-assign]
    return seen


# ── config / structure ───────────────────────────────────────────────────────

def test_auth_config_defaults():
    cfg = ServerConfig()
    assert cfg.auth.windows_security_index == "windows-security"
    assert cfg.auth.linux_syslog_index == "linux-syslog"
    # Tool queries BOTH substrates in one request.
    assert AuthTool(cfg).index == "windows-security,linux-syslog"


def test_signature_defaults():
    sig = inspect.signature(_tool().search_auth_events)
    p = sig.parameters
    assert p["event_id"].default == 0
    assert p["logon_type"].default == -1  # -1 sentinel: 0 is a valid LogonType
    assert p["result"].default == ""
    assert p["timerange_minutes"].default == 240


# ── filter -> query-body mapping (offline) ─────────────────────────────────────

def _musts(body: dict) -> list:
    return body["query"]["bool"]["must"]


def _flat(obj) -> str:
    import json
    return json.dumps(obj)


async def test_range_always_present():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(timerange_minutes=99)
    assert any("range" in m and "@timestamp" in m["range"] for m in _musts(seen[0]))
    assert "now-99m" in _flat(seen[0])


async def test_result_failure_maps_to_4625_4771_and_failed_password():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(result="failure")
    blob = _flat(seen[0])
    assert '"EventID": 4625' in blob and '"EventID": 4771' in blob
    assert "Failed password" in blob


async def test_result_success_maps_to_4624_and_accepted():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(result="success")
    blob = _flat(seen[0])
    assert '"EventID": 4624' in blob and "Accepted" in blob


async def test_event_id_restricts_to_windows():
    """Both spellings, OR'd. apt_inject's parse_evtx writes lowercase
    `event_id` for every Windows EVTX stream including Security, so a
    single-field term misses that whole population (issue #37)."""
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(event_id=4625)
    should = next(c["bool"]["should"] for c in _musts(seen[0])
                  if "bool" in c and any("EventID" in str(x) for x in c["bool"].get("should", [])))
    assert {"term": {"EventID": 4625}} in should
    assert {"term": {"event_id": 4625}} in should


async def test_result_filters_match_both_event_id_spellings():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(result="success")
    flat = _flat(seen[0])
    assert '"EventID": 4624' in flat and '"event_id": 4624' in flat
    tool2 = _tool(); seen2 = _capture(tool2)
    await tool2.search_auth_events(result="failure")
    flat2 = _flat(seen2[0])
    for eid in (4625, 4771):
        assert f'"EventID": {eid}' in flat2 and f'"event_id": {eid}' in flat2


async def test_logon_type_zero_is_filtered_not_ignored():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(logon_type=0)
    assert "LogonType" in _flat(seen[0])  # 0 must NOT be treated as "no filter"


async def test_logon_type_default_absent():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events()
    assert "LogonType" not in _flat(seen[0])


async def test_account_matches_windows_and_linux_fields():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(account="svc_deploy")
    blob = _flat(seen[0])
    assert "SubjectUserName" in blob and "TargetUserName" in blob and "message" in blob


async def test_src_ip_matches_windows_ip_and_syslog_message():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(src_ip="198.51.100.42")
    blob = _flat(seen[0])
    assert "IpAddress" in blob and "match_phrase" in blob


async def test_host_filter_never_bare_match_on_text_field():
    """Issue #46. Computer / host are text-mapped; a bare `match` analyzes an
    FQDN into `wkst 13 corp example invalid` OR'd together and matches every
    host in the domain. The host clause must be exact (`term` on the .keyword
    subfield) with a `match_phrase` fallback for short names -- and it must
    stay a `should` so either substrate's spelling can satisfy it."""
    host = "wkst-13.corp.example.invalid"
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(host=host)
    clause = next(c for c in _musts(seen[0])
                  if "bool" in c and any("Computer" in str(x) for x in c["bool"].get("should", [])))
    assert clause["bool"]["minimum_should_match"] == 1
    should = clause["bool"]["should"]
    # Structural check, not a substring check: "match_phrase" and
    # "minimum_should_match" both contain the substring "match".
    for sub in should:
        (kind, body), = sub.items()
        assert kind in ("term", "match_phrase"), f"bare {kind!r} on {list(body)}"
    assert {"match": {"Computer": host}} not in should
    assert {"match": {"host": host}} not in should
    assert {"term": {"Computer.keyword": host}} in should
    assert {"term": {"host.keyword": host}} in should
    assert {"match_phrase": {"Computer": host}} in should
    assert {"match_phrase": {"host": host}} in should


# ── live (ES up) ───────────────────────────────────────────────────────────────

@requires_es
async def test_live_returns_string():
    out = await _tool().search_auth_events(timerange_minutes=60000)
    assert isinstance(out, str) and len(out) > 0


@requires_es
async def test_live_failure_filter_shape():
    out = await _tool().search_auth_events(result="failure", timerange_minutes=60000)
    # Valid JSON array or a well-formed error; must not raise.
    assert out.startswith("[") or out.startswith("Error:")


@requires_es
async def test_live_host_filter_matches_only_that_host():
    """Issue #46, on the real corpus. The tool's host clause must match
    exactly the docs whose Computer.keyword is that host -- not every host
    sharing the `corp example invalid` tokens. Compares counts (the tool caps
    returned docs at max_results), using the exact query body the tool builds."""
    import httpx
    host = "wkst-13.corp.example.invalid"
    window = 60000
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(host=host, timerange_minutes=window)
    params = {"ignore_unavailable": "true", "allow_no_indices": "true"}
    url = f"{ES_URL}/{tool.index}/_count"
    tool_count = httpx.post(url, json={"query": seen[0]["query"]}, params=params,
                            timeout=60).json()["count"]
    exact = {"query": {"bool": {"must": [
        {"range": {"@timestamp": {"gte": f"now-{window}m", "lte": "now"}}},
        {"term": {"Computer.keyword": host}},
    ]}}}
    exact_count = httpx.post(url, json=exact, params=params, timeout=60).json()["count"]
    if exact_count == 0:
        pytest.skip(f"{host} not present in the live corpus; 0 == 0 would prove nothing")
    assert tool_count == exact_count
