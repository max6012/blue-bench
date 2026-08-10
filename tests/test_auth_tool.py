"""AuthTool unit tests.

Offline: config defaults, signature, and the filter->ES-query-body mapping
(captured by stubbing _query — no ES needed). Live: real queries when ES is up.
"""
import inspect

import pytest

from blue_bench_mcp.config import AuthConfig, ElasticConfig, LimitsConfig, ServerConfig
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
    """Stub _query to capture the request body instead of hitting ES."""
    seen: list[dict] = []

    async def fake_query(body: dict) -> list:
        seen.append(body)
        return []

    tool._query = fake_query  # type: ignore[method-assign]
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
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(event_id=4625)
    assert {"term": {"EventID": 4625}} in _musts(seen[0])


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
    await tool.search_auth_events(src_ip="185.220.101.42")
    blob = _flat(seen[0])
    assert "IpAddress" in blob and "match_phrase" in blob


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
