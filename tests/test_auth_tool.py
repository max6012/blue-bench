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


# ── absolute since / until ────────────────────────────────────────────────────
# Credential abuse is investigated one slice at a time; a lookback cannot bound
# the slice's trailing edge.

async def test_since_and_until_replace_the_lookback():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(timerange_minutes=99, since="2026-08-26T00:00:00Z",
                                  until="2026-08-27T00:00:00Z")
    assert {"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z",
                                     "lte": "2026-08-27T00:00:00Z"}}} in _musts(seen[0])
    assert "now-" not in _flat(seen[0])


async def test_since_alone_runs_to_now():
    tool = _tool(); seen = _capture(tool)
    await tool.search_auth_events(since="2026-08-26T00:00:00+00:00")
    assert {"range": {"@timestamp": {"gte": "2026-08-26T00:00:00Z",
                                     "lte": "now"}}} in _musts(seen[0])


async def test_bad_bound_is_refused_without_calling_es():
    tool = _tool()

    async def boom(body: dict):
        raise AssertionError("ES was called for an unparseable since")

    tool._search = boom  # type: ignore[method-assign]
    out = await tool.search_auth_events(since="last tuesday")
    assert out.startswith("Error: since/until must be ISO-8601 UTC")
    assert "2026-08-26T00:00:00Z" in out


async def test_since_after_until_is_refused_without_calling_es():
    tool = _tool()

    async def boom(body: dict):
        raise AssertionError("ES was called for a reversed range")

    tool._search = boom  # type: ignore[method-assign]
    out = await tool.search_auth_events(since="2026-08-27T00:00:00Z",
                                        until="2026-08-26T00:00:00Z")
    assert out.startswith("Error:") and "after" in out


# ── the ES _id every record now carries ───────────────────────────────────────

async def test_auth_records_carry_the_es_id_and_index_first(monkeypatch):
    """Ground truth is keyed on the ES _id; the auth substrate has to surface it
    like the others, and at the front of the record."""
    import json as _json

    from blue_bench_mcp.tool_classes import auth as auth_mod

    class _Resp:
        def raise_for_status(self): pass
        def json(self):
            return {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_index": "windows-security", "_id": "abc123",
                 "_source": {"EventID": 4625, "Computer": "dc-01.corp.example.invalid"}},
            ]}}

    class _Client:
        def __call__(self, *a, **k): return self
        async def __aenter__(self): return self
        async def __aexit__(self, *exc): return False
        async def post(self, url, json=None, **k): return _Resp()

    monkeypatch.setattr(auth_mod.httpx, "AsyncClient", _Client())
    out = await _tool().search_auth_events(result="failure")
    records = _json.loads(out.split("\n\n---")[0])
    assert list(records[0])[:2] == ["_id", "_index"]
    assert records[0]["_id"] == "abc123"


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
