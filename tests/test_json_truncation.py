"""Issue #41 — JSON-returning tools must return PARSEABLE JSON when truncated.

`guardrails.truncate_results` does head+tail splicing with a marker in the
middle. That is correct for free text and corrupting for JSON: the head stops
mid-object, the marker is not JSON, and the tail resumes mid-object. The result
still *looks* fine at both ends (starts `[{"Provider": ...`, ends `}\n]`), which
is why it survived so long, and `max_result_chars` defaults to 8000, so routine
results were affected.

Every tool here promises "Returns JSON-formatted array/object" in its docstring.
These tests hold them to it. No live ES: the defect is in serialization, not
retrieval, so `_query` is mocked and the tests always run.
"""
from __future__ import annotations

import json

import pytest

from blue_bench_mcp.config import (
    AuthConfig,
    ElasticConfig,
    LimitsConfig,
    ServerConfig,
    SysmonConfig,
    WazuhConfig,
    ZeekConfig,
)
from blue_bench_mcp.guardrails import json_dump_within
from blue_bench_mcp.tool_classes.auth import AuthTool
from blue_bench_mcp.tool_classes.elastic import ElasticTool
from blue_bench_mcp.tool_classes.wazuh import WazuhTool

# Small enough that any realistic record set overflows it.
MAX_CHARS = 4000
N_RECORDS = 60


def _fat_records(n: int = N_RECORDS) -> list[dict]:
    """Records shaped like real Sysmon/Zeek docs and big enough to overflow."""
    return [
        {
            "EventID": 1,
            "EventRecordID": str(2814000 + i),
            "Computer": f"wkst-{i:02d}.corp.example.invalid",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand " + "QQBB" * 40,
            "Hashes": "SHA256=" + "ab" * 32,
            "@timestamp": f"2026-09-09T14:{i % 60:02d}:09.271536+00:00",
        }
        for i in range(n)
    ]


def _json_part(out: str) -> str:
    """Strip the documented non-JSON decorations these tools add.

    A `\n\n--- ... ---` footer (the existing convention, which the live sysmon
    test already strips) and a leading `[source: ...]` line from get_agent_alerts.
    Anything left must parse.
    """
    body = out.split("\n\n---")[0]
    if body.startswith("[source:"):
        body = body.split("\n", 1)[1]
    return body


def _cfg() -> ServerConfig:
    return ServerConfig(
        elastic=ElasticConfig(url="http://localhost:9200", index_pattern="bb-test-*"),
        zeek=ZeekConfig(index="bb-test-*", use_elastic=True),
        sysmon=SysmonConfig(index="windows-sysmon"),
        auth=AuthConfig(),
        wazuh=WazuhConfig(),
        limits=LimitsConfig(max_results=50, max_result_chars=MAX_CHARS, query_timeout=5),
    )


# --- the helper ---------------------------------------------------------------

def test_json_dump_within_keeps_output_parseable_and_within_budget():
    recs = _fat_records()
    text, dropped = json_dump_within(recs, MAX_CHARS)
    assert len(text) <= MAX_CHARS
    parsed = json.loads(text)                      # must not raise
    assert isinstance(parsed, list)
    assert dropped > 0, "fixture must actually overflow, or this proves nothing"
    assert len(parsed) == len(recs) - dropped


def test_json_dump_within_is_a_noop_when_everything_fits():
    recs = _fat_records(2)
    text, dropped = json_dump_within(recs, 100_000)
    assert dropped == 0
    assert json.loads(text) == json.loads(json.dumps(recs, indent=2, default=str))


def test_json_dump_within_shrinks_named_lists_and_preserves_the_rest():
    payload = {
        "process_guid": "{01f3cb34-afd6-698e-5800-00108413dbf4}",
        "self_and_parent": _fat_records(10),
        "children": _fat_records(),
    }
    text, dropped = json_dump_within(
        payload, MAX_CHARS, shrink=("self_and_parent", "children"))
    parsed = json.loads(text)
    assert len(text) <= MAX_CHARS and dropped > 0
    # the non-shrinkable scalar survives — it is what makes the response addressable
    assert parsed["process_guid"] == payload["process_guid"]
    assert set(parsed) == set(payload)


def test_json_dump_within_still_emits_valid_json_when_nothing_fits():
    """The non-shrinkable part alone can exceed the budget. Even then the model
    must get JSON it can act on, not a corrupt payload."""
    payload = {"coverage": "y" * 5000, "candidates": _fat_records()}
    text, _ = json_dump_within(payload, 500, shrink=("candidates",))
    parsed = json.loads(text)
    assert len(text) <= 500
    assert "error" in parsed and "hint" in parsed


# --- the tools ----------------------------------------------------------------

@pytest.mark.parametrize("method,kwargs", [
    ("search_alerts", {}),
    ("get_connections", {}),
    ("get_process_events", {"event_id": 1}),
])
async def test_elastic_list_tools_return_parseable_json_when_truncated(
    monkeypatch, method, kwargs
):
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records()))
    out = await getattr(tool, method)(timerange_minutes=60, **kwargs)
    body = _json_part(out)
    records = json.loads(body)                     # the assertion that matters
    assert isinstance(records, list) and records
    assert len(records) < N_RECORDS, "fixture must overflow, or this proves nothing"


async def test_get_process_tree_returns_parseable_json_when_truncated(monkeypatch):
    tool = ElasticTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records()))
    out = await tool.get_process_tree(process_guid="{abc}", timerange_minutes=60)
    parsed = json.loads(_json_part(out))
    assert parsed["process_guid"] == "{abc}"
    assert isinstance(parsed["children"], list)


async def test_search_auth_events_returns_parseable_json_when_truncated(monkeypatch):
    tool = AuthTool(_cfg())
    monkeypatch.setattr(tool, "_query", lambda *a, **k: _async(_fat_records()))
    out = await tool.search_auth_events(timerange_minutes=60)
    records = json.loads(_json_part(out))
    assert isinstance(records, list) and records


async def test_get_agent_alerts_returns_parseable_json_when_truncated(monkeypatch):
    """Covers the Wazuh API path; the `[source: ...]` prefix is part of the
    contract and is budgeted, not spliced."""
    tool = WazuhTool(_cfg())
    monkeypatch.setattr(
        tool, "_api_get",
        lambda *a, **k: _async({"data": {"affected_items": _fat_records()}}))
    out = await tool.get_agent_alerts(agent_id="001")
    assert out.startswith("[source:")
    records = json.loads(_json_part(out))
    assert isinstance(records, list) and records


def _async(value):
    """Wrap a value in an awaitable, for monkeypatching async methods."""
    async def _coro():
        return value
    return _coro()
