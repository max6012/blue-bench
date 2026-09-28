"""A partial-shard Elasticsearch response reaches the model as a warning.

ES answers a multi-index search that fails on some indices with HTTP 200 and
the other indices' results; the failure is only in ``_shards.failed``. Every
tool call now runs inside ShardWarningMiddleware, which appends one warning
line to the result -- on both halves of the wire result -- when any ES call
made during it was partial.
"""
import asyncio
import json
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import httpx
import pytest

from blue_bench_mcp.shard_check import WARNING_PREFIX, note_shards, warning_text

REPO = Path(__file__).resolve().parents[1]
PARTIAL = {"_shards": {"total": 2, "successful": 1, "failed": 1, "failures": [
    {"index": "zeek-conn", "reason": {"type": "query_shard_exception",
                                      "reason": "'wkst-05' is not an IP string literal."}}]}}

# A real server; the process-search tool is replaced by one that runs a body
# through the production _agg path (so note_shards is the real call site).
_STUB = '''
import json, sys
sys.path.insert(0, {repo!r})
from blue_bench_mcp.tool_classes.elastic import ElasticTool

async def probe(self, **kwargs):
    body = json.loads(kwargs["command_line_contains"])
    data = await self._agg(body, index=kwargs.get("image") or None)
    return f"hits={{data['hits']['total']['value']}}"

ElasticTool.get_process_events = probe
from blue_bench_mcp.server import main
main()
'''


def _call(tmp_path, args):
    stub = tmp_path / "stub.py"
    stub.write_text(_STUB.format(repo=str(REPO)), encoding="utf-8")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def go():
        async with AsyncExitStack() as st:
            r, w = await st.enter_async_context(stdio_client(StdioServerParameters(
                command=sys.executable, args=[str(stub)])))
            s = await st.enter_async_context(ClientSession(r, w))
            await s.initialize()
            return await s.call_tool("get_process_events", args)
    return asyncio.run(go())


def test_warning_names_the_failed_index_and_cause():
    from blue_bench_mcp import shard_check
    tok = shard_check._FAILURES.set([])
    note_shards(PARTIAL, "zeek-conn,windows-sysmon")
    text = warning_text(shard_check._FAILURES.get())
    shard_check._FAILURES.reset(tok)
    assert WARNING_PREFIX in text and "1 of 2 shards" in text
    assert "zeek-conn" in text and "not an IP string literal" in text


def test_a_clean_response_and_no_open_call_record_nothing():
    note_shards(PARTIAL, "x")                       # outside a tool call: ignored, no crash
    from blue_bench_mcp import shard_check
    tok = shard_check._FAILURES.set([])
    note_shards({"_shards": {"total": 2, "successful": 2, "failed": 0}}, "x")
    assert shard_check._FAILURES.get() == []
    shard_check._FAILURES.reset(tok)


def _es_up() -> bool:
    try:
        return httpx.get("http://localhost:9200/zeek-conn/_count", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.mark.skipif(not _es_up(), reason="needs live Elasticsearch with zeek-conn")
def test_live_partial_result_carries_the_warning_on_both_halves(tmp_path):
    body = {"size": 0, "track_total_hits": True, "query": {"term": {"id.orig_h": "wkst-05"}}}
    resp = _call(tmp_path, {"command_line_contains": json.dumps(body), "image": "zeek-conn,windows-sysmon"})
    text = resp.content[-1].text
    assert text.startswith("hits=")
    assert WARNING_PREFIX in text and "zeek-conn" in text
    structured = getattr(resp, "structuredContent", None) or getattr(resp, "structured_content", None)
    assert structured["result"] == text


@pytest.mark.skipif(not _es_up(), reason="needs live Elasticsearch with zeek-conn")
def test_live_clean_result_has_no_warning(tmp_path):
    body = {"size": 0, "track_total_hits": True, "query": {"term": {"id.orig_h": "10.10.0.15"}}}
    resp = _call(tmp_path, {"command_line_contains": json.dumps(body), "image": "zeek-conn"})
    assert WARNING_PREFIX not in resp.content[-1].text


def test_short_circuit_results_carry_resulttype_on_2026_era_connections():
    """Protocol revision 2026-07-28 requires resultType; the claude CLI rejects
    a result without it as malformed, so the model saw a schema error instead
    of the budget/refusal message. Legacy connections get no extra key."""
    from types import SimpleNamespace

    from mcp_types.version import MODERN_PROTOCOL_VERSIONS

    from blue_bench_mcp.shard_check import text_result
    modern = text_result(SimpleNamespace(protocol_version=sorted(MODERN_PROTOCOL_VERSIONS)[-1]), "x")
    assert modern["resultType"] == "complete"
    assert modern["structuredContent"] == {"result": "x"} and modern["content"][0]["text"] == "x"
    legacy = text_result(SimpleNamespace(protocol_version="2025-06-18"), "x")
    assert "resultType" not in legacy
