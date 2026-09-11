"""Fan-out worker: slice binding, the bound client, and run_worker end to end
with a stubbed model loop. No ES, no model, no MCP subprocess.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from blue_bench_client import runner
from blue_bench_client.fanout import worker as w
from blue_bench_client.fanout.schema import Slice, SliceFilters
from blue_bench_client.mcp_client import ToolSpec
from blue_bench_client.trace import ToolCall, Turn
from blue_bench_mcp.profiles import ModelProfile, load_profile

REPO = Path(__file__).parent.parent
PROFILES = REPO / "blue_bench_mcp" / "profiles"

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
T0 = NOW - timedelta(days=3)          # 4320 minutes ago
T1 = NOW - timedelta(days=1)
HOST = "wkst-03.corp.example.invalid"


def _slice(turn_budget: int = 6, **filters) -> Slice:
    return Slice(
        id="s03",
        question="What ran on wkst-03 on the injection days?",
        filters=SliceFilters(**filters),
        turn_budget=turn_budget,
        rationale="the attacked host class, process-creates only",
    )


# ── bind_slice ───────────────────────────────────────────────────────────────

def test_process_events_slice_wins_and_overrides_are_recorded():
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    args = {"host": "dc-01.corp.example.invalid", "event_id": 3, "command_line_contains": "-enc",
            "timerange_minutes": 60}
    bound, over = w.bind_slice(args, "get_process_events", sl, now=NOW)
    assert bound["host"] == HOST
    assert bound["event_id"] == 1
    assert bound["timerange_minutes"] == 4320
    # The model's own investigative choice survives untouched.
    assert bound["command_line_contains"] == "-enc"
    assert over["host"] == "dc-01.corp.example.invalid"
    assert over["event_id"] == 3
    assert over["timerange_minutes"] == 60
    # Absolute end cannot be expressed through a lookback-from-now interface.
    assert over["_unexpressible"]["time_end"]["value"] == T1.isoformat()
    # Pure: the model's dict is not mutated.
    assert args["host"] == "dc-01.corp.example.invalid"


def test_no_override_recorded_when_model_already_matches_the_slice():
    sl = _slice(hosts=[HOST], time_start=T0)
    bound, over = w.bind_slice({"host": HOST, "event_id": 1}, "get_process_events", sl, now=NOW)
    assert bound == {"host": HOST, "event_id": 1, "timerange_minutes": 4320}
    assert over == {}


def test_lookback_rounds_up_so_the_slice_start_is_inside():
    sl = _slice(time_start=NOW - timedelta(minutes=90, seconds=1))
    bound, _ = w.bind_slice({}, "count_by_field", sl, now=NOW)
    assert bound["timerange_minutes"] == 91


def test_auth_and_tree_tools_bind_host():
    sl = _slice(hosts=[HOST], event_ids=[4624], time_start=T0)
    bound, over = w.bind_slice({"account": "svc_backup", "host": "x"}, "search_auth_events", sl, now=NOW)
    assert bound["host"] == HOST and bound["event_id"] == 4624 and bound["account"] == "svc_backup"
    assert over["host"] == "x"
    bound, over = w.bind_slice({"process_guid": "{g}"}, "get_process_tree", sl, now=NOW)
    assert bound == {"process_guid": "{g}", "host": HOST, "timerange_minutes": 4320}
    assert "event_id" not in bound  # the tree tool has no event_id argument


def test_network_tools_bind_host_ip_when_the_tool_accepts_it():
    sl = _slice(host_ips=["10.1.20.33"], time_start=T0)
    accepted = {"host_ip", "src_ip", "dest_ip", "dest_port", "proto", "timerange_minutes"}
    bound, over = w.bind_slice({"dest_port": 443, "host_ip": "10.9.9.9"}, "get_connections", sl,
                               now=NOW, accepted_params=accepted)
    assert bound["host_ip"] == "10.1.20.33" and bound["dest_port"] == 443
    assert over["host_ip"] == "10.9.9.9"
    bound, over = w.bind_slice({"severity": 1}, "search_alerts", sl, now=NOW, accepted_params=accepted)
    assert bound["host_ip"] == "10.1.20.33" and bound["severity"] == 1


def test_unbindable_when_the_registered_tool_lacks_host_ip():
    # The registered wrappers may not expose host_ip yet; the bound arg is
    # dropped so the call still runs, and the drop is on record.
    sl = _slice(host_ips=["10.1.20.33"], time_start=T0)
    accepted = {"src_ip", "dest_ip", "dest_port", "proto", "timerange_minutes"}
    bound, over = w.bind_slice({"dest_port": 443}, "get_connections", sl, now=NOW, accepted_params=accepted)
    assert "host_ip" not in bound
    assert bound["timerange_minutes"] == 4320
    assert over["_unbindable"] == {"host_ip": "10.1.20.33"}


def test_count_by_field_binds_a_comma_list_of_indices():
    sl = _slice(indices=["windows-sysmon", "windows-security"], time_start=T0)
    bound, over = w.bind_slice({"field": "EventID", "index": "zeek-conn"}, "count_by_field", sl, now=NOW)
    assert bound["index"] == "windows-sysmon,windows-security"
    assert bound["field"] == "EventID"
    assert over["index"] == "zeek-conn"


def test_fixed_index_tool_outside_slice_indices_is_recorded_not_rejected():
    # The slice is Sysmon-only; a network pivot reads zeek-conn. The pivot is
    # what the worker prompt asks for, so it goes through — on record.
    sl = _slice(indices=["windows-sysmon"], time_start=T0)
    bound, over = w.bind_slice({"dest_port": 443}, "get_connections", sl, now=NOW)
    assert bound == {"dest_port": 443, "timerange_minutes": 4320}
    assert over["_unexpressible"]["indices"]["values"] == ["windows-sysmon"]
    assert "zeek-conn" in over["_unexpressible"]["indices"]["tool_reads"]
    # Same tool inside an index-compatible slice: nothing to record.
    sl = _slice(indices=["zeek-conn", "windows-sysmon"], time_start=T0)
    _, over = w.bind_slice({"dest_port": 443}, "get_connections", sl, now=NOW)
    assert over == {}
    _, over = w.bind_slice({"host": HOST}, "get_process_events", sl, now=NOW)
    assert over == {}


def test_multi_value_host_is_unexpressible_and_out_of_slice_value_is_rejected():
    sl = _slice(hosts=[HOST, "wkst-04.corp.example.invalid"], time_start=T0)
    # Model passes nothing: cannot bind, recorded, left open.
    bound, over = w.bind_slice({}, "get_process_events", sl, now=NOW)
    assert "host" not in bound
    assert over["_unexpressible"]["hosts"]["values"] == sl.filters.hosts
    # Model passes a member: kept as-is, no override.
    bound, over = w.bind_slice({"host": "wkst-04.corp.example.invalid"}, "get_process_events", sl, now=NOW)
    assert bound["host"] == "wkst-04.corp.example.invalid"
    assert "host" not in over
    # Model passes an outsider: refused, not silently swapped.
    bound, over = w.bind_slice({"host": "dc-01.corp.example.invalid"}, "get_process_events", sl, now=NOW)
    assert "_rejected" in over and "dc-01" in over["_rejected"]["host"]["reason"]


def test_tools_without_slice_fields_are_untouched():
    sl = _slice(hosts=[HOST], host_ips=["10.1.20.33"], time_start=T0, event_ids=[1])
    for name, args in (
        ("list_evidence", {}),
        ("file_hash", {"filename": "a.bin"}),
        ("nmap_quick_scan", {"target": "10.1.20.33"}),
        ("validate_sigma_rule", {"rule_yaml": "title: x"}),
    ):
        bound, over = w.bind_slice(args, name, sl, now=NOW)
        assert bound == args and over == {}


def test_empty_slice_binds_nothing():
    bound, over = w.bind_slice({"host": "any"}, "get_process_events", _slice(), now=NOW)
    assert bound == {"host": "any"} and over == {}


# ── BoundMCPClient ───────────────────────────────────────────────────────────

class FakeInner:
    """Stands in for MCPStdioClient: records calls, answers with a footer."""

    def __init__(self, server_cmd=None):
        self.calls: list[tuple[str, dict]] = []
        self.entered = False

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, *a):
        self.entered = False

    async def list_tools(self):
        return [
            ToolSpec("get_process_events", "sysmon", {"properties": {
                "host": {}, "image": {}, "parent_image": {}, "command_line_contains": {},
                "event_id": {}, "timerange_minutes": {}}}),
            ToolSpec("get_connections", "zeek", {"properties": {
                "src_ip": {}, "dest_ip": {}, "dest_port": {}, "proto": {}, "timerange_minutes": {}}}),
            ToolSpec("count_by_field", "agg", {"properties": {
                "field": {}, "index": {}, "timerange_minutes": {}, "top_n": {}}}),
        ]

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        return "[]\n\n--- matched 5,619; fetched the newest 500. Narrow your query. ---"


def test_bound_client_binds_each_call_and_records_it():
    sl = _slice(hosts=[HOST], host_ips=["10.1.20.33"], time_start=T0, time_end=T1)
    inner = FakeInner()
    client = w.BoundMCPClient(["x"], sl, now=NOW, inner=inner)

    async def go():
        async with client:
            await client.list_tools()
            r1 = await client.call_tool("get_process_events", {"host": "dc-01", "command_line_contains": "iex"})
            r2 = await client.call_tool("get_connections", {"dest_port": 443})
            return r1, r2

    r1, r2 = asyncio.run(go())
    assert "matched 5,619" in r1 and "matched 5,619" in r2
    assert inner.calls[0] == ("get_process_events", {
        "host": HOST, "command_line_contains": "iex", "timerange_minutes": 4320})
    # host_ip is not in the fake tool's schema: dropped from the wire, recorded.
    assert inner.calls[1] == ("get_connections", {"dest_port": 443, "timerange_minutes": 4320})
    assert client.records[1]["overrides"]["_unbindable"] == {"host_ip": "10.1.20.33"}
    assert client.records[0]["args"] == {"host": "dc-01", "command_line_contains": "iex"}
    assert client.records[0]["overrides"]["host"] == "dc-01"


def test_bound_client_refuses_out_of_slice_call_without_reaching_the_server():
    sl = _slice(hosts=[HOST, "wkst-04.corp.example.invalid"])
    inner = FakeInner()
    client = w.BoundMCPClient(["x"], sl, now=NOW, inner=inner)

    async def go():
        async with client:
            await client.list_tools()
            return await client.call_tool("get_process_events", {"host": "dc-01.corp.example.invalid"})

    result = asyncio.run(go())
    assert result.startswith("Error: call refused by the slice binding")
    assert inner.calls == []
    assert "_rejected" in client.records[0]["overrides"]


# ── run_worker with a stubbed model loop ─────────────────────────────────────

REPORT = {
    "slice_id": "s03",
    "findings": [{
        "statement": "encoded powershell from winword",
        "pointers": [{"index": "windows-sysmon", "event_record_id": 77, "process_guid": "{g}"}],
        "confidence": 0.8,
        "technique_hints": ["T1059.001"],
    }],
    "nothing_found": False,
    "nothing_found_reason": "",
    "advice": "keep",
    "sub_plan": None,
}


@pytest.fixture
def profile() -> ModelProfile:
    return load_profile(PROFILES / "claude-opus-4-8.yaml")


@pytest.fixture
def fake_loop(monkeypatch):
    """Replace the anthropic transport with a scripted model: one survey call,
    one process-events call with an out-of-slice host, then the report."""
    seen: dict = {}

    async def scripted(profile, system_prompt, question, tools, mcp, max_turns, trace):
        seen["max_turns"] = max_turns
        seen["system_prompt"] = system_prompt
        seen["question"] = question
        script = [
            [ToolCall(name="count_by_field", args={"field": "EventID", "index": "windows-sysmon"})],
            [ToolCall(name="get_process_events", args={"host": "dc-01.corp.example.invalid", "event_id": 1})],
            [],
        ]
        for calls in script[:max_turns]:
            trace.turns.append(Turn(role="assistant", content="" if calls else json.dumps(REPORT), tool_calls=calls))
            trace.turns_used += 1
            if not calls:
                trace.final_answer = json.dumps(REPORT)
                return
            for tc in calls:
                result = await mcp.call_tool(tc.name, tc.args)
                trace.turns.append(Turn(role="tool", content=result, tool_name=tc.name))
        trace.error = f"max_turns ({max_turns}) exhausted without final answer"

    monkeypatch.setattr(runner, "_run_anthropic", scripted)
    # The bound client wraps a fake server instead of spawning one.
    inner = FakeInner()
    monkeypatch.setattr(w, "MCPStdioClient", lambda cmd: inner)
    seen["inner"] = inner
    return seen


def test_run_worker_composes_fan_worker_role_without_mutating_the_profile(profile, fake_loop):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    trace, report = asyncio.run(w.run_worker(
        profile, sl, depth=0, config_path=None, server_cmd=["x"], max_turns_ceiling=20, now=NOW))
    sp = trace.composed_system_prompt
    assert "You are one WORKER in a fan-out investigation" in sp
    assert "Blue Team security analyst AI assistant" not in sp
    assert "slice `s03`" in sp
    assert '"slice_id": "s07"' in sp  # the embedded report example
    assert "You have 6 tool-calling turns" in sp
    assert "Set its `depth` to 1" in sp
    # The caller's profile still carries the analyst role.
    assert profile.prompt_parts["role"] == "blue_team_analyst.md"
    # The slice is rendered into the question, with the open-end caveat.
    assert "Slice s03:" in fake_loop["question"]
    assert HOST in fake_loop["question"]
    assert "window END is not" in fake_loop["question"]
    assert trace.prompt_id == "fan:d0:s03"
    assert report is not None and report.slice_id == "s03" and report.turns_used == 3


def test_run_worker_budget_is_min_of_slice_and_ceiling(profile, fake_loop):
    sl = _slice(hosts=[HOST])
    asyncio.run(w.run_worker(profile, sl, depth=0, config_path=None, server_cmd=["x"], max_turns_ceiling=20, now=NOW))
    assert fake_loop["max_turns"] == 6
    asyncio.run(w.run_worker(profile, sl, depth=0, config_path=None, server_cmd=["x"], max_turns_ceiling=2, now=NOW))
    assert fake_loop["max_turns"] == 2
    assert "You have 2 tool-calling turns" in fake_loop["system_prompt"]


def test_run_worker_overrides_land_on_the_trace(profile, fake_loop):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    trace, _ = asyncio.run(w.run_worker(
        profile, sl, depth=0, config_path=None, server_cmd=["x"], max_turns_ceiling=20, now=NOW))
    calls = [tc for t in trace.turns for tc in t.tool_calls]
    assert [c.name for c in calls] == ["count_by_field", "get_process_events"]
    # Model's own args are preserved for scoring...
    assert calls[1].args == {"host": "dc-01.corp.example.invalid", "event_id": 1}
    # ...the bound args are what went to the server...
    assert calls[1].bound_args == {"host": HOST, "event_id": 1, "timerange_minutes": 4320}
    assert fake_loop["inner"].calls[1][1] == calls[1].bound_args
    # ...and every replacement plus the absolute-end limitation is on record.
    assert calls[1].overrides["host"] == "dc-01.corp.example.invalid"
    assert "time_end" in calls[1].overrides["_unexpressible"]
    assert calls[0].bound_args["index"] == "windows-sysmon"
    assert calls[0].overrides == {"_unexpressible": {"time_end": calls[1].overrides["_unexpressible"]["time_end"]}}
    # Serialises: the judge reads traces from JSON.
    assert json.loads(trace.model_dump_json())["turns"][2]["tool_calls"][0]["overrides"]["host"]


def test_run_worker_budget_exhausted_reports_none_with_error(profile, fake_loop):
    sl = _slice(hosts=[HOST], turn_budget=1)
    trace, report = asyncio.run(w.run_worker(
        profile, sl, depth=1, config_path=None, server_cmd=["x"], max_turns_ceiling=20, now=NOW))
    assert report is None
    assert "max_turns (1) exhausted" in trace.error
    assert trace.prompt_id == "fan:d1:s03"


def test_run_worker_unparseable_answer_reports_none(profile, fake_loop, monkeypatch):
    async def prose_only(profile, system_prompt, question, tools, mcp, max_turns, trace):
        trace.turns.append(Turn(role="assistant", content="I looked and saw nothing worth reporting."))
        trace.turns_used = 1
        trace.final_answer = "I looked and saw nothing worth reporting."

    monkeypatch.setattr(runner, "_run_anthropic", prose_only)
    trace, report = asyncio.run(w.run_worker(
        profile, _slice(hosts=[HOST]), depth=0, config_path=None, server_cmd=["x"], max_turns_ceiling=20, now=NOW))
    assert report is None
    assert "WorkerReportParseError" in trace.error and "no JSON object" in trace.error


def test_run_worker_refuses_anthropic_cli_transport(profile):
    cli = profile.model_copy(update={"tool_protocol": "anthropic-cli"})
    with pytest.raises(ValueError, match="anthropic-cli"):
        asyncio.run(w.run_worker(cli, _slice(), depth=0, config_path=None, server_cmd=["x"], max_turns_ceiling=5))


def test_runner_default_path_is_unchanged(monkeypatch):
    """The seam must not change a plain run: default factory is the stdio
    client and the composed context is exactly _build_context's."""
    captured = {}
    inner = FakeInner()
    monkeypatch.setattr(runner, "MCPStdioClient", lambda cmd: inner)

    async def stub(profile, system_prompt, question, tools, mcp, max_turns, trace):
        captured["mcp"] = mcp
        captured["system_prompt"] = system_prompt
        trace.final_answer = "ok"

    monkeypatch.setattr(runner, "_run_anthropic", stub)
    prof = load_profile(PROFILES / "claude-opus-4-8.yaml")
    trace = asyncio.run(runner.run(prof, "q", server_cmd=["x"]))
    assert captured["mcp"] is inner
    assert "Blue Team security analyst" in captured["system_prompt"]
    assert trace.turns == [] and trace.final_answer == "ok"
    for tc in (tc for t in trace.turns for tc in t.tool_calls):
        assert tc.bound_args is None and tc.overrides is None
