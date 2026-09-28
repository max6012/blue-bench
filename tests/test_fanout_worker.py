"""Fan-out worker: run_worker end to end with a stubbed model loop and a fake
MCP server that applies the real binding rules. No ES, no model, no subprocess.

The binding rules themselves are tested in tests/test_fanout_bind.py — they
live in the server now (blue_bench_mcp.fanout_bind). What is tested here is the
worker's side of that arrangement: it launches the server with --slice and
--slice-log, and it reads the log back onto the trace.
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
from blue_bench_mcp.fanout_bind import bind_args, load_slice, refusal_text, slice_footer
from blue_bench_mcp.profiles import ModelProfile, load_profile
from blue_bench_client.trace import ToolCall, Turn

REPO = Path(__file__).parent.parent
PROFILES = REPO / "blue_bench_mcp" / "profiles"

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
T0 = NOW - timedelta(days=3)
T1 = NOW - timedelta(days=1)
T0_Z = "2026-09-08T12:00:00Z"
T1_Z = "2026-09-10T12:00:00Z"
HOST = "wkst-03.corp.example.invalid"


def _slice(turn_budget: int = 6, **filters) -> Slice:
    return Slice(
        id="s03",
        question="What ran on wkst-03 on the injection days?",
        filters=SliceFilters(**filters),
        turn_budget=turn_budget,
        rationale="the attacked host class, process-creates only",
    )


class FakeServer:
    """Stands in for MCPStdioClient plus the server it would have spawned.

    Reads ``--slice`` / ``--slice-log`` off the command exactly as the real
    server does, applies the real ``bind_args``, and appends the same JSONL
    record — so the worker's read-back path is exercised against the real log
    format rather than a hand-written one.
    """

    TOOLS = [
        ToolSpec("get_process_events", "sysmon", {"properties": {
            "host": {}, "image": {}, "parent_image": {}, "command_line_contains": {},
            "event_id": {}, "timerange_minutes": {}, "since": {}, "until": {}}}),
        ToolSpec("get_connections", "zeek", {"properties": {
            "src_ip": {}, "dest_ip": {}, "dest_port": {}, "proto": {},
            "timerange_minutes": {}, "since": {}, "until": {}}}),
        ToolSpec("count_by_field", "agg", {"properties": {
            "field": {}, "index": {}, "timerange_minutes": {}, "top_n": {},
            "since": {}, "until": {}}}),
    ]

    def __init__(self, server_cmd):
        self.server_cmd = list(server_cmd)
        self.calls: list[tuple[str, dict]] = []
        self.slice = None
        self.log_path = None
        for flag, attr in (("--slice", "slice"), ("--slice-log", "log_path")):
            if flag in self.server_cmd:
                value = self.server_cmd[self.server_cmd.index(flag) + 1]
                setattr(self, attr, load_slice(value) if flag == "--slice" else Path(value))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def list_tools(self):
        return self.TOOLS

    async def call_tool(self, name, args):
        schema = next((t.input_schema for t in self.TOOLS if t.name == name), None)
        if self.slice is None:
            self.calls.append((name, args))
            return "[]"
        bound, over = bind_args(name, args, self.slice, schema, now=NOW)
        if self.log_path is not None:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": NOW.isoformat(), "tool": name, "requested_args": args,
                    "bound_args": bound, "overrides": over,
                    "rejected": "_rejected" in over,
                }) + "\n")
        if "_rejected" in over:
            return refusal_text(over["_rejected"])
        self.calls.append((name, bound))
        body = "[]\n\n--- matched 5,619; fetched the newest 500. Narrow your query. ---"
        return body + slice_footer(self.slice.id, args, bound, over)


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
    one process-events call with an out-of-slice host, then the report. The MCP
    client is the FakeServer above, built from whatever command runner.run
    assembled — including the --slice flags run_worker appended."""
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

    def factory(cmd):
        seen["server"] = FakeServer(cmd)
        seen["cmd"] = list(cmd)
        return seen["server"]

    monkeypatch.setattr(runner, "MCPStdioClient", factory)
    return seen


def test_run_worker_launches_the_server_with_the_slice(profile, fake_loop):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    asyncio.run(w.run_worker(profile, sl, depth=0, config_path=None, server_cmd=["srv"],
                             max_turns_ceiling=20))
    cmd = fake_loop["cmd"]
    assert cmd[0] == "srv"
    assert "--slice" in cmd and "--slice-log" in cmd
    # The serialized slice on disk is the one the worker was given.
    assert fake_loop["server"].slice == sl


def test_run_worker_composes_fan_worker_role_without_mutating_the_profile(profile, fake_loop):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    trace, report = asyncio.run(w.run_worker(
        profile, sl, depth=0, config_path=None, server_cmd=["srv"], max_turns_ceiling=20))
    sp = trace.composed_system_prompt
    assert "You are one WORKER in a fan-out investigation" in sp
    assert "Blue Team security analyst AI assistant" not in sp
    assert "slice `s03`" in sp
    assert '"slice_id": "s07"' in sp  # the embedded report example
    assert "You have 6 tool calls" in sp
    assert "Set its `depth` to 1" in sp
    # Role only: the analyst-facing site/guidelines parts and the coaching
    # hints are not composed for a worker, whatever the profile carries.
    assert "Site Context" not in sp
    assert "## Coaching hints" not in sp
    assert "Later sections of this prompt" not in sp
    # The enforcement section states what the server does: both time edges.
    assert "sets BOTH edges" in sp
    assert "`_id` and `_index`" in sp
    # The caller's profile still carries the analyst role and its other parts.
    assert profile.prompt_parts["role"] == "blue_team_analyst.md"
    assert set(profile.prompt_parts) > {"role"}
    # The slice is rendered into the question, and the window is now enforced
    # on both edges rather than caveated as open-ended.
    assert "Slice s03:" in fake_loop["question"]
    assert HOST in fake_loop["question"]
    assert "the server sets since/until" in fake_loop["question"]
    assert trace.prompt_id == "fan:d0:s03"
    assert report is not None and report.slice_id == "s03" and report.turns_used == 3


def test_run_worker_budget_is_min_of_slice_and_ceiling(profile, fake_loop):
    sl = _slice(hosts=[HOST])
    asyncio.run(w.run_worker(profile, sl, depth=0, config_path=None, server_cmd=["srv"], max_turns_ceiling=20))
    # The server enforces the budget; the client's turn cap sits above it.
    assert fake_loop["max_turns"] == 6 + w.BUDGET_SLACK_TURNS
    assert json.loads(fake_loop["server"].slice.model_dump_json())["turn_budget"] == 6
    asyncio.run(w.run_worker(profile, sl, depth=0, config_path=None, server_cmd=["srv"], max_turns_ceiling=2))
    assert fake_loop["max_turns"] == 2 + w.BUDGET_SLACK_TURNS
    # The capped budget is what the server is given and what the model is told.
    assert fake_loop["server"].slice.turn_budget == 2
    assert "You have 2 tool calls" in fake_loop["system_prompt"]


def test_run_worker_reads_the_slice_log_onto_the_trace(profile, fake_loop):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    trace, _ = asyncio.run(w.run_worker(
        profile, sl, depth=0, config_path=None, server_cmd=["srv"], max_turns_ceiling=20))
    calls = [tc for t in trace.turns for tc in t.tool_calls]
    assert [c.name for c in calls] == ["count_by_field", "get_process_events"]
    # Model's own args are preserved for scoring...
    assert calls[1].args == {"host": "dc-01.corp.example.invalid", "event_id": 1}
    # ...the bound args are what the server ran...
    assert calls[1].bound_args == {"host": HOST, "event_id": 1, "since": T0_Z, "until": T1_Z}
    assert fake_loop["server"].calls[1][1] == calls[1].bound_args
    # ...and every replacement is on record.
    assert calls[1].overrides["host"] == "dc-01.corp.example.invalid"
    # The whole band binds now, so there is nothing lossy left to record.
    assert "_unexpressible" not in calls[1].overrides
    assert calls[0].bound_args["index"] == "windows-sysmon"
    assert calls[0].overrides == {}
    # Serialises: the judge reads traces from JSON.
    assert json.loads(trace.model_dump_json())["turns"][2]["tool_calls"][0]["overrides"]["host"]


def test_run_worker_tool_results_carry_the_slice_footer(profile, fake_loop):
    sl = _slice(hosts=[HOST], time_start=T0, time_end=T1)
    trace, _ = asyncio.run(w.run_worker(
        profile, sl, depth=0, config_path=None, server_cmd=["srv"], max_turns_ceiling=20))
    results = [t.content for t in trace.turns if t.role == "tool"]
    assert all("slice s03 in force" in r for r in results)
    assert "replaced your host" in results[1]


def test_run_worker_budget_exhausted_reports_none_with_error(profile, fake_loop, monkeypatch):
    # A model that never writes its report inside the client's turn cap.
    monkeypatch.setattr(w, "BUDGET_SLACK_TURNS", 0)
    sl = _slice(hosts=[HOST], turn_budget=1)
    trace, report = asyncio.run(w.run_worker(
        profile, sl, depth=1, config_path=None, server_cmd=["srv"], max_turns_ceiling=20))
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
        profile, _slice(hosts=[HOST]), depth=0, config_path=None, server_cmd=["srv"],
        max_turns_ceiling=20))
    assert report is None
    assert "WorkerReportParseError" in trace.error and "no JSON object" in trace.error


def test_run_worker_passes_the_slice_to_the_anthropic_cli_transport(profile, fake_loop, monkeypatch):
    """The frontier ceiling profile spawns `claude`, which talks to the MCP
    server itself. The slice reaches it because it is on the server command the
    CLI is told to launch — which is the whole reason binding moved server-side.
    """
    captured: dict = {}

    def fake_run(args, **kwargs):
        cfg_path = args[args.index("--mcp-config") + 1]
        captured["mcp_config"] = json.loads(Path(cfg_path).read_text())
        import subprocess as sp
        return sp.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    cli = profile.model_copy(update={"tool_protocol": "anthropic-cli"})
    sl = _slice(hosts=[HOST], time_start=T0)
    asyncio.run(w.run_worker(cli, sl, depth=0, config_path=None, server_cmd=["srv"],
                             max_turns_ceiling=5))
    server = captured["mcp_config"]["mcpServers"]["blue-bench"]
    assert server["command"] == "srv"
    assert "--slice" in server["args"] and "--slice-log" in server["args"]


def test_runner_default_path_is_unchanged(monkeypatch):
    """A plain run is untouched: no slice flags on the server command, and the
    composed context is exactly _build_context's."""
    captured = {}
    server = FakeServer(["x"])
    monkeypatch.setattr(runner, "MCPStdioClient", lambda cmd: server)

    async def stub(profile, system_prompt, question, tools, mcp, max_turns, trace):
        captured["mcp"] = mcp
        captured["system_prompt"] = system_prompt
        trace.final_answer = "ok"

    monkeypatch.setattr(runner, "_run_anthropic", stub)
    prof = load_profile(PROFILES / "claude-opus-4-8.yaml")
    trace = asyncio.run(runner.run(prof, "q", server_cmd=["x"]))
    assert captured["mcp"] is server
    assert server.slice is None
    assert "Blue Team security analyst" in captured["system_prompt"]
    assert trace.turns == [] and trace.final_answer == "ok"
    for tc in (tc for t in trace.turns for tc in t.tool_calls):
        assert tc.bound_args is None and tc.overrides is None


class StubHostResolver:
    """Answers one host with one address, without ES. Stands in for
    HostResolver in the completion path; the resolver's own behaviour is
    tested in tests/test_host_resolve.py."""

    def __init__(self, ip: str) -> None:
        self.ip = ip

    async def resolve_ips(self, host, *, since="", until=""):
        from blue_bench_client.fanout.host_resolve import Resolution
        return Resolution([self.ip], "zeek-dhcp")

    async def resolve_hosts(self, ip, *, since="", until=""):
        from blue_bench_client.fanout.host_resolve import Resolution
        return Resolution([], "")


def test_run_worker_completes_the_slice_before_writing_it(profile, fake_loop):
    """With a resolver, the slice the SERVER reads already carries the address
    half, so the network tools are bound too — and the worker's prompt says
    which value the harness added rather than passing it off as the lead's."""
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    asyncio.run(w.run_worker(profile, sl, depth=0, config_path=None, server_cmd=["srv"],
                             max_turns_ceiling=20, resolver=StubHostResolver("10.10.0.13")))
    on_disk = fake_loop["server"].slice
    assert on_disk.filters.host_ips == ["10.10.0.13"]
    assert on_disk.filters.hosts == [HOST]
    assert on_disk.resolved["host_ips"] == {"supplied": [], "resolved": ["10.10.0.13"]}
    assert "the harness resolved 10.10.0.13 from the corpus" in fake_loop["question"]
    # The dispatcher's own Slice object is untouched.
    assert sl.filters.host_ips == [] and sl.resolved == {}


def test_run_worker_without_a_resolver_writes_the_slice_as_given(profile, fake_loop):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    asyncio.run(w.run_worker(profile, sl, depth=0, config_path=None, server_cmd=["srv"],
                             max_turns_ceiling=20))
    assert fake_loop["server"].slice == sl
