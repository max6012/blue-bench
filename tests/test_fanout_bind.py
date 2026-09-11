"""Slice binding rules (blue_bench_mcp.fanout_bind) plus the server middleware
that applies them. No model, no ES — the middleware test drives the real server
over stdio with the ES-backed tool method monkeypatched to echo its arguments.
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from blue_bench_client.fanout.schema import Slice, SliceFilters
from blue_bench_client.mcp_client import MCPStdioClient
from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.fanout_bind import (
    REFUSAL_PREFIX,
    bind_args,
    load_slice,
    slice_footer,
)
from blue_bench_mcp.server import create_server

REPO = Path(__file__).parent.parent

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
T0 = NOW - timedelta(days=3)          # 4320 minutes ago
T1 = NOW - timedelta(days=1)
HOST = "wkst-03.corp.example.invalid"
T0_Z = "2026-09-08T12:00:00Z"
T1_Z = "2026-09-10T12:00:00Z"


def _slice(turn_budget: int = 6, **filters) -> Slice:
    return Slice(
        id="s03",
        question="What ran on wkst-03 on the injection days?",
        filters=SliceFilters(**filters),
        turn_budget=turn_budget,
        rationale="the attacked host class, process-creates only",
    )


@pytest.fixture(scope="module")
def schemas() -> dict[str, dict]:
    """The REAL input schemas of the registered tools.

    Taken from a live server rather than hand-written, so a change to a
    registered signature (a wrapper that starts or stops exposing ``host_ip``,
    say) shows up here as a failing binding test instead of as a slice that
    quietly stopped holding. ``detect_beaconing`` is off by default, so the
    fixture turns it on — it is the only tool left on the lookback-only path
    and the one that pins that tier.
    """
    cfg = ServerConfig()
    cfg.beaconing.enabled = True
    server = create_server(cfg)
    tools = asyncio.run(server.list_tools())
    return {t.name: (t.input_schema or {}) for t in tools}


# ── the time band ────────────────────────────────────────────────────────────

def test_absolute_band_binds_to_since_and_until(schemas):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    args = {"host": "dc-01.corp.example.invalid", "event_id": 3,
            "command_line_contains": "-enc", "timerange_minutes": 60}
    bound, over = bind_args("get_process_events", args, sl, schemas["get_process_events"])
    assert bound["host"] == HOST
    assert bound["event_id"] == 1
    assert bound["since"] == T0_Z and bound["until"] == T1_Z
    # The model's own investigative choice survives untouched.
    assert bound["command_line_contains"] == "-enc"
    # The tools ignore timerange_minutes once since/until are set, so the
    # model's lookback is dead weight, not a competing filter.
    assert bound["timerange_minutes"] == 60
    assert over["host"] == "dc-01.corp.example.invalid"
    assert over["event_id"] == 3
    # Nothing about the band is lossy any more.
    assert "_unexpressible" not in over
    # Pure: the model's dict is not mutated.
    assert args["host"] == "dc-01.corp.example.invalid"


def test_open_ended_band_binds_only_the_edge_it_has(schemas):
    bound, over = bind_args("count_by_field", {"field": "EventID"},
                            _slice(time_start=T0), schemas["count_by_field"])
    assert bound["since"] == T0_Z and "until" not in bound
    assert over == {}
    bound, _ = bind_args("count_by_field", {"field": "EventID"},
                         _slice(time_end=T1), schemas["count_by_field"])
    assert bound["until"] == T1_Z and "since" not in bound


def test_model_supplied_absolute_bounds_are_overridden_and_recorded(schemas):
    sl = _slice(time_start=T0, time_end=T1)
    bound, over = bind_args("get_process_events",
                            {"since": "2020-01-01T00:00:00Z", "until": "2030-01-01T00:00:00Z"},
                            sl, schemas["get_process_events"])
    assert bound["since"] == T0_Z and bound["until"] == T1_Z
    assert over["since"] == "2020-01-01T00:00:00Z"
    assert over["until"] == "2030-01-01T00:00:00Z"


def test_lookback_only_tool_binds_the_leading_edge_and_records_the_trailing_one(schemas):
    # detect_beaconing takes timerange_minutes and nothing absolute. The slice
    # start becomes a lookback; the end cannot be said at all, so it is on record.
    sl = _slice(host_ips=["10.1.20.33"], time_start=T0, time_end=T1)
    bound, over = bind_args("detect_beaconing", {}, sl, schemas["detect_beaconing"], now=NOW)
    assert bound["timerange_minutes"] == 4320
    assert over["_unexpressible"]["time_end"]["value"] == T1.isoformat()
    assert "timerange_minutes from now" in over["_unexpressible"]["time_end"]["reason"]


def test_lookback_rounds_up_so_the_slice_start_is_inside(schemas):
    sl = _slice(time_start=NOW - timedelta(minutes=90, seconds=1))
    bound, _ = bind_args("detect_beaconing", {}, sl, schemas["detect_beaconing"], now=NOW)
    assert bound["timerange_minutes"] == 91


def test_tool_with_no_time_argument_records_the_whole_window():
    # No registered tool is on this tier today; the rule exists so that adding
    # one cannot silently widen a slice.
    sl = _slice(hosts=[HOST], time_start=T0, time_end=T1)
    schema = {"properties": {"host": {}}}
    bound, over = bind_args("get_process_events", {}, sl, schema)
    assert bound == {"host": HOST}
    assert over["_unexpressible"]["time_window"]["start"] == T0.isoformat()
    assert over["_unexpressible"]["time_window"]["end"] == T1.isoformat()


def test_naive_free_slice_timestamps_are_rendered_as_utc_z(schemas):
    sl = _slice(time_start=datetime(2026, 9, 8, 8, 0, tzinfo=timezone(timedelta(hours=-4))))
    bound, _ = bind_args("count_by_field", {"field": "x"}, sl, schemas["count_by_field"])
    assert bound["since"] == "2026-09-08T12:00:00Z"


# ── hosts, IPs, event ids, indices ───────────────────────────────────────────

def test_no_override_recorded_when_model_already_matches_the_slice(schemas):
    sl = _slice(hosts=[HOST], time_start=T0)
    bound, over = bind_args("get_process_events", {"host": HOST, "event_id": 1}, sl,
                            schemas["get_process_events"])
    assert bound == {"host": HOST, "event_id": 1, "since": T0_Z}
    assert over == {}


def test_auth_and_tree_tools_bind_host(schemas):
    sl = _slice(hosts=[HOST], event_ids=[4624], time_start=T0)
    bound, over = bind_args("search_auth_events", {"account": "svc_backup", "host": "x"}, sl,
                            schemas["search_auth_events"])
    assert bound["host"] == HOST and bound["event_id"] == 4624 and bound["account"] == "svc_backup"
    assert over["host"] == "x"
    bound, over = bind_args("get_process_tree", {"process_guid": "{g}"}, sl,
                            schemas["get_process_tree"])
    assert bound == {"process_guid": "{g}", "host": HOST, "since": T0_Z}
    assert "event_id" not in bound  # the tree tool has no event_id argument


def test_network_tools_cannot_take_host_ip_today_and_the_drop_is_recorded(schemas):
    # The tool CLASSES implement host_ip as an OR over src/dest, but the
    # registered search_alerts / get_connections wrappers expose only src_ip
    # and dest_ip. Binding the slice host to both would AND them and match
    # nothing but self-loops, so the bound argument is dropped and recorded
    # instead. Known gap: the slice's host dimension does not hold on these two.
    sl = _slice(host_ips=["10.1.20.33"], time_start=T0)
    for name in ("get_connections", "search_alerts"):
        bound, over = bind_args(name, {"dest_port": 443}, sl, schemas[name])
        assert "host_ip" not in bound and "src_ip" not in bound and "dest_ip" not in bound
        assert bound["since"] == T0_Z
        assert over["_unbindable"] == {"host_ip": "10.1.20.33"}


def test_network_tools_bind_host_ip_when_the_tool_accepts_it():
    # The shape the binding takes the day the wrappers expose host_ip.
    sl = _slice(host_ips=["10.1.20.33"], time_start=T0)
    schema = {"properties": {k: {} for k in
                             ("host_ip", "src_ip", "dest_ip", "dest_port", "proto",
                              "timerange_minutes", "since", "until")}}
    bound, over = bind_args("get_connections", {"dest_port": 443, "host_ip": "10.9.9.9"},
                            sl, schema)
    assert bound["host_ip"] == "10.1.20.33" and bound["dest_port"] == 443
    assert over["host_ip"] == "10.9.9.9"


def test_count_by_field_binds_a_comma_list_of_indices(schemas):
    sl = _slice(indices=["windows-sysmon", "windows-security"], time_start=T0)
    bound, over = bind_args("count_by_field", {"field": "EventID", "index": "zeek-conn"}, sl,
                            schemas["count_by_field"])
    assert bound["index"] == "windows-sysmon,windows-security"
    assert bound["field"] == "EventID"
    assert over["index"] == "zeek-conn"


def test_fixed_index_tool_outside_slice_indices_is_recorded_not_rejected(schemas):
    # The slice is Sysmon-only; a network pivot reads zeek-conn. The pivot is
    # what the worker prompt asks for, so it goes through — on record.
    sl = _slice(indices=["windows-sysmon"], time_start=T0)
    bound, over = bind_args("get_connections", {"dest_port": 443}, sl, schemas["get_connections"])
    assert bound == {"dest_port": 443, "since": T0_Z}
    assert over["_unexpressible"]["indices"]["values"] == ["windows-sysmon"]
    assert "zeek-conn" in over["_unexpressible"]["indices"]["tool_reads"]
    # Same tool inside an index-compatible slice: nothing to record.
    sl = _slice(indices=["zeek-conn", "windows-sysmon"], time_start=T0)
    _, over = bind_args("get_connections", {"dest_port": 443}, sl, schemas["get_connections"])
    assert over == {}
    _, over = bind_args("get_process_events", {"host": HOST}, sl, schemas["get_process_events"])
    assert over == {}


def test_multi_value_host_is_unexpressible_and_out_of_slice_value_is_rejected(schemas):
    sl = _slice(hosts=[HOST, "wkst-04.corp.example.invalid"], time_start=T0)
    schema = schemas["get_process_events"]
    # Model passes nothing: cannot bind, recorded, left open.
    bound, over = bind_args("get_process_events", {}, sl, schema)
    assert "host" not in bound
    assert over["_unexpressible"]["hosts"]["values"] == sl.filters.hosts
    # Model passes a member: kept as-is, no override.
    bound, over = bind_args("get_process_events", {"host": "wkst-04.corp.example.invalid"}, sl, schema)
    assert bound["host"] == "wkst-04.corp.example.invalid"
    assert "host" not in over
    # Model passes an outsider: refused, not silently swapped.
    bound, over = bind_args("get_process_events", {"host": "dc-01.corp.example.invalid"}, sl, schema)
    assert "_rejected" in over and "dc-01" in over["_rejected"]["host"]["reason"]
    # CONTRACT: bound_args still carries the offending value; the caller checks.
    assert bound["host"] == "dc-01.corp.example.invalid"


def test_tools_without_slice_fields_are_untouched(schemas):
    sl = _slice(hosts=[HOST], host_ips=["10.1.20.33"], time_start=T0, event_ids=[1])
    for name, args in (
        ("list_evidence", {}),
        ("file_hash", {"filename": "a.bin"}),
        ("nmap_quick_scan", {"target": "10.1.20.33"}),
        ("validate_sigma_rule", {"rule_yaml": "title: x"}),
        # get_agent_alerts takes an agent id, a level floor and a limit — no
        # host, no index, no time. Nothing a slice can say reaches it.
        ("get_agent_alerts", {"agent_id": "003"}),
    ):
        bound, over = bind_args(name, args, sl, schemas[name])
        assert bound == args and over == {}


def test_empty_slice_binds_nothing(schemas):
    bound, over = bind_args("get_process_events", {"host": "any"}, _slice(),
                            schemas["get_process_events"])
    assert bound == {"host": "any"} and over == {}


# ── footer + slice file ──────────────────────────────────────────────────────

def test_footer_names_what_was_bound_and_what_it_replaced():
    footer = slice_footer("s03", {"host": "dc-01"},
                          {"host": HOST, "since": T0_Z}, {"host": "dc-01"})
    assert footer.startswith("\n\n--- slice s03 in force: bound ")
    assert f"host={HOST}" in footer and f"since={T0_Z}" in footer
    assert "replaced your host" in footer
    assert footer.endswith(". ---")


def test_footer_says_so_when_the_slice_binds_nothing_on_this_tool():
    assert "nothing on this tool to bind" in slice_footer("s03", {"a": 1}, {"a": 1}, {})


def test_footer_names_a_dimension_the_tool_cannot_take():
    footer = slice_footer("s03", {}, {"since": T0_Z}, {"_unbindable": {"host_ip": "10.1.20.33"}})
    assert "cannot take host_ip" in footer


def test_load_slice_round_trips(tmp_path):
    sl = _slice(hosts=[HOST], time_start=T0, time_end=T1)
    p = tmp_path / "slice.json"
    p.write_text(sl.model_dump_json(), encoding="utf-8")
    assert load_slice(p) == sl


# ── the server middleware, over real stdio ───────────────────────────────────

_STUB_SERVER = '''
"""A real blue-bench MCP server whose ES-backed process search echoes its
arguments instead of querying. Everything else — registration, the slice
middleware, the stdio transport — is the production path."""
import json, sys
sys.path.insert(0, {repo!r})
from blue_bench_mcp.tool_classes.elastic import ElasticTool

async def echo(self, **kwargs):
    return json.dumps(kwargs, sort_keys=True)

ElasticTool.get_process_events = echo
from blue_bench_mcp.server import main
main()
'''


def _server_cmd(tmp_path: Path, sl: Slice) -> tuple[list[str], Path]:
    stub = tmp_path / "stub_server.py"
    stub.write_text(_STUB_SERVER.format(repo=str(REPO)), encoding="utf-8")
    slice_file = tmp_path / "slice.json"
    slice_file.write_text(sl.model_dump_json(), encoding="utf-8")
    log = tmp_path / "slice-log.jsonl"
    return [sys.executable, str(stub), "--slice", str(slice_file), "--slice-log", str(log)], log


def _call(cmd: list[str], name: str, args: dict) -> str:
    async def go() -> str:
        async with MCPStdioClient(cmd) as c:
            await c.list_tools()
            return await c.call_tool(name, args)
    return asyncio.run(go())


def _call_raw(cmd: list[str], name: str, args: dict):
    """The raw CallToolResult, not the text our client flattens it to.

    Needed because the two transports read different halves: the SDK path
    concatenates text blocks, the anthropic-cli path unwraps
    ``structuredContent['result']`` (runner._cli_tool_result_text). A footer on
    one and not the other would be a silent asymmetry on the frontier profile.
    """
    from contextlib import AsyncExitStack

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def go():
        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(
                stdio_client(StdioServerParameters(command=cmd[0], args=cmd[1:])))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            return await session.call_tool(name, args)
    return asyncio.run(go())


def _structured(resp) -> dict | None:
    return getattr(resp, "structuredContent", None) or getattr(resp, "structured_content", None)


def test_both_halves_of_the_result_carry_the_slice_footer(tmp_path):
    sl = _slice(hosts=[HOST], time_start=T0, time_end=T1)
    cmd, _ = _server_cmd(tmp_path, sl)
    resp = _call_raw(cmd, "get_process_events", {"host": "dc-01.corp.example.invalid"})
    text = resp.content[-1].text
    assert "slice s03 in force" in text
    assert _structured(resp)["result"] == text


def test_a_refusal_reaches_both_halves_too(tmp_path):
    sl = _slice(hosts=[HOST, "wkst-04.corp.example.invalid"])
    cmd, _ = _server_cmd(tmp_path, sl)
    resp = _call_raw(cmd, "get_process_events", {"host": "dc-01.corp.example.invalid"})
    text = resp.content[-1].text
    assert text.startswith(REFUSAL_PREFIX)
    # Same envelope the SDK builds for a string-returning tool, so the CLI
    # transport's {"result": ...} unwrap sees the sentence, not JSON noise.
    assert _structured(resp)["result"] == text
    assert not resp.is_error


def test_server_binds_an_out_of_slice_call_and_logs_it(tmp_path):
    sl = _slice(hosts=[HOST], event_ids=[1], time_start=T0, time_end=T1)
    cmd, log = _server_cmd(tmp_path, sl)
    out = _call(cmd, "get_process_events",
                {"host": "dc-01.corp.example.invalid", "timerange_minutes": 43200,
                 "command_line_contains": "-enc"})

    echoed = json.loads(out.split("\n\n---")[0])
    assert echoed["host"] == HOST
    assert echoed["event_id"] == 1
    assert echoed["since"] == T0_Z and echoed["until"] == T1_Z
    assert echoed["command_line_contains"] == "-enc"   # the model's own choice survives

    # The result says a slice is in force and what it did.
    assert f"--- slice s03 in force: bound event_id=1, host={HOST}" in out
    assert "replaced your host" in out

    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(records) == 1
    rec = records[0]
    assert rec["tool"] == "get_process_events"
    assert rec["requested_args"]["host"] == "dc-01.corp.example.invalid"
    assert rec["bound_args"]["host"] == HOST
    assert rec["overrides"]["host"] == "dc-01.corp.example.invalid"
    assert rec["rejected"] is False
    # Exactly what the model sent — no pydantic defaults it never chose.
    assert set(rec["requested_args"]) == {"host", "timerange_minutes", "command_line_contains"}


def test_server_refuses_an_out_of_slice_call_on_a_multi_value_slice(tmp_path):
    sl = _slice(hosts=[HOST, "wkst-04.corp.example.invalid"])
    cmd, log = _server_cmd(tmp_path, sl)
    out = _call(cmd, "get_process_events", {"host": "dc-01.corp.example.invalid"})
    assert out.startswith(REFUSAL_PREFIX)
    assert "Stay inside your slice" in out
    rec = json.loads(log.read_text().splitlines()[0])
    assert rec["rejected"] is True
    assert "_rejected" in rec["overrides"]


def test_server_without_a_slice_is_unchanged(tmp_path):
    stub = tmp_path / "stub_server.py"
    stub.write_text(_STUB_SERVER.format(repo=str(REPO)), encoding="utf-8")
    out = _call([sys.executable, str(stub)], "get_process_events", {"host": "dc-01"})
    assert json.loads(out)["host"] == "dc-01"
    assert "slice" not in out


def test_slice_log_requires_a_slice(tmp_path):
    import subprocess
    r = subprocess.run(
        [sys.executable, "-m", "blue_bench_mcp.server", "--slice-log", str(tmp_path / "l")],
        cwd=REPO, capture_output=True, text=True, timeout=60,
    )
    assert r.returncode != 0 and "--slice-log requires --slice" in r.stderr
