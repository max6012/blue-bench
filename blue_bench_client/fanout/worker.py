"""Fan-out WORKER — one slice, one fresh context, tools hard-bound to the slice.

A worker is a plain ``runner.run()`` with three changes: the role prompt is
``prompts/role/fan_worker.md``, the question is built from the slice, and the
MCP server it talks to is launched with ``--slice``, so every tool call has the
slice's filters merged in before the tool runs.

The binding itself is NOT here. It lives in ``blue_bench_mcp.fanout_bind`` and
runs inside the server, because the frontier-ceiling profile uses the
``anthropic-cli`` transport: the ``claude`` subprocess talks to the MCP server
directly and nothing in this process sees its tool calls. A client-side proxy
would bind the harnesses that go through our client and silently leave that one
— and OpenCode, and Hermes — unscoped. What this module does with the binding
is read the server's slice-log back and attach each call's requested/bound
arguments to the trace, so the judge scores the model on its own choices and
never on fields the harness set.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from blue_bench_client import runner
from blue_bench_client.fanout.schema import (
    Slice,
    WorkerReport,
    WorkerReportParseError,
    parse_worker_report,
    render_report_schema_for_prompt,
)
from blue_bench_client.trace import Trace
from blue_bench_mcp.profiles import ModelProfile

WORKER_ROLE_FILE = "fan_worker.md"


def _render_slice_for_question(sl: Slice, max_turns: int) -> str:
    f = sl.filters
    lines = [f"Slice {sl.id}: {sl.question}", "", "Bound filters (the harness merges these into every tool call):"]
    if f.hosts:
        lines.append(f"- hosts: {', '.join(f.hosts)}")
    if f.host_ips:
        lines.append(f"- host IPs: {', '.join(f.host_ips)}")
    if f.indices:
        lines.append(f"- indices: {', '.join(f.indices)}")
    if f.time_start or f.time_end:
        start = f.time_start.isoformat() if f.time_start else "(open)"
        end = f.time_end.isoformat() if f.time_end else "(open)"
        lines.append(f"- time window: {start} to {end}")
        lines.append(
            "  (the server sets since/until on every query tool from this window; "
            "a lookback you pass yourself is ignored while it is set)"
        )
    if f.event_ids:
        lines.append(f"- event ids: {', '.join(str(e) for e in f.event_ids)}")
    if len(f.hosts) > 1 or len(f.host_ips) > 1 or len(f.event_ids) > 1:
        lines.append(
            "  (a list with several values cannot be bound to an exact-match argument; "
            "pass one member of the list yourself on each call)"
        )
    if f.is_empty():
        lines.append("- (none — the slice is scoped by its question only)")
    if f.notes:
        lines += ["", f"Notes from the lead: {f.notes}"]
    lines += [
        "",
        f"Why this slice exists: {sl.rationale}",
        "",
        f"Turn budget: {max_turns} tool-calling turns. Your last message must be the "
        f"WorkerReport JSON for slice_id \"{sl.id}\".",
    ]
    return "\n".join(lines)


def worker_profile(profile: ModelProfile) -> ModelProfile:
    """A copy of ``profile`` with the role part swapped for the worker role.
    The caller's profile is not mutated: the same profile object runs the lead
    and reducer with their own roles."""
    return profile.model_copy(
        update={"prompt_parts": {**profile.prompt_parts, "role": WORKER_ROLE_FILE}},
        deep=True,
    )


def read_slice_log(path: Path) -> list[dict[str, Any]]:
    """The server's slice-log as a list of records, in dispatch order.

    Missing file means the server never took a tool call — a run that failed
    before its first one, which is not itself an error here. A truncated final
    line (server killed mid-write) is dropped rather than raising: the records
    before it are still the truth about the calls that ran.
    """
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            break
    return out


def _attach_records(trace: Trace, records: list[dict[str, Any]]) -> None:
    """Copy the server's per-call slice-log records onto the trace's ToolCalls.

    The server logs one line per ``tools/call`` in arrival order, and a
    transport dispatches a turn's tool calls in list order, so the records line
    up positionally. A tool exception ends the run early and leaves the record
    list shorter than the call list; match by name and stop at the first
    mismatch instead of guessing.
    """
    calls = [tc for turn in trace.turns for tc in turn.tool_calls]
    for tc, rec in zip(calls, records):
        if tc.name != rec["tool"]:
            break
        tc.bound_args = rec["bound_args"]
        tc.overrides = rec["overrides"]


async def run_worker(
    profile: ModelProfile,
    slice: Slice,
    *,
    depth: int,
    config_path: Path | None,
    server_cmd: list[str] | None,
    max_turns_ceiling: int,
) -> tuple[Trace, WorkerReport | None]:
    """Run one slice as a worker. Returns the trace and the parsed report, or
    ``None`` for the report when the final answer did not parse — the parse
    error is then on ``trace.error`` so the dispatcher records it and moves on.

    ``max_turns`` is ``min(slice.turn_budget, max_turns_ceiling)``: the lead
    assigns, the harness caps.

    Every transport is supported, ``anthropic-cli`` included: the slice is
    enforced by the server the transport spawns, not by anything in this
    process.
    """
    max_turns = min(slice.turn_budget, max_turns_ceiling)
    wprofile = worker_profile(profile)
    question = _render_slice_for_question(slice, max_turns)
    base_cmd = list(server_cmd) if server_cmd else [sys.executable, "-m", "blue_bench_mcp.server"]

    with tempfile.TemporaryDirectory(prefix=f"bb-slice-{slice.id}-") as tmp:
        slice_file = Path(tmp) / "slice.json"
        slice_file.write_text(slice.model_dump_json(), encoding="utf-8")
        log_file = Path(tmp) / "slice-log.jsonl"
        cmd = [*base_cmd, "--slice", str(slice_file), "--slice-log", str(log_file)]

        trace = await runner.run(
            wprofile,
            question,
            prompt_id=f"fan:d{depth}:{slice.id}",
            server_cmd=cmd,
            config_path=config_path,
            max_turns=max_turns,
            extra_prompt_context={
                "report_schema": render_report_schema_for_prompt(),
                "turn_budget": str(max_turns),
                "slice_id": slice.id,
                "sub_depth": str(depth + 1),
            },
        )
        # Read inside the context, after runner.run returned: the server
        # subprocess has exited by then, so the log is complete, and the temp
        # directory still exists.
        _attach_records(trace, read_slice_log(log_file))

    if trace.error and not trace.final_answer:
        return trace, None
    try:
        report = parse_worker_report(trace.final_answer)
    except WorkerReportParseError as e:
        trace.error = f"{trace.error + '; ' if trace.error else ''}WorkerReportParseError: {e}"
        return trace, None
    report.turns_used = trace.turns_used
    if report.slice_id != slice.id:
        # The model answered for a slice it does not own (copied the example
        # id, most likely). Keep the report but say so; the id is the join key.
        report.error = f"report slice_id {report.slice_id!r} != assigned {slice.id!r}"
        report.slice_id = slice.id
    if trace.error:
        report.error = f"{report.error + '; ' if report.error else ''}{trace.error}"
    return trace, report
