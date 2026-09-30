"""Fan-out WORKER run through OpenCode -- the harness the range uses.

Same slice, same prompt, same tools, same enforcement as
:func:`blue_bench_client.fanout.worker.run_worker`; only the loop that drives
the model differs. That is possible because everything that defines a worker
lives outside the loop:

* the prompt is ``fan_worker.md`` composed role-only, exactly as run_worker
  composes it, and handed to OpenCode as the agent's prompt;
* the tools are the Blue-Bench MCP server, launched by OpenCode with
  ``--slice`` / ``--slice-log``, so the slice binding AND the tool-call budget
  are enforced by the server (fanout_bind), not by OpenCode;
* every OpenCode built-in tool is disabled, ``skill`` included (it leaked in
  the 2026-08-13 spike when only the obvious ones were switched off).

What OpenCode does not do is retry a provider failure: an HTTP 429/5xx or an
empty completion ends the run with a non-``stop`` terminal step (spike finding
4). Such a run is re-run whole, with backoff, and the attempts are recorded on
the trace; a run that never completes is marked as a provider failure, which
the scorer keeps out of accuracy.

Each attempt gets its own temp directory holding the generated
``opencode.json``, so no two slices share config, and OpenCode runs with
``--pure`` (no external plugins).
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from blue_bench_client import runner
from blue_bench_client.fanout.host_resolve import HostResolver, complete_slice_scope
from blue_bench_client.fanout.schema import (
    Slice,
    WorkerReport,
    WorkerReportParseError,
    parse_worker_report,
    render_report_schema_for_prompt,
    render_sub_plan_example_for_prompt,
)
from blue_bench_client.fanout.worker import (
    BUDGET_SLACK_TURNS,
    _attach_records,
    _render_slice_for_question,
    read_slice_log,
    worker_profile,
)
from blue_bench_client.mcp_client import MCPStdioClient
from blue_bench_client.trace import ToolCall, Trace, Turn
from blue_bench_mcp.profiles import ModelProfile
from blue_bench_mcp.prompts_compose import compose

MCP_NAME = "bluebench"
"""OpenCode prefixes MCP tool names with ``<server>_``; stripped in the trace."""

# Every OpenCode built-in, disabled. Audited against opencode 1.18.30; the
# spike's lesson is that a partial list leaks (skill did).
BUILTINS = ("bash", "edit", "write", "read", "grep", "glob", "list", "patch", "multiedit",
            "webfetch", "websearch", "codesearch", "todowrite", "todoread", "task",
            "skill", "lsp", "question", "batch", "invalid")

RETRY_BACKOFF = (20, 45, 90)
RUN_TIMEOUT_S = 900


def opencode_config(model: str, context: int, prompt_file: Path, server_cmd: list[str],
                    steps: int, temperature: float, top_p: float) -> dict[str, Any]:
    """The per-run OpenCode config: one provider, one MCP server, one agent."""
    provider, _, model_id = model.partition("/")
    return {
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            provider: {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Ollama Cloud",
                "options": {"baseURL": "https://ollama.com/v1", "apiKey": "{env:OLLAMA_API_KEY}"},
                "models": {model_id: {"name": model_id, "limit": {"context": context, "output": 32768}}},
            }
        },
        "mcp": {MCP_NAME: {"type": "local", "command": server_cmd, "enabled": True}},
        "agent": {
            "bbworker": {
                "description": "Blue-Bench fan-out worker -- MCP only, no built-ins",
                "mode": "primary",
                "steps": steps,
                "temperature": temperature,
                "top_p": top_p,
                "prompt": f"{{file:{prompt_file}}}",
                "tools": {name: False for name in BUILTINS},
            }
        },
    }


def _events(raw: str) -> list[dict[str, Any]]:
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(e, dict):
                out.append(e)
    return out


def _terminal_reason(events: list[dict[str, Any]]) -> str | None:
    reasons = [(e.get("part") or {}).get("reason") for e in events if e.get("type") == "step_finish"]
    return reasons[-1] if reasons else None


def events_to_trace(events: list[dict[str, Any]], trace: Trace) -> None:
    """OpenCode JSON events -> Trace turns, tool calls and final answer."""
    texts: list[str] = []
    for e in events:
        typ, part = e.get("type"), (e.get("part") or {})
        if typ == "text":
            t = part.get("text") or ""
            if t.strip():
                trace.turns.append(Turn(role="assistant", content=t))
                texts.append(t)
        elif typ == "tool_use":
            name = str(part.get("tool", "?")).removeprefix(f"{MCP_NAME}_")
            st = part.get("state") or {}
            trace.turns.append(Turn(role="assistant", content="",
                                    tool_calls=[ToolCall(name=name, args=dict(st.get("input") or {}))]))
            out = st.get("output")
            if out is None and st.get("error"):
                out = f"Error: {st.get('error')}"
            trace.turns.append(Turn(role="tool", content=str(out or ""), tool_name=name))
            trace.turns_used += 1
    trace.final_answer = texts[-1] if texts else ""


def _run_opencode(cwd: Path, question: str, model: str, raw: Path) -> tuple[int, bool]:
    env = {**os.environ, "OPENCODE_CONFIG": str(cwd / "opencode.json")}
    with open(raw, "w") as out, open(f"{raw}.err", "w") as err:
        p = subprocess.Popen(
            ["opencode", "run", question, "-m", model, "--agent", "bbworker",
             "--format", "json", "--pure", "--auto"],
            cwd=cwd, stdout=out, stderr=err, env=env, start_new_session=True)
        try:
            return p.wait(timeout=RUN_TIMEOUT_S), False
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except OSError:
                pass
            p.wait(timeout=15)
            return -9, True


async def run_worker_opencode(
    profile: ModelProfile,
    slice: Slice,
    *,
    model: str,
    depth: int,
    max_turns_ceiling: int,
    resolver: HostResolver | None = None,
    server_cmd: list[str] | None = None,
) -> tuple[Trace, WorkerReport | None]:
    """Run one slice as a worker through ``opencode run``.

    ``model`` is OpenCode's ``provider/model`` (``ollama-cloud/gpt-oss:120b``).
    ``profile`` supplies the prompt parts and generation settings, exactly as
    for run_worker; its transport is ignored.
    """
    budget = min(slice.turn_budget, max_turns_ceiling)
    wprofile = worker_profile(profile)
    if resolver is not None:
        slice, _ = await complete_slice_scope(slice, resolver)
    question = _render_slice_for_question(slice, budget)
    base_cmd = list(server_cmd) if server_cmd else [sys.executable, "-m", "blue_bench_mcp.server"]

    trace: Trace | None = None
    for attempt, delay in enumerate((0, *RETRY_BACKOFF)):
        if delay:
            await asyncio.sleep(delay)
        with tempfile.TemporaryDirectory(prefix=f"bb-oc-{slice.id}-") as tmp:
            tmpd = Path(tmp)
            slice_file = tmpd / "slice.json"
            slice_file.write_text(
                slice.model_copy(update={"turn_budget": budget}).model_dump_json(), encoding="utf-8")
            log_file = tmpd / "slice-log.jsonl"
            cmd = [*base_cmd, "--slice", str(slice_file), "--slice-log", str(log_file)]

            # The prompt names the tools, so list them from the same server.
            async with MCPStdioClient(cmd) as mcp:
                tools = await mcp.list_tools()
            log_file.unlink(missing_ok=True)  # listing is not a call; start clean
            context = {**runner._build_context(wprofile, tools),
                       "report_schema": render_report_schema_for_prompt(),
                       "sub_plan_schema": render_sub_plan_example_for_prompt(depth + 1),
                       "turn_budget": str(budget), "slice_id": slice.id, "sub_depth": str(depth + 1)}
            system_prompt = compose(wprofile, context)
            prompt_file = tmpd / "worker_prompt.md"
            prompt_file.write_text(system_prompt, encoding="utf-8")
            cfg = opencode_config(model, profile.context_size, prompt_file, cmd,
                                  steps=budget + BUDGET_SLACK_TURNS,
                                  temperature=profile.generation.temperature,
                                  top_p=profile.generation.top_p)
            (tmpd / "opencode.json").write_text(json.dumps(cfg, indent=1), encoding="utf-8")

            raw = tmpd / "events.jsonl"
            t0 = time.monotonic()
            rc, timed_out = await asyncio.to_thread(_run_opencode, tmpd, question, model, raw)
            events = _events(raw.read_text(encoding="utf-8", errors="replace"))
            stderr_tail = Path(f"{raw}.err").read_text(errors="replace")[-400:]

            trace = Trace(prompt_id=f"fan:d{depth}:{slice.id}", profile_name=f"opencode-{model}",
                          model_id=model, tool_protocol="openai-native", question=question,
                          composed_system_prompt=system_prompt,
                          tools_available=[t.name for t in tools], max_turns=budget)
            trace.total_duration_ms = int((time.monotonic() - t0) * 1000)
            events_to_trace(events, trace)
            _attach_records(trace, read_slice_log(log_file))
            trace.provider_retries = attempt
            reason = _terminal_reason(events)
            if timed_out:
                trace.error = f"TransportError: opencode run timed out after {RUN_TIMEOUT_S}s"
            elif reason != "stop":
                trace.error = (f"TransportError: opencode run ended without completing "
                               f"(terminal reason {reason!r}, exit {rc}): {stderr_tail.strip()[-200:]}")
            elif not trace.final_answer.strip():
                # A clean stop with nothing said is the model's doing, not the
                # provider's: no retry, and it scores as an unparsed report.
                trace.error = "ModelError: the run stopped normally with an empty final answer"
                break
            else:
                trace.error = None
                break

    assert trace is not None
    if trace.error and not trace.final_answer:
        return trace, None
    try:
        report = parse_worker_report(trace.final_answer)
    except WorkerReportParseError as e:
        trace.error = f"{trace.error + '; ' if trace.error else ''}WorkerReportParseError: {e}"
        return trace, None
    report.turns_used = trace.turns_used
    if report.slice_id != slice.id:
        report.error = f"report slice_id {report.slice_id!r} != assigned {slice.id!r}"
        report.slice_id = slice.id
    if trace.error:
        report.error = f"{report.error + '; ' if report.error else ''}{trace.error}"
    return trace, report
