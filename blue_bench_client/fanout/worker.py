"""Fan-out WORKER — one slice, one fresh context, tools hard-bound to the slice.

A worker is a plain ``runner.run()`` with three changes: the role prompt is
``prompts/role/fan_worker.md``, the question is built from the slice, and the
MCP client is wrapped so every tool call has the slice's filters merged in
before it reaches the server. The slice wins over whatever the model asked
for; both are recorded on the trace so the judge scores the model on its own
choices (tool, event type, command-line filter, pivots) and never on fields
the harness set.

Binding is honest about what the tools can express. They take a lookback
``timerange_minutes`` from *now*, so a slice's absolute ``time_start`` binds
but its ``time_end`` cannot; a multi-host slice cannot bind an exact-match
``host``. Every such gap is recorded under ``overrides['_unexpressible']``
rather than silently narrowed or silently widened.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
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
from blue_bench_client.mcp_client import MCPStdioClient, ToolSpec
from blue_bench_client.trace import Trace
from blue_bench_mcp.profiles import ModelProfile

WORKER_ROLE_FILE = "fan_worker.md"

# Which slice dimension maps to which argument, per tool. A tool absent here
# (evidence, nmap, sigma, wazuh, openedr) is passed through untouched — it has
# no field a slice constrains. Keys are slice-filter names; values are the
# tool's argument names. Keep this table in step with the registered
# signatures in blue_bench_mcp/tools/*.py.
_BINDINGS: dict[str, dict[str, str]] = {
    "get_process_events": {"host": "host", "event_id": "event_id", "time": "timerange_minutes"},
    "get_process_tree": {"host": "host", "time": "timerange_minutes"},
    "search_auth_events": {"host": "host", "event_id": "event_id", "time": "timerange_minutes"},
    "get_connections": {"host_ip": "host_ip", "time": "timerange_minutes"},
    "search_alerts": {"host_ip": "host_ip", "time": "timerange_minutes"},
    "count_by_field": {"index": "index", "time": "timerange_minutes"},
    "count_by_time": {"host": "host", "event_id": "event_id", "index": "index", "time": "timerange_minutes"},
    "get_agent_alerts": {"time": "timerange_minutes"},
    "detect_beaconing": {"time": "timerange_minutes"},
}


# The indices each fixed-index tool reads (repo config defaults). A tool that
# takes no ``index`` argument cannot be bound to a slice's indices; when its
# native index is outside the slice this is recorded, not rejected — the
# worker prompt tells the model to pivot host<->network, and that crosses
# indices by construction. The lead has to know an index-scoped slice and a
# pivot instruction do not compose.
_NATIVE_INDICES: dict[str, set[str]] = {
    "get_process_events": {"windows-sysmon"},
    "get_process_tree": {"windows-sysmon"},
    "search_auth_events": {"windows-security", "linux-syslog"},
    "get_connections": {"zeek-conn", "ot-conn"},
    "search_alerts": {"logstash-suricata-alerts", "wazuh-alerts", "zeek-conn"},
    "get_agent_alerts": {"wazuh-alerts"},
    "detect_beaconing": {"zeek-conn"},
}


def _single(values: list, what: str, unexpressible: dict[str, Any]) -> Any | None:
    """A slice list binds to an exact-match argument only when it has one
    value. Several values cannot be expressed in one call; record that and
    leave the argument to the model — the prompt tells it to pass a member."""
    if len(values) == 1:
        return values[0]
    if len(values) > 1:
        unexpressible[what] = {
            "values": list(values),
            "reason": f"tool argument is exact-match; a {len(values)}-value slice cannot bind it",
        }
    return None


def slice_lookback_minutes(sl: Slice, now: datetime) -> int | None:
    """Minutes from ``time_start`` to ``now``, rounded up so the whole slice is
    inside the lookback. None when the slice has no start."""
    if sl.filters.time_start is None:
        return None
    delta = now - sl.filters.time_start
    return max(1, math.ceil(delta.total_seconds() / 60))


def bind_slice(
    args: dict[str, Any],
    tool_name: str,
    slice: Slice,
    *,
    now: datetime | None = None,
    accepted_params: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Merge the slice into one tool call. Pure: returns (bound_args, overrides).

    ``bound_args`` is what goes to the server. ``overrides`` records every
    model-supplied value the slice replaced (``{arg: model_value}``), plus two
    audit keys when they apply:

    - ``_unexpressible``: slice constraints the tool interface cannot state
      (an absolute ``time_end``; a multi-value host/event-id list against an
      exact-match argument). The call is NOT narrowed to compensate; the
      dispatcher and judge read this to know the slice was open on that edge.
    - ``_unbindable``: bound arguments the registered tool does not accept
      (from ``accepted_params``, i.e. the tool's input schema). Dropped so the
      call still succeeds; recorded so nobody believes the slice held.
    - ``_rejected``: the model asked for a value outside a multi-value slice
      list. CONTRACT: ``bound_args`` still carries that value — a caller that
      sends it without first checking ``overrides`` for ``_rejected`` sends an
      out-of-slice query. ``BoundMCPClient`` checks and returns the reason to
      the model as the tool result instead of calling the server; any other
      consumer of ``bind_slice`` (dispatcher, OpenCode/Hermes harness) must do
      the same.

    ``now`` is injectable for deterministic tests; default is the wall clock.
    """
    now = now or datetime.now(timezone.utc)
    bound = dict(args)
    overrides: dict[str, Any] = {}
    unexpressible: dict[str, Any] = {}
    rejected: dict[str, Any] = {}
    f = slice.filters
    table = _BINDINGS.get(tool_name)
    if table is None:
        return bound, overrides

    def _set(arg: str, value: Any) -> None:
        if arg in bound and bound[arg] not in (None, "", 0, -1) and bound[arg] != value:
            overrides[arg] = bound[arg]
        bound[arg] = value

    for dim, key in (("hosts", "host"), ("host_ips", "host_ip"), ("event_ids", "event_id")):
        values = getattr(f, dim)
        if key not in table or not values:
            continue
        arg = table[key]
        v = _single(values, dim, unexpressible)
        if v is not None:
            _set(arg, v)
        elif bound.get(arg) not in (None, "", 0) and bound[arg] not in values:
            # Several values in the slice and the model asked for one outside
            # it. Leaving it would leak out of the slice; picking a slice value
            # for the model would be the harness investigating. Reject the
            # call instead: the wrapper returns the reason as the tool result
            # and the model re-issues with a member of the list.
            rejected[arg] = {
                "value": bound[arg],
                "reason": f"{bound[arg]!r} is outside the slice's {dim}: {values}",
            }

    if f.indices:
        if "index" in table:
            # ES index arguments take a comma list, so a multi-index slice binds whole.
            _set(table["index"], ",".join(f.indices))
        elif tool_name in _NATIVE_INDICES and not _NATIVE_INDICES[tool_name] & set(f.indices):
            unexpressible["indices"] = {
                "values": list(f.indices),
                "tool_reads": sorted(_NATIVE_INDICES[tool_name]),
                "reason": "tool reads a fixed index outside the slice's indices and takes no index argument",
            }

    if "time" in table:
        minutes = slice_lookback_minutes(slice, now)
        if minutes is not None:
            _set(table["time"], minutes)
        if f.time_end is not None:
            # The tools only take a lookback from now. The slice's leading edge
            # binds; the trailing edge is open to now, and the model's results
            # can include events after time_end. Not papered over.
            unexpressible["time_end"] = {
                "value": f.time_end.isoformat(),
                "reason": "tool takes timerange_minutes from now; an absolute end cannot be expressed",
            }

    if accepted_params is not None:
        unbindable = {k: bound[k] for k in list(bound) if k not in accepted_params and k not in args}
        for k in unbindable:
            del bound[k]
        if unbindable:
            overrides["_unbindable"] = unbindable

    if unexpressible:
        overrides["_unexpressible"] = unexpressible
    if rejected:
        overrides["_rejected"] = rejected
    return bound, overrides


class BoundMCPClient:
    """Proxy around ``MCPStdioClient`` that binds every ``call_tool`` to a slice.

    Same async-context / ``list_tools`` / ``call_tool`` surface as the client
    it wraps, so ``runner.run`` uses it unchanged via ``mcp_factory``. Each
    call's (name, model args, bound args, overrides) is appended to
    ``records`` in dispatch order; ``run_worker`` copies them onto the trace.
    """

    def __init__(self, server_cmd: list[str], slice: Slice, *, now: datetime | None = None,
                 inner: Any | None = None) -> None:
        self.slice = slice
        self.now = now
        self._inner = inner if inner is not None else MCPStdioClient(server_cmd)
        self._accepted: dict[str, set[str]] = {}
        self.records: list[dict[str, Any]] = []

    async def __aenter__(self) -> "BoundMCPClient":
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._inner.__aexit__(exc_type, exc, tb)

    async def list_tools(self) -> list[ToolSpec]:
        tools = await self._inner.list_tools()
        # Cache what each tool accepts so binding can drop (and record) an
        # argument the registered wrapper does not take.
        self._accepted = {
            t.name: set((t.input_schema or {}).get("properties", {}).keys()) for t in tools
        }
        return tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> str:
        bound, overrides = bind_slice(
            args, name, self.slice, now=self.now, accepted_params=self._accepted.get(name),
        )
        self.records.append({"name": name, "args": dict(args), "bound_args": bound, "overrides": overrides})
        if "_rejected" in overrides:
            reasons = "; ".join(r["reason"] for r in overrides["_rejected"].values())
            return f"Error: call refused by the slice binding — {reasons}. Stay inside your slice."
        return await self._inner.call_tool(name, bound)


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
        if f.time_end:
            lines.append(
                "  (the tools only take a lookback from now, so the window END is not "
                "enforced — results may include events after it; ignore those)"
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


def _attach_records(trace: Trace, records: list[dict[str, Any]]) -> None:
    """Copy the wrapper's per-call records onto the trace's ToolCalls.

    The in-process transports dispatch a turn's tool calls in list order, so
    the records line up positionally. A tool exception ends the run early and
    leaves the record list shorter than the call list; match by name and stop
    at the first mismatch instead of guessing.
    """
    calls = [tc for turn in trace.turns for tc in turn.tool_calls]
    for tc, rec in zip(calls, records):
        if tc.name != rec["name"]:
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
    now: datetime | None = None,
) -> tuple[Trace, WorkerReport | None]:
    """Run one slice as a worker. Returns the trace and the parsed report, or
    ``None`` for the report when the final answer did not parse — the parse
    error is then on ``trace.error`` so the dispatcher records it and moves on.

    ``max_turns`` is ``min(slice.turn_budget, max_turns_ceiling)``: the lead
    assigns, the harness caps.
    """
    if profile.tool_protocol == "anthropic-cli":
        # The claude subprocess calls the MCP server itself; nothing in this
        # process sees its tool calls, so the slice could not be enforced and
        # max_turns is ignored. Refusing beats returning an unscoped trace
        # labelled as a worker.
        raise ValueError(
            "run_worker cannot bind a slice on the anthropic-cli transport; "
            "binding would have to happen server-side"
        )

    max_turns = min(slice.turn_budget, max_turns_ceiling)
    wprofile = worker_profile(profile)
    question = _render_slice_for_question(slice, max_turns)
    client_holder: list[BoundMCPClient] = []

    def factory(cmd: list[str]) -> BoundMCPClient:
        client = BoundMCPClient(cmd, slice, now=now)
        client_holder.append(client)
        return client

    trace = await runner.run(
        wprofile,
        question,
        prompt_id=f"fan:d{depth}:{slice.id}",
        server_cmd=server_cmd,
        config_path=config_path,
        max_turns=max_turns,
        mcp_factory=factory,
        extra_prompt_context={
            "report_schema": render_report_schema_for_prompt(),
            "turn_budget": str(max_turns),
            "slice_id": slice.id,
            "sub_depth": str(depth + 1),
        },
    )
    if client_holder:
        _attach_records(trace, client_holder[0].records)

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
