"""Slice binding — the fan-out harness's hard constraint, enforced in the server.

A fan-out WORKER investigates one slice of the corpus (host × index × absolute
time band × event type). The slice is a HARD constraint: whatever the model
asks for, the slice's filters are merged into the call before it runs, and
both the model's arguments and the bound ones are recorded so the judge scores
the model on its own choices (tool, event type, command-line filter, pivots)
and never on fields the harness set.

The rules live here, server-side, rather than in the reference client, because
not every harness goes through our client. The ``anthropic-cli`` transport (the
Opus-5 frontier ceiling profile) spawns ``claude``, which talks to this server
directly; OpenCode and Hermes do the same. A client-side proxy binds the one
harness it wraps and silently leaves the others unscoped. A server started with
``--slice`` binds all of them.

Binding is honest about what the tool surface can express, and the surface
differs per tool — so every decision here reads the tool's own input schema
rather than a constant:

* ``since`` / ``until`` accepted (the seven query tools): the slice's absolute
  band binds whole, both edges.
* only ``timerange_minutes``: the leading edge binds as a lookback from now and
  the trailing edge is recorded under ``overrides['_unexpressible']`` — the
  results can include events after the slice's end.
* neither: the time dimension is recorded as unexpressible.

The same rule governs ``host_ip``. ``search_alerts`` and ``get_connections``
take it and bind it whole: it is an OR over both ends of the connection (src OR
dest, ``id.orig_h`` OR ``id.resp_h``), which is what a slice's host means.
Binding to ``src_ip`` and ``dest_ip`` instead would AND them and match nothing
but self-loops — a near-empty result the model reads as "this host is clean" —
so a tool that does not take ``host_ip`` does not get the slice host under
another name: ``detect_beaconing`` is the one such tool left (it ranks
(src,dest) pairs and has no either-end filter at all), and its slice host is
recorded as ``_unbindable`` rather than guessed at.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from blue_bench_client.fanout.schema import Slice
from blue_bench_mcp.shard_check import append_to_result

# Which slice dimension maps to which argument, per tool. A tool absent here
# (evidence, nmap, sigma, wazuh, get_agent_alerts) is passed through untouched —
# it has no argument a slice constrains and nothing about it a slice narrows.
# Whether the named argument is actually accepted is decided against the tool's
# input schema, not here: this table says what WOULD bind, the schema says what
# DOES. An entry naming an argument the tool does not take is deliberate, not a
# mistake — it is how a dimension the tool cannot express reaches
# ``_unbindable`` instead of vanishing (``detect_beaconing``'s host_ip and
# ``list_endpoints``'s hostname are both there for that reason).
#
# Keys are slice-filter field names; values are the tool's argument names.
_BINDINGS: dict[str, dict[str, str]] = {
    "get_process_events": {"hosts": "host", "event_ids": "event_id"},
    "get_process_tree": {"hosts": "host"},
    "search_auth_events": {"hosts": "host", "event_ids": "event_id"},
    # host and host_ip are ORed inside the tool (one host, two spellings), so
    # binding both is safe here where it is not for src_ip AND dest_ip.
    "count_by_field": {"hosts": "host", "host_ips": "host_ip", "indices": "index"},
    "count_by_time": {"hosts": "host", "host_ips": "host_ip", "event_ids": "event_id", "indices": "index"},
    "get_connections": {"host_ips": "host_ip"},
    "search_alerts": {"host_ips": "host_ip"},
    "detect_beaconing": {"host_ips": "host_ip"},
    # The two OpenEDR tools. Their backend is a canned mock, not the corpus, so
    # nothing they return is slice data in the first place — but the worker
    # surface offers them, so they bind like everything else rather than being
    # the one pair of tools that walks out of the slice with no record.
    # get_detections takes a hostname and a lookback: the slice's hosts bind,
    # its leading time edge binds as minutes-ago and its trailing edge lands in
    # _unexpressible (the detect_beaconing tier). list_endpoints takes only
    # status — it enumerates the whole estate whatever the slice says, so its
    # host dimension is recorded _unbindable and its time band _unexpressible.
    "get_detections": {"hosts": "hostname"},
    "list_endpoints": {"hosts": "hostname"},
    # The OT asset inventory. Both halves of a slice's host scope bind, and
    # ANDing them is safe here where it is not for src_ip/dest_ip: name and ip
    # are two fields of ONE inventory record, so a slice whose hosts and
    # host_ips describe the same device matches that device's record. (The
    # resolver fills the missing half from this same index, so the two are
    # consistent by construction.) `name` already takes a short label or an
    # FQDN. The inventory carries no @timestamp, so the slice's band lands in
    # _unexpressible['time_window'] like list_endpoints.
    "list_assets": {"hosts": "name", "host_ips": "ip"},
}

# The indices each fixed-index tool reads (repo config defaults). A tool that
# takes no ``index`` argument cannot be bound to a slice's indices; when its
# native index is outside the slice this is recorded, not rejected — the worker
# prompt tells the model to pivot host<->network, and that crosses indices by
# construction. The lead has to know an index-scoped slice and a pivot
# instruction do not compose.
_NATIVE_INDICES: dict[str, set[str]] = {
    "get_process_events": {"windows-sysmon"},
    "get_process_tree": {"windows-sysmon"},
    "search_auth_events": {"windows-security", "linux-syslog"},
    "get_connections": {"zeek-conn", "ot-conn"},
    "search_alerts": {"logstash-suricata-alerts", "wazuh-alerts", "zeek-conn"},
    "detect_beaconing": {"zeek-conn"},
    "list_assets": {"ot-assets"},
}

BUDGET_PREFIX = "Error: tool budget exhausted"
"""Opening of the tool result every call past the slice's budget gets."""


def budget_text(slice_id: str, budget: int) -> str:
    return (f"{BUDGET_PREFIX} for slice {slice_id}: this slice allows {budget} tool calls "
            "and all of them are used. No further tool call will run. Write your final "
            "report now, from what you have already seen.")


REFUSAL_PREFIX = "Error: call refused by the slice binding"
"""Opening of the tool result a rejected call gets. Pinned: traces from
different runs are compared on it."""

# Values that count as "the model did not set this argument". The registered
# signatures use "" / 0 / -1 as their no-filter defaults, so a bound value
# replacing one of those is not an override of a model choice.
_UNSET = (None, "", 0, -1)


def _accepted(tool_input_schema: dict[str, Any] | None) -> set[str]:
    """The argument names the registered tool takes, from its JSON Schema."""
    return set(((tool_input_schema or {}).get("properties") or {}).keys())


def _iso_z(dt: datetime) -> str:
    """One slice bound in the form the tools document (ISO-8601 UTC, ``Z``)."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# Argument names that carry a value of the given slice dimension, as a name
# pattern applied to the tool's own schema. ``host_ips`` reaches host_ip, src_ip
# and dest_ip; ``hosts`` reaches host and hostname. Patterns rather than a fixed
# list because the surface moves: a wrapper that starts exposing a new address
# argument is covered the day it appears, not the day someone remembers to add
# it here. ``event_ids`` has no pattern — its values are integers and a name
# sweep over integer arguments would catch counts and ports.
_DIMENSION_ARG_PATTERNS: dict[str, re.Pattern[str]] = {
    "hosts": re.compile(r"(?:^|_)hosts?(?:name)?$"),
    "host_ips": re.compile(r"(?:^|_)ips?$"),
}


def _carrying_args(dim: str, mapped: str, tool_input_schema: dict[str, Any] | None) -> list[str]:
    """Every argument of this tool that could carry a value of ``dim``.

    The out-of-list refusal runs on all of them, not only the one the slice
    binds to. A two-IP slice cannot bind ``host_ip``, and checking ``host_ip``
    alone lets the same model reach the same out-of-slice traffic by passing
    ``src_ip`` — the slice would hold on the argument nobody used.

    Derived from the schema's own property names and types: ``top_n_hosts``
    matches the host name pattern but is an integer count, so the type check is
    what keeps it out. The mapped argument is always included, so a caller that
    passes no schema still gets the narrow check it had before.
    """
    args = {mapped}
    pattern = _DIMENSION_ARG_PATTERNS.get(dim)
    props = ((tool_input_schema or {}).get("properties") or {}) if pattern else {}
    for name, spec in props.items():
        # An untyped property (hand-written schemas in tests) is taken at its
        # name; an explicitly non-string one never carries a host or an address.
        if pattern.search(name) and (spec or {}).get("type", "string") == "string":
            args.add(name)
    return sorted(args)


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


def bind_args(
    tool_name: str,
    args: dict[str, Any],
    slice: Slice,
    tool_input_schema: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Merge the slice into one tool call. Pure: returns (bound_args, overrides).

    ``bound_args`` is what goes to the tool. ``overrides`` records every
    model-supplied value the slice replaced (``{arg: model_value}``), plus three
    audit keys when they apply:

    - ``_unexpressible``: slice constraints the tool interface cannot state (a
      time band against a tool that only takes a lookback; a multi-value
      host/event-id list against an exact-match argument; a fixed-index tool
      outside the slice's indices). The call is NOT narrowed to compensate;
      the dispatcher and judge read this to know the slice was open there.
    - ``_unbindable``: arguments this slice would bind that the registered tool
      does not accept. Dropped so the call still succeeds; recorded so nobody
      believes the slice held.
    - ``_rejected``: the model asked for a value outside a multi-value slice
      list. CONTRACT: ``bound_args`` still carries that value — a caller that
      sends it without first checking ``overrides`` for ``_rejected`` sends an
      out-of-slice query. :class:`SliceBindingMiddleware` checks and returns the
      reason to the model as the tool result instead of running the tool; any
      other consumer of ``bind_args`` must do the same.

    ``now`` is injectable for deterministic tests; it is only read on the
    lookback fallback path, where the leading edge has to be expressed as
    minutes-ago.
    """
    bound = dict(args)
    overrides: dict[str, Any] = {}
    unexpressible: dict[str, Any] = {}
    rejected: dict[str, Any] = {}
    f = slice.filters
    table = _BINDINGS.get(tool_name)
    if table is None:
        return bound, overrides
    accepted = _accepted(tool_input_schema)

    def _set(arg: str, value: Any) -> None:
        if arg in bound and bound[arg] not in _UNSET and bound[arg] != value:
            overrides[arg] = bound[arg]
        bound[arg] = value

    for dim in ("hosts", "host_ips", "event_ids"):
        values = getattr(f, dim)
        if dim not in table or not values:
            continue
        arg = table[dim]
        v = _single(values, dim, unexpressible)
        if v is not None:
            _set(arg, v)
            continue
        # Several values in the slice and the model asked for one outside it.
        # Leaving it would leak out of the slice; picking a slice value for the
        # model would be the harness investigating. Reject the call instead: the
        # caller returns the reason as the tool result and the model re-issues
        # with a member of the list. Checked on every argument that can carry
        # this dimension, not just the one it binds to — see _carrying_args.
        for carrier in _carrying_args(dim, arg, tool_input_schema):
            asked = bound.get(carrier)
            if asked not in _UNSET and asked not in values:
                rejected[carrier] = {
                    "value": asked,
                    "reason": f"{carrier}={asked!r} is outside the slice's {dim}: {values}",
                }

    if f.indices:
        if "indices" in table:
            # ES index arguments take a comma list, so a multi-index slice binds whole.
            _set(table["indices"], ",".join(f.indices))
        elif tool_name in _NATIVE_INDICES and not _NATIVE_INDICES[tool_name] & set(f.indices):
            unexpressible["indices"] = {
                "values": list(f.indices),
                "tool_reads": sorted(_NATIVE_INDICES[tool_name]),
                "reason": "tool reads a fixed index outside the slice's indices and takes no index argument",
            }

    if f.time_start is not None or f.time_end is not None:
        _bind_time(f, bound, accepted, _set, unexpressible, now)

    if tool_input_schema is not None:
        unbindable = {k: bound[k] for k in list(bound) if k not in accepted and k not in args}
        for k in unbindable:
            del bound[k]
        if unbindable:
            overrides["_unbindable"] = unbindable

    if unexpressible:
        overrides["_unexpressible"] = unexpressible
    if rejected:
        overrides["_rejected"] = rejected
    return bound, overrides


def _bind_time(f, bound, accepted, _set, unexpressible, now) -> None:
    """Bind the slice's absolute time band, the best way this tool allows.

    Three tiers, in order of how much of the band survives. The middle tier is
    why ``_unexpressible['time_end']`` still exists: ``detect_beaconing`` and
    ``get_detections`` take a lookback and nothing else, so a slice bound to a
    two-day band gets its leading edge only and its results run to now. The
    bottom tier is ``list_endpoints``, which takes no time argument at all.
    """
    if "since" in accepted or "until" in accepted:
        if f.time_start is not None and "since" in accepted:
            _set("since", _iso_z(f.time_start))
        if f.time_end is not None and "until" in accepted:
            _set("until", _iso_z(f.time_end))
        # The tools ignore timerange_minutes once either absolute bound is set
        # (blue_bench_mcp.timerange), so a model-supplied lookback is dead
        # weight rather than a competing filter; left alone, not recorded.
        return

    if "timerange_minutes" in accepted:
        if f.time_start is not None:
            # Round up so the whole slice is inside the lookback.
            delta = (now or datetime.now(timezone.utc)) - f.time_start
            _set("timerange_minutes", max(1, -(-int(delta.total_seconds()) // 60)))
        if f.time_end is not None:
            unexpressible["time_end"] = {
                "value": f.time_end.isoformat(),
                "reason": "tool takes timerange_minutes from now; an absolute end cannot be expressed",
            }
        return

    unexpressible["time_window"] = {
        "start": f.time_start.isoformat() if f.time_start else None,
        "end": f.time_end.isoformat() if f.time_end else None,
        "reason": "tool takes no time argument; the slice's band cannot be expressed",
    }


def refusal_text(rejected: dict[str, Any], slice_id: str = "") -> str:
    """The tool result a rejected call gets — an explanation, not an exception.

    A raised error ends the CLI transport's turn with a stack trace the model
    cannot act on. A string tells it what to do instead: pass a member of the
    slice's list.

    It names the slice, the argument and value that were refused, and the values
    that would be accepted. A worker that cannot tell which of its arguments was
    the problem retries the same call with a different one and spends its whole
    turn budget guessing.
    """
    which = f" (slice {slice_id})" if slice_id else ""
    reasons = "; ".join(r["reason"] for r in rejected.values())
    return (f"{REFUSAL_PREFIX}{which} — {reasons}. Re-issue the call with one of "
            f"the listed values, or leave the argument out. Stay inside your slice.")


def slice_footer(slice_id: str, args: dict[str, Any], bound: dict[str, Any],
                 overrides: dict[str, Any]) -> str:
    """One line saying a slice is in force and what it bound.

    Same shape and honesty as :func:`blue_bench_mcp.guardrails.result_footer`:
    the model should be able to see from the result alone why its arguments
    are not the ones it passed. Without this a worker reads a result for
    ``host=dc-01`` that is really ``host=wkst-03`` and reasons from it.
    """
    set_by_slice = {k: v for k, v in bound.items() if args.get(k) != v}
    parts: list[str] = []
    if set_by_slice:
        parts.append("bound " + ", ".join(f"{k}={v}" for k, v in sorted(set_by_slice.items())))
    replaced = sorted(k for k in overrides if not k.startswith("_"))
    if replaced:
        parts.append("replaced your " + ", ".join(replaced))
    dropped = overrides.get("_unbindable")
    if dropped:
        parts.append("this tool cannot take " + ", ".join(sorted(dropped)))
    if not parts:
        parts.append("nothing on this tool to bind")
    return f"\n\n--- slice {slice_id} in force: {'; '.join(parts)}. ---"


class SliceBindingMiddleware:
    """Server middleware that binds every ``tools/call`` to one slice.

    Registered on ``MCPServer.middleware`` when the server is started with
    ``--slice``. Middleware is the right tier for this: it runs before params
    validation, so the arguments it records are exactly what the model sent —
    wrapping the tool functions instead would see pydantic's filled-in
    defaults and log ``timerange_minutes=240`` as a model choice the slice
    overrode, corrupting what the judge scores.

    Every call appends one JSONL line to ``log_path`` (opened, written,
    flushed and closed per line, so a killed server still leaves a complete
    log for the harness to read back).
    """

    def __init__(self, server: Any, slice: Slice, log_path: Path | None = None,
                 *, now: datetime | None = None) -> None:
        self.slice = slice
        self.log_path = Path(log_path) if log_path else None
        self.now = now
        self._server = server
        self._schemas: dict[str, dict[str, Any]] | None = None
        self.records: list[dict[str, Any]] = []
        self.calls = 0
        server.middleware.append(self)

    async def _schema_for(self, name: str) -> dict[str, Any] | None:
        """The tool's input schema, via the server's public tool listing.

        Cached on first use: the surface is fixed at registration, and
        ``list_tools`` rebuilds the models from the tool manager every call.
        """
        if self._schemas is None:
            self._schemas = {
                t.name: (t.input_schema or {}) for t in await self._server.list_tools()
            }
        return self._schemas.get(name)

    def _log(self, record: dict[str, Any]) -> None:
        self.records.append(record)
        if self.log_path is None:
            return
        line = json.dumps(record, default=str)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    async def __call__(self, ctx, call_next):
        if ctx.method != "tools/call":
            return await call_next(ctx)
        params = dict(ctx.params or {})
        name = str(params.get("name", ""))
        args = dict(params.get("arguments") or {})
        # The tool-call budget is enforced here, not in the client, for the
        # same reason the slice is: the anthropic-cli transport runs its own
        # tool loop and has no turn limit, so a client-side cap would leave the
        # frontier ceiling unbounded while open-weight workers stop at the
        # budget. Every call counts, refused ones included.
        self.calls += 1
        if self.calls > self.slice.turn_budget:
            self._log({"ts": datetime.now(timezone.utc).isoformat(), "tool": name,
                       "requested_args": args, "bound_args": {}, "overrides": {},
                       "rejected": True, "over_budget": True})
            text = budget_text(self.slice.id, self.slice.turn_budget)
            return {"content": [{"type": "text", "text": text}],
                    "isError": False,
                    "structuredContent": {"result": text}}
        schema = await self._schema_for(name)
        bound, overrides = bind_args(name, args, self.slice, schema, now=self.now)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": name,
            "requested_args": args,
            "bound_args": bound,
            "overrides": overrides,
            "rejected": "_rejected" in overrides,
        }
        self._log(record)

        if "_rejected" in overrides:
            # Short-circuit: the tool never runs. The envelope mirrors what the
            # SDK emits for a string-returning tool (probed, not guessed) so
            # every transport reads it the same way — the CLI transport reads
            # structuredContent, the SDK path reads the text block.
            text = refusal_text(overrides["_rejected"], self.slice.id)
            return {"content": [{"type": "text", "text": text}],
                    "isError": False,
                    "structuredContent": {"result": text}}

        result = await call_next(replace(ctx, params={**params, "arguments": bound}))
        return _append_footer(result, slice_footer(self.slice.id, args, bound, overrides))


def _append_footer(result: Any, footer: str) -> Any:
    """Append the slice line to both halves of a ``tools/call`` wire result."""
    return append_to_result(result, footer)


def load_slice(path: Path | str) -> Slice:
    """Read a serialized :class:`Slice` from disk (the ``--slice`` argument)."""
    return Slice.model_validate_json(Path(path).read_text(encoding="utf-8"))
