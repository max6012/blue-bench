"""Tell the model when Elasticsearch answered a query from only some shards.

A search over several indices that fails on some of them is NOT an error in
Elasticsearch: the response is 200, carries the hits and aggregations from the
shards that worked, and reports the rest only in ``_shards.failed``. A tool that
does not read that field hands the model a partial count as a whole one -- how
``count_by_time host=<fqdn>`` over ``zeek-conn,windows-sysmon`` returned 2,099
instead of 4,117 with nothing to say half was missing.

Every ES call site passes its response through :func:`note_shards`; a server
middleware opens a per-call record before the tool runs and, when anything was
noted, appends one plain warning line to the tool result. The record is a
context variable, so concurrent calls do not see each other's failures.
"""
from __future__ import annotations

import contextvars
from typing import Any

_FAILURES: contextvars.ContextVar[list[dict[str, Any]] | None] = contextvars.ContextVar(
    "bb_shard_failures", default=None)

WARNING_PREFIX = "--- WARNING: incomplete result"
"""Opening of the line appended to a partial result. Pinned: traces are compared on it."""


def note_shards(data: Any, index: str) -> None:
    """Record a partial-shard response for the tool call in progress."""
    shards = (data or {}).get("_shards") if isinstance(data, dict) else None
    if not isinstance(shards, dict) or not shards.get("failed"):
        return
    reasons = sorted({
        str(((f.get("reason") or {}).get("reason")) or (f.get("reason") or {}).get("type") or "unknown")
        for f in shards.get("failures") or [] if isinstance(f, dict)
    })
    failed_indices = sorted({str(f.get("index")) for f in shards.get("failures") or []
                             if isinstance(f, dict) and f.get("index")})
    rec = {"index": index, "failed": int(shards.get("failed") or 0),
           "total": int(shards.get("total") or 0), "failed_indices": failed_indices,
           "reasons": reasons}
    bucket = _FAILURES.get()
    if bucket is not None:
        bucket.append(rec)


def warning_text(failures: list[dict[str, Any]]) -> str:
    failed = sum(f["failed"] for f in failures)
    total = sum(f["total"] for f in failures)
    where = sorted({i for f in failures for i in f["failed_indices"]}) or sorted({f["index"] for f in failures})
    reasons = sorted({r for f in failures for r in f["reasons"]})
    return (f"\n\n{WARNING_PREFIX}: Elasticsearch failed {failed} of {total} shards "
            f"({', '.join(where)}), so the counts and records above cover only the rest "
            f"and are too low. Cause: {'; '.join(reasons)[:300]}. ---")


def append_to_result(result: Any, text: str) -> Any:
    """Append ``text`` to a ``tools/call`` wire result, on both halves.

    ``MCPServer`` mirrors a string-returning tool into
    ``structuredContent['result']``; the ``anthropic-cli`` transport reads that
    copy and the SDK path concatenates text blocks. Patching one would leave the
    other transport reading a result without the addition.
    """
    if not isinstance(result, dict):
        return result
    content = result.get("content")
    if isinstance(content, list):
        for block in reversed(content):
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                block["text"] = block["text"] + text
                break
    structured = result.get("structuredContent")
    if isinstance(structured, dict) and isinstance(structured.get("result"), str):
        structured["result"] = structured["result"] + text
    return result


def text_result(ctx: Any, text: str) -> dict[str, Any]:
    """A complete ``tools/call`` result for a middleware that answers without
    running the tool (a slice refusal, an exhausted budget).

    The SDK only builds the envelope for results that come back through
    ``call_next``; a short-circuiting middleware "owns its result, envelope
    included" (mcp.server.runner). Protocol revision 2026-07-28 requires
    ``resultType`` on every result: without it the claude CLI rejects the
    whole result as malformed, and the model reads a schema error instead of
    the refusal (Opus 5.5 ceiling run, 2026-09-28). The Python SDK client
    tolerates its absence, which is why only the CLI transport showed it.
    """
    out: dict[str, Any] = {"content": [{"type": "text", "text": text}],
                           "isError": False,
                           "structuredContent": {"result": text}}
    try:
        from mcp_types.version import MODERN_PROTOCOL_VERSIONS
    except ImportError:  # older SDK: no 2026-era wire, nothing to add
        return out
    if getattr(ctx, "protocol_version", None) in MODERN_PROTOCOL_VERSIONS:
        out["resultType"] = "complete"
    return out


class ShardWarningMiddleware:
    """Open a per-call failure record; append the warning when anything failed."""

    def __init__(self, server) -> None:
        server.middleware.append(self)

    async def __call__(self, ctx, call_next):
        if ctx.method != "tools/call":
            return await call_next(ctx)
        token = _FAILURES.set([])
        try:
            result = await call_next(ctx)
            failures = _FAILURES.get() or []
        finally:
            _FAILURES.reset(token)
        return append_to_result(result, warning_text(failures)) if failures else result
