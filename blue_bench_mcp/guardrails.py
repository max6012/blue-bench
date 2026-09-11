"""Shared tool guardrails — truncation + filesystem-path validation + network-target validation.

All tool classes apply these consistently (see docs/internal/TOOL_CLASS_PATTERN.md).
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

TRUNC_MARKER = "\n... [truncated] ...\n"


def truncate_results(text: str, max_chars: int) -> str:
    """Truncate long FREE-TEXT tool output with head+tail preservation + marker.

    Do NOT use this on serialized JSON. Splicing head + marker + tail through
    the middle of a JSON document produces a string that is not parseable: the
    head stops mid-object, the marker is not JSON, and the tail resumes
    mid-object. It looks fine at both ends, which is why issue #41 survived so
    long -- the output still began ``[{"Provider": ...`` and ended ``}\n]``.

    For JSON payloads use :func:`json_dump_within`, which drops whole records
    instead of slicing characters.
    """
    if len(text) <= max_chars:
        return text
    keep = max(1, (max_chars - len(TRUNC_MARKER)) // 2)
    return text[:keep] + TRUNC_MARKER + text[-keep:]


def _dump_keeping(payload: Any, keep: int, shrink: tuple[str, ...] | None,
                  indent: int, default: Any) -> str:
    if shrink is None:
        return json.dumps(payload[:keep], indent=indent, default=default)
    out = dict(payload)
    for k in shrink:
        v = payload.get(k)
        if isinstance(v, list):
            out[k] = v[:keep]
    return json.dumps(out, indent=indent, default=default)


def json_dump_within(
    payload: Any,
    max_chars: int,
    *,
    shrink: tuple[str, ...] | None = None,
    indent: int = 2,
    default: Any = str,
) -> tuple[str, int]:
    """Serialize ``payload`` into at most ``max_chars``, ALWAYS as valid JSON.

    Truncates by dropping whole records rather than by slicing the serialized
    string, so the result always parses. Returns ``(json_text, dropped)`` where
    ``dropped`` is how many records were left out (0 when everything fit).

    ``payload`` is either a list, or a dict whose list-valued keys named in
    ``shrink`` carry the bulk (``get_process_tree`` returns
    ``self_and_parent``/``children``; ``detect_beaconing`` returns
    ``candidates`` beside a coverage block that must survive intact).

    The same record count is kept from every shrinkable list, found by bisection
    -- length is monotone in that count, so bisection is exact and costs
    O(log n) serializations rather than one per dropped record.
    """
    full = json.dumps(payload, indent=indent, default=default)
    if len(full) <= max_chars:
        return full, 0

    if shrink is None:
        total = len(payload)
    else:
        total = max((len(v) for k in shrink
                     if isinstance(v := payload.get(k), list)), default=0)

    lo, hi = 0, total
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(_dump_keeping(payload, mid, shrink, indent, default)) <= max_chars:
            lo = mid
        else:
            hi = mid - 1

    text = _dump_keeping(payload, lo, shrink, indent, default)
    if len(text) > max_chars:
        # Even zero records overflows -- the non-shrinkable part alone is too
        # big. Emit a valid JSON object saying so rather than a corrupt payload:
        # a model can act on this, and it cannot act on broken JSON.
        text = json.dumps(
            {"error": "result too large to serialize within the configured limit",
             "max_result_chars": max_chars,
             "hint": "narrow the query (fewer fields, shorter timerange, add filters)"},
            indent=indent,
        )
    if shrink is None:
        dropped = total - lo
    else:
        # Sum the drops across EVERY shrinkable list, not `total - lo`. `total`
        # is the LONGEST list, so a payload with two 40-record lists cut to 8
        # each omits 64 records while `total - lo` reports 32. The footer prints
        # this number, so the arithmetic has to be the real total.
        dropped = sum(max(0, len(v) - lo) for k in shrink
                      if isinstance(v := payload.get(k), list))
    return text, dropped


def truncate_result_list(items: list, max_results: int) -> tuple[list, bool]:
    """Truncate a list of result records. Returns (items, was_truncated)."""
    if len(items) <= max_results:
        return items, False
    return items[:max_results], True


def validate_path_under(path: Path | str, root: Path | str) -> Path:
    """Resolve path and assert it's inside root. Raises ValueError on traversal."""
    p = Path(path).resolve()
    r = Path(root).resolve()
    if not p.is_relative_to(r):
        raise ValueError(f"path {p} is not under root {r}")
    return p


def validate_target_in_range(target: str, allowed_ranges: list[str]) -> bool:
    """Check whether a target IP or CIDR is a subnet of any allowed range.

    Returns False for hostnames (safer default — callers requiring hostname
    support should resolve first).
    """
    try:
        target_net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for allowed in allowed_ranges:
        try:
            allowed_net = ipaddress.ip_network(allowed, strict=False)
        except ValueError:
            continue
        if target_net.subnet_of(allowed_net):
            return True
    return False
