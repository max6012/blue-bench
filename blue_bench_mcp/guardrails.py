"""Shared tool guardrails — truncation + filesystem-path validation + network-target validation.

All tool classes apply these consistently (see docs/internal/TOOL_CLASS_PATTERN.md).
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

TRUNC_MARKER = "\n... [truncated] ...\n"


def truncate_results(text: str, max_chars: int) -> str:
    """Truncate long tool output with head+tail preservation + marker."""
    if len(text) <= max_chars:
        return text
    keep = max(1, (max_chars - len(TRUNC_MARKER)) // 2)
    return text[:keep] + TRUNC_MARKER + text[-keep:]


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
