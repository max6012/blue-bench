#!/usr/bin/env python3
"""Emit blue_bench_frontend/profiles.json from blue_bench_mcp/profiles/*.yaml.

Static manifest consumed by the browser UI. Includes each profile's metadata
plus a composed system-prompt template that still carries `{tool_list}`,
`{tool_count}`, `{tool_categories}`, `{workflows}`, `{tool_call_format}`,
`{tool_schema_hint}`, and `{max_words}` placeholders. The browser substitutes
these at run time from the live MCP `tools/list` response — the same approach
the Python runner uses, just split across a precompute step + a thin runtime
substitution so the UI needs no Python.

Run:
    python scripts/emit_profiles_manifest.py

Output: blue_bench_frontend/profiles.json (sorted by profile name).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from blue_bench_mcp.profiles import load_profile  # noqa: E402
from blue_bench_mcp.prompts_compose import (  # noqa: E402
    PROMPTS_ROOT,
    SECTION_ORDER,
    _HTML_COMMENT_RE,
)

PROFILES_DIR = REPO / "blue_bench_mcp" / "profiles"
OUTPUT = REPO / "blue_bench_frontend" / "profiles.json"


def _compose_template(profile) -> str:
    """Like prompts_compose.compose(), but leaves {placeholders} intact."""
    parts: list[str] = []
    for section in SECTION_ORDER:
        filename = profile.prompt_parts.get(section)
        if not filename:
            continue
        path = PROMPTS_ROOT / section / filename
        if not path.exists():
            # Missing coaching file is soft — frontier profiles ship without one.
            print(
                f"  note: prompt part missing, skipping: {section}/{filename}",
                file=sys.stderr,
            )
            continue
        text = _HTML_COMMENT_RE.sub("", path.read_text()).rstrip()
        parts.append(text)
    return "\n\n".join(parts)


def main() -> int:
    yaml_paths = sorted(PROFILES_DIR.glob("*.yaml"))
    if not yaml_paths:
        print(f"no profiles found under {PROFILES_DIR}", file=sys.stderr)
        return 1

    entries = []
    for p in yaml_paths:
        prof = load_profile(p)
        entries.append(
            {
                "name": prof.name,
                "model_id": prof.model_id,
                "tool_protocol": prof.tool_protocol,
                "prompt_style": prof.prompt_style,
                "context_size": prof.context_size,
                "generation": prof.generation.model_dump(exclude_none=True),
                "recommended_workflows": prof.recommended_workflows,
                "coaching_hints": prof.coaching_hints,
                "system_prompt_template": _compose_template(prof),
            }
        )

    manifest = {"version": 1, "profiles": entries}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {OUTPUT} ({len(entries)} profile(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
