"""Pure-function prompt composer — profile + context → assembled system prompt.

Reads markdown parts referenced by profile.prompt_parts, substitutes {placeholder}
values from the context dict, concatenates in SECTION_ORDER. Missing placeholders
raise ValueError with the list of missing keys — silent defaults hide misconfig.
"""
from __future__ import annotations

import re
from pathlib import Path

from blue_bench_mcp.profiles import ModelProfile

SECTION_ORDER = ("role", "site", "guidelines", "coaching")
PROMPTS_ROOT = Path(__file__).parent / "prompts"

_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z_0-9]*)\}")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def compose(
    profile: ModelProfile,
    context: dict[str, str],
    prompts_root: Path | None = None,
) -> str:
    root = prompts_root or PROMPTS_ROOT
    parts: list[str] = []
    missing: set[str] = set()

    for section in SECTION_ORDER:
        filename = profile.prompt_parts.get(section)
        if not filename:
            continue
        path = root / section / filename
        if not path.exists():
            raise FileNotFoundError(f"prompt part not found: {path}")
        text = path.read_text()
        # Strip HTML comments (used as source-file frontmatter) before substitution —
        # otherwise placeholders inside comments get substituted and leak to the model.
        text = _HTML_COMMENT_RE.sub("", text)

        def _sub(m: re.Match) -> str:
            key = m.group(1)
            if key not in context:
                missing.add(key)
                return m.group(0)
            return context[key]

        text = _PLACEHOLDER_RE.sub(_sub, text)
        parts.append(text.rstrip())

    if missing:
        raise ValueError(f"missing prompt placeholders: {sorted(missing)}")

    return "\n\n".join(parts)
