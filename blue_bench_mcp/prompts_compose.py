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

    def _sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in context:
            missing.add(key)
            return m.group(0)
        return context[key]

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
        text = _PLACEHOLDER_RE.sub(_sub, text)
        parts.append(text.rstrip())

    # Coaching hints are profile-level (not a prompt_parts file). They are the
    # coached arm's actual intervention — append them so the coached/uncoached
    # A/B measures the hints, not just a guidelines-file swap. Run them through
    # the same HTML-comment strip + placeholder substitution as every other part
    # so a hint carrying a {placeholder} or an HTML comment behaves identically.
    if profile.coaching_hints:
        hint_lines = []
        for h in profile.coaching_hints:
            h = _HTML_COMMENT_RE.sub("", h)
            h = _PLACEHOLDER_RE.sub(_sub, h)
            hint_lines.append(f"- {h}")
        parts.append("## Coaching hints\n\n" + "\n".join(hint_lines))

    # Raise on missing placeholders AFTER the hints block, so a {bogus_key} in a
    # hint raises the same way it does in a prompt-part file (not leak silently).
    if missing:
        raise ValueError(f"missing prompt placeholders: {sorted(missing)}")

    return "\n\n".join(parts)
