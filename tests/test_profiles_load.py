"""Every profile YAML must load (valid YAML) and compose from a clean clone.

Guards D1 (claude-opus-5.yaml was invalid YAML) and D1b (the coaching/claude.md
file was gitignored, so Anthropic profiles failed to compose). A profile that
cannot load or compose is a silent run-killer — this test makes it loud.
"""
from pathlib import Path

import yaml

from blue_bench_mcp.profiles import load_profile
from blue_bench_mcp.prompts_compose import compose

REPO = Path(__file__).parent.parent
PROFILES = REPO / "blue_bench_mcp" / "profiles"

_CTX = {
    "tool_list": "- search_alerts(src_ip): search",
    "tool_count": "1",
    "tool_categories": "1",
    "workflows": "triage",
    "tool_schema_hint": "Use the native tool schema.",
    "tool_call_format": "```tool_call\n{...}\n```",
    "max_words": "200",
}


def test_every_profile_loads_and_composes():
    profiles = sorted(PROFILES.glob("*.yaml"))
    assert profiles, "no profiles found"
    for p in profiles:
        # D1: the file must be valid YAML.
        yaml.safe_load(p.read_text())
        # D1b: the profile must compose (its prompt_parts files must exist and
        # be tracked — a gitignored coaching/claude.md would raise here).
        profile = load_profile(p)
        out = compose(profile, _CTX)
        assert out.strip(), f"{p.name} composed to an empty prompt"
