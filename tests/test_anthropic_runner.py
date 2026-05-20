"""Unit tests for the Anthropic runner branch — no live API calls."""
from pathlib import Path

import pytest

from blue_bench_client.mcp_client import ToolSpec
from blue_bench_client.runner import _tool_specs_to_anthropic
from blue_bench_mcp.profiles import load_profile
from blue_bench_mcp.prompts_compose import compose

REPO = Path(__file__).parent.parent
PROFILES = REPO / "blue_bench_mcp" / "profiles"


def test_tool_specs_to_anthropic_flat_format():
    tools = [
        ToolSpec(
            name="search_alerts",
            description="Search alerts",
            input_schema={"type": "object", "properties": {"src_ip": {"type": "string"}}},
        )
    ]
    specs = _tool_specs_to_anthropic(tools)
    assert len(specs) == 1
    s = specs[0]
    # Anthropic format: flat top-level, no `type: function` wrapper.
    assert "type" not in s
    assert "function" not in s
    assert s["name"] == "search_alerts"
    assert s["description"] == "Search alerts"
    assert s["input_schema"]["properties"]["src_ip"]["type"] == "string"


def test_tool_specs_to_anthropic_empty_schema():
    tools = [ToolSpec(name="list_evidence", description="List evidence", input_schema={})]
    specs = _tool_specs_to_anthropic(tools)
    # Empty schema is replaced with an empty object schema so the API accepts it.
    assert specs[0]["input_schema"] == {"type": "object", "properties": {}}


def test_sonnet_profile_loads_and_composes():
    profile = load_profile(PROFILES / "claude-sonnet-4-6.yaml")
    assert profile.model_id == "claude-sonnet-4-6"
    assert profile.tool_protocol == "anthropic-native"
    assert profile.context_size == 200_000
    out = compose(
        profile,
        {
            "tool_list": "- search_alerts(src_ip): ...",
            "tool_count": "1",
            "tool_categories": "1",
            "workflows": "triage",
            "tool_schema_hint": "Use the native tool schema.",
        },
    )
    assert "Blue Team security analyst" in out
    assert "Claude coaching" in out
    assert "<!--" not in out


def test_opus_profile_loads():
    profile = load_profile(PROFILES / "claude-opus-4-7.yaml")
    assert profile.model_id == "claude-opus-4-7"
    assert profile.tool_protocol == "anthropic-native"


def test_profile_schema_accepts_anthropic_native():
    from blue_bench_mcp.profiles import ModelProfile
    p = ModelProfile.model_validate(
        {
            "name": "x",
            "model_id": "y",
            "tool_protocol": "anthropic-native",
            "prompt_style": "terse",
            "context_size": 100,
        }
    )
    assert p.tool_protocol == "anthropic-native"


def test_profile_schema_rejects_bogus_protocol():
    from blue_bench_mcp.profiles import ModelProfile
    with pytest.raises(Exception):
        ModelProfile.model_validate(
            {
                "name": "x",
                "model_id": "y",
                "tool_protocol": "made-up-protocol",
                "prompt_style": "terse",
                "context_size": 100,
            }
        )
