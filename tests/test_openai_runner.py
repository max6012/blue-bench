"""Unit tests for the OpenAI-native runner branch — no live API calls."""
from pathlib import Path

import pytest

from blue_bench_client.mcp_client import ToolSpec
from blue_bench_client.runner import _tool_specs_to_openai
from blue_bench_mcp.profiles import load_profile
from blue_bench_mcp.prompts_compose import compose

REPO = Path(__file__).parent.parent
PROFILES = REPO / "blue_bench_mcp" / "profiles"


def test_tool_specs_to_openai_function_wrapper():
    tools = [
        ToolSpec(
            name="search_alerts",
            description="Search alerts",
            input_schema={"type": "object", "properties": {"src_ip": {"type": "string"}}},
        )
    ]
    specs = _tool_specs_to_openai(tools)
    assert len(specs) == 1
    s = specs[0]
    # OpenAI format: `type: function` wrapper around a `function` object.
    assert s["type"] == "function"
    assert s["function"]["name"] == "search_alerts"
    assert s["function"]["description"] == "Search alerts"
    assert s["function"]["parameters"]["properties"]["src_ip"]["type"] == "string"


def test_tool_specs_to_openai_empty_schema():
    tools = [ToolSpec(name="list_evidence", description="List evidence", input_schema={})]
    specs = _tool_specs_to_openai(tools)
    assert specs[0]["function"]["parameters"] == {"type": "object", "properties": {}}


def test_profile_schema_accepts_openai_native():
    from blue_bench_mcp.profiles import ModelProfile
    p = ModelProfile.model_validate(
        {
            "name": "x",
            "model_id": "y",
            "tool_protocol": "openai-native",
            "prompt_style": "terse",
            "context_size": 100,
        }
    )
    assert p.tool_protocol == "openai-native"


def test_generic_openai_profile_uses_openai_native():
    from blue_bench_client.cloud_models import generic_openai_profile
    p = generic_openai_profile("qwen3.5:9b")
    assert p.tool_protocol == "openai-native"
    assert p.model_id == "qwen3.5:9b"
    assert p.name == "openai-qwen3.5-9b"
    assert p.coaching_hints  # coached by default


def test_generic_openai_profile_uncoached():
    from blue_bench_client.cloud_models import generic_openai_profile
    p = generic_openai_profile("qwen3.5:9b", coached=False)
    assert p.name == "openai-qwen3.5-9b-uncoached"
    assert p.coaching_hints == []
