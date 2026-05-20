from pathlib import Path

import pytest

from blue_bench_mcp.profiles import ModelProfile, load_profile


VALID = {
    "name": "g3-4b",
    "model_id": "gemma3:4b",
    "tool_protocol": "text-embedded",
    "prompt_style": "terse",
    "context_size": 131072,
    "generation": {"temperature": 0.3, "top_p": 0.9},
    "coaching_hints": ["a"],
    "recommended_workflows": ["triage"],
    "prompt_parts": {"role": "blue_team_analyst.md"},
}


def test_validate_ok():
    p = ModelProfile.model_validate(VALID)
    assert p.tool_protocol == "text-embedded"
    assert p.context_size == 131072


def test_invalid_tool_protocol_rejected():
    bad = {**VALID, "tool_protocol": "banana"}
    with pytest.raises(Exception):
        ModelProfile.model_validate(bad)


def test_context_size_must_be_positive():
    bad = {**VALID, "context_size": 0}
    with pytest.raises(Exception):
        ModelProfile.model_validate(bad)


def test_yaml_loader(tmp_path: Path):
    import yaml
    f = tmp_path / "p.yaml"
    f.write_text(yaml.safe_dump(VALID))
    p = load_profile(f)
    assert p.name == "g3-4b"
    assert p.prompt_parts["role"] == "blue_team_analyst.md"
