from pathlib import Path

import pytest

from blue_bench_mcp.profiles import load_profile
from blue_bench_mcp.prompts_compose import compose

REPO = Path(__file__).parent.parent
PROFILES = REPO / "blue_bench_mcp" / "profiles"

CTX_FULL = {
    "tool_list": "- evidence_list(): list files\n- evidence_hash(filename): compute hash",
    "tool_count": "2",
    "tool_categories": "1",
    "workflows": "triage, forensics-lite",
    "tool_call_format": '```tool_call\n{"name": "X", "parameters": {}}\n```',
    "tool_schema_hint": "Call tools via the native schema; parameters follow input_schema.",
    "max_words": "200",
}


@pytest.fixture
def g4_profile():
    return load_profile(PROFILES / "gemma4-e4b.yaml")


@pytest.fixture
def g3_profile():
    return load_profile(PROFILES / "gemma3-tools-12b.yaml")


def test_compose_g4_happy(g4_profile):
    out = compose(g4_profile, CTX_FULL)
    assert "Blue Team security analyst" in out
    assert "evidence_list" in out
    assert "triage, forensics-lite" in out
    assert "Gemma 4" in out
    # Ordering — role, guidelines, coaching.
    assert out.index("Blue Team security analyst") < out.index("Investigation Guidelines")
    assert out.index("Investigation Guidelines") < out.index("Gemma 4")


def test_compose_missing_placeholder_raises(g4_profile):
    with pytest.raises(ValueError) as exc:
        compose(g4_profile, {"tool_list": "x"})
    msg = str(exc.value)
    # At minimum one of the declared placeholders should be missing.
    assert any(
        k in msg
        for k in ("workflows", "tool_schema_hint", "tool_count", "tool_categories")
    )


def test_compose_swap_produces_diff(g4_profile, g3_profile):
    g4 = compose(g4_profile, CTX_FULL)
    g3 = compose(g3_profile, CTX_FULL)
    assert g4 != g3
    assert "Gemma 4" in g4
    assert "Gemma 3 Tools" in g3 or "Gemma 3" in g3
    # Both must include the investigation protocol section.
    assert "Investigation Guidelines" in g4
    assert "Investigation Guidelines" in g3
    # No raw HTML comments.
    assert "<!--" not in g4
    assert "<!--" not in g3


def test_compose_includes_site_context(g4_profile):
    # After the adaptability refactor, env-specifics live in prompts/site/,
    # not hardcoded into role/ or coaching/. The site section is authoritative.
    out = compose(g4_profile, CTX_FULL)
    assert "Site Context" in out
    # The default site doc documents the reference deployment's data sources.
    assert "Suricata" in out
    assert "Wazuh" in out
    assert "Zeek" in out
    assert "severity" in out


def test_compose_includes_investigation_guidelines(g4_profile):
    out = compose(g4_profile, CTX_FULL)
    # Abstract guidelines — no tool-specific names. Look for general discipline.
    assert "aggregation" in out.lower()
    assert "pivot" in out.lower()
    assert "stop" in out.lower()
    assert "Cite specific values" in out or "cite specific" in out.lower()


def test_compose_g3_includes_tool_call_format(g3_profile):
    out = compose(g3_profile, CTX_FULL)
    assert "tool_call" in out
    assert "MUST emit" in out or "must emit" in out.lower()
