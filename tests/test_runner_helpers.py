"""Unit tests for runner's pure-function helpers — no Ollama, no MCP."""
import json

from blue_bench_client.mcp_client import ToolSpec
from blue_bench_client.runner import (
    TOOL_CALL_RE,
    _build_context,
    _format_tool_list,
    _tool_specs_to_ollama,
)
from blue_bench_client.trace import Trace, Turn, ToolCall
from blue_bench_mcp.profiles import load_profile

from pathlib import Path

REPO = Path(__file__).parent.parent
PROFILES = REPO / "blue_bench_mcp" / "profiles"


def test_format_tool_list():
    tools = [
        ToolSpec(name="evidence_list", description="List files", input_schema={"properties": {}}),
        ToolSpec(
            name="evidence_hash",
            description="Hash a file",
            input_schema={"properties": {"filename": {}, "algorithm": {}}},
        ),
    ]
    out = _format_tool_list(tools)
    assert "evidence_list" in out
    assert "evidence_hash(filename, algorithm)" in out
    assert "List files" in out


def test_build_context_g4():
    profile = load_profile(PROFILES / "gemma4-e4b.yaml")
    tools = [ToolSpec(name="evidence_list", description="List", input_schema={"properties": {}})]
    ctx = _build_context(profile, tools)
    assert "tool_list" in ctx
    assert "workflows" in ctx
    assert "tool_call_format" in ctx
    assert "triage" in ctx["workflows"]


def test_tool_call_regex_single():
    text = 'I will call the tool.\n<tool>evidence_list</tool><args>{}</args>\n'
    m = TOOL_CALL_RE.search(text)
    assert m is not None
    assert m.group(1) == "evidence_list"
    assert json.loads(m.group(2)) == {}


def test_tool_call_regex_with_args():
    text = '<tool>evidence_hash</tool><args>{"filename": "hello.txt", "algorithm": "sha256"}</args>'
    m = TOOL_CALL_RE.search(text)
    assert m is not None
    assert m.group(1) == "evidence_hash"
    args = json.loads(m.group(2))
    assert args["filename"] == "hello.txt"
    assert args["algorithm"] == "sha256"


def test_tool_call_regex_multiple():
    text = (
        "<tool>evidence_list</tool><args>{}</args>\n"
        "then\n"
        '<tool>evidence_hash</tool><args>{"filename": "a"}</args>'
    )
    matches = TOOL_CALL_RE.findall(text)
    assert len(matches) == 2
    assert matches[0][0] == "evidence_list"
    assert matches[1][0] == "evidence_hash"


def test_tool_call_regex_ignores_prose_braces():
    # Double-braces in examples (e.g., YARA syntax) must not be parsed as tool calls.
    text = "Here is YARA syntax: rule NAME {{ strings: ... }} — that's not a tool call."
    assert TOOL_CALL_RE.search(text) is None


def test_tool_call_regex_no_args_block():
    # Models may elide <args>{}</args> for no-arg tools. Regex must still match.
    text = "Okay, let's start by listing the evidence files.\n\n<tool>evidence_list</tool>\n"
    m = TOOL_CALL_RE.search(text)
    assert m is not None
    assert m.group(1) == "evidence_list"
    assert m.group(2) is None


def test_extract_json_tool_calls_single():
    from blue_bench_client.runner import _extract_json_tool_calls
    text = '{"name": "count_by_field", "parameters": {"field": "src_ip", "top_n": 10}}'
    calls = _extract_json_tool_calls(text)
    assert len(calls) == 1
    name, raw = calls[0]
    assert name == "count_by_field"
    obj = json.loads(raw)
    assert obj["parameters"]["field"] == "src_ip"


def test_extract_json_tool_calls_multiple():
    from blue_bench_client.runner import _extract_json_tool_calls
    text = (
        'first call:\n'
        '{"name": "list_evidence", "parameters": {}}\n'
        'and a second:\n'
        '{"name": "file_hash", "parameters": {"filename": "x.bin"}}\n'
    )
    calls = _extract_json_tool_calls(text)
    assert len(calls) == 2
    assert calls[0][0] == "list_evidence"
    assert calls[1][0] == "file_hash"


def test_extract_json_tool_calls_ignores_non_tool_json():
    from blue_bench_client.runner import _extract_json_tool_calls
    # JSON objects without a "name" key as first field are ignored.
    text = '{"foo": "bar"}\n{"name": "real_tool", "parameters": {}}'
    calls = _extract_json_tool_calls(text)
    assert len(calls) == 1
    assert calls[0][0] == "real_tool"


def test_extract_json_tool_calls_handles_nested_json():
    from blue_bench_client.runner import _extract_json_tool_calls
    # Nested objects in parameters must not confuse the bracket walker.
    text = (
        '{"name": "complex_tool", "parameters": '
        '{"filter": {"nested": {"deeper": "value"}}, "list": [1, 2]}}'
    )
    calls = _extract_json_tool_calls(text)
    assert len(calls) == 1
    obj = json.loads(calls[0][1])
    assert obj["parameters"]["filter"]["nested"]["deeper"] == "value"


def test_extract_json_tool_calls_handles_escaped_quotes():
    from blue_bench_client.runner import _extract_json_tool_calls
    text = r'{"name": "search", "parameters": {"q": "has \"quote\" inside"}}'
    calls = _extract_json_tool_calls(text)
    assert len(calls) == 1
    obj = json.loads(calls[0][1])
    assert "quote" in obj["parameters"]["q"]


def test_force_synthesis_prompt_shape():
    # Smoke check the forcing prompt literal — it's important for reproducibility
    # that the content stays stable across runs so behavioral comparisons across
    # iterations are controlled.
    from blue_bench_client.runner import FORCE_SYNTHESIS_PROMPT
    assert "specific findings" in FORCE_SYNTHESIS_PROMPT
    assert "not a plan" in FORCE_SYNTHESIS_PROMPT


def test_tool_specs_to_ollama():
    tools = [
        ToolSpec(
            name="evidence_hash",
            description="Hash",
            input_schema={"type": "object", "properties": {"filename": {"type": "string"}}},
        )
    ]
    specs = _tool_specs_to_ollama(tools)
    assert len(specs) == 1
    assert specs[0]["type"] == "function"
    assert specs[0]["function"]["name"] == "evidence_hash"
    assert "filename" in specs[0]["function"]["parameters"]["properties"]


def test_trace_roundtrip():
    t = Trace(
        prompt_id="smoke",
        profile_name="gemma4-e4b",
        model_id="gemma4:e4b",
        tool_protocol="text-embedded",
        question="q",
        composed_system_prompt="sys",
        tools_available=["evidence_list"],
    )
    t.turns.append(Turn(role="assistant", content="x", tool_calls=[ToolCall(name="evidence_list", args={})]))
    as_json = t.model_dump_json()
    restored = Trace.model_validate_json(as_json)
    assert restored.prompt_id == "smoke"
    assert len(restored.turns) == 1
    assert restored.turns[0].tool_calls[0].name == "evidence_list"
