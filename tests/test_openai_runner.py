"""Unit tests for the OpenAI-native runner branch — no live API calls.

Covers the schema converter, the generic profile, and (via a stub client) the
``_run_openai`` loop itself — the latter guards the B3 regression where
``function.arguments`` (a JSON *string* on the OpenAI wire protocol) was passed
to ``dict()`` and crashed the loop on the first tool call.
"""
import asyncio

from blue_bench_client import _openai
from blue_bench_client.mcp_client import ToolSpec
from blue_bench_client.runner import _openai_args, _run_openai, _tool_specs_to_openai
from blue_bench_client.trace import Trace
from blue_bench_mcp.profiles import ModelProfile


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


# ── B3 regression: _run_openai must parse JSON-string arguments ───────────────

def _profile() -> ModelProfile:
    return ModelProfile.model_validate(
        {
            "name": "x",
            "model_id": "test-model",
            "tool_protocol": "openai-native",
            "prompt_style": "terse",
            "context_size": 100,
        }
    )


class _FakeFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _FakeToolCall:
    def __init__(self, id, name, arguments):
        self.id = id
        self.type = "function"
        self.function = _FakeFunction(name, arguments)


class _FakeMessage:
    def __init__(self, content, tool_calls):
        self.content = content
        self.tool_calls = tool_calls


class _FakeChoice:
    def __init__(self, message):
        self.message = message


class _FakeResp:
    def __init__(self, choices):
        self.choices = choices


class _FakeCompletions:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class _FakeClient:
    def __init__(self, responses):
        self.chat = type("Chat", (), {"completions": _FakeCompletions(responses)})()


class _FakeMCP:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        return f"result-for-{name}"


def _trace() -> Trace:
    return Trace(
        prompt_id="t",
        profile_name="x",
        model_id="test-model",
        tool_protocol="openai-native",
        question="q",
        composed_system_prompt="sys",
        tools_available=["search_alerts"],
    )


def test_openai_args_parses_json_string():
    assert _openai_args('{"src_ip": "10.0.0.5"}') == {"src_ip": "10.0.0.5"}
    assert _openai_args("{}") == {}
    assert _openai_args(None) == {}
    assert _openai_args("") == {}
    # A malformed string must not crash the loop.
    assert _openai_args("not json") == {}
    # A non-object JSON value is not a valid tool-arg mapping.
    assert _openai_args("[1,2]") == {}
    # A non-string input (dict) must not raise TypeError.
    assert _openai_args({"src_ip": "10.0.0.5"}) == {"src_ip": "10.0.0.5"}


def test_run_openai_dispatches_tool_call_and_returns_answer(monkeypatch):
    # First response: a tool call with arguments as a JSON string (the wire
    # protocol shape that previously crashed the loop). Second: final answer.
    responses = [
        _FakeResp(
            [
                _FakeChoice(
                    _FakeMessage(
                        content=None,
                        tool_calls=[_FakeToolCall("call_1", "search_alerts", '{"src_ip": "10.0.0.5"}')],
                    )
                )
            ]
        ),
        _FakeResp([_FakeChoice(_FakeMessage(content="found it", tool_calls=[]))]),
    ]
    client = _FakeClient(responses)
    monkeypatch.setattr(_openai, "make_async_client", lambda: client)

    mcp = _FakeMCP()
    trace = _trace()
    tools = [ToolSpec(name="search_alerts", description="Search", input_schema={})]

    asyncio.run(_run_openai(_profile(), "sys", "q", tools, mcp, 10, trace))

    assert trace.error is None
    assert trace.final_answer == "found it"
    # The tool call was parsed and dispatched with the decoded args.
    assert mcp.calls == [("search_alerts", {"src_ip": "10.0.0.5"})]
    # The assistant turn recorded the parsed tool call.
    assert trace.turns[0].tool_calls[0].name == "search_alerts"
    assert trace.turns[0].tool_calls[0].args == {"src_ip": "10.0.0.5"}
    # The tool result was fed back as a role=tool message with tool_call_id.
    tool_msgs = [c for c in client.chat.completions.calls[1]["messages"] if c["role"] == "tool"]
    assert tool_msgs[0]["tool_call_id"] == "call_1"
    assert tool_msgs[0]["content"] == "result-for-search_alerts"


def test_run_openai_no_tool_calls_returns_content(monkeypatch):
    responses = [_FakeResp([_FakeChoice(_FakeMessage(content="direct answer", tool_calls=[]))])]
    client = _FakeClient(responses)
    monkeypatch.setattr(_openai, "make_async_client", lambda: client)

    trace = _trace()
    asyncio.run(_run_openai(_profile(), "sys", "q", [], _FakeMCP(), 10, trace))
    assert trace.final_answer == "direct answer"
    assert trace.turns_used == 1
