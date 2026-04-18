"""Runner — profile + question → model loop with tool dispatch → trace.

Three paths keyed on profile.tool_protocol:
- "native": Ollama chat() with tools= schema, parses message.tool_calls
- "text-embedded": model emits <tool>name</tool><args>{...}</args> in content,
  parsed with regex, tool result injected as a user message
- "anthropic-native": Anthropic Messages API with tool_use / tool_result blocks

All three paths write the same Trace schema, so Phase 2 scoring is protocol-agnostic.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import ollama
from dotenv import load_dotenv

from blue_bench_client.mcp_client import MCPStdioClient, ToolSpec
from blue_bench_client.trace import ToolCall, Trace, Turn
from blue_bench_mcp.profiles import ModelProfile
from blue_bench_mcp.prompts_compose import compose

# Load .env if present — picks up ANTHROPIC_API_KEY + BLUE_BENCH_* secrets.
# Idempotent and harmless when .env is missing.
load_dotenv(Path(__file__).parent.parent / ".env", override=False)

TOOL_CALL_FORMAT = '```tool_call\\n{"name": "tool_name", "parameters": {"arg": "value"}}\\n```'
# Primary: markdown-fenced tool_call block (standard Blue-Bench convention for
# text-embedded tool calling; matches the Modelfile template of our Gemma-3-Tools
# variant and preserves continuity with the archived Phase 2 harness format).
#   ```tool_call
#   {"name": "X", "parameters": {...}}
#   ```
_TOOL_FENCE_RE = re.compile(
    r"```tool_(?:call|code)\s*\n(.*?)\n\s*```",
    re.DOTALL,
)
# Legacy: <tool>NAME</tool><args>{...}</args>. Still supported for any profile
# that explicitly coaches it. Not emitted by our current profiles.
TOOL_CALL_RE = re.compile(
    r"<tool>([\w_]+)</tool>(?:\s*<args>(\{.*?\})</args>)?",
    re.DOTALL,
)
# Fallback: bare JSON object that starts with "name" key, no surrounding tags.
_JSON_TOOL_RE = re.compile(r'\{\s*"name"\s*:\s*"([\w_]+)"', re.DOTALL)
DEFAULT_MAX_WORDS = "200"


def _fix_json_quirks(raw: str) -> str:
    """Minor repairs for common model quirks in emitted JSON: trailing commas."""
    # Remove trailing commas before } or ].
    return re.sub(r",\s*([}\]])", r"\1", raw.strip())


def _extract_json_tool_calls(text: str) -> list[tuple[str, str]]:
    """Find bare `{"name": ..., "parameters": {...}}` tool calls in text.

    Returns a list of (name, raw_json_str) tuples. Uses bracket-depth counting
    to correctly capture nested JSON objects.
    """
    out: list[tuple[str, str]] = []
    for m in _JSON_TOOL_RE.finditer(text):
        start = m.start()
        depth = 0
        i = start
        in_string = False
        escape = False
        while i < len(text):
            ch = text[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        out.append((m.group(1), text[start : i + 1]))
                        break
            i += 1
    return out


def _format_tool_list(tools: list[ToolSpec]) -> str:
    lines = []
    for t in tools:
        props = t.input_schema.get("properties", {}) if t.input_schema else {}
        arg_names = ", ".join(props.keys())
        lines.append(f"- {t.name}({arg_names}): {t.description}")
    return "\n".join(lines)


def _build_context(profile: ModelProfile, tools: list[ToolSpec]) -> dict[str, str]:
    # Category roll-up — matches archive's "9 categories" framing.
    category_prefixes = {t.name.split("_")[0] for t in tools}
    return {
        "tool_list": _format_tool_list(tools),
        "tool_count": str(len(tools)),
        "tool_categories": str(len(category_prefixes)) if category_prefixes else "several",
        "workflows": ", ".join(profile.recommended_workflows),
        "tool_call_format": TOOL_CALL_FORMAT,
        "tool_schema_hint": "Call tools using the native schema the runtime provides; parameters follow the input_schema field names.",
        "max_words": DEFAULT_MAX_WORDS,
    }


def _ollama_options(profile: ModelProfile) -> dict[str, Any]:
    g = profile.generation
    opts: dict[str, Any] = {
        "temperature": g.temperature,
        "top_p": g.top_p,
        "num_ctx": profile.context_size,
    }
    if g.top_k is not None:
        opts["top_k"] = g.top_k
    return opts


def _tool_specs_to_ollama(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    out = []
    for t in tools:
        out.append(
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema or {"type": "object", "properties": {}},
                },
            }
        )
    return out


def _tool_specs_to_anthropic(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    """Convert MCP tool specs to Anthropic Messages API tool schema.

    Anthropic format is flatter than Ollama's — no `type: function` wrapper.
    """
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema or {"type": "object", "properties": {}},
        }
        for t in tools
    ]


async def _run_native(
    profile: ModelProfile,
    system_prompt: str,
    question: str,
    tools: list[ToolSpec],
    mcp: MCPStdioClient,
    max_turns: int,
    trace: Trace,
) -> None:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question},
    ]
    tool_specs = _tool_specs_to_ollama(tools)
    client = ollama.AsyncClient()

    for _ in range(max_turns):
        t0 = time.monotonic()
        resp = await client.chat(
            model=profile.model_id,
            messages=messages,
            tools=tool_specs,
            options=_ollama_options(profile),
        )
        dur = int((time.monotonic() - t0) * 1000)
        msg = resp.message
        content = msg.content or ""
        tool_calls_raw = list(msg.tool_calls or [])

        tool_calls = [ToolCall(name=tc.function.name, args=dict(tc.function.arguments or {})) for tc in tool_calls_raw]
        trace.turns.append(Turn(role="assistant", content=content, tool_calls=tool_calls, duration_ms=dur))
        messages.append({"role": "assistant", "content": content, "tool_calls": [tc.model_dump() for tc in tool_calls_raw]})

        trace.turns_used += 1

        if not tool_calls:
            # Normal exit: model stopped calling tools.
            if content:
                trace.final_answer = content
                return
            # Empty final turn — known G4 failure mode where the model produces
            # a preamble ("I will now check...") then stalls on synthesis.
            # Issue a single forcing retry before falling back to salvage.
            await _force_final_synthesis_native(
                client, profile, messages, tool_specs, trace
            )
            return

        for tc in tool_calls:
            t1 = time.monotonic()
            result = await mcp.call_tool(tc.name, tc.args)
            tdur = int((time.monotonic() - t1) * 1000)
            trace.turns.append(Turn(role="tool", content=result, tool_name=tc.name, duration_ms=tdur))
            messages.append({"role": "tool", "content": result})

    # Max turns exhausted — try to salvage an answer from the last meaningful
    # assistant turn before declaring error.
    for prior in reversed(trace.turns):
        if prior.role == "assistant" and prior.content:
            trace.final_answer = prior.content
            break
    trace.error = f"max_turns ({max_turns}) exhausted without final answer"


FORCE_SYNTHESIS_PROMPT = (
    "Based on your tool results so far, produce the final analyst-facing "
    "answer now. Include the specific findings from each tool call — "
    "IPs, signatures, counts, hashes, filenames — not a plan or a "
    "summary of what you'll do next. The answer itself."
)


async def _force_final_synthesis_native(
    client: "ollama.AsyncClient",
    profile: ModelProfile,
    messages: list[dict[str, Any]],
    tool_specs: list[dict[str, Any]],
    trace: Trace,
) -> None:
    """One-shot retry when the native loop ends with empty content.

    Appends a forcing user message and takes the retry response as the final
    answer. If the retry is ALSO empty, falls back to salvaging the last
    non-empty assistant content from prior turns (old behavior).
    """
    messages.append({"role": "user", "content": FORCE_SYNTHESIS_PROMPT})
    t0 = time.monotonic()
    resp = await client.chat(
        model=profile.model_id,
        messages=messages,
        tools=tool_specs,
        options=_ollama_options(profile),
    )
    dur = int((time.monotonic() - t0) * 1000)
    retry_content = resp.message.content or ""
    trace.turns.append(
        Turn(role="assistant", content=retry_content, tool_calls=[], duration_ms=dur)
    )
    trace.turns_used += 1
    if retry_content:
        trace.final_answer = retry_content
        return
    # Retry also empty — salvage from prior turns (skip the empty final and
    # the just-appended empty retry response).
    for prior in reversed(trace.turns[:-2]):
        if prior.role == "assistant" and prior.content:
            trace.final_answer = prior.content
            break


async def _run_text_embedded(
    profile: ModelProfile,
    system_prompt: str,
    question: str,
    tools: list[ToolSpec],
    mcp: MCPStdioClient,
    max_turns: int,
    trace: Trace,
) -> None:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question},
    ]
    client = ollama.AsyncClient()

    for _ in range(max_turns):
        t0 = time.monotonic()
        resp = await client.chat(
            model=profile.model_id,
            messages=messages,
            options=_ollama_options(profile),
        )
        dur = int((time.monotonic() - t0) * 1000)
        content = resp.message.content or ""

        parsed_calls: list[ToolCall] = []
        # Primary format: ```tool_call ... ``` fence.
        for m in _TOOL_FENCE_RE.finditer(content):
            raw = _fix_json_quirks(m.group(1))
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            name = obj.get("name", "")
            args = obj.get("parameters") or obj.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if name:
                parsed_calls.append(ToolCall(name=name, args=args))
        # Legacy tag format: <tool>NAME</tool><args>{...}</args>.
        if not parsed_calls:
            for m in TOOL_CALL_RE.finditer(content):
                name = m.group(1)
                args_str = m.group(2)
                args: dict = {}
                if args_str is not None:
                    try:
                        args = json.loads(_fix_json_quirks(args_str))
                    except json.JSONDecodeError:
                        args = {}
                parsed_calls.append(ToolCall(name=name, args=args))
        # Last resort: bare JSON `{"name": ..., "parameters": ...}` — matches
        # models that skip the fence but still emit structured JSON.
        if not parsed_calls:
            for name, raw in _extract_json_tool_calls(content):
                try:
                    obj = json.loads(_fix_json_quirks(raw))
                    args = obj.get("parameters") or obj.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                except json.JSONDecodeError:
                    args = {}
                parsed_calls.append(ToolCall(name=name, args=args))

        trace.turns.append(Turn(role="assistant", content=content, tool_calls=parsed_calls, duration_ms=dur))
        messages.append({"role": "assistant", "content": content})
        trace.turns_used += 1

        if not parsed_calls:
            trace.final_answer = content
            return

        for tc in parsed_calls:
            t1 = time.monotonic()
            result = await mcp.call_tool(tc.name, tc.args)
            tdur = int((time.monotonic() - t1) * 1000)
            trace.turns.append(Turn(role="tool", content=result, tool_name=tc.name, duration_ms=tdur))
            messages.append(
                {
                    "role": "user",
                    "content": f"<tool_result name=\"{tc.name}\">\n{result}\n</tool_result>",
                }
            )

    trace.error = f"max_turns ({max_turns}) exhausted without final answer"


async def _run_anthropic(
    profile: ModelProfile,
    system_prompt: str,
    question: str,
    tools: list[ToolSpec],
    mcp: MCPStdioClient,
    max_turns: int,
    trace: Trace,
) -> None:
    """Anthropic Messages API tool-use loop.

    Content blocks: text | tool_use | thinking. Loop continues while the
    response contains tool_use blocks; we dispatch them via the MCP client
    and feed tool_result blocks back as a user message. The system prompt
    is cached (ephemeral) to cut cost across a multi-prompt run.
    """
    # Import here so tests that don't exercise the Anthropic path don't
    # require the SDK to be installed.
    from anthropic import AsyncAnthropic

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set. Add it to .env or export it before running."
        )

    client = AsyncAnthropic()
    tool_specs = _tool_specs_to_anthropic(tools)

    # Anthropic expects 'system' as either a string or a list of content blocks.
    # Using the block form lets us apply ephemeral caching to the system prompt.
    system_blocks = [
        {
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    messages: list[dict[str, Any]] = [{"role": "user", "content": question}]

    g = profile.generation
    # Anthropic requires max_tokens; pick a generous-but-bounded default.
    max_tokens = 4096

    for _ in range(max_turns):
        t0 = time.monotonic()
        kwargs: dict[str, Any] = {
            "model": profile.model_id,
            "max_tokens": max_tokens,
            "system": system_blocks,
            "messages": messages,
            "tools": tool_specs,
            "temperature": g.temperature,
        }
        # Anthropic API rejects temperature + top_p together — pass only temperature.
        # top_p in the profile is ignored for this path.
        resp = await client.messages.create(**kwargs)
        dur = int((time.monotonic() - t0) * 1000)

        # Collect text content and tool_use blocks from the response.
        text_parts: list[str] = []
        tool_uses: list[dict[str, Any]] = []
        for block in resp.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                tool_uses.append(
                    {
                        "id": block.id,
                        "name": block.name,
                        "input": dict(block.input) if block.input else {},
                    }
                )
        content_text = "\n".join(text_parts)
        tool_calls = [ToolCall(name=tu["name"], args=tu["input"]) for tu in tool_uses]

        trace.turns.append(
            Turn(
                role="assistant",
                content=content_text,
                tool_calls=tool_calls,
                duration_ms=dur,
            )
        )
        # Append the assistant turn to messages using the SDK's expected shape.
        # Re-send blocks as-is; Anthropic requires the tool_use blocks to be
        # present when the next user message contains their tool_result.
        messages.append({"role": "assistant", "content": [b.model_dump() for b in resp.content]})
        trace.turns_used += 1

        if resp.stop_reason != "tool_use":
            # Natural end of turn — no more tools to call.
            if content_text:
                trace.final_answer = content_text
            else:
                for prior in reversed(trace.turns[:-1]):
                    if prior.role == "assistant" and prior.content:
                        trace.final_answer = prior.content
                        break
            return

        # Dispatch each tool_use via MCP and send tool_result blocks back.
        tool_result_blocks: list[dict[str, Any]] = []
        for tu in tool_uses:
            t1 = time.monotonic()
            result = await mcp.call_tool(tu["name"], tu["input"])
            tdur = int((time.monotonic() - t1) * 1000)
            trace.turns.append(
                Turn(role="tool", content=result, tool_name=tu["name"], duration_ms=tdur)
            )
            tool_result_blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tu["id"],
                    "content": result,
                }
            )
        messages.append({"role": "user", "content": tool_result_blocks})

    # Max turns exhausted — salvage last non-empty assistant content.
    for prior in reversed(trace.turns):
        if prior.role == "assistant" and prior.content:
            trace.final_answer = prior.content
            break
    trace.error = f"max_turns ({max_turns}) exhausted without final answer"


async def run(
    profile: ModelProfile,
    question: str,
    *,
    prompt_id: str = "adhoc",
    server_cmd: list[str] | None = None,
    config_path: Path | None = None,
    max_turns: int = 10,
) -> Trace:
    cmd = server_cmd or [sys.executable, "-m", "blue_bench_mcp.server"]
    if config_path is not None:
        cmd = [*cmd, "--config", str(config_path)]

    async with MCPStdioClient(cmd) as mcp:
        tools = await mcp.list_tools()
        system_prompt = compose(profile, _build_context(profile, tools))

        trace = Trace(
            prompt_id=prompt_id,
            profile_name=profile.name,
            model_id=profile.model_id,
            tool_protocol=profile.tool_protocol,
            question=question,
            composed_system_prompt=system_prompt,
            tools_available=[t.name for t in tools],
            max_turns=max_turns,
        )

        t0 = time.monotonic()
        try:
            if profile.tool_protocol == "native":
                await _run_native(profile, system_prompt, question, tools, mcp, max_turns, trace)
            elif profile.tool_protocol == "anthropic-native":
                await _run_anthropic(profile, system_prompt, question, tools, mcp, max_turns, trace)
            else:
                await _run_text_embedded(profile, system_prompt, question, tools, mcp, max_turns, trace)
        except Exception as e:
            trace.error = f"{type(e).__name__}: {e}"
        trace.total_duration_ms = int((time.monotonic() - t0) * 1000)

    return trace
