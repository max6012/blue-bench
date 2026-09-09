"""Runner — profile + question → model loop with tool dispatch → trace.

Four paths keyed on profile.tool_protocol:
- "native": Ollama chat() with tools= schema, parses message.tool_calls
- "text-embedded": model emits <tool>name</tool><args>{...}</args> in content,
  parsed with regex, tool result injected as a user message
- "anthropic-native": Anthropic Messages API with tool_use / tool_result blocks
- "openai-native": OpenAI-compatible Chat Completions (vLLM/TGI/SGLang/Ollama
  /v1, e.g. a Cray) with tools= schema, parses message.tool_calls

All paths write the same Trace schema, so Phase 2 scoring is protocol-agnostic.

Operator note (Cray / OpenAI-compatible endpoint): set OPENAI_BASE_URL to the
inference server's /v1 (e.g. http://localhost:11434/v1 for local Ollama, or the
Cray's /v1) and OPENAI_API_KEY to a non-empty value, then run with
`blue-bench qualify --openai --profile <model_id>`. Pointing at the Cray is a
config change only. THEN verify per served-model that native tool-calling works
through the Cray's inference server — vLLM/TGI/SGLang each parse tool calls
differently (vLLM needs --enable-auto-tool-choice, a per-model
--tool-call-parser, and a per-model --chat-template for tool-role messages; a
mis-config silently returns empty tool_calls). Where a served model does not do
native tool-calling, fall back to the text-embedded protocol. This per-model
verification is the real variable cost and needs the live Cray.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import ollama

from blue_bench_client._ollama import make_async_client
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


def _coerce_messages_for_ollama(messages: list[dict]) -> list[dict]:
    """Flatten Anthropic-format content blocks to plain strings for Ollama.

    When a session history was built under the anthropic-native protocol,
    assistant messages carry content as a list of typed blocks
    (text/tool_use/tool_result, possibly with a citations field). Ollama's
    Message model requires content: str | None. This function produces a
    copy of the message list safe to pass to the Ollama client.

    Block-type handling preserves data the new model needs to continue an
    investigation without re-calling tools:
      - ``text``           → kept as plain text
      - ``tool_use``       → emitted as ``[Called <name>(<args>)]`` text so the
                             new model sees what was dispatched
      - ``tool_result``    → emitted as ``[Tool result]: <body>`` text so the
                             actual returned data survives the protocol swap
      - everything else    → dropped
    """
    out = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, list):
            parts: list[str] = []
            for b in content:
                if not isinstance(b, dict):
                    continue
                btype = b.get("type")
                if btype == "text":
                    parts.append(b.get("text", ""))
                elif btype == "tool_use":
                    name = b.get("name", "tool")
                    args = b.get("input") or {}
                    parts.append(f"[Called {name}({args})]")
                elif btype == "tool_result":
                    body = b.get("content")
                    if isinstance(body, list):
                        # tool_result.content can itself be a list of blocks
                        body = "\n".join(
                            blk.get("text", "") if isinstance(blk, dict) else str(blk)
                            for blk in body
                        )
                    parts.append(f"[Tool result]: {body}")
            joined = "\n".join(p for p in parts if p)
            msg = {**msg, "content": joined or None}
        out.append(msg)
    return out


def _coerce_native_history_for_anthropic(messages: list[dict]) -> list[dict]:
    """Convert native-protocol history into a payload Anthropic accepts.

    Native (Ollama) protocol pattern for a tool exchange::

        user        "what alerts?"
        assistant   content="" + tool_calls=[search_alerts(...)]
        tool        "result body"
        assistant   "Synthesis text"

    Anthropic's Messages API rejects role="tool" entirely, rejects the
    ``tool_calls`` field on assistant messages, and requires strict
    user/assistant alternation with non-empty content. Folding the tool
    exchange into the *next* assistant message preserves what was called
    and what came back as plain text the new model can read, while keeping
    the alternation valid.

    Also drops role="system" messages (Anthropic takes system as a top-level
    parameter, not in messages).
    """
    out: list[dict[str, Any]] = []
    # Pending tool exchange records collected since the last text-bearing
    # assistant message. We flush these into the next assistant turn.
    pending: list[str] = []
    pending_call_names: list[str] = []

    for m in messages:
        role = m.get("role")
        if role == "system":
            continue
        if role == "tool":
            body = m.get("content") or ""
            if isinstance(body, list):
                body = "\n".join(str(b) for b in body)
            # Pair with the most recent unresolved tool call name if available.
            name = pending_call_names.pop(0) if pending_call_names else "tool"
            pending.append(f"[Tool result from {name}]: {body}")
            continue
        if role == "assistant":
            content = m.get("content") or ""
            tool_calls = m.get("tool_calls") or []
            if tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function") if isinstance(tc, dict) else None
                    if isinstance(fn, dict):
                        name = fn.get("name") or "tool"
                    else:
                        name = tc.get("name", "tool") if isinstance(tc, dict) else "tool"
                    pending_call_names.append(name)
            if not content and tool_calls:
                # Pure dispatch turn — defer; the tool result lines will be
                # prepended to the next text-bearing assistant message.
                continue
            if pending:
                prefix = "\n".join(pending)
                content = f"{prefix}\n\n{content}" if content else prefix
                pending = []
                pending_call_names = []
            new_m = {k: v for k, v in m.items() if k != "tool_calls"}
            new_m["content"] = content
            out.append(new_m)
            continue
        # user (or anything else) — pass through, but flush any unresolved
        # pending tool results in front of it as a synthetic assistant turn so
        # the new model still sees the data.
        if pending:
            out.append({"role": "assistant", "content": "\n".join(pending)})
            pending = []
            pending_call_names = []
        out.append(m)

    # Trailing pending (shouldn't normally happen, but safe-guard)
    if pending:
        out.append({"role": "assistant", "content": "\n".join(pending)})

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


def _tool_specs_to_openai(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    """Convert MCP tool specs to OpenAI function schema.

    OpenAI format matches Ollama's: a ``type: function`` wrapper around a
    ``function`` object with name/description/parameters. The parameters schema
    is the MCP input_schema (already JSON Schema).
    """
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.input_schema or {"type": "object", "properties": {}},
            },
        }
        for t in tools
    ]


def _openai_args(arguments: str | None) -> dict[str, Any]:
    """Parse an OpenAI tool-call ``arguments`` field into a dict.

    In the OpenAI wire protocol ``function.arguments`` is a JSON *string* (unlike
    Ollama's native protocol, where it is already a mapping). Tolerate a decode
    error by returning an empty dict rather than crashing the loop.
    """
    if not arguments:
        return {}
    try:
        parsed = json.loads(arguments)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


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
    client = make_async_client()

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
    client = make_async_client()

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
        }
        # Only send temperature when the profile sets it: newer models (e.g.
        # claude-opus-4-8) reject `temperature` outright ("deprecated for this
        # model"). Anthropic also rejects temperature + top_p together, so
        # top_p in the profile is ignored for this path regardless.
        if g.temperature is not None:
            kwargs["temperature"] = g.temperature
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


async def _run_openai(
    profile: ModelProfile,
    system_prompt: str,
    question: str,
    tools: list[ToolSpec],
    mcp: MCPStdioClient,
    max_turns: int,
    trace: Trace,
) -> None:
    """OpenAI-compatible tool-use loop (vLLM/TGI/SGLang/Ollama /v1, e.g. a Cray).

    Mirrors ``_run_anthropic`` but against the OpenAI Chat Completions wire
    protocol: send messages + tools, parse ``choices[0].message.tool_calls``,
    dispatch each via MCP, feed results back as ``{role: tool, tool_call_id,
    content}`` messages, and loop until the model stops calling tools.
    """
    # Import here so tests that don't exercise the OpenAI path don't require
    # the SDK to be installed.
    from blue_bench_client._openai import make_async_client

    client = make_async_client()
    tool_specs = _tool_specs_to_openai(tools)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question},
    ]

    g = profile.generation
    kwargs: dict[str, Any] = {
        "model": profile.model_id,
        "messages": messages,
        "tools": tool_specs,
    }
    if g.temperature is not None:
        kwargs["temperature"] = g.temperature
    if g.top_p is not None:
        kwargs["top_p"] = g.top_p

    for _ in range(max_turns):
        t0 = time.monotonic()
        resp = await client.chat.completions.create(**kwargs)
        dur = int((time.monotonic() - t0) * 1000)

        choice = resp.choices[0] if resp.choices else None
        if choice is None:
            trace.error = "openai-native: empty choices in response"
            return
        msg = choice.message
        content = msg.content or ""
        tool_calls_raw = list(msg.tool_calls or [])

        tool_calls = [
            ToolCall(name=tc.function.name, args=_openai_args(tc.function.arguments))
            for tc in tool_calls_raw
        ]
        trace.turns.append(
            Turn(role="assistant", content=content, tool_calls=tool_calls, duration_ms=dur)
        )
        # Append the assistant turn with its tool_calls so the next request
        # carries the full context (OpenAI requires the tool_calls to be echoed
        # back when the following message is a tool result).
        messages.append(
            {
                "role": "assistant",
                "content": content or None,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments or "{}",
                        },
                    }
                    for tc in tool_calls_raw
                ],
            }
        )
        trace.turns_used += 1

        if not tool_calls:
            # Normal exit: model stopped calling tools.
            if content:
                trace.final_answer = content
                return
            # Empty final turn — salvage from prior turns.
            for prior in reversed(trace.turns[:-1]):
                if prior.role == "assistant" and prior.content:
                    trace.final_answer = prior.content
                    break
            return

        # Dispatch each tool call via MCP and feed results back as tool messages.
        for tc in tool_calls_raw:
            name = tc.function.name
            args = _openai_args(tc.function.arguments)
            t1 = time.monotonic()
            result = await mcp.call_tool(name, args)
            tdur = int((time.monotonic() - t1) * 1000)
            trace.turns.append(
                Turn(role="tool", content=result, tool_name=name, duration_ms=tdur)
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                }
            )

    # Max turns exhausted — salvage last non-empty assistant content.
    for prior in reversed(trace.turns):
        if prior.role == "assistant" and prior.content:
            trace.final_answer = prior.content
            break
    trace.error = f"max_turns ({max_turns}) exhausted without final answer"


# ── anthropic-cli transport ──────────────────────────────────────────────────
# Drives a Claude model via the `claude` CLI headless on the SUBSCRIPTION (OAuth),
# not the metered API. Only OAuth tokens are available in this deployment, and the
# SDK rejects them as x-api-key — the LLM-judge hit the same wall and solved it the
# same way. The CLI runs the tool-use loop itself against our MCP server; we parse
# its stream-json into the same Trace shape the SDK/native paths emit.
_MCP_SERVER_NAME = "blue-bench"
_MCP_TOOL_PREFIX = f"mcp__{_MCP_SERVER_NAME}__"


def _strip_mcp_prefix(name: str) -> str:
    return name[len(_MCP_TOOL_PREFIX):] if name.startswith(_MCP_TOOL_PREFIX) else name


def _cli_oauth_env() -> dict[str, str]:
    """Subprocess env for `claude` on the subscription: OAuth token in
    CLAUDE_CODE_OAUTH_TOKEN, api-key vars stripped so it can't fall back to a
    metered key (mirrors the judge's CLI auth)."""
    env = dict(os.environ)
    tok = env.get("CLAUDE_CODE_OAUTH_TOKEN")
    if not tok:
        for v in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"):
            if env.get(v, "").startswith("sk-ant-oat"):
                tok = env[v]
                break
    if tok:
        env["CLAUDE_CODE_OAUTH_TOKEN"] = tok
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("ANTHROPIC_AUTH_TOKEN", None)
    return env


def _cli_tool_result_text(content: Any) -> str:
    """Flatten a CLI tool_result block to the raw payload the judge expects."""
    if isinstance(content, str):
        s = content
    elif isinstance(content, list):
        s = "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
        s = s or json.dumps(content, default=str)
    else:
        s = json.dumps(content, default=str)
    # MCPServer wraps a bare-string tool return as {"result": "..."} — unwrap it so
    # the judge sees the same payload the SDK/native paths deliver.
    try:
        obj = json.loads(s)
        if isinstance(obj, dict) and list(obj.keys()) == ["result"] and isinstance(obj["result"], str):
            return obj["result"]
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    return s


async def _run_anthropic_cli(
    profile: ModelProfile,
    system: str,
    question: str,
    tools: list[ToolSpec],
    server_cmd: list[str],
    max_turns: int,
    trace: Trace,
) -> None:
    # NOTE: ``max_turns`` is NOT enforced here. The `claude` CLI runs its own
    # tool-use loop and exposes no --max-turns flag, so the frontier ceiling is
    # measured with an unbounded tool-call budget while local models are capped
    # at max_turns. Accepted asymmetry (see claude-opus-5.yaml); the parameter is
    # kept for signature parity with the other _run_* loops.
    claude = shutil.which("claude") or "claude"
    mcp_cfg = {"mcpServers": {_MCP_SERVER_NAME: {"command": server_cmd[0], "args": list(server_cmd[1:])}}}
    fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="bb-mcp-")
    with os.fdopen(fd, "w") as f:
        json.dump(mcp_cfg, f)
    args = [
        claude, "-p", question,
        "--model", profile.model_id,
        "--system-prompt", system,
        "--mcp-config", cfg_path, "--strict-mcp-config",
        "--tools", "",  # disable all built-in tools; only the blue-bench MCP surface remains
        "--permission-mode", "bypassPermissions",
        "--output-format", "stream-json", "--verbose",
    ]
    allowed = [f"{_MCP_TOOL_PREFIX}{t.name}" for t in tools]
    if allowed:
        args += ["--allowed-tools", *allowed]
    env = _cli_oauth_env()

    def _run() -> subprocess.CompletedProcess:
        return subprocess.run(args, input="", capture_output=True, text=True, env=env, timeout=1800)

    try:
        r = await asyncio.to_thread(_run)
    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

    names_by_id: dict[str, str] = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = e.get("type")
        if etype == "assistant":
            blocks = (e.get("message") or {}).get("content") or []
            text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
            calls: list[ToolCall] = []
            for b in blocks:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    nm = _strip_mcp_prefix(str(b.get("name", "")))
                    calls.append(ToolCall(name=nm, args=dict(b.get("input") or {})))
                    names_by_id[str(b.get("id", ""))] = nm
            if text or calls:
                trace.turns.append(Turn(role="assistant", content=text, tool_calls=calls))
                trace.turns_used += 1
        elif etype == "user":
            blocks = (e.get("message") or {}).get("content") or []
            for b in blocks:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    trace.turns.append(Turn(
                        role="tool",
                        content=_cli_tool_result_text(b.get("content")),
                        tool_name=names_by_id.get(str(b.get("tool_use_id", ""))),
                    ))
        elif etype == "result":
            res = e.get("result")
            if isinstance(res, str) and res.strip():
                trace.final_answer = res
            if e.get("is_error"):
                trace.error = f"claude CLI result: {e.get('subtype', 'error')}"

    if not trace.final_answer:
        for prior in reversed(trace.turns):
            if prior.role == "assistant" and prior.content:
                trace.final_answer = prior.content
                break
    if r.returncode != 0 and not trace.error:
        trace.error = f"claude CLI exit {r.returncode}: {(r.stderr or '')[-200:]}"


async def run(
    profile: ModelProfile,
    question: str,
    *,
    prompt_id: str = "adhoc",
    server_cmd: list[str] | None = None,
    config_path: Path | None = None,
    max_turns: int = 10,
    disable_tools: bool = False,
) -> Trace:
    cmd = server_cmd or [sys.executable, "-m", "blue_bench_mcp.server"]
    if config_path is not None:
        cmd = [*cmd, "--config", str(config_path)]

    async with MCPStdioClient(cmd) as mcp:
        all_tools = await mcp.list_tools()
        tools = [] if disable_tools else all_tools
        system_prompt = compose(profile, _build_context(profile, all_tools))

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
            elif profile.tool_protocol == "anthropic-cli":
                await _run_anthropic_cli(profile, system_prompt, question, tools, cmd, max_turns, trace)
            elif profile.tool_protocol == "openai-native":
                await _run_openai(profile, system_prompt, question, tools, mcp, max_turns, trace)
            else:
                await _run_text_embedded(profile, system_prompt, question, tools, mcp, max_turns, trace)
        except Exception as e:
            trace.error = f"{type(e).__name__}: {e}"
        trace.total_duration_ms = int((time.monotonic() - t0) * 1000)

    return trace
