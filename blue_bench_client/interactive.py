"""Interactive (REPL-shaped) runner — multi-turn conversation, event stream.

Companion to :mod:`blue_bench_client.runner` for the CLI analyst console.
The qualify runner mutates a Trace and is single-question shaped; this
module exposes an event-stream API designed for live rendering and
multi-turn context preservation.

Usage::

    async with InteractiveSession(profile, task_class="ALERT_TRIAGE") as session:
        print(session.banner())
        async for event in session.iter_turn("What's going on?"):
            render(event)
        # history persists; next iter_turn() builds on it
        async for event in session.iter_turn("What about 10.10.5.22?"):
            render(event)

Task class is operator-declared and required at session entry — the session
refuses to launch without it (no silent defaulting), and refuses to launch
if the profile's ``allowed_task_classes`` does not include it. Tool gate,
mid-session profile/model swap, and history clear are all mutations on the
session object — they take effect on the next turn. Mid-session profile
swap re-validates the bound task class against the new profile.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Literal

import ollama

from blue_bench_client._ollama import make_async_client

from blue_bench_client.mcp_client import MCPStdioClient, ToolSpec
from blue_bench_client.runner import (
    _build_context,
    _coerce_messages_for_ollama,
    _coerce_native_history_for_anthropic,
    _extract_json_tool_calls,
    _ollama_options,
    _tool_specs_to_anthropic,
    _tool_specs_to_ollama,
    TOOL_CALL_RE,
)
from blue_bench_mcp.profiles import ModelProfile, load_profile
from blue_bench_mcp.prompts_compose import compose
from blue_bench_mcp.task_classes import TaskClass, UnknownTaskClassError, get_task_class


class EngagementScopeError(Exception):
    """Raised when a session is launched against a task class the profile
    does not permit, or without an explicit task class at all."""


# ── events ────────────────────────────────────────────────────────────────────

@dataclass
class TurnStart:
    turn_index: int
    """Zero-indexed within the current `iter_turn()` invocation."""


@dataclass
class TextDelta:
    """A streamed chunk of assistant text. Concatenate to reconstruct."""
    text: str


@dataclass
class AssistantText:
    """Full assistant text for a turn (emitted when streaming wasn't used or
    on turn-end as a backstop). Renderers can ignore this if they already
    accumulated TextDelta events for this turn."""
    text: str
    duration_ms: int


@dataclass
class ToolCall:
    call_id: str
    name: str
    args: dict[str, Any]


@dataclass
class ToolResult:
    call_id: str
    name: str
    result: str
    elapsed_ms: int
    error: str | None = None  # set when the result text indicates a server-side error


@dataclass
class FinalAnswer:
    text: str
    """The final synthesized response to the analyst's question."""


@dataclass
class Error:
    message: str


@dataclass
class TurnComplete:
    """Emitted at the end of every iter_turn() call.

    Carries aggregate counters so the renderer can print a footer without
    counting events itself.
    """
    turns_used: int
    tool_calls: int
    duration_ms: int
    salvaged: bool = False
    """True if max_turns was exhausted and we salvaged a prior assistant turn."""


Event = (
    TurnStart
    | TextDelta
    | AssistantText
    | ToolCall
    | ToolResult
    | FinalAnswer
    | Error
    | TurnComplete
)


# ── session ───────────────────────────────────────────────────────────────────

class InteractiveSession:
    """A live MCP + LLM session that an analyst drives across multiple turns.

    History is preserved across `iter_turn()` calls. Mid-session, the analyst
    can swap profile/model and adjust the tool gate; the next turn picks up
    the change. Use `clear_history()` to reset the conversation while keeping
    profile/gate/MCP connection.
    """

    def __init__(
        self,
        profile: ModelProfile,
        *,
        config_path: Path | None = None,
        server_cmd: list[str] | None = None,
        max_turns: int = 10,
        tool_gate: set[str] | None = None,
        stream: bool = True,
        task_class: str | TaskClass | None = None,
    ) -> None:
        self.profile = profile
        self.config_path = config_path
        self.server_cmd = server_cmd
        self.max_turns = max_turns
        self.tool_gate: set[str] | None = tool_gate
        """If set, only tools whose name is in this set are exposed to the model.
        None means unrestricted."""
        self.stream = stream
        self.task_class: TaskClass | None = (
            self._coerce_task_class(task_class) if task_class is not None else None
        )
        """Operator-declared task class for this engagement. Validated against
        ``profile.allowed_task_classes`` at session entry. Surfaced in the
        engagement banner, recorded in the audit log, and consumed by the
        grounding/coverage passes."""

        self._mcp: MCPStdioClient | None = None
        self._all_tools: list[ToolSpec] = []
        self._messages: list[dict[str, Any]] = []  # mutable conversation history
        self._native_seeded = False
        self._anthropic_seeded = False

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "InteractiveSession":
        self._enforce_scope(at_entry=True)
        cmd = self.server_cmd or [sys.executable, "-m", "blue_bench_mcp.server"]
        if self.config_path is not None:
            cmd = [*cmd, "--config", str(self.config_path)]
        self._mcp = MCPStdioClient(cmd)
        await self._mcp.__aenter__()
        self._all_tools = await self._mcp.list_tools()
        return self

    # ── engagement scope ─────────────────────────────────────────────────────

    @staticmethod
    def _coerce_task_class(value: str | TaskClass) -> TaskClass:
        """Resolve a string-or-enum task class to the enum, raising a session-
        level :class:`EngagementScopeError` (not :class:`UnknownTaskClassError`)
        so callers handle a single exception type at session boundary."""
        if isinstance(value, TaskClass):
            return value
        try:
            return get_task_class(value).name
        except UnknownTaskClassError as e:
            raise EngagementScopeError(str(e)) from e

    def _enforce_scope(self, *, at_entry: bool = False) -> None:
        """Validate the bound task class against the profile. Called at session
        entry and after :meth:`set_profile`. Raises :class:`EngagementScopeError`
        with a message naming the offending profile + class + permitted set.

        When ``profile.require_task_class`` is False, enforcement is skipped
        entirely — task_class may remain None and no allowed-list check runs.
        Use this to unblock operators while the full control surface is built.

        ``at_entry=True`` additionally enforces that a class IS bound when the
        profile requires one. On mid-session profile swaps (``at_entry=False``)
        the absence of a class is allowed — the engagement scope was already
        established at start; only a mismatched class is an error.
        """
        if not self.profile.require_task_class:
            return
        if self.task_class is None:
            if at_entry:
                raise EngagementScopeError(
                    "task_class is required at engagement start — no silent defaulting. "
                    "Pass task_class= when constructing InteractiveSession."
                )
            return  # no class bound is fine on a swap; allowed-list check is moot
        allowed = self.profile.allowed_task_classes
        if self.task_class not in allowed:
            permitted = ", ".join(c.value for c in allowed)
            raise EngagementScopeError(
                f"task class {self.task_class.value!r} is not permitted by "
                f"profile {self.profile.name!r}. permitted: {permitted}"
            )

    def banner(self) -> str:
        """Human-readable engagement banner for the CLI to render right after
        session entry. Single line per fact so a renderer can split if needed."""
        if self.task_class:
            tc = self.task_class.value
        elif not self.profile.require_task_class:
            tc = "(disabled by profile)"
        else:
            tc = "(unbound)"
        return (
            f"Engagement bound\n"
            f"  Profile:    {self.profile.name} ({self.profile.model_id})\n"
            f"  Task class: {tc}\n"
            f"  Citation enforcement: {'on' if self.profile.require_evidence_citation else 'off'}\n"
        )

    async def __aexit__(self, *exc: Any) -> None:
        if self._mcp is not None:
            await self._mcp.__aexit__(*exc)
            self._mcp = None

    # ── public mutators ──────────────────────────────────────────────────────

    @property
    def tools_available(self) -> list[ToolSpec]:
        """The tool surface as restricted by the current tool gate."""
        if self.tool_gate is None:
            return self._all_tools
        return [t for t in self._all_tools if t.name in self.tool_gate]

    @property
    def all_tools(self) -> list[ToolSpec]:
        return self._all_tools

    def set_tool_gate(self, tool_names: set[str] | None) -> None:
        """Set or clear the tool gate. None = unrestricted."""
        self.tool_gate = tool_names

    def set_profile(self, new_profile: ModelProfile, *, keep_history: bool = True) -> None:
        """Swap profile mid-session.

        With `keep_history=True` (default), the user/assistant message
        history is retained but the system prompt for the next turn is
        re-composed under the new profile. Native and Anthropic seedings
        are reset so the next turn re-sends the new system prompt.

        Re-validates the bound task class against the new profile. Raises
        :class:`EngagementScopeError` if the new profile does not permit the
        currently bound class — the operator must restart the engagement with
        a compatible class rather than silently widening permitted scope.
        """
        self.profile = new_profile
        self._enforce_scope()
        self._native_seeded = False
        self._anthropic_seeded = False
        if not keep_history:
            self._messages = []

    def set_model_id(self, model_id: str) -> None:
        """Override model_id within the current profile (e.g. an Ollama tag swap)."""
        self.profile = self.profile.model_copy(update={"model_id": model_id})

    def set_task_class(self, value: str | TaskClass | None) -> None:
        """Rebind the engagement task class mid-session and re-validate against
        the current profile's ``allowed_task_classes``.

        Passing ``None`` clears the binding. Direct attribute assignment
        (``session.task_class = ...``) bypasses validation; this method is the
        supported path for CLI ``/task-class`` rebinds and any other mid-session
        change. Raises :class:`EngagementScopeError` if the new class is not
        permitted by the current profile.
        """
        if value is None:
            self.task_class = None
            return
        coerced = self._coerce_task_class(value)
        if (
            self.profile.require_task_class
            and coerced not in self.profile.allowed_task_classes
        ):
            permitted = ", ".join(c.value for c in self.profile.allowed_task_classes)
            raise EngagementScopeError(
                f"task class {coerced.value!r} is not permitted by "
                f"profile {self.profile.name!r}. permitted: {permitted}"
            )
        self.task_class = coerced

    def clear_history(self) -> None:
        """Drop all user/assistant/tool messages. Keep profile, model, gate, MCP."""
        self._messages = []
        self._native_seeded = False
        self._anthropic_seeded = False

    @property
    def history_message_count(self) -> int:
        return len(self._messages)

    @property
    def history_token_estimate(self) -> int:
        """Rough char-count proxy for tokens (~4 chars/token). Good enough for
        the context-window guard; precise tokenization isn't worth the dep."""
        total = 0
        for m in self._messages:
            c = m.get("content")
            if isinstance(c, str):
                total += len(c)
            elif isinstance(c, list):
                for block in c:
                    if isinstance(block, dict):
                        if "text" in block:
                            total += len(str(block["text"]))
                        elif "content" in block:
                            total += len(str(block["content"]))
        return total // 4

    # ── core: per-turn event stream ──────────────────────────────────────────

    async def iter_turn(self, question: str) -> AsyncIterator[Event]:
        """Stream events for one user question. Updates conversation history
        in place so subsequent turns build on the same context."""
        if self._mcp is None:
            raise RuntimeError("InteractiveSession not entered (use `async with`)")

        # Reset per-turn flags that are independent of seeding.
        protocol = self.profile.tool_protocol
        try:
            if protocol == "native":
                async for ev in self._iter_native(question):
                    yield ev
            elif protocol == "anthropic-native":
                async for ev in self._iter_anthropic(question):
                    yield ev
            else:
                async for ev in self._iter_text_embedded(question):
                    yield ev
        except Exception as e:  # pragma: no cover - last-resort safety net
            yield Error(message=f"{type(e).__name__}: {e}")

    # ── native (Ollama tool_use) ─────────────────────────────────────────────

    async def _iter_native(self, question: str) -> AsyncIterator[Event]:
        if not self._native_seeded:
            self._messages = [
                {"role": "system", "content": self._compose_system_prompt()},
            ] + [m for m in self._messages if m.get("role") != "system"]
            self._native_seeded = True
        self._messages.append({"role": "user", "content": question})

        tool_specs = _tool_specs_to_ollama(self.tools_available)
        client = make_async_client()

        turn_start = time.monotonic()
        turns_used = 0
        tool_calls_total = 0
        salvaged = False
        final_emitted = False

        for turn_idx in range(self.max_turns):
            yield TurnStart(turn_index=turn_idx)
            t0 = time.monotonic()
            content = ""
            tool_calls_raw: list[Any] = []
            ollama_messages = _coerce_messages_for_ollama(self._messages)

            if self.stream:
                # Stream content tokens; tool_calls arrive on the final chunk.
                async for chunk in await client.chat(
                    model=self.profile.model_id,
                    messages=ollama_messages,
                    tools=tool_specs,
                    options=_ollama_options(self.profile),
                    stream=True,
                ):
                    msg = chunk.message
                    delta = msg.content or ""
                    if delta:
                        content += delta
                        yield TextDelta(text=delta)
                    if msg.tool_calls:
                        tool_calls_raw = list(msg.tool_calls)
            else:
                resp = await client.chat(
                    model=self.profile.model_id,
                    messages=ollama_messages,
                    tools=tool_specs,
                    options=_ollama_options(self.profile),
                )
                msg = resp.message
                content = msg.content or ""
                tool_calls_raw = list(msg.tool_calls or [])

            dur = int((time.monotonic() - t0) * 1000)
            yield AssistantText(text=content, duration_ms=dur)
            turns_used += 1

            self._messages.append(
                {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [tc.model_dump() for tc in tool_calls_raw],
                }
            )

            if not tool_calls_raw:
                if content:
                    yield FinalAnswer(text=content)
                    final_emitted = True
                else:
                    salvaged_text = self._salvage_native_assistant_text()
                    if salvaged_text:
                        yield FinalAnswer(text=salvaged_text)
                        final_emitted = True
                        salvaged = True
                    else:
                        yield Error(message="model produced empty content with no tools")
                break

            for tc in tool_calls_raw:
                call_id = f"call_{turn_idx}_{tool_calls_total}"
                name = tc.function.name
                args = dict(tc.function.arguments or {})
                yield ToolCall(call_id=call_id, name=name, args=args)
                tool_calls_total += 1

                # Defensive gate: refuse calls outside the active gate.
                if self.tool_gate is not None and name not in self.tool_gate:
                    err = (
                        f'Tool "{name}" is outside the active tool gate '
                        f"({sorted(self.tool_gate)})"
                    )
                    yield ToolResult(
                        call_id=call_id, name=name, result=err, elapsed_ms=0, error=err
                    )
                    self._messages.append({"role": "tool", "content": err})
                    continue

                t1 = time.monotonic()
                try:
                    result = await self._mcp.call_tool(name, args)
                    err = self._detect_error(result)
                except Exception as e:
                    result = f"{type(e).__name__}: {e}"
                    err = result
                tdur = int((time.monotonic() - t1) * 1000)
                yield ToolResult(
                    call_id=call_id, name=name, result=result, elapsed_ms=tdur, error=err
                )
                self._messages.append({"role": "tool", "content": result})

        else:
            # Loop fell through without break — max turns exhausted.
            salvaged_text = self._salvage_native_assistant_text()
            if salvaged_text:
                yield FinalAnswer(text=salvaged_text)
                final_emitted = True
                salvaged = True
            yield Error(message=f"max_turns ({self.max_turns}) exhausted without final answer")

        if not final_emitted:
            # Defensive: every turn must end with FinalAnswer if anything renders downstream.
            yield FinalAnswer(text="")

        yield TurnComplete(
            turns_used=turns_used,
            tool_calls=tool_calls_total,
            duration_ms=int((time.monotonic() - turn_start) * 1000),
            salvaged=salvaged,
        )

    def _salvage_native_assistant_text(self) -> str:
        for m in reversed(self._messages):
            if m.get("role") == "assistant" and m.get("content"):
                return str(m["content"])
        return ""

    # ── anthropic native (tool_use blocks) ────────────────────────────────────

    async def _iter_anthropic(self, question: str) -> AsyncIterator[Event]:
        from anthropic import AsyncAnthropic

        if not os.environ.get("ANTHROPIC_API_KEY"):
            yield Error(
                message="ANTHROPIC_API_KEY not set. Add it to .env or export it."
            )
            yield TurnComplete(turns_used=0, tool_calls=0, duration_ms=0)
            return

        if not self._anthropic_seeded:
            # System prompt is sent as a parameter (not inside messages) for
            # Anthropic. We track the seeding flag so we know to recompose it
            # if the profile is swapped mid-session.
            self._anthropic_seeded = True
        self._messages.append({"role": "user", "content": question})

        client = AsyncAnthropic()
        tool_specs = _tool_specs_to_anthropic(self.tools_available)
        system_blocks = [
            {
                "type": "text",
                "text": self._compose_system_prompt(),
                "cache_control": {"type": "ephemeral"},
            }
        ]
        max_tokens = 4096
        g = self.profile.generation

        turn_start = time.monotonic()
        turns_used = 0
        tool_calls_total = 0
        final_emitted = False

        for turn_idx in range(self.max_turns):
            yield TurnStart(turn_index=turn_idx)
            t0 = time.monotonic()

            # Coerce native-format history into Anthropic's expected shape.
            # Tool exchanges are folded into adjacent assistant messages as
            # plain text so (a) Anthropic gets clean user/assistant alternation
            # and (b) the new model can read what tools ran and what they
            # returned — without re-calling them.
            anthropic_messages = _coerce_native_history_for_anthropic(self._messages)
            kwargs: dict[str, Any] = {
                "model": self.profile.model_id,
                "max_tokens": max_tokens,
                "system": system_blocks,
                "messages": anthropic_messages,
                "tools": tool_specs,
            }
            if g.temperature is not None:
                kwargs["temperature"] = g.temperature

            text_parts: list[str] = []
            tool_uses: list[dict[str, Any]] = []
            stop_reason: str | None = None
            response_blocks: list[Any] = []

            if self.stream:
                async with client.messages.stream(**kwargs) as stream:
                    async for delta_text in stream.text_stream:
                        text_parts.append(delta_text)
                        yield TextDelta(text=delta_text)
                    final_msg = await stream.get_final_message()
                    response_blocks = list(final_msg.content)
                    stop_reason = final_msg.stop_reason
            else:
                resp = await client.messages.create(**kwargs)
                response_blocks = list(resp.content)
                stop_reason = resp.stop_reason

            for block in response_blocks:
                btype = getattr(block, "type", None)
                if btype == "text" and not self.stream:
                    text_parts.append(getattr(block, "text", ""))
                elif btype == "tool_use":
                    tool_uses.append(
                        {
                            "id": block.id,
                            "name": block.name,
                            "input": dict(block.input) if block.input else {},
                        }
                    )

            dur = int((time.monotonic() - t0) * 1000)
            content_text = "".join(text_parts) if self.stream else "\n".join(text_parts)
            yield AssistantText(text=content_text, duration_ms=dur)
            turns_used += 1

            # Append assistant turn to history — must include tool_use blocks
            # verbatim so the subsequent tool_result blocks resolve.
            # Strip parsed_output: the streaming path attaches it to TextBlocks
            # but the Anthropic API rejects it if it appears in a follow-up message.
            def _block_dict(b: Any) -> dict[str, Any]:
                d = b.model_dump()
                d.pop("parsed_output", None)
                return d

            self._messages.append(
                {"role": "assistant", "content": [_block_dict(b) for b in response_blocks]}
            )

            if stop_reason != "tool_use":
                if content_text:
                    yield FinalAnswer(text=content_text)
                    final_emitted = True
                else:
                    salvaged = self._salvage_anthropic_text()
                    yield FinalAnswer(text=salvaged)
                    final_emitted = True
                break

            tool_result_blocks: list[dict[str, Any]] = []
            for tu in tool_uses:
                call_id = tu["id"]
                yield ToolCall(call_id=call_id, name=tu["name"], args=tu["input"])
                tool_calls_total += 1

                if self.tool_gate is not None and tu["name"] not in self.tool_gate:
                    err = (
                        f'Tool "{tu["name"]}" is outside the active tool gate '
                        f"({sorted(self.tool_gate)})"
                    )
                    yield ToolResult(
                        call_id=call_id, name=tu["name"], result=err, elapsed_ms=0, error=err
                    )
                    tool_result_blocks.append(
                        {"type": "tool_result", "tool_use_id": call_id, "content": err}
                    )
                    continue

                t1 = time.monotonic()
                try:
                    result = await self._mcp.call_tool(tu["name"], tu["input"])
                    err = self._detect_error(result)
                except Exception as e:
                    result = f"{type(e).__name__}: {e}"
                    err = result
                tdur = int((time.monotonic() - t1) * 1000)
                yield ToolResult(
                    call_id=call_id, name=tu["name"], result=result, elapsed_ms=tdur, error=err
                )
                tool_result_blocks.append(
                    {"type": "tool_result", "tool_use_id": call_id, "content": result}
                )
            self._messages.append({"role": "user", "content": tool_result_blocks})

        else:
            salvaged = self._salvage_anthropic_text()
            if salvaged:
                yield FinalAnswer(text=salvaged)
                final_emitted = True
            yield Error(message=f"max_turns ({self.max_turns}) exhausted without final answer")

        if not final_emitted:
            yield FinalAnswer(text="")

        yield TurnComplete(
            turns_used=turns_used,
            tool_calls=tool_calls_total,
            duration_ms=int((time.monotonic() - turn_start) * 1000),
        )

    def _salvage_anthropic_text(self) -> str:
        # Walk back through messages looking for the most recent assistant
        # turn that contained text content.
        for m in reversed(self._messages):
            if m.get("role") != "assistant":
                continue
            content = m.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "")
                        if text:
                            return str(text)
        return ""

    # ── text-embedded (Gemma 3 Tools, etc.) ──────────────────────────────────

    async def _iter_text_embedded(self, question: str) -> AsyncIterator[Event]:
        # Streaming for this protocol is not supported in v1 — we'd have to
        # detect the tool fence within the stream. Tell the user.
        if self.stream:
            yield TextDelta(text="")  # noop, signals "we tried"
        if not self._native_seeded:
            self._messages = [
                {"role": "system", "content": self._compose_system_prompt()},
            ] + [m for m in self._messages if m.get("role") != "system"]
            self._native_seeded = True
        self._messages.append({"role": "user", "content": question})

        client = make_async_client()
        turn_start = time.monotonic()
        turns_used = 0
        tool_calls_total = 0
        final_emitted = False

        for turn_idx in range(self.max_turns):
            yield TurnStart(turn_index=turn_idx)
            t0 = time.monotonic()
            resp = await client.chat(
                model=self.profile.model_id,
                messages=self._messages,
                options=_ollama_options(self.profile),
            )
            dur = int((time.monotonic() - t0) * 1000)
            content = resp.message.content or ""
            yield AssistantText(text=content, duration_ms=dur)
            turns_used += 1

            calls = _extract_json_tool_calls(content) or [
                (m.group(1), m.group(2) or "{}")
                for m in TOOL_CALL_RE.finditer(content)
            ]

            self._messages.append({"role": "assistant", "content": content})

            if not calls:
                if content:
                    yield FinalAnswer(text=content)
                    final_emitted = True
                else:
                    yield Error(message="model produced empty content")
                break

            for raw_name, raw_args in calls:
                import json as _json

                call_id = f"call_{turn_idx}_{tool_calls_total}"
                try:
                    args = _json.loads(raw_args) if raw_args else {}
                except Exception:
                    args = {}
                yield ToolCall(call_id=call_id, name=raw_name, args=args)
                tool_calls_total += 1

                if self.tool_gate is not None and raw_name not in self.tool_gate:
                    err = (
                        f'Tool "{raw_name}" is outside the active tool gate '
                        f"({sorted(self.tool_gate)})"
                    )
                    yield ToolResult(
                        call_id=call_id, name=raw_name, result=err, elapsed_ms=0, error=err
                    )
                    self._messages.append({"role": "user", "content": f"<tool_result>{err}</tool_result>"})
                    continue

                t1 = time.monotonic()
                try:
                    result = await self._mcp.call_tool(raw_name, args)
                    err = self._detect_error(result)
                except Exception as e:
                    result = f"{type(e).__name__}: {e}"
                    err = result
                tdur = int((time.monotonic() - t1) * 1000)
                yield ToolResult(
                    call_id=call_id, name=raw_name, result=result, elapsed_ms=tdur, error=err
                )
                self._messages.append(
                    {"role": "user", "content": f"<tool_result>{result}</tool_result>"}
                )
        else:
            yield Error(message=f"max_turns ({self.max_turns}) exhausted without final answer")

        if not final_emitted:
            yield FinalAnswer(text="")

        yield TurnComplete(
            turns_used=turns_used,
            tool_calls=tool_calls_total,
            duration_ms=int((time.monotonic() - turn_start) * 1000),
        )

    # ── helpers ──────────────────────────────────────────────────────────────

    def _compose_system_prompt(self) -> str:
        return compose(self.profile, _build_context(self.profile, self.tools_available))

    @staticmethod
    def _detect_error(result_text: str) -> str | None:
        """Heuristic: detect tool errors from result text. The MCP tools we
        have today either return valid JSON / structured text on success or
        a leading ``Error:`` / ``Exception`` line on failure. We surface those
        to the renderer so it can mark the call red without parsing blindly."""
        if not result_text:
            return None
        lower = result_text.lstrip().lower()
        if lower.startswith(("error:", "exception:", "traceback")):
            return result_text.split("\n", 1)[0].strip()
        return None
