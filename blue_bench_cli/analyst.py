"""`blue-bench analyst` — interactive analyst console (CLI peer to the frontend).

The frontend's controls have flag/slash-command equivalents here:

==============  ==================================  =============================
Frontend                  Startup flag                In-REPL slash command
==============  ==================================  =============================
profile         `-p / --profile <name>`              `/profile <name>`
model override  `-m / --model <id>`                  `/model <id>`
tool gate       `-t / --tools <cat,cat>`             `/tools <cat,cat>` (empty = all)
==============  ==================================  =============================

History persists across turns by default. `/clear` resets the conversation;
profile/model/gate stay. Type `/help` inside the REPL for the full list.
"""
from __future__ import annotations

import asyncio
import json
import shlex
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.text import Text

from blue_bench_cli._sessions import (
    SessionState,
    auto_session_id,
    default_sessions_dir,
    ensure_sessions_dir,
    list_sessions,
    load_session,
    save_session,
    session_exists,
)
from blue_bench_cli._tool_categories import TOOL_CATEGORIES
from blue_bench_client.interactive import (
    AssistantText,
    EngagementScopeError,
    Error,
    FinalAnswer,
    InteractiveSession,
    TextDelta,
    ToolCall,
    ToolResult,
    TurnComplete,
    TurnStart,
)
from blue_bench_mcp.profiles import ModelProfile, load_profile
from blue_bench_mcp.task_classes import (
    TASK_CLASSES,
    TaskClass,
    UnknownTaskClassError,
    get_task_class,
)

REPO = Path(__file__).resolve().parent.parent
PROFILES_DIR = REPO / "blue_bench_mcp" / "profiles"
DEFAULT_CONFIG = REPO / "config.yaml"

console = Console()
err_console = Console(stderr=True)

CTX_WARN_FRAC = 0.75  # warn the analyst when history exceeds this share of context
CTX_HARD_FRAC = 0.95  # refuse to send when this share is exceeded
AUTO_COMPACT_FRAC = 0.70  # auto-trigger heuristic /compact at this share


# ── helpers ───────────────────────────────────────────────────────────────────

def _list_profiles() -> list[str]:
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))


def _parse_categories(arg: str | None) -> list[str] | None:
    """Validate a category-id list (e.g. ``"elastic,wazuh"``).

    Returns the parsed ids (preserving input order), or None for an empty/
    missing argument (= unrestricted gate). Raises ValueError on unknown ids.
    """
    if not arg:
        return None
    raw_ids = [c.strip() for c in arg.split(",") if c.strip()]
    if not raw_ids:
        return None
    valid = {c["id"] for c in TOOL_CATEGORIES}
    unknown = [c for c in raw_ids if c not in valid]
    if unknown:
        raise ValueError(
            f"unknown tool categor{'ies' if len(unknown) > 1 else 'y'}: "
            f"{sorted(set(unknown))}. Known: {sorted(valid)}"
        )
    # Dedupe but keep first occurrence.
    seen: set[str] = set()
    out: list[str] = []
    for c in raw_ids:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _categories_to_tools(category_ids: list[str] | None) -> set[str] | None:
    """Translate validated category ids to the union of MCP tool names."""
    if not category_ids:
        return None
    cat_ids = set(category_ids)
    tools: set[str] = set()
    for c in TOOL_CATEGORIES:
        if c["id"] in cat_ids:
            tools.update(c["tools"])
    return tools


def _resolve_gate(arg: str | None) -> set[str] | None:
    """Compatibility wrapper: parse + translate in one step."""
    return _categories_to_tools(_parse_categories(arg))


def _prompt_task_class(
    profile: ModelProfile,
    allow_disable: bool = False,
) -> "TaskClass | None | bool":
    """Interactive prompt for the engagement task class.

    Lists the profile's ``allowed_task_classes`` with verifiability annotation,
    accepts a number or name (case-insensitive).

    Returns:
      TaskClass  — the selected class
      None       — operator aborted (Ctrl+C / EOF); caller should make no change
      False      — operator explicitly picked "disable"; caller should clear binding
                   (only possible when allow_disable=True)
    """
    classes = list(profile.allowed_task_classes)
    if not classes:
        err_console.print(
            f"[red]profile {profile.name!r} declares no allowed_task_classes — "
            f"cannot start an engagement[/red]"
        )
        return None
    console.print(Text("Engagement task class", style="bold"))
    if allow_disable:
        console.print("  [0] (none)  disable task class")
    for i, c in enumerate(classes, 1):
        annot = "mechanically verifiable" if TASK_CLASSES[c].verifiable else "operator-led only"
        console.print(f"  [{i}] {c.value}  ({annot})")
    while True:
        try:
            answer = console.input("Select (number or name, Enter to cancel) > ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print()
            return None
        if not answer:
            return None  # empty Enter = cancel, no change
        if answer == "0" and allow_disable:
            return False  # sentinel: disable requested
        if answer.isdigit():
            idx = int(answer) - 1
            if 0 <= idx < len(classes):
                return classes[idx]
            err_console.print(f"[yellow]out of range; pick 0..{len(classes)}[/yellow]" if allow_disable else f"[yellow]out of range; pick 1..{len(classes)}[/yellow]")
            continue
        upper = answer.upper()
        if allow_disable and upper in ("NONE", "DISABLE"):
            return False
        for c in classes:
            if c.value == upper:
                return c
        err_console.print(
            f"[yellow]unknown class {answer!r}; allowed: "
            f"{', '.join(c.value for c in classes)}[/yellow]"
        )


def _gate_label(gate: set[str] | None) -> str:
    if gate is None:
        return "all tools"
    cat_labels: list[str] = []
    for c in TOOL_CATEGORIES:
        if any(t in gate for t in c["tools"]):
            cat_labels.append(c["label"])
    return ", ".join(cat_labels) or "(none)"


def _truncate(text: str, n: int = 80) -> str:
    text = text.replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _format_args_oneline(args: dict) -> str:
    if not args:
        return "(no args)"
    parts: list[str] = []
    for k, v in args.items():
        if isinstance(v, str):
            parts.append(f'{k}="{_truncate(v, 32)}"')
        else:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


DEEP_COMPACT_INSTRUCTION = (
    "You will be given the early portion of a security analyst's investigation. "
    "Write a concise summary of what was learned. Preserve specific findings "
    "literally: IPs, hostnames, port numbers, hashes, timestamps, signature names, "
    "process names, paths. Keep tool names and key arguments where they affect the "
    "conclusions. The summary will replace the early conversation in the analyst's "
    "working context, so future turns can reference earlier findings without "
    "re-querying. 2-3 paragraphs, no headings, no preamble — start with the facts."
)


def _render_messages_for_summary(messages: list[dict[str, Any]]) -> str:
    """Flatten the message list into a readable transcript for summarization."""
    lines: list[str] = []
    for m in messages:
        role = m.get("role", "?")
        c = m.get("content")
        if role == "system":
            continue  # the model knows its role; the recap doesn't need that
        if isinstance(c, str):
            label = role.upper()
            if role == "user" and c.lstrip().startswith("<tool_result>"):
                label = "TOOL_RESULT"
            lines.append(f"{label}: {c}")
        elif isinstance(c, list):
            for block in c:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    lines.append(f"{role.upper()}: {block.get('text', '')}")
                elif btype == "tool_use":
                    name = block.get("name", "?")
                    inp = block.get("input", {})
                    lines.append(f"ASSISTANT: [calls {name}({inp})]")
                elif btype == "tool_result":
                    body = str(block.get("content", ""))
                    lines.append(f"TOOL_RESULT: {body}")
    return "\n".join(lines)


async def _summarize_excerpt(profile: ModelProfile, excerpt: str) -> str:
    """Run a single non-tool inference under ``profile`` to summarize ``excerpt``."""
    user_msg = (
        f"{DEEP_COMPACT_INSTRUCTION}\n\n"
        f"Investigation excerpt:\n{excerpt}\n\n"
        "Summary:"
    )
    if profile.tool_protocol == "anthropic-native":
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic()
        resp = await client.messages.create(
            model=profile.model_id,
            max_tokens=1024,
            messages=[{"role": "user", "content": user_msg}],
            temperature=profile.generation.temperature,
        )
        out_parts: list[str] = []
        for block in resp.content:
            if getattr(block, "type", None) == "text":
                out_parts.append(getattr(block, "text", ""))
        return "\n".join(out_parts).strip()

    # native / text-embedded — both use Ollama under the hood
    import ollama

    client_o = ollama.AsyncClient()
    resp_o = await client_o.chat(
        model=profile.model_id,
        messages=[{"role": "user", "content": user_msg}],
        options={"temperature": profile.generation.temperature},
    )
    return (resp_o.message.content or "").strip()


async def compact_history_deep(
    profile: ModelProfile,
    messages: list[dict[str, Any]],
    *,
    keep_recent_user_turns: int = 2,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """LLM-driven compaction. Replaces ``messages[1..boundary]`` with a
    user/assistant pair carrying a synthesized summary. Costs one extra
    inference call.

    Returns ``(new_messages, stats)``. Stats keys:
      ``summarized_messages``, ``tokens_freed``, ``summary_chars``.
    Returns the original list unchanged when there's nothing to summarize.
    """
    user_prompt_indices: list[int] = []
    for i, m in enumerate(messages):
        if m.get("role") != "user":
            continue
        c = m.get("content")
        if isinstance(c, list):
            if all(
                isinstance(b, dict) and b.get("type") == "tool_result" for b in c
            ):
                continue
            user_prompt_indices.append(i)
        elif isinstance(c, str):
            if c.lstrip().startswith("<tool_result>"):
                continue
            user_prompt_indices.append(i)

    stats: dict[str, Any] = {"summarized_messages": 0, "tokens_freed": 0, "summary_chars": 0}
    if len(user_prompt_indices) <= keep_recent_user_turns:
        return list(messages), stats

    boundary = user_prompt_indices[-keep_recent_user_turns]
    head = messages[:boundary]
    tail = messages[boundary:]

    # Find the system message (if any). Native + text-embedded keep system
    # as messages[0]; Anthropic does not (it's sent out-of-band).
    system_msg: dict[str, Any] | None = None
    body = head
    if head and head[0].get("role") == "system":
        system_msg = head[0]
        body = head[1:]

    if not body:
        return list(messages), stats

    excerpt = _render_messages_for_summary(body)
    summary = await _summarize_excerpt(profile, excerpt)
    if not summary:
        # Empty completion — bail out rather than silently corrupt history.
        return list(messages), stats

    if profile.tool_protocol == "anthropic-native":
        recap_assistant = {
            "role": "assistant",
            "content": [{"type": "text", "text": summary}],
        }
    else:
        recap_assistant = {"role": "assistant", "content": summary}

    new: list[dict[str, Any]] = []
    if system_msg is not None:
        new.append(system_msg)
    new.append(
        {"role": "user", "content": "Earlier in this investigation, we established:"}
    )
    new.append(recap_assistant)
    new.extend(tail)

    def _est(seq: list[dict[str, Any]]) -> int:
        total = 0
        for mm in seq:
            cc = mm.get("content")
            if isinstance(cc, str):
                total += len(cc)
            elif isinstance(cc, list):
                for bb in cc:
                    if isinstance(bb, dict):
                        if "text" in bb:
                            total += len(str(bb["text"]))
                        elif "content" in bb:
                            total += len(str(bb["content"]))
        return total // 4

    stats["summarized_messages"] = len(body)
    stats["summary_chars"] = len(summary)
    stats["tokens_freed"] = max(0, _est(messages) - _est(new))
    return new, stats


def compact_history_heuristic(
    messages: list[dict[str, Any]],
    *,
    keep_recent_user_turns: int = 2,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Drop the bodies of tool results that predate the last N user turns.

    No LLM call. Replaces each old tool-result content with a short
    placeholder so the model still sees the *structure* of the conversation
    (it knows a tool ran) but not the bulk text. The most recent user-turn
    boundary is preserved verbatim so the analyst's current line of
    inquiry stays intact.

    Returns ``(new_messages, stats)``. Stats keys: ``compacted`` (count of
    tool-result entries shrunk), ``tokens_freed`` (estimated using the
    same char/4 heuristic as ``InteractiveSession.history_token_estimate``).

    No-op when there are fewer than ``keep_recent_user_turns + 1`` user
    turns — nothing to compact yet.
    """
    user_prompt_indices: list[int] = []
    for i, m in enumerate(messages):
        if m.get("role") != "user":
            continue
        c = m.get("content")
        if isinstance(c, list):
            # Anthropic: tool_result-only user messages are not real user turns.
            if all(
                isinstance(b, dict) and b.get("type") == "tool_result"
                for b in c
            ):
                continue
            user_prompt_indices.append(i)
        elif isinstance(c, str):
            # Text-embedded: tool_result wrappers are not real user turns.
            if c.lstrip().startswith("<tool_result>"):
                continue
            user_prompt_indices.append(i)

    stats = {"compacted": 0, "tokens_freed": 0}
    if len(user_prompt_indices) <= keep_recent_user_turns:
        return list(messages), stats

    boundary = user_prompt_indices[-keep_recent_user_turns]

    out: list[dict[str, Any]] = []
    for i, m in enumerate(messages):
        if i >= boundary:
            out.append(m)
            continue
        role = m.get("role")
        c = m.get("content")

        if role == "tool" and isinstance(c, str) and not c.startswith("[tool result"):
            old_chars = len(c)
            summary = f"[tool result · ~{old_chars:,}c, compacted]"
            out.append({**m, "content": summary})
            stats["compacted"] += 1
            stats["tokens_freed"] += max(0, (old_chars - len(summary)) // 4)
        elif role == "user" and isinstance(c, list):
            new_blocks: list[Any] = []
            changed = False
            for block in c:
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_result"
                    and isinstance(block.get("content"), str)
                    and not str(block["content"]).startswith("[tool result")
                ):
                    body = str(block["content"])
                    summary = f"[tool result · ~{len(body):,}c, compacted]"
                    new_blocks.append({**block, "content": summary})
                    stats["compacted"] += 1
                    stats["tokens_freed"] += max(0, (len(body) - len(summary)) // 4)
                    changed = True
                else:
                    new_blocks.append(block)
            out.append({**m, "content": new_blocks} if changed else m)
        elif (
            role == "user"
            and isinstance(c, str)
            and c.lstrip().startswith("<tool_result>")
            and "[compacted]" not in c
        ):
            old_chars = len(c)
            summary = "<tool_result>[compacted]</tool_result>"
            out.append({**m, "content": summary})
            stats["compacted"] += 1
            stats["tokens_freed"] += max(0, (old_chars - len(summary)) // 4)
        else:
            out.append(m)

    return out, stats


def _top_context_contributors(
    messages: list[dict[str, Any]],
    *,
    top_n: int = 3,
) -> list[tuple[str, int, str]]:
    """Return the largest messages in the live conversation history.

    Each result is ``(label, tokens_estimate, excerpt)``. The label
    classifies the message (``system``, ``user``, ``tool: search_alerts``,
    etc.) so the analyst can pinpoint *which* tool result is fattening
    context. Token count is the same char/4 heuristic the session uses
    elsewhere — accurate enough for triage."""
    sized: list[tuple[str, int, str]] = []
    for idx, m in enumerate(messages):
        role = m.get("role", "?")
        content = m.get("content")
        text_total = 0
        excerpt_src = ""

        if isinstance(content, str):
            text_total = len(content)
            excerpt_src = content
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if "text" in block:
                    text_total += len(str(block["text"]))
                    excerpt_src = excerpt_src or str(block["text"])
                elif "content" in block:
                    body = str(block["content"])
                    text_total += len(body)
                    excerpt_src = excerpt_src or body
                    # Anthropic tool_result blocks reference a tool_use_id —
                    # not human-readable, so don't use it for excerpt.

        # Refine the role label. Native: tool messages have role="tool".
        # Anthropic: tool_result blocks live inside a user-role message.
        label = role
        if role == "tool":
            # The first 60 chars of the result usually contains the tool
            # signature in our tools' return text (e.g. JSON head); but
            # we can't recover the tool name from here without joining
            # back to the prior tool_call. Show a generic label.
            label = "tool"
        elif role == "user" and isinstance(content, list):
            # Anthropic: user messages with tool_result blocks
            if any(
                isinstance(b, dict) and b.get("type") == "tool_result"
                for b in content
            ):
                label = "tool result"

        excerpt = _truncate(excerpt_src, 56)
        sized.append((label, text_total // 4, excerpt))

    sized.sort(key=lambda x: x[1], reverse=True)
    return sized[:top_n]


# ── auto-save ─────────────────────────────────────────────────────────────────

class AutoSaver:
    """Snapshots InteractiveSession + recorder state to disk after each turn.

    Default = on. Disabled when ``--no-save`` is passed; in that case the
    saver still exists but ``save()`` is a no-op so call sites don't need
    null checks. The ``session_id`` may be analyst-supplied (``--session``)
    or auto-generated.
    """

    def __init__(
        self,
        session_id: str,
        sessions_dir: Path,
        *,
        enabled: bool = True,
        name: Optional[str] = None,
    ) -> None:
        self.id = session_id
        self.sessions_dir = sessions_dir
        self.enabled = enabled
        self.name = name
        self.last_path: Optional[Path] = None
        self.started_at = time.time()

    def save(
        self,
        session: InteractiveSession,
        recorder: "TranscriptRecorder",
        active_category_ids: list[str] | None,
    ) -> None:
        if not self.enabled:
            return
        try:
            state = SessionState(
                id=self.id,
                profile_name=session.profile.name,
                model_id=session.profile.model_id,
                tool_protocol=session.profile.tool_protocol,
                tool_gate=active_category_ids,
                messages=list(session._messages),  # snapshot
                turns=list(recorder.turns),
                started_at=self.started_at,
                last_updated=time.time(),
                name=self.name,
            )
            self.last_path = save_session(state, self.sessions_dir)
        except Exception as e:  # pragma: no cover — disk full, permission, etc.
            err_console.print(
                f"[yellow]auto-save failed ({type(e).__name__}: {e}); "
                f"continuing without persistence[/yellow]"
            )


# ── transcript ────────────────────────────────────────────────────────────────

class TranscriptRecorder:
    """Append events to a session log; flush to JSON on demand."""

    def __init__(self, profile_name: str, model_id: str, tool_protocol: str) -> None:
        self.started_at = time.time()
        self.profile_name = profile_name
        self.model_id = model_id
        self.tool_protocol = tool_protocol
        self.turns: list[dict] = []
        self._current_turn: dict | None = None

    def begin_turn(self, question: str) -> None:
        self._current_turn = {
            "question": question,
            "started_at": time.time(),
            "events": [],
        }
        self.turns.append(self._current_turn)

    def record(self, event_type: str, payload: dict) -> None:
        if self._current_turn is not None:
            self._current_turn["events"].append({"type": event_type, **payload})

    def to_dict(self) -> dict:
        return {
            "schema": "blue-bench-analyst/1",
            "profile_name": self.profile_name,
            "model_id": self.model_id,
            "tool_protocol": self.tool_protocol,
            "started_at": self.started_at,
            "ended_at": time.time(),
            "turns": self.turns,
        }

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))


# ── live renderer ─────────────────────────────────────────────────────────────

class LiveRenderer:
    """Pretty-prints events as they arrive. Stateful across a turn.

    Streaming mode renders the model's reasoning as live Markdown via
    ``rich.Live``: headers, tables, and lists form in front of the analyst
    as tokens arrive. When a tool call interrupts a text segment, the live
    region is committed to scrollback (formatted), the tool card prints
    below, and a fresh live region opens for the next segment.

    Non-streaming mode buffers ``AssistantText`` and renders it as Markdown
    once at end of turn.
    """

    def __init__(
        self,
        *,
        quiet: bool = False,
        streamed: bool = True,
        session: "InteractiveSession | None" = None,
    ) -> None:
        self.quiet = quiet
        self.streamed = streamed
        self.session = session
        """Optional reference to the active session, used to render ctx %
        on the per-turn footer. None disables that fragment."""
        self._buffer = ""
        self._live: Live | None = None
        self._streamed_anything_this_turn = False

    def reset_turn(self) -> None:
        self._stop_live(commit=True)
        self._buffer = ""
        self._streamed_anything_this_turn = False

    def _start_live(self) -> None:
        if self._live is None:
            self._buffer = ""
            # transient=True: the live region clears on stop so the final
            # committed Markdown is printed cleanly to scrollback below.
            # vertical_overflow="crop": Rich shouldn't try to overflow — we
            # cap the renderable to a tail view ourselves so Live can always
            # repaint inside the viewport without spilling into scrollback.
            self._live = Live(
                Markdown(""),
                console=console,
                refresh_per_second=12,
                transient=True,
                vertical_overflow="crop",
            )
            self._live.start()

    def _live_max_lines(self) -> int:
        """Lines available for the live region. Leave headroom for the prompt
        and the tool-card row that may appear between segments."""
        return max(8, console.height - 4)

    def _tail_view(self, text: str) -> str:
        """Return the trailing slice of ``text`` whose source-line count fits
        in the live viewport. This is an approximation — markdown that renders
        wider than 1 source line per output line (tables, code blocks) may
        still get cropped — but it prevents the unbounded-growth case where
        the rendered output exceeds terminal height and Rich's cursor-up
        repaint loses coherence, leaking each frame into scrollback."""
        cap = self._live_max_lines()
        lines = text.split("\n")
        if len(lines) <= cap:
            return text
        return "\n".join(lines[-cap:])

    def _stop_live(self, *, commit: bool) -> None:
        """Stop the active Live region.

        With commit=True, after clearing the transient live region we print the
        final buffered Markdown to scrollback once. commit=False is for resets
        where the buffer is being discarded anyway."""
        if self._live is None:
            return
        buffered = self._buffer
        self._live.stop()
        self._live = None
        if commit and buffered:
            console.print(Markdown(buffered))

    def render(self, ev) -> None:
        if isinstance(ev, TurnStart):
            if not self.quiet:
                console.print(
                    Text(f"  turn {ev.turn_index} ── thinking…", style="dim"),
                    soft_wrap=True,
                )
        elif isinstance(ev, TextDelta):
            if not ev.text or not self.streamed:
                return
            self._start_live()
            self._buffer += ev.text
            self._streamed_anything_this_turn = True
            assert self._live is not None
            # Cap the live region to a tail view so it can always repaint
            # inside the viewport — the full markdown gets printed to
            # scrollback once when _stop_live commits.
            self._live.update(Markdown(self._tail_view(self._buffer)))
        elif isinstance(ev, AssistantText):
            # In streaming mode, AssistantText is just a backstop — the
            # text already showed via Live. Settle the live region.
            if self.streamed:
                self._stop_live(commit=True)
                self._buffer = ""
                return
            # Non-streaming: render the full content as Markdown once.
            if ev.text:
                console.print(Markdown(ev.text))
        elif isinstance(ev, ToolCall):
            # Commit any in-flight text so the tool card renders below it.
            self._stop_live(commit=True)
            self._buffer = ""
            console.print()
            console.print(
                Text("  tool ", style="cyan")
                + Text(f"{ev.name:<24}", style="bold cyan")
                + Text(f"  args  {_format_args_oneline(ev.args)}", style="dim"),
                soft_wrap=True,
            )
        elif isinstance(ev, ToolResult):
            mark = (
                Text("  ✗  ", style="bold red")
                if ev.error
                else Text("  ✓  ", style="bold green")
            )
            preview = Text(f"{ev.elapsed_ms:>4} ms", style="dim") + Text(
                "   →  ", style="dim"
            )
            if ev.error:
                preview += Text(_truncate(ev.error, 80), style="red")
            else:
                preview += Text(_truncate(ev.result, 80), style="dim")
            console.print(mark + preview, soft_wrap=True)
        elif isinstance(ev, FinalAnswer):
            # Streaming path: the live region already rendered the answer.
            # Non-streaming path: AssistantText already printed the markdown.
            # Either way, settle and don't re-render.
            self._stop_live(commit=True)
            if not self.streamed and not self._streamed_anything_this_turn and ev.text:
                # Belt-and-braces: the model produced a final answer with
                # no AssistantText event preceding it (rare, but possible
                # for some text-embedded paths). Render now.
                console.print(Markdown(ev.text))
        elif isinstance(ev, Error):
            self._stop_live(commit=True)
            console.print(Text(f"  error: {ev.message}", style="bold red"))
        elif isinstance(ev, TurnComplete):
            self._stop_live(commit=True)
            footer_text = Text("  ── ", style="dim") + Text(
                f"{ev.turns_used} turn(s) · {ev.tool_calls} tool call(s) · "
                f"{ev.duration_ms / 1000:.1f}s",
                style="dim",
            )
            if ev.salvaged:
                footer_text += Text(" · salvaged", style="dim")
            ctx_fragment = self._ctx_fragment()
            if ctx_fragment is not None:
                footer_text += Text(" · ", style="dim") + ctx_fragment
            footer_text += Text(" ──", style="dim")
            console.print()
            console.print(footer_text)

    def _ctx_fragment(self) -> Text | None:
        """Render the context-fill segment of the footer.

        Returns None when no session reference is available. Yellow at
        >=75% fill, red at >=95% — same thresholds as the in-session
        soft warn / hard refuse policy.
        """
        if self.session is None:
            return None
        ctx_max = self.session.profile.context_size
        if not ctx_max:
            return None
        used = self.session.history_token_estimate
        frac = used / ctx_max
        # Compact denominator: 131072 -> 131k, 200000 -> 200k.
        denom = f"{ctx_max // 1000}k"
        body = f"ctx {frac:.0%}/{denom}"
        if frac >= CTX_HARD_FRAC:
            return Text(body, style="bold red")
        if frac >= CTX_WARN_FRAC:
            return Text(body, style="yellow")
        return Text(body, style="dim")


# ── REPL ─────────────────────────────────────────────────────────────────────

SLASH_HELP = """\
[bold]Slash commands[/bold]
  /profile <name>      swap profile (history kept)
  /profiles            list available profiles
  /models              list pullable Ollama models (active marked with →)
  /sessions            list saved sessions (active marked with →)
  /load <id>           replace current state with a saved session
                       (confirms first if current has history)
  /model <id>          override model_id within current profile
  /tools <cat,cat>     restrict tools to these categories (empty = all)
  /tools               show current gate + full tool list (✓ active, ✗ gated out)
  /cats                list categories with their member tools
  /compact             drop bodies of tool results older than the
                       last 2 user turns (heuristic, no LLM call)
  /compact deep        ask the model to summarize earlier turns into
                       a recap; replaces them in context (1 LLM call)
  /undo                drop the last user prompt + its replies
                       (history rewinds one turn; tools called are
                       NOT re-runnable — model just won't see them)
  /clear               drop conversation context sent to model
                       (terminal scrollback stays; profile/gate kept)
  /save <name>         save session under a named slot
                       (use `--resume <name>` to load it later)
  /save <path>         write transcript JSON to a path
  /task-class          show current class, then pick a new one
  /task-class <name>   bind directly (e.g. /task-class ALERT_TRIAGE)
  /status              show profile, model, gate, history size
  /help                show this list
  /quit | /q | exit    exit
  Ctrl-C  during turn  abort (REPL stays alive)
  Ctrl-D  at prompt    exit
"""


class AnalystRepl:
    def __init__(
        self,
        session: InteractiveSession,
        *,
        recorder: TranscriptRecorder,
        renderer: LiveRenderer,
        autosaver: "AutoSaver",
        active_category_ids: list[str] | None,
        transcript_path: Path | None = None,
        auto_compact: bool = True,
    ) -> None:
        self.session = session
        self.recorder = recorder
        self.renderer = renderer
        self.autosaver = autosaver
        self.active_category_ids = active_category_ids
        self.transcript_path = transcript_path
        self.auto_compact = auto_compact

    def _print_status(self) -> None:
        from rich.progress import BarColumn, Progress, TextColumn

        ctx_max = self.session.profile.context_size
        used = self.session.history_token_estimate
        used_frac = used / ctx_max if ctx_max else 0.0
        console.print(
            Text("  profile  ", style="dim")
            + Text(self.session.profile.name, style="bold")
            + Text("    model  ", style="dim")
            + Text(self.session.profile.model_id, style="bold")
            + Text("    proto  ", style="dim")
            + Text(self.session.profile.tool_protocol, style="bold"),
            soft_wrap=True,
        )
        console.print(
            Text("  gate     ", style="dim")
            + Text(_gate_label(self.session.tool_gate), style="bold"),
            soft_wrap=True,
        )

        # Context fill bar.
        bar_color = (
            "red" if used_frac >= CTX_HARD_FRAC
            else "yellow" if used_frac >= CTX_WARN_FRAC
            else "green"
        )
        progress = Progress(
            TextColumn("  context  "),
            BarColumn(bar_width=30, complete_style=bar_color),
            TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
            TextColumn(
                f"[dim]~{used:,} / {ctx_max:,} tokens · "
                f"{self.session.history_message_count} msg(s)[/dim]"
            ),
            console=console,
            transient=False,
        )
        with progress:
            progress.add_task("ctx", total=100, completed=min(100.0, used_frac * 100))

        # Top-3 contributors to context size.
        contribs = _top_context_contributors(self.session._messages, top_n=3)
        if contribs:
            console.print(Text("  top context contributors:", style="dim"))
            for label, tokens, excerpt in contribs:
                console.print(
                    Text(f"    {tokens:>6,} ", style="bold yellow")
                    + Text(f"{label:<14} ", style="cyan")
                    + Text(excerpt, style="dim"),
                    soft_wrap=True,
                )

    def _list_categories(self) -> None:
        for c in TOOL_CATEGORIES:
            console.print(
                Text(f"  {c['id']:<10}", style="cyan")
                + Text(f"{c['label']:<28}", style="bold")
                + Text(f"  {', '.join(c['tools'])}", style="dim"),
                soft_wrap=True,
            )

    def _undo_last_turn(self) -> None:
        """Truncate _messages back to the state before the last user prompt.

        Drops the last user-prompt message + all messages that followed
        it (assistant turns, tool calls, tool results). The last completed
        turn before that point becomes the visible end of context."""
        msgs = self.session._messages
        last_user_idx: int | None = None
        for i in range(len(msgs) - 1, -1, -1):
            m = msgs[i]
            if m.get("role") != "user":
                continue
            c = m.get("content")
            if isinstance(c, list):
                # Anthropic: skip tool_result-wrapping user messages.
                if all(
                    isinstance(b, dict) and b.get("type") == "tool_result" for b in c
                ):
                    continue
            elif isinstance(c, str):
                # Text-embedded: skip tool-result wrappers.
                if c.lstrip().startswith("<tool_result>"):
                    continue
            last_user_idx = i
            break

        if last_user_idx is None:
            console.print(Text("  /undo: no prior user turn to drop", style="dim"))
            return

        dropped = msgs[last_user_idx:]
        prompt_preview = msgs[last_user_idx].get("content")
        if isinstance(prompt_preview, list):
            for b in prompt_preview:
                if isinstance(b, dict) and "text" in b:
                    prompt_preview = b["text"]
                    break
        prompt_preview = _truncate(str(prompt_preview), 56)

        self.session._messages = msgs[:last_user_idx]
        # Drop the matching transcript turn so /save reflects the undo too.
        if self.recorder.turns:
            self.recorder.turns = self.recorder.turns[:-1]

        kept_user_turns = sum(
            1
            for m in self.session._messages
            if m.get("role") == "user"
            and (
                (isinstance(m.get("content"), str) and not m["content"].lstrip().startswith("<tool_result>"))
                or (
                    isinstance(m.get("content"), list)
                    and any(
                        isinstance(b, dict) and b.get("type") != "tool_result"
                        for b in m["content"]
                    )
                )
            )
        )
        console.print(
            Text(
                f"  undone: \"{prompt_preview}\" "
                f"(dropped {len(dropped)} message(s); kept {kept_user_turns} earlier turn(s))",
                style="bold green",
            )
        )

    def _maybe_auto_compact(self) -> None:
        """If context is past AUTO_COMPACT_FRAC, run heuristic compaction
        and print a one-line yellow notification. No-op otherwise."""
        ctx_max = self.session.profile.context_size or 1
        before = self.session.history_token_estimate
        before_frac = before / ctx_max
        if before_frac < AUTO_COMPACT_FRAC:
            return
        new_messages, stats = compact_history_heuristic(self.session._messages)
        if stats["compacted"] == 0:
            return
        self.session._messages = new_messages
        after_frac = self.session.history_token_estimate / ctx_max
        console.print(
            Text(
                f"  ⚠ context {before_frac:.0%} — auto-compacted "
                f"{stats['compacted']} old tool result(s), freed "
                f"~{stats['tokens_freed']:,} tokens (now {after_frac:.0%})",
                style="yellow",
            )
        )

    def _compact_heuristic(self) -> None:
        ctx_max = self.session.profile.context_size or 1
        before = self.session.history_token_estimate
        new_messages, stats = compact_history_heuristic(self.session._messages)
        self.session._messages = new_messages
        after = self.session.history_token_estimate
        if stats["compacted"] == 0:
            console.print(
                Text(
                    "  /compact: nothing to compact yet (need 3+ user turns)",
                    style="dim",
                )
            )
            return
        console.print(
            Text(
                f"  compacted {stats['compacted']} old tool result(s), "
                f"freed ~{stats['tokens_freed']:,} tokens "
                f"(was {before / ctx_max:.0%}, now {after / ctx_max:.0%})",
                style="bold green",
            )
        )

    async def _compact_deep(self) -> None:
        """LLM-driven summarization. One extra inference call against the
        active profile; replaces older turns with a 2-3 paragraph recap."""
        ctx_max = self.session.profile.context_size or 1
        before = self.session.history_token_estimate
        console.print(
            Text("  /compact deep: summarizing earlier turns…", style="dim")
        )
        try:
            new_messages, stats = await compact_history_deep(
                self.session.profile, self.session._messages
            )
        except Exception as e:
            console.print(
                Text(f"  /compact deep failed: {type(e).__name__}: {e}", style="bold red")
            )
            return
        if stats["summarized_messages"] == 0:
            console.print(
                Text(
                    "  /compact deep: nothing to summarize yet (need 3+ user turns)",
                    style="dim",
                )
            )
            return
        self.session._messages = new_messages
        after = self.session.history_token_estimate
        console.print(
            Text(
                f"  summarized {stats['summarized_messages']} message(s) into "
                f"~{stats['summary_chars']:,}c recap; freed ~{stats['tokens_freed']:,} tokens "
                f"(was {before / ctx_max:.0%}, now {after / ctx_max:.0%})",
                style="bold green",
            )
        )

    def _has_active_history(self) -> bool:
        """True if the running session has anything worth confirming-before-discarding."""
        return self.session.history_message_count > 1  # > 1 = system + at least one user

    def _restore_session(self, session_id: str) -> None:
        """Replace the running session's state with a saved one in place.

        Keeps the running InteractiveSession (and its MCP connection) alive;
        we just swap out profile, model, tool gate, and message history.
        """
        try:
            loaded = load_session(session_id)
        except (ValueError, OSError) as e:
            console.print(f"[red]could not load {session_id!r}: {e}[/red]")
            return

        try:
            new_profile = load_profile(PROFILES_DIR / f"{loaded.profile_name}.yaml")
        except Exception as e:
            console.print(
                f"[red]session referenced profile {loaded.profile_name!r} which "
                f"could not be loaded: {e}[/red]"
            )
            return
        if loaded.model_id and loaded.model_id != new_profile.model_id:
            new_profile = new_profile.model_copy(update={"model_id": loaded.model_id})

        # Profile change — set it on the session, but pass keep_history=False
        # so it doesn't try to keep the *old* messages; we'll install the
        # loaded ones explicitly below.
        self.session.set_profile(new_profile, keep_history=False)
        self.session._messages = list(loaded.messages)
        self.session._native_seeded = bool(
            loaded.messages and loaded.messages[0].get("role") == "system"
        )
        self.session._anthropic_seeded = new_profile.tool_protocol == "anthropic-native"

        gate = _categories_to_tools(loaded.tool_gate) if loaded.tool_gate else None
        self.session.set_tool_gate(gate)
        self.active_category_ids = list(loaded.tool_gate) if loaded.tool_gate else None

        # Re-point the autosaver at this slot so subsequent turns continue
        # to update the loaded session, not the previous one.
        self.autosaver.id = loaded.id
        self.autosaver.name = loaded.name
        self.autosaver.started_at = loaded.started_at

        # Recorder: refresh metadata + replay the saved turns so /save (path)
        # produces a coherent transcript.
        self.recorder.turns = list(loaded.turns)
        self.recorder.profile_name = new_profile.name
        self.recorder.model_id = new_profile.model_id
        self.recorder.tool_protocol = new_profile.tool_protocol

        n_turns = sum(1 for t in loaded.turns if "events" in t)
        est = self.session.history_token_estimate
        console.print(
            Text(
                f"  loaded {loaded.id!r}: profile={new_profile.name}, "
                f"{n_turns} turn(s), ~{est:,} tokens",
                style="bold green",
            )
        )

    def _list_models_table(self) -> None:
        """Query Ollama for locally pulled tags and render as a table.

        These are the values that ``--model <id>`` or ``/model <id>`` accept.
        Anthropic models are profile-bound (swap via ``/profile``) so they
        are not listed here.
        """
        import os

        import httpx
        from rich.table import Table

        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"http://{host}"
        try:
            resp = httpx.get(f"{host}/api/tags", timeout=5.0)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            console.print(f"[red]could not reach Ollama at {host}: {e}[/red]")
            return

        models = data.get("models", [])
        if not models:
            console.print(Text("  (no models pulled)", style="dim"))
            console.print(Text("  pull one with `ollama pull <name>`", style="dim"))
            return

        active = self.session.profile.model_id
        table = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
        table.add_column("", width=2)
        table.add_column("name", style="cyan", overflow="fold")
        table.add_column("params", justify="right", style="bold")
        table.add_column("size", justify="right")
        table.add_column("quant", style="dim")
        table.add_column("modified", style="dim")

        # Sort: active first, then largest first
        models.sort(key=lambda m: (m.get("name") != active, -int(m.get("size", 0))))

        for m in models:
            name = m.get("name", "?")
            size_bytes = int(m.get("size", 0))
            size_gb = size_bytes / (1024 ** 3)
            details = m.get("details", {}) or {}
            params = details.get("parameter_size", "?")
            quant = details.get("quantization_level", "?")
            modified = m.get("modified_at", "")[:10]  # YYYY-MM-DD

            marker = "→" if name == active else " "
            table.add_row(marker, name, params, f"{size_gb:.1f} GB", quant, modified)

        console.print(table)
        console.print(
            Text(
                f"  swap with `/model <name>` (current: {active})",
                style="dim",
            )
        )

    def _list_sessions_table(self) -> None:
        """Render the saved-session library as a table, newest first."""
        from datetime import datetime, timezone
        from rich.table import Table

        rows = list_sessions()
        if not rows:
            console.print(Text("  (no saved sessions)", style="dim"))
            return
        active_id = self.autosaver.id
        table = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
        table.add_column("", width=2)
        table.add_column("id", style="cyan", overflow="fold")
        table.add_column("profile", style="bold")
        table.add_column("name", style="dim")
        table.add_column("turns", justify="right")
        table.add_column("~tokens", justify="right")
        table.add_column("last updated", style="dim")
        for s in rows:
            marker = "→" if s.id == active_id else " "
            tokens_est = sum(
                len(str(m.get("content", ""))) for m in s.messages
            ) // 4
            n_turns = sum(1 for t in s.turns if "events" in t)
            try:
                ts = datetime.fromtimestamp(s.last_updated, tz=timezone.utc)
                last_label = ts.strftime("%Y-%m-%d %H:%M")
            except (TypeError, ValueError, OSError):
                last_label = "?"
            table.add_row(
                marker,
                s.id,
                s.profile_name,
                s.name or "",
                str(n_turns),
                f"{tokens_est:,}",
                last_label,
            )
        console.print(table)

    def _list_profiles(self) -> None:
        active = self.session.profile.name
        for name in _list_profiles():
            marker = "→" if name == active else " "
            style = "bold green" if name == active else "dim"
            console.print(Text(f"  {marker} {name}", style=style))

    async def _handle_slash(self, line: str) -> bool:
        """Returns True if the REPL should exit."""
        parts = shlex.split(line)
        if not parts:
            return False
        cmd, *args = parts
        if cmd in ("/quit", "/q"):
            return True
        if cmd == "/help":
            console.print(SLASH_HELP)
            return False
        if cmd == "/status":
            self._print_status()
            return False
        if cmd == "/cats":
            self._list_categories()
            return False
        if cmd == "/profiles":
            self._list_profiles()
            return False
        if cmd == "/models":
            self._list_models_table()
            return False
        if cmd == "/sessions":
            self._list_sessions_table()
            return False
        if cmd == "/load":
            if not args:
                console.print("[red]usage: /load <id>[/red]")
                return False
            target_id = args[0]
            if not session_exists(target_id):
                console.print(
                    Text(
                        f"  no session named {target_id!r} (try /sessions)",
                        style="red",
                    )
                )
                return False
            # If we already have meaningful history, confirm — replacing
            # mid-investigation should not be silent.
            if self._has_active_history():
                resp = console.input(
                    "[yellow]  current session has history that will be replaced. "
                    "Continue?[/yellow] [y/N] "
                )
                if resp.strip().lower() not in ("y", "yes"):
                    console.print(Text("  /load aborted", style="dim"))
                    return False
            self._restore_session(target_id)
            return False
        if cmd == "/profile":
            if not args:
                console.print("[red]usage: /profile <name>[/red]")
                return False
            name = args[0]
            try:
                new_profile = load_profile(PROFILES_DIR / f"{name}.yaml")
            except Exception as e:
                console.print(f"[red]could not load profile {name!r}: {e}[/red]")
                return False
            old_proto = self.session.profile.tool_protocol
            new_proto = new_profile.tool_protocol
            warn_proto = old_proto != new_proto
            if warn_proto:
                console.print(
                    Text(
                        f"  warning: protocol changes ({old_proto} → {new_proto}); "
                        f"history is kept but the new model may misread it.",
                        style="yellow",
                    )
                )
            self.session.set_profile(new_profile, keep_history=True)
            self.recorder.profile_name = new_profile.name
            self.recorder.model_id = new_profile.model_id
            self.recorder.tool_protocol = new_profile.tool_protocol
            console.print(
                Text(
                    f"  profile → {new_profile.name} ({new_profile.model_id})",
                    style="bold green",
                )
            )
            return False
        if cmd == "/model":
            if not args:
                console.print("[red]usage: /model <id>[/red]")
                return False
            new_id = args[0]
            self.session.set_model_id(new_id)
            self.recorder.model_id = new_id
            console.print(Text(f"  model → {new_id}", style="bold green"))
            return False
        if cmd == "/tools":
            if not args or args[0] in ("", "show"):
                gate = self.session.tool_gate
                all_tools = self.session.all_tools
                if gate is None:
                    console.print(
                        Text(
                            f"  gate: all tools ({len(all_tools)})",
                            style="bold green",
                        )
                    )
                else:
                    console.print(
                        Text(
                            f"  gate: {_gate_label(gate)} ({len(gate)} of "
                            f"{len(all_tools)} tools)",
                            style="bold green",
                        )
                    )
                for t in sorted(all_tools, key=lambda x: x.name):
                    if gate is None or t.name in gate:
                        console.print(f"    [green]✓[/green] {t.name}")
                    else:
                        console.print(f"    [dim]✗ {t.name}[/dim]")
                return False
            try:
                cat_ids = _parse_categories(args[0])
                gate = _categories_to_tools(cat_ids)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                return False
            self.session.set_tool_gate(gate)
            self.active_category_ids = cat_ids
            console.print(
                Text(
                    f"  gate → {_gate_label(gate)} ("
                    f"{'all' if gate is None else len(gate)} tools)",
                    style="bold green",
                )
            )
            return False
        if cmd == "/clear":
            self.session.clear_history()
            console.print(Text("  history cleared", style="bold green"))
            return False
        if cmd == "/undo":
            self._undo_last_turn()
            return False
        if cmd == "/compact":
            mode = (args[0] if args else "").lower()
            if mode == "deep":
                await self._compact_deep()
                return False
            self._compact_heuristic()
            return False
        if cmd == "/save":
            if not args:
                console.print(
                    "[red]usage: /save <name>          # session, named slot[/red]"
                )
                console.print(
                    "[red]       /save <path/to.json>  # transcript only[/red]"
                )
                return False
            arg = args[0]
            looks_like_path = (
                "/" in arg or "\\" in arg or arg.startswith("~") or arg.endswith(".json")
            )
            if looks_like_path:
                path = Path(arg).expanduser()
                self.recorder.save(path)
                console.print(
                    Text(f"  transcript → {path}", style="bold green")
                )
                return False
            # Treat the argument as a session name. Save full session state
            # (profile + gate + messages + turns) under the named slot so
            # /load <name> or --resume <name> can pick it up later.
            try:
                sessions_dir = ensure_sessions_dir()
                state = SessionState(
                    id=arg,
                    profile_name=self.session.profile.name,
                    model_id=self.session.profile.model_id,
                    tool_protocol=self.session.profile.tool_protocol,
                    tool_gate=self.active_category_ids,
                    messages=list(self.session._messages),
                    turns=list(self.recorder.turns),
                    started_at=self.autosaver.started_at,
                    last_updated=time.time(),
                    name=arg,
                )
                target = save_session(state, sessions_dir)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                return False
            # Switch the autosaver onto the new id so subsequent turns
            # continue updating this slot, not the previous auto-id.
            self.autosaver.id = arg
            self.autosaver.name = arg
            console.print(
                Text(f"  session → {target}", style="bold green")
            )
            console.print(
                Text(
                    f"  next turns auto-save here; resume later with "
                    f"`blue-bench analyst --resume {arg}`",
                    style="dim",
                )
            )
            return False
        if cmd == "/task-class":
            profile = self.session.profile
            if args:
                # /task-class <NAME> — bind directly. set_task_class re-validates
                # against profile.allowed_task_classes when require_task_class is on.
                try:
                    self.session.set_task_class(args[0])
                except (UnknownTaskClassError, EngagementScopeError) as e:
                    console.print(f"[red]{e}[/red]")
                    return False
                console.print(
                    Text(f"  task class → {self.session.task_class.value}", style="bold green")
                )
            else:
                # /task-class — show current, then offer interactive pick
                tc = self.session.task_class
                if tc:
                    console.print(Text(f"  current: {tc.value}", style="dim"))
                elif not profile.require_task_class:
                    console.print(Text("  current: (optional for this profile)", style="dim"))
                else:
                    console.print(Text("  current: (unbound)", style="dim"))
                picked = _prompt_task_class(profile, allow_disable=tc is not None)
                if picked is False:
                    self.session.set_task_class(None)
                    console.print(Text("  task class cleared", style="bold green"))
                elif picked is not None:
                    try:
                        self.session.set_task_class(picked)
                    except EngagementScopeError as e:
                        console.print(f"[red]{e}[/red]")
                        return False
                    console.print(Text(f"  task class → {picked.value}", style="bold green"))
            return False
        console.print(f"[red]unknown command: {cmd} (try /help)[/red]")
        return False

    def _check_context_window(self) -> bool:
        """Returns False (= refuse to send) when context is over the hard cap."""
        ctx_max = self.session.profile.context_size
        if not ctx_max:
            return True
        frac = self.session.history_token_estimate / ctx_max
        if frac >= CTX_HARD_FRAC:
            console.print(
                Text(
                    f"  context too full ({frac:.0%} of {ctx_max:,}). "
                    f"Use /clear or /save && /clear to continue.",
                    style="bold red",
                )
            )
            return False
        if frac >= CTX_WARN_FRAC:
            console.print(
                Text(
                    f"  warning: context at {frac:.0%} of {ctx_max:,}; "
                    f"consider /clear soon.",
                    style="yellow",
                )
            )
        return True

    async def loop(self) -> None:
        try:
            import readline  # noqa: F401  enables history + line editing
        except ImportError:
            pass

        # Greeting
        console.print()
        console.print(Text("  Blue-Bench Analyst", style="bold"))
        self._print_status()
        console.print(Text("  type /help for commands. ctrl-d or /quit to exit.\n", style="dim"))

        while True:
            try:
                line = console.input("[bold cyan]>[/bold cyan] ").strip()
            except EOFError:
                console.print()
                break
            except KeyboardInterrupt:
                console.print()
                continue

            if not line:
                continue

            if line.startswith("/") or line in ("quit", "exit"):
                if line in ("quit", "exit"):
                    line = "/quit"
                if await self._handle_slash(line):
                    break
                continue

            if not self._check_context_window():
                continue

            self.recorder.begin_turn(line)
            self.renderer.reset_turn()

            cancelled = False
            try:
                async for ev in self.session.iter_turn(line):
                    self.renderer.render(ev)
                    self._record_event(ev)
            except (KeyboardInterrupt, asyncio.CancelledError):
                cancelled = True
                console.print(Text("\n  ⏸  aborted by user", style="yellow"))
            except Exception as e:
                console.print(Text(f"\n  unhandled: {type(e).__name__}: {e}", style="bold red"))

            # Auto-compact when context fills up. Heuristic only — auto-deep
            # would be a surprising LLM call. Self-resolves quickly because
            # heuristic compaction always pulls below the threshold.
            if self.auto_compact:
                self._maybe_auto_compact()

            # Auto-save the full session state (opt-out via --no-save).
            self.autosaver.save(self.session, self.recorder, self.active_category_ids)

            if self.transcript_path:
                self.recorder.save(self.transcript_path)

    def _record_event(self, ev) -> None:
        if isinstance(ev, ToolCall):
            self.recorder.record("tool_call", {"name": ev.name, "args": ev.args, "call_id": ev.call_id})
        elif isinstance(ev, ToolResult):
            self.recorder.record(
                "tool_result",
                {
                    "call_id": ev.call_id,
                    "name": ev.name,
                    "elapsed_ms": ev.elapsed_ms,
                    "error": ev.error,
                    "result": ev.result,
                },
            )
        elif isinstance(ev, FinalAnswer):
            self.recorder.record("final_answer", {"text": ev.text})
        elif isinstance(ev, Error):
            self.recorder.record("error", {"message": ev.message})
        elif isinstance(ev, TurnComplete):
            self.recorder.record(
                "turn_complete",
                {
                    "turns_used": ev.turns_used,
                    "tool_calls": ev.tool_calls,
                    "duration_ms": ev.duration_ms,
                    "salvaged": ev.salvaged,
                },
            )


# ── single-shot mode ─────────────────────────────────────────────────────────

async def _run_single_shot(
    session: InteractiveSession,
    question: str,
    renderer: LiveRenderer,
    recorder: TranscriptRecorder,
    autosaver: "AutoSaver",
    active_category_ids: list[str] | None,
    transcript_path: Path | None,
) -> int:
    recorder.begin_turn(question)
    rc = 0
    async for ev in session.iter_turn(question):
        renderer.render(ev)
        if isinstance(ev, Error):
            rc = 1
        if isinstance(ev, ToolCall):
            recorder.record("tool_call", {"name": ev.name, "args": ev.args, "call_id": ev.call_id})
        elif isinstance(ev, ToolResult):
            recorder.record(
                "tool_result",
                {
                    "call_id": ev.call_id,
                    "name": ev.name,
                    "elapsed_ms": ev.elapsed_ms,
                    "error": ev.error,
                    "result": ev.result,
                },
            )
        elif isinstance(ev, FinalAnswer):
            recorder.record("final_answer", {"text": ev.text})
        elif isinstance(ev, TurnComplete):
            recorder.record(
                "turn_complete",
                {
                    "turns_used": ev.turns_used,
                    "tool_calls": ev.tool_calls,
                    "duration_ms": ev.duration_ms,
                },
            )
    autosaver.save(session, recorder, active_category_ids)
    if transcript_path:
        recorder.save(transcript_path)
    return rc


# ── entry point ──────────────────────────────────────────────────────────────

async def _amain(
    profile_name: str | None,
    model: str | None,
    tools: str | None,
    config_path: Path,
    max_turns: int,
    transcript: Path | None,
    quiet: bool,
    no_history: bool,
    stream: bool,
    prompt: str | None,
    session_name: str | None,
    no_save: bool,
    resume_id: str | None,
    no_auto_compact: bool,
    task_class: str | None,
) -> int:
    # ── Resume an existing session, if requested ────────────────────────────
    resumed: SessionState | None = None
    if resume_id:
        sessions_dir_for_load = ensure_sessions_dir()
        if not session_exists(resume_id, sessions_dir_for_load):
            err_console.print(
                f"[red]no session named {resume_id!r} in {sessions_dir_for_load}[/red]"
            )
            sample = list_sessions(sessions_dir_for_load)[:5]
            if sample:
                err_console.print("[dim]nearby sessions:[/dim]")
                for s in sample:
                    err_console.print(f"  [dim]{s.id}[/dim]  ({s.profile_name})")
            else:
                err_console.print("[dim](no sessions found)[/dim]")
            return 2
        try:
            resumed = load_session(resume_id, sessions_dir_for_load)
        except (ValueError, OSError) as e:
            err_console.print(f"[red]could not load session {resume_id!r}: {e}[/red]")
            return 2

    # ── Determine the effective profile ────────────────────────────────────
    if resumed is not None and not profile_name:
        profile_name = resumed.profile_name
    if not profile_name:
        err_console.print(
            "[red]--profile is required (or pass --resume <id> to load a saved session)[/red]"
        )
        return 2

    profile = load_profile(PROFILES_DIR / f"{profile_name}.yaml")
    if resumed is not None and resumed.model_id and resumed.profile_name == profile_name:
        # Restore the per-session model_id override that may have been set
        # via /model in the prior session.
        profile = profile.model_copy(update={"model_id": resumed.model_id})
    if model:
        if profile.tool_protocol == "anthropic-native":
            err_console.print(
                "[yellow]warning: --model override on anthropic-native profile is "
                "ignored; use a different --profile to switch Anthropic models.[/yellow]"
            )
        else:
            profile = profile.model_copy(update={"model_id": model})

    # ── Task class: --task-class > interactive prompt (only when required) ──
    # If --task-class is explicitly passed, always validate and bind it — even
    # on profiles where require_task_class=False, since the operator opted in.
    # If require_task_class=True and no class given, prompt or fail.
    bound_class: TaskClass | None = None
    if task_class:
        try:
            bound_class = get_task_class(task_class).name
        except UnknownTaskClassError as e:
            err_console.print(f"[red]{e}[/red]")
            return 2
        if (
            profile.require_task_class
            and bound_class not in profile.allowed_task_classes
        ):
            permitted = ", ".join(c.value for c in profile.allowed_task_classes)
            err_console.print(
                f"[red]task class {bound_class.value!r} is not permitted by profile "
                f"{profile.name!r}. permitted: {permitted}[/red]"
            )
            return 2
    elif profile.require_task_class:
        prompted = _prompt_task_class(profile)
        if prompted is None:
            err_console.print("[red]task class required — engagement not started[/red]")
            return 2
        bound_class = prompted
        if bound_class not in profile.allowed_task_classes:
            permitted = ", ".join(c.value for c in profile.allowed_task_classes)
            err_console.print(
                f"[red]task class {bound_class.value!r} is not permitted by profile "
                f"{profile.name!r}. permitted: {permitted}[/red]"
            )
            return 2

    # ── Tool gate: --tools overrides resumed gate; otherwise inherit ───────
    try:
        category_ids = _parse_categories(tools)
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        return 2
    if category_ids is None and resumed is not None and resumed.tool_gate:
        category_ids = list(resumed.tool_gate)
    gate = _categories_to_tools(category_ids)

    sessions_dir = ensure_sessions_dir() if not no_save else default_sessions_dir()
    session_id = (
        resume_id if resumed is not None else (session_name or auto_session_id(profile.name))
    )
    autosaver = AutoSaver(
        session_id=session_id,
        sessions_dir=sessions_dir,
        enabled=not no_save,
        name=session_name or (resumed.name if resumed else None),
    )
    if resumed is not None:
        # Carry the original started_at forward so the session preserves a
        # consistent timeline instead of appearing to "start" on every resume.
        autosaver.started_at = resumed.started_at

    async with InteractiveSession(
        profile,
        config_path=config_path,
        max_turns=max_turns,
        tool_gate=gate,
        stream=stream,
        task_class=bound_class,
    ) as session:
        console.print(Text(session.banner(), style="dim"))
        recorder = TranscriptRecorder(profile.name, profile.model_id, profile.tool_protocol)
        renderer = LiveRenderer(quiet=quiet, streamed=stream, session=session)

        # Restore prior history before any iter_turn call. We populate
        # _messages directly and mark the seeded flags so the next turn
        # does not re-prepend a fresh system prompt onto the loaded one.
        if resumed is not None:
            session._messages = list(resumed.messages)
            session._native_seeded = bool(
                resumed.messages
                and resumed.messages[0].get("role") == "system"
            )
            session._anthropic_seeded = profile.tool_protocol == "anthropic-native"
            recorder.turns = list(resumed.turns)
            est_tokens = session.history_token_estimate
            user_turns = sum(1 for t in resumed.turns if "events" in t)
            console.print(
                Text(
                    f"  resumed: {user_turns} turn(s), ~{est_tokens:,} tokens, "
                    f"{len(resumed.messages)} message(s)",
                    style="bold green",
                )
            )

        if not no_save:
            console.print(
                Text(f"  session id: {session_id}  (auto-saved to {sessions_dir})", style="dim")
            )

        if prompt:
            return await _run_single_shot(
                session, prompt, renderer, recorder, autosaver, category_ids, transcript
            )

        repl = AnalystRepl(
            session,
            recorder=recorder,
            renderer=renderer,
            autosaver=autosaver,
            active_category_ids=category_ids,
            transcript_path=transcript,
            auto_compact=not no_auto_compact,
        )
        try:
            await repl.loop()
        finally:
            # Final write on exit so a graceful /quit also reflects the latest state.
            autosaver.save(session, recorder, repl.active_category_ids)
            if transcript:
                recorder.save(transcript)
        if no_history:
            session.clear_history()  # cosmetic — session is about to exit anyway
        return 0


def cli(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Profile YAML stem (e.g. gemma4-e4b). Required unless --resume is given."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override model_id within the profile"),
    tools: Optional[str] = typer.Option(None, "--tools", "-t", help="Comma-separated category IDs (e.g. elastic,wazuh)"),
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="MCP server config.yaml"),
    max_turns: int = typer.Option(10, "--max-turns", help="Tool-calling rounds per analyst turn"),
    transcript: Optional[Path] = typer.Option(None, "--transcript", help="Write session transcript JSON on exit"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress per-tool live rendering"),
    no_history: bool = typer.Option(False, "--no-history", help="Don't carry history across turns"),
    no_stream: bool = typer.Option(False, "--no-stream", help="Disable token streaming (render after each turn)"),
    prompt: Optional[str] = typer.Option(None, "--prompt", help="Run a single question and exit (skip the REPL)"),
    session_name: Optional[str] = typer.Option(
        None, "--session", help="Name this session (otherwise auto: timestamp-profile)"
    ),
    no_save: bool = typer.Option(
        False, "--no-save", help="Disable auto-save to ~/.blue-bench/sessions/"
    ),
    resume_id: Optional[str] = typer.Option(
        None, "--resume", help="Resume a saved session by id (see /sessions for the list)"
    ),
    no_auto_compact: bool = typer.Option(
        False, "--no-auto-compact", help="Disable auto-compact at 70% context fill"
    ),
    task_class: Optional[str] = typer.Option(
        None,
        "--task-class",
        "-T",
        help=(
            "Engagement task class (e.g. ALERT_TRIAGE, SIGMA_DRAFT, IOC_EXTRACTION). "
            "Prompted interactively if not provided. Required — no silent defaulting."
        ),
    ),
) -> None:
    """Interactive analyst console. Same controls as the browser frontend."""
    rc = asyncio.run(
        _amain(
            profile_name=profile,
            model=model,
            tools=tools,
            config_path=config,
            max_turns=max_turns,
            transcript=transcript,
            quiet=quiet,
            no_history=no_history,
            stream=not no_stream,
            prompt=prompt,
            session_name=session_name,
            no_save=no_save,
            resume_id=resume_id,
            no_auto_compact=no_auto_compact,
            task_class=task_class,
        )
    )
    raise typer.Exit(rc)
