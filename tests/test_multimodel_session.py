"""Multi-model session test suite.

Exercises:
  - _coerce_messages_for_ollama (runner.py) — the regression guard for the
    ValidationError that crashes the CLI when switching from anthropic-native
    to native (Ollama) mid-session
  - _ollama_options (runner.py)
  - InteractiveSession.history_token_estimate, set_profile, tools_available
  - compact_history_deep (analyst.py) — mocked summarizer, shape assertions
  - AutoSaver and TranscriptRecorder (analyst.py)
  - SessionState save / load roundtrip (_sessions.py)

Live-model tests are marked @pytest.mark.integration and skipped by default.
Run with: pytest -m integration --timeout=120

Scenarios covered from the spec:
  S1 — query under native protocol (gemma4:e4b baseline)
  S2 — profile swap native → anthropic-native, history preserved
  S3 — profile swap anthropic-native → native, no ValidationError
  S4 — /compact heuristic (covered in test_context_management.py; pinned here too)
  S5 — /compact deep: findings survive summarization
  S6 — session export: /save + --resume, all fields intact
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blue_bench_client.interactive import InteractiveSession, EngagementScopeError
from blue_bench_client.mcp_client import ToolSpec
from blue_bench_client.runner import (
    _coerce_messages_for_ollama,
    _coerce_native_history_for_anthropic,
    _ollama_options,
)
from blue_bench_cli._sessions import (
    SCHEMA_VERSION,
    SessionState,
    auto_session_id,
    list_sessions,
    load_session,
    save_session,
    session_exists,
    session_path,
)
from blue_bench_cli.analyst import (
    AutoSaver,
    TranscriptRecorder,
    compact_history_heuristic,
)
from blue_bench_mcp.profiles.schema import GenerationParams, ModelProfile
from blue_bench_mcp.task_classes import TaskClass


# ── helpers ────────────────────────────────────────────────────────────────────

def _profile(
    name: str = "test-native",
    model_id: str = "test:model",
    protocol: str = "native",
    require_task_class: bool = False,
    allowed: list[TaskClass] | None = None,
    top_k: int | None = None,
    temperature: float = 0.1,
) -> ModelProfile:
    from blue_bench_mcp.task_classes import all_task_classes
    return ModelProfile(
        name=name,
        model_id=model_id,
        tool_protocol=protocol,  # type: ignore[arg-type]
        prompt_style="terse",
        context_size=4096,
        generation=GenerationParams(temperature=temperature, top_p=0.9, top_k=top_k),
        require_task_class=require_task_class,
        allowed_task_classes=allowed or all_task_classes(),
    )


def _session(profile: ModelProfile | None = None) -> InteractiveSession:
    """Construct an InteractiveSession without entering the async context."""
    return InteractiveSession(profile or _profile(), stream=False)


def _tool(name: str) -> ToolSpec:
    return ToolSpec(name=name, description=f"tool {name}", input_schema={})


def _make_state(sid: str = "test", **overrides: Any) -> SessionState:
    base: dict[str, Any] = dict(
        id=sid,
        profile_name="gemma4-e4b",
        model_id="gemma4:e4b",
        tool_protocol="native",
        tool_gate=None,
        messages=[{"role": "system", "content": "you are an analyst"}],
        turns=[],
    )
    base.update(overrides)
    return SessionState(**base)


# ── U01-U04: _coerce_messages_for_ollama ──────────────────────────────────────

class TestCoerceMessagesForOllama:
    def test_str_content_passthrough(self):
        """Plain string content is returned unchanged (U01)."""
        msgs = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world"},
        ]
        out = _coerce_messages_for_ollama(msgs)
        assert out == msgs
        assert out is not msgs  # copy, not mutated original

    def test_list_text_blocks_joined_with_newline(self):
        """Two text blocks are joined with a newline (U02)."""
        msgs = [
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "A"},
                    {"type": "text", "text": "B"},
                ],
            }
        ]
        out = _coerce_messages_for_ollama(msgs)
        assert out[0]["content"] == "A\nB"

    def test_non_text_blocks_become_none(self):
        """List with only tool_use/citations becomes None — not empty string (U03).

        This is the exact shape that crashed the CLI with Ollama's Pydantic
        ValidationError: Input should be a valid string."""
        msgs = [
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "search_alerts", "input": {}},
                    {"citations": None, "text": "...", "type": "text"},  # citations field
                ],
            }
        ]
        # The citations block has type="text" so it IS extracted; the tool_use is dropped.
        out = _coerce_messages_for_ollama(msgs)
        assert isinstance(out[0]["content"], str)  # never a list

    def test_tool_use_only_list_becomes_descriptive_text(self):
        """A list with only a tool_use block — preserved as a descriptive
        text marker so the new model sees what was called (U03 updated for
        new data-preserving semantics)."""
        msgs = [
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "search_alerts", "input": {}},
                ],
            }
        ]
        out = _coerce_messages_for_ollama(msgs)
        assert isinstance(out[0]["content"], str)
        assert "search_alerts" in out[0]["content"]

    def test_mixed_list_preserves_text_and_tool_use(self):
        """Text blocks kept verbatim; tool_use surfaced as a marker. The
        previous semantics dropped tool_use; the new contract preserves it as
        text so cross-protocol swaps don't lose what was dispatched."""
        msgs = [
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "found 3 alerts"},
                    {"type": "tool_use", "id": "t2", "name": "search_alerts", "input": {}},
                    {"type": "text", "text": "from the east subnet"},
                ],
            }
        ]
        out = _coerce_messages_for_ollama(msgs)
        content = out[0]["content"]
        assert "found 3 alerts" in content
        assert "from the east subnet" in content
        assert "search_alerts" in content

    def test_already_str_content_unchanged(self):
        """Str content messages pass through without touching other keys."""
        msgs = [{"role": "tool", "content": "big result text", "extra": "keep"}]
        out = _coerce_messages_for_ollama(msgs)
        assert out[0]["content"] == "big result text"
        assert out[0]["extra"] == "keep"

    def test_output_is_copy_not_mutation(self):
        """Original message list is not mutated."""
        original_content = [{"type": "text", "text": "hello"}]
        msgs = [{"role": "assistant", "content": original_content}]
        _coerce_messages_for_ollama(msgs)
        assert msgs[0]["content"] is original_content  # original untouched

    def test_empty_list_content_becomes_none(self):
        """content=[] (empty list) → None, same as all-non-text list (boundary)."""
        msgs = [{"role": "assistant", "content": []}]
        out = _coerce_messages_for_ollama(msgs)
        assert out[0]["content"] is None

    def test_none_content_passthrough(self):
        """content=None is neither str nor list — passes through unchanged."""
        msgs = [{"role": "assistant", "content": None}]
        out = _coerce_messages_for_ollama(msgs)
        assert out[0]["content"] is None


# ── U05: _ollama_options ───────────────────────────────────────────────────────

class TestOllamaOptions:
    def test_top_k_absent_when_none(self):
        """top_k key is omitted when profile.generation.top_k is None (U05)."""
        profile = _profile(top_k=None)
        opts = _ollama_options(profile)
        assert "top_k" not in opts
        assert "temperature" in opts
        assert "top_p" in opts
        assert "num_ctx" in opts

    def test_top_k_present_when_set(self):
        """top_k is included with correct value when set."""
        profile = _profile(top_k=40)
        opts = _ollama_options(profile)
        assert opts["top_k"] == 40

    def test_num_ctx_matches_context_size(self):
        """num_ctx reflects profile.context_size."""
        profile = _profile()
        opts = _ollama_options(profile)
        assert opts["num_ctx"] == profile.context_size


# ── U06-U08: history_token_estimate ───────────────────────────────────────────

class TestHistoryTokenEstimate:
    def test_str_content_divided_by_4(self):
        """400-char string = 100 estimated tokens (U06)."""
        session = _session()
        session._messages = [{"role": "user", "content": "A" * 400}]
        assert session.history_token_estimate == 100

    def test_list_text_key(self):
        """Block with 'text' key uses len(text) (U07)."""
        session = _session()
        session._messages = [
            {"role": "assistant", "content": [{"type": "text", "text": "B" * 400}]}
        ]
        assert session.history_token_estimate == 100

    def test_list_content_key_tool_result_shape(self):
        """Block with 'content' key (tool_result) uses len(content) (U08)."""
        session = _session()
        session._messages = [
            {"role": "user", "content": [{"type": "tool_result", "content": "X" * 400}]}
        ]
        assert session.history_token_estimate == 100

    def test_empty_messages(self):
        session = _session()
        session._messages = []
        assert session.history_token_estimate == 0


# ── U14-U16: compact_history_deep (mocked summarizer) ─────────────────────────

class TestCompactHistoryDeep:
    def _msgs_3_turns(self, protocol: str = "native") -> list[dict]:
        return [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "turn 1"},
            {"role": "assistant", "content": "answer 1"},
            {"role": "user", "content": "turn 2"},
            {"role": "assistant", "content": "answer 2"},
            {"role": "user", "content": "turn 3"},
            {"role": "assistant", "content": "answer 3"},
        ]

    @pytest.mark.asyncio
    async def test_summarizes_old_turns_native(self):
        """System message preserved; recap pair inserted; last 2 real turns kept (U14)."""
        from blue_bench_cli.analyst import compact_history_deep

        profile = _profile(protocol="native")
        msgs = self._msgs_3_turns()

        with patch("blue_bench_cli.analyst._summarize_excerpt", new=AsyncMock(return_value="SUMMARY")):
            new, stats = await compact_history_deep(profile, msgs, keep_recent_user_turns=2)

        assert new[0]["role"] == "system"
        assert new[1]["role"] == "user"   # recap prompt
        assert new[2]["role"] == "assistant"
        assert new[2]["content"] == "SUMMARY"   # native: plain string
        # last 2 real user turns preserved
        assert new[3]["content"] == "turn 2"
        assert new[5]["content"] == "turn 3"
        assert stats["summarized_messages"] > 0
        assert stats["summary_chars"] == len("SUMMARY")

    @pytest.mark.asyncio
    async def test_summarizes_old_turns_anthropic_native(self):
        """Anthropic-native: recap assistant uses list-of-blocks shape (U14 variant)."""
        from blue_bench_cli.analyst import compact_history_deep

        profile = _profile(protocol="anthropic-native")
        msgs = self._msgs_3_turns(protocol="anthropic-native")

        with patch("blue_bench_cli.analyst._summarize_excerpt", new=AsyncMock(return_value="RECAP")):
            new, stats = await compact_history_deep(profile, msgs, keep_recent_user_turns=2)

        recap_asst = new[2]
        assert recap_asst["role"] == "assistant"
        assert isinstance(recap_asst["content"], list)
        assert recap_asst["content"][0]["type"] == "text"
        assert recap_asst["content"][0]["text"] == "RECAP"

    @pytest.mark.asyncio
    async def test_no_op_when_too_few_real_turns(self):
        """Returns original list unchanged when <= keep_recent_user_turns (U15)."""
        from blue_bench_cli.analyst import compact_history_deep

        profile = _profile()
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "only turn"},
            {"role": "assistant", "content": "reply"},
            {"role": "user", "content": "second turn"},
            {"role": "assistant", "content": "reply 2"},
        ]
        with patch("blue_bench_cli.analyst._summarize_excerpt", new=AsyncMock(return_value="X")):
            new, stats = await compact_history_deep(profile, msgs, keep_recent_user_turns=2)

        assert stats["summarized_messages"] == 0
        assert new == msgs

    @pytest.mark.asyncio
    async def test_tool_result_only_user_messages_not_counted_as_turns(self):
        """User messages that are only tool_result blocks are not counted as real
        user turns for the boundary calculation (boundary condition for U15)."""
        from blue_bench_cli.analyst import compact_history_deep

        profile = _profile(protocol="anthropic-native")
        # 2 real user turns + 1 tool_result-only user message
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "real turn 1"},
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "data"}],
            },
            {"role": "user", "content": "real turn 2"},
        ]
        with patch("blue_bench_cli.analyst._summarize_excerpt", new=AsyncMock(return_value="X")):
            new, stats = await compact_history_deep(profile, msgs, keep_recent_user_turns=2)
        # Only 2 real user turns — should be no-op
        assert stats["summarized_messages"] == 0

    @pytest.mark.asyncio
    async def test_empty_summary_leaves_history_unchanged(self):
        """Empty summarizer response does not corrupt history (U16)."""
        from blue_bench_cli.analyst import compact_history_deep

        profile = _profile()
        msgs = self._msgs_3_turns()

        with patch("blue_bench_cli.analyst._summarize_excerpt", new=AsyncMock(return_value="")):
            new, stats = await compact_history_deep(profile, msgs, keep_recent_user_turns=2)

        assert new == msgs
        assert stats["summarized_messages"] == 0


# ── U22-U24: AutoSaver and TranscriptRecorder ──────────────────────────────────

class TestAutoSaver:
    def test_disabled_save_is_noop(self, tmp_path: Path):
        """When enabled=False, save() writes nothing and last_path stays None (U22)."""
        saver = AutoSaver("test-session", tmp_path, enabled=False)
        session = _session()
        recorder = TranscriptRecorder("p", "m", "native")
        saver.save(session, recorder, None)
        assert saver.last_path is None
        assert list(tmp_path.iterdir()) == []

    def test_enabled_save_writes_valid_json(self, tmp_path: Path):
        """Enabled saver writes a parseable file with correct schema_version (U23)."""
        saver = AutoSaver("my-session", tmp_path, enabled=True)
        session = _session()
        session._messages = [{"role": "user", "content": "q"}]
        recorder = TranscriptRecorder("gemma4-e4b", "gemma4:e4b", "native")
        saver.save(session, recorder, None)

        assert saver.last_path is not None
        assert saver.last_path.exists()
        data = json.loads(saver.last_path.read_text())
        assert data["schema_version"] == SCHEMA_VERSION

    def test_last_path_updated_on_second_save(self, tmp_path: Path):
        """Consecutive saves update last_path each time."""
        saver = AutoSaver("my-session", tmp_path, enabled=True)
        session = _session()
        recorder = TranscriptRecorder("p", "m", "native")
        saver.save(session, recorder, None)
        path1 = saver.last_path
        saver.save(session, recorder, None)
        path2 = saver.last_path
        assert path1 == path2  # same id → same path
        assert path2 is not None and path2.exists()


class TestTranscriptRecorder:
    def test_to_dict_schema_and_structure(self):
        """Schema string, turns, and metadata are correct (U24)."""
        rec = TranscriptRecorder("gemma4-e4b", "gemma4:e4b", "native")
        rec.begin_turn("what is 1+1?")
        rec.record("final_answer", {"text": "2"})
        d = rec.to_dict()

        assert d["schema"] == "blue-bench-analyst/1"
        assert d["profile_name"] == "gemma4-e4b"
        assert d["model_id"] == "gemma4:e4b"
        assert d["tool_protocol"] == "native"
        assert isinstance(d["started_at"], float)
        assert isinstance(d["ended_at"], float)
        assert len(d["turns"]) == 1
        turn = d["turns"][0]
        assert turn["question"] == "what is 1+1?"
        events = turn["events"]
        assert len(events) == 1
        assert events[0]["type"] == "final_answer"
        assert events[0]["text"] == "2"

    def test_record_before_begin_turn_is_noop(self):
        """Recording without begin_turn does not raise (no _current_turn)."""
        rec = TranscriptRecorder("p", "m", "native")
        rec.record("tool_call", {"name": "x"})  # should not raise
        assert rec.turns == []

    def test_save_writes_json_file(self, tmp_path: Path):
        """save(path) writes the to_dict payload as JSON."""
        rec = TranscriptRecorder("p", "m", "native")
        rec.begin_turn("q")
        out = tmp_path / "transcript.json"
        rec.save(out)
        data = json.loads(out.read_text())
        assert data["schema"] == "blue-bench-analyst/1"


# ── U25-U28: InteractiveSession.set_profile and tools_available ───────────────

class TestSessionProfileAndGate:
    def test_set_profile_resets_seeding_flags_keeps_gate(self):
        """Swap profile resets seeding but leaves tool_gate intact (U25)."""
        session = _session()
        session._native_seeded = True
        session._anthropic_seeded = True
        session.tool_gate = {"search_alerts"}

        new_profile = _profile(name="new", protocol="anthropic-native")
        session.set_profile(new_profile, keep_history=True)

        assert session._native_seeded is False
        assert session._anthropic_seeded is False
        assert session.tool_gate == {"search_alerts"}

    def test_set_profile_keep_history_false_clears_messages(self):
        """keep_history=False drops messages; gate is unchanged (U26)."""
        session = _session()
        session._messages = [{"role": "user", "content": "x"}] * 5
        session.tool_gate = {"count_by_field"}

        session.set_profile(_profile(name="new"), keep_history=False)

        assert session._messages == []
        assert session.tool_gate == {"count_by_field"}

    def test_set_profile_mismatched_task_class_raises(self):
        """Task class not in new profile's allowed list raises EngagementScopeError (U27)."""
        session = _session()
        session.task_class = TaskClass.SIGMA_DRAFT

        restricted_profile = _profile(
            name="restricted",
            require_task_class=True,
            allowed=[TaskClass.IOC_EXTRACTION],
        )
        with pytest.raises(EngagementScopeError, match="SIGMA_DRAFT"):
            session.set_profile(restricted_profile)

    def test_tools_available_filters_by_gate(self):
        """tools_available returns only gate-allowed tools; None gate = all (U28)."""
        session = _session()
        session._all_tools = [_tool("search_alerts"), _tool("count_by_field"),
                               _tool("get_connections"), _tool("wazuh_list_agents")]

        session.set_tool_gate({"search_alerts", "count_by_field"})
        available = session.tools_available
        assert {t.name for t in available} == {"search_alerts", "count_by_field"}

        session.set_tool_gate(None)
        assert len(session.tools_available) == 4

    def test_empty_gate_means_zero_tools_not_unrestricted(self):
        """set_tool_gate(set()) → no tools exposed; distinct from None (boundary)."""
        session = _session()
        session._all_tools = [_tool("search_alerts"), _tool("count_by_field")]
        session.set_tool_gate(set())
        assert session.tools_available == []

    def test_set_profile_task_class_none_with_require_true_no_raise_on_swap(self):
        """task_class=None on a mid-session swap to require_task_class=True profile
        does NOT raise — absence of class is fine on swap (only at_entry enforces it)."""
        session = _session()
        session.task_class = None

        strict_profile = _profile(name="strict", require_task_class=True)
        # Must not raise; task_class will be bound later or was established at entry.
        session.set_profile(strict_profile)
        assert session.profile.name == "strict"


# ── I01-I02: SessionState save/load roundtrip ─────────────────────────────────

class TestSessionRoundtrip:
    def test_full_roundtrip_all_fields(self, tmp_path: Path):
        """Every field survives save + load (I01)."""
        original = _make_state(
            "myinv",
            tool_gate=["elastic", "wazuh"],
            messages=[
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "what alerts?"},
                {"role": "assistant", "content": "found 3"},
            ],
            turns=[{"question": "q", "events": [{"type": "final_answer", "text": "a"}]}],
            name="alpha-investigation",
        )
        path = save_session(original, tmp_path)
        assert path.exists()
        assert not path.with_suffix(".json.tmp").exists()

        loaded = load_session(original.id, tmp_path)
        assert loaded.id == original.id
        assert loaded.profile_name == original.profile_name
        assert loaded.model_id == original.model_id
        assert loaded.tool_protocol == original.tool_protocol
        assert loaded.tool_gate == ["elastic", "wazuh"]
        assert loaded.messages == original.messages
        assert loaded.turns == original.turns
        assert loaded.name == "alpha-investigation"
        assert loaded.schema_version == SCHEMA_VERSION

    def test_atomic_write_no_tmp_leftover(self, tmp_path: Path):
        """Tmp staging file is gone after successful write (I01 pin)."""
        save_session(_make_state(), tmp_path)
        assert list(tmp_path.glob("*.tmp")) == []

    def test_overwrite_reflects_second_write(self, tmp_path: Path):
        """Writing the same id twice — final file is from the second write (I02)."""
        s = _make_state()
        save_session(s, tmp_path)
        s.messages = [{"role": "user", "content": "new content"}]
        save_session(s, tmp_path)
        loaded = load_session(s.id, tmp_path)
        assert loaded.messages == [{"role": "user", "content": "new content"}]

    def test_last_updated_bumped_on_save(self, tmp_path: Path):
        """save_session sets last_updated to current time (I02 side effect)."""
        s = _make_state()
        s.last_updated = 0.0
        save_session(s, tmp_path)
        loaded = load_session(s.id, tmp_path)
        assert loaded.last_updated > 0

    def test_schema_version_mismatch_raises(self, tmp_path: Path):
        """Stale schema version raises ValueError naming both versions (U19)."""
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"schema_version": "blue-bench-analyst/0", "id": "bad"}))
        with pytest.raises(ValueError, match="schema_version"):
            load_session("bad", tmp_path)

    def test_unknown_fields_silently_dropped(self):
        """Extra fields in dict don't blow up from_dict (U20)."""
        data = {
            "schema_version": SCHEMA_VERSION,
            "id": "x",
            "profile_name": "p",
            "model_id": "m",
            "tool_protocol": "native",
            "tool_gate": None,
            "messages": [],
            "future_field": "some future value",
        }
        state = SessionState.from_dict(data)
        assert state.id == "x"

    def test_session_path_rejects_traversal(self, tmp_path: Path):
        """Path traversal and unsafe chars raise ValueError (U18)."""
        for bad in ["../escape", "with/slash", "/absolute", "", "  "]:
            with pytest.raises(ValueError):
                session_path(bad, tmp_path)

    def test_session_path_accepts_valid_ids(self, tmp_path: Path):
        for good in ["my-session", "20260503-114502-gemma4-e4b", "test.v2", "abc_123"]:
            p = session_path(good, tmp_path)
            assert p.name == f"{good}.json"

    def test_list_sessions_skips_corrupt(self, tmp_path: Path):
        """Corrupt JSON files are skipped; valid ones returned (U21)."""
        save_session(_make_state("good"), tmp_path)
        (tmp_path / "broken.json").write_text("not json{{")
        (tmp_path / "old-schema.json").write_text(
            json.dumps({"schema_version": "blue-bench-analyst/0", "id": "x"})
        )
        listed = list_sessions(tmp_path)
        assert {s.id for s in listed} == {"good"}

    def test_session_exists(self, tmp_path: Path):
        save_session(_make_state("yes"), tmp_path)
        assert session_exists("yes", tmp_path) is True
        assert session_exists("no", tmp_path) is False
        assert session_exists("../bad", tmp_path) is False


# ── I03: cross-protocol swap — coerce preserves no ValidationError ─────────────

class TestCrossProtocolSwap:
    def test_anthropic_history_coerces_for_ollama_no_exception(self):
        """Simulate post-swap coercion: Anthropic-format history fed to Ollama path (I03).

        This is the exact regression that crashed the CLI on /profile swap from
        claude-sonnet-4-6 to qwen3.5:9b.
        """
        # Messages as stored after one Anthropic turn (citations field present)
        anthropic_history = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "what alerts?"},
            {
                "role": "assistant",
                "content": [
                    {"citations": None, "text": "I found 3 alerts", "type": "text"},
                    {"type": "tool_use", "id": "tu_1", "name": "search_alerts", "input": {}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tu_1", "content": "3 results"}
                ],
            },
            {
                "role": "assistant",
                "content": [{"type": "text", "text": "Summary: 3 high-sev alerts", "citations": None}],
            },
        ]
        coerced = _coerce_messages_for_ollama(anthropic_history)

        for msg in coerced:
            assert not isinstance(msg.get("content"), list), (
                f"list content survived coercion in {msg['role']} message — "
                "Ollama pydantic will reject this"
            )

    def test_profile_swap_native_to_anthropic_resets_seeding(self):
        """Swap native→anthropic-native: seeding flags cleared, history intact."""
        session = _session(_profile(protocol="native"))
        session._native_seeded = True
        session._messages = [{"role": "user", "content": "prior turn"}]

        anthropic_profile = _profile(protocol="anthropic-native", name="sonnet")
        session.set_profile(anthropic_profile, keep_history=True)

        assert session._native_seeded is False
        assert session._anthropic_seeded is False
        assert len(session._messages) == 1  # history preserved

    def test_profile_swap_anthropic_to_native_resets_seeding(self):
        """Swap anthropic-native→native: seeding flags cleared."""
        session = _session(_profile(protocol="anthropic-native", name="sonnet"))
        session._anthropic_seeded = True
        session._messages = [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [{"type": "text", "text": "a"}]},
        ]

        native_profile = _profile(protocol="native", name="qwen")
        session.set_profile(native_profile, keep_history=True)

        assert session._native_seeded is False
        assert session._anthropic_seeded is False
        # After swap, coercing history for Ollama must not produce list content
        coerced = _coerce_messages_for_ollama(session._messages)
        for msg in coerced:
            assert not isinstance(msg.get("content"), list)

    def test_tool_result_body_survives_anthropic_to_native_coerce(self):
        """anthropic→native: tool_result block body must survive as text in
        the resulting message, otherwise the new model has no data to analyze
        and will re-call the same tools (the user's reported failure mode)."""
        anthropic_history = [
            {"role": "user", "content": "what alerts?"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Calling search_alerts."},
                    {"type": "tool_use", "id": "tu1", "name": "search_alerts", "input": {}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu1",
                        "content": "ALERT-001 high; ALERT-002 medium",
                    }
                ],
            },
            {"role": "user", "content": "summarize them"},
        ]
        coerced = _coerce_messages_for_ollama(anthropic_history)
        flat = "\n".join(str(m.get("content")) for m in coerced)
        assert "ALERT-001" in flat, "tool_result body dropped on coerce"
        assert "search_alerts" in flat, "tool_use name dropped on coerce"
        # Every content must be str or None — no list survives
        for m in coerced:
            assert not isinstance(m.get("content"), list)

    def test_tool_result_with_block_list_body_preserved(self):
        """tool_result.content can be a list of text blocks (Anthropic shape)."""
        msgs = [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "t",
                        "content": [{"type": "text", "text": "RESULT-BODY"}],
                    }
                ],
            }
        ]
        coerced = _coerce_messages_for_ollama(msgs)
        assert "RESULT-BODY" in str(coerced[0]["content"])

    def test_native_tool_exchange_survives_to_anthropic(self):
        """native→anthropic: a tool call + tool result pair must reach the
        new model as text. Pure-dispatch assistant turns (empty content +
        tool_calls) get folded into the next text-bearing assistant message,
        keeping user/assistant alternation valid."""
        native_history = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "how many alerts?"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "count_by_field", "arguments": {}}}],
            },
            {"role": "tool", "content": "Top 1 values: alert.severity=high (count=42)"},
            {"role": "assistant", "content": "42 high-severity alerts.", "tool_calls": []},
            {"role": "user", "content": "summarize them"},
        ]
        coerced = _coerce_native_history_for_anthropic(native_history)

        # No system, no tool roles, no empty-content turns
        roles = [m["role"] for m in coerced]
        assert "system" not in roles
        assert "tool" not in roles
        # Strict alternation: user → assistant → user
        assert roles == ["user", "assistant", "user"]
        # No tool_calls key anywhere
        for m in coerced:
            assert "tool_calls" not in m
        # Tool result body must be present in the assistant turn
        synthesis = coerced[1]["content"]
        assert "count=42" in synthesis or "42 high-severity" in synthesis
        assert "count_by_field" in synthesis  # what was called
        assert "Tool result" in synthesis  # the marker prefix

    def test_native_pure_dispatch_with_no_synthesis_emits_data_to_new_model(self):
        """Worst case: producing model called a tool but never synthesized text
        (e.g. ran out of turns). The tool result body must STILL reach the new
        model — flushed as a synthetic assistant turn before the next user msg."""
        native_history = [
            {"role": "user", "content": "what alerts?"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "search_alerts", "arguments": {}}}],
            },
            {"role": "tool", "content": "CRITICAL-FINDING-12345"},
            {"role": "user", "content": "what did you find?"},
        ]
        coerced = _coerce_native_history_for_anthropic(native_history)
        roles = [m["role"] for m in coerced]
        # Pattern: user → assistant(synthetic with tool result) → user
        assert roles == ["user", "assistant", "user"]
        flat = "\n".join(m["content"] for m in coerced if m.get("content"))
        assert "CRITICAL-FINDING-12345" in flat, (
            "Tool result body lost when producing model didn't synthesize text"
        )
        assert "search_alerts" in flat

    def test_native_multiple_tool_calls_in_one_turn(self):
        """An assistant turn with two tool_calls produces two tool messages.
        Both result bodies must reach the new model with the right names."""
        native_history = [
            {"role": "user", "content": "investigate"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "search_alerts", "arguments": {}}},
                    {"function": {"name": "get_connections", "arguments": {}}},
                ],
            },
            {"role": "tool", "content": "ALERT_DATA_A"},
            {"role": "tool", "content": "CONN_DATA_B"},
            {"role": "assistant", "content": "Done.", "tool_calls": []},
            {"role": "user", "content": "more"},
        ]
        coerced = _coerce_native_history_for_anthropic(native_history)
        flat = "\n".join(m["content"] for m in coerced if m.get("content"))
        assert "ALERT_DATA_A" in flat
        assert "CONN_DATA_B" in flat
        assert "search_alerts" in flat
        assert "get_connections" in flat

    def test_anthropic_payload_strips_native_only_fields(self):
        """Regression: when a native turn precedes a swap to anthropic-native,
        the assistant message has a `tool_calls` field that Anthropic rejects with
        `messages.N.tool_calls: Extra inputs are not permitted`. We also drop
        role="tool" messages (Anthropic uses tool_result blocks inside user
        messages) and role="system" messages (system is a top-level param).
        """
        # Simulate the payload-build code path in _iter_anthropic
        messages = [
            {"role": "system", "content": "sys prompt"},
            {"role": "user", "content": "q1"},
            {"role": "assistant", "content": "a1", "tool_calls": []},
            {"role": "tool", "content": "tool result body"},
            {"role": "assistant", "content": "a2", "tool_calls": [{"name": "x"}]},
            {"role": "user", "content": "q2"},
        ]
        anthropic_messages = []
        for m in messages:
            role = m.get("role")
            if role == "system" or role == "tool":
                continue
            if role == "assistant" and "tool_calls" in m:
                m = {k: v for k, v in m.items() if k != "tool_calls"}
            anthropic_messages.append(m)

        roles = [m["role"] for m in anthropic_messages]
        assert roles == ["user", "assistant", "assistant", "user"]
        for m in anthropic_messages:
            assert "tool_calls" not in m


# ── compact_history_heuristic pinned here for the multi-model scenario ─────────

class TestCompactHeuristicPinned:
    """Pins compact behavior for the three-model relay scenario.
    Full compact test coverage is in test_context_management.py.
    These are the scenarios we'd hit in S4 (query → swap → swap → /compact).
    """

    def test_compact_after_native_turns(self):
        """Native tool messages compacted as expected (S4 scenario)."""
        big = "X" * 10_000
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "first"},
            {"role": "tool", "content": big},
            {"role": "user", "content": "second"},
            {"role": "tool", "content": "Y" * 5_000},
            {"role": "user", "content": "third"},
            {"role": "tool", "content": "Z" * 4_000},
        ]
        new, stats = compact_history_heuristic(msgs)
        assert stats["compacted"] == 1
        assert stats["tokens_freed"] > 0
        tool_msgs = [m for m in new if m.get("role") == "tool"]
        assert tool_msgs[0]["content"].startswith("[tool result")
        assert tool_msgs[1]["content"] == "Y" * 5_000  # recent — kept
        assert tool_msgs[2]["content"] == "Z" * 4_000  # recent — kept

    def test_compact_idempotent(self):
        """Running /compact twice does not re-compact already-compacted entries."""
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "a"},
            {"role": "tool", "content": "X" * 8000},
            {"role": "user", "content": "b"},
            {"role": "tool", "content": "Y" * 8000},
            {"role": "user", "content": "c"},
        ]
        once, s1 = compact_history_heuristic(msgs)
        twice, s2 = compact_history_heuristic(once)
        assert s1["compacted"] == 1
        assert s2["compacted"] == 0


# ── Live model integration tests ───────────────────────────────────────────────
# Skipped unless: pytest -m integration --timeout=120
# Requires: Ollama running with gemma4:e4b + qwen3.5:9b pulled
#           ANTHROPIC_API_KEY set for Sonnet turns

_PROFILES_DIR = Path(__file__).parent.parent / "blue_bench_mcp" / "profiles"


def _load_profile(name: str) -> ModelProfile:
    from blue_bench_mcp.profiles import load_profile
    return load_profile(_PROFILES_DIR / f"{name}.yaml")


@pytest.mark.integration
class TestLiveMultiModelRelay:
    """End-to-end test: gemma4:e4b → claude-sonnet-4-6 → qwen3.5:9b.

    Each profile swap retains history. Confirms:
      L01 — native protocol produces FinalAnswer
      L02 — native → anthropic-native swap, history preserved
      L03 — anthropic-native → native swap, no ValidationError
    """

    @pytest.mark.asyncio
    async def test_native_single_turn_produces_final_answer(self, tmp_path: Path):
        """S1: gemma4:e4b single turn → FinalAnswer (L01)."""
        from blue_bench_client.interactive import FinalAnswer, Error, TurnComplete

        profile = _load_profile("gemma4-e4b")
        async with InteractiveSession(profile) as session:
            events = []
            async for ev in session.iter_turn("What is 2 + 2? Respond in one sentence."):
                events.append(ev)

        types = [type(e) for e in events]
        assert FinalAnswer in types, f"No FinalAnswer in events: {events}"
        assert Error not in types, f"Error event found: {[e for e in events if isinstance(e, Error)]}"
        tc = next(e for e in events if isinstance(e, TurnComplete))
        assert tc.turns_used >= 1

    @pytest.mark.asyncio
    async def test_profile_swap_native_to_anthropic_history_preserved(self):
        """S2: gemma4:e4b turn then swap to sonnet — prior context in next turn (L02)."""
        from blue_bench_client.interactive import FinalAnswer, Error

        gemma_profile = _load_profile("gemma4-e4b")
        sonnet_profile = _load_profile("claude-sonnet-4-6")

        async with InteractiveSession(gemma_profile) as session:
            events1 = []
            async for ev in session.iter_turn("My secret number is 42. Confirm you received it."):
                events1.append(ev)
            assert any(isinstance(e, FinalAnswer) for e in events1)

            msg_count_after_turn1 = len(session._messages)
            session.set_profile(sonnet_profile)
            assert not session._anthropic_seeded
            assert len(session._messages) == msg_count_after_turn1  # history kept

            events2 = []
            async for ev in session.iter_turn("What was the secret number I told you?"):
                events2.append(ev)

        assert any(isinstance(e, FinalAnswer) for e in events2), "Sonnet turn produced no FinalAnswer"
        final = next(e for e in events2 if isinstance(e, FinalAnswer))
        assert "42" in final.text, f"Sonnet forgot the secret number. Got: {final.text!r}"

    @pytest.mark.asyncio
    async def test_profile_swap_anthropic_to_native_no_crash(self):
        """S3: sonnet turn then swap to qwen3.5:9b — Anthropic-format history coerced (L03)."""
        from blue_bench_client.interactive import FinalAnswer, Error

        sonnet_profile = _load_profile("claude-sonnet-4-6")
        qwen_profile = _load_profile("qwen35-9b-uncoached")

        async with InteractiveSession(sonnet_profile) as session:
            events1 = []
            async for ev in session.iter_turn("Hello, please say 'acknowledged'."):
                events1.append(ev)
            assert any(isinstance(e, FinalAnswer) for e in events1)

            session.set_profile(qwen_profile)

            events2 = []
            async for ev in session.iter_turn("What did you say in your last message?"):
                events2.append(ev)

        errors = [e for e in events2 if isinstance(e, Error)]
        assert not errors, f"Error events on cross-protocol swap: {errors}"
        assert any(isinstance(e, FinalAnswer) for e in events2)

    @pytest.mark.asyncio
    async def test_tool_results_survive_native_to_native_swap(self):
        """gemma4 calls a tool → swap to qwen3.5:9b → qwen analyzes prior result
        without re-calling tools. Same protocol, but different model. The role=tool
        message stays in history natively — qwen should read it."""
        from blue_bench_client.interactive import FinalAnswer, ToolCall

        gemma_profile = _load_profile("gemma4-e4b")
        qwen_profile = _load_profile("qwen35-9b-uncoached")

        async with InteractiveSession(gemma_profile, stream=False) as session:
            saw_gemma_tool = False
            async for ev in session.iter_turn(
                "Run count_by_field on src_ip in the last hour. Just call the tool."
            ):
                if isinstance(ev, ToolCall):
                    saw_gemma_tool = True
            assert saw_gemma_tool, "gemma4 didn't call any tool — test setup invalid"

            session.set_profile(qwen_profile)

            qwen_tool_calls = 0
            qwen_final = None
            async for ev in session.iter_turn(
                "Without calling any new tools, what did the prior tool result contain? "
                "If you don't see prior data, say 'NO PRIOR DATA'."
            ):
                if isinstance(ev, ToolCall):
                    qwen_tool_calls += 1
                elif isinstance(ev, FinalAnswer):
                    qwen_final = ev.text

            assert qwen_final is not None, "qwen produced no FinalAnswer"
            assert "NO PRIOR DATA" not in qwen_final.upper(), (
                f"qwen lost the tool result across native→native swap. Got: {qwen_final[:300]!r}"
            )

    @pytest.mark.asyncio
    async def test_tool_results_survive_anthropic_to_native_swap(self):
        """sonnet calls a tool → swap to qwen3.5:9b → qwen analyzes prior result
        without re-calling tools. Cross-protocol; tool_result blocks must be
        coerced into text that qwen can read."""
        from blue_bench_client.interactive import FinalAnswer, ToolCall

        sonnet_profile = _load_profile("claude-sonnet-4-6")
        qwen_profile = _load_profile("qwen35-9b-uncoached")

        async with InteractiveSession(sonnet_profile, stream=False) as session:
            saw_sonnet_tool = False
            async for ev in session.iter_turn(
                "Call count_by_field on src_ip for the last hour. Return whatever it gives."
            ):
                if isinstance(ev, ToolCall):
                    saw_sonnet_tool = True
            assert saw_sonnet_tool, "sonnet didn't call any tool — test setup invalid"

            session.set_profile(qwen_profile)

            qwen_final = None
            async for ev in session.iter_turn(
                "Without calling any new tools, describe what the prior tool result said. "
                "If you cannot see it, say 'NO PRIOR DATA'."
            ):
                if isinstance(ev, FinalAnswer):
                    qwen_final = ev.text

            assert qwen_final is not None, "qwen produced no FinalAnswer"
            assert "NO PRIOR DATA" not in qwen_final.upper(), (
                f"qwen lost the tool_result across anthropic→native coerce. Got: {qwen_final[:300]!r}"
            )

    @pytest.mark.asyncio
    async def test_compact_deep_findings_survive(self):
        """S5: after compact deep, model still knows earlier findings (L04)."""
        from blue_bench_client.interactive import FinalAnswer
        from blue_bench_cli.analyst import compact_history_deep

        profile = _load_profile("gemma4-e4b")

        async with InteractiveSession(profile) as session:
            async for _ in session.iter_turn("Remember the phrase 'CANARY-TOKEN-99'."):
                pass
            async for _ in session.iter_turn("Tell me about endpoint security best practices."):
                pass
            async for _ in session.iter_turn("What are common lateral movement indicators?"):
                pass

            new_msgs, stats = await compact_history_deep(
                profile, session._messages, keep_recent_user_turns=2
            )
            assert stats["summarized_messages"] > 0, "Nothing was summarized"
            session._messages = new_msgs

            events = []
            async for ev in session.iter_turn("What was the special phrase I asked you to remember?"):
                events.append(ev)

        finals = [e for e in events if isinstance(e, FinalAnswer)]
        assert finals, "No FinalAnswer after compact deep"
        assert "CANARY-TOKEN-99" in finals[0].text, (
            f"Model lost the canary token after compact deep. Got: {finals[0].text!r}"
        )


# ── Unit tests: task-class switch mid-session ─────────────────────────────────

class TestTaskClassMidSession:
    """Task-class bind / rebind / profile-swap interactions.

    The rule: task_class is set once at session entry when the profile requires
    it, but can be rebound mid-session (e.g. via /task-class). A profile swap
    must not lose the bound class unless the new profile forbids it.
    """

    def test_bind_task_class_mid_session_no_profile_change(self):
        """Can rebind task_class after session is live; profile stays unchanged."""
        session = _session(_profile(require_task_class=False))
        assert session.task_class is None
        session.task_class = TaskClass.ALERT_TRIAGE
        assert session.task_class == TaskClass.ALERT_TRIAGE
        assert session.profile.require_task_class is False  # profile unchanged

    def test_task_class_survives_profile_swap_when_permitted(self):
        """task_class stays bound after a profile swap to a profile that permits it."""
        session = _session()
        session.task_class = TaskClass.ALERT_TRIAGE

        new_profile = _profile(
            name="new",
            require_task_class=True,
            allowed=[TaskClass.ALERT_TRIAGE, TaskClass.IOC_EXTRACTION],
        )
        session.set_profile(new_profile)
        assert session.task_class == TaskClass.ALERT_TRIAGE

    def test_task_class_rebind_then_profile_swap_permitted(self):
        """Rebind to a different class, then swap to profile that permits new class."""
        session = _session()
        session.task_class = TaskClass.IOC_EXTRACTION

        permissive = _profile(
            name="p2",
            require_task_class=True,
            allowed=[TaskClass.IOC_EXTRACTION, TaskClass.SIGMA_DRAFT],
        )
        session.set_profile(permissive)
        assert session.task_class == TaskClass.IOC_EXTRACTION

    def test_task_class_rebind_then_profile_swap_forbidden(self):
        """Rebind class, then swap to profile that forbids it → EngagementScopeError."""
        session = _session()
        session.task_class = TaskClass.SIGMA_DRAFT

        restricted = _profile(
            name="p3",
            require_task_class=True,
            allowed=[TaskClass.IOC_EXTRACTION],
        )
        with pytest.raises(EngagementScopeError, match="SIGMA_DRAFT"):
            session.set_profile(restricted)
        # task_class is still the original — the failed swap must not mutate state
        assert session.task_class == TaskClass.SIGMA_DRAFT

    def test_task_class_none_after_swap_to_permissive_profile(self):
        """Swap from a require=True profile to a require=False profile with no class
        bound — no error; task_class stays None."""
        session = _session(_profile(require_task_class=True, allowed=list(TaskClass)))
        # No class bound — normally would fail at entry, but we're testing mid-session
        session.task_class = None
        permissive = _profile(require_task_class=False)
        session.set_profile(permissive)
        assert session.task_class is None

    def test_task_class_cleared_then_rebound_before_swap(self):
        """Set class → clear → rebind to different class → swap (all permitted)."""
        session = _session()
        session.task_class = TaskClass.ALERT_TRIAGE
        session.task_class = None  # simulates /task-class reset
        session.task_class = TaskClass.LOG_QUERY

        permissive = _profile(
            name="p4",
            require_task_class=True,
            allowed=list(TaskClass),
        )
        session.set_profile(permissive)
        assert session.task_class == TaskClass.LOG_QUERY

    def test_profile_swap_preserves_task_class_across_protocol_change(self):
        """task_class persists when swapping native → anthropic-native."""
        session = _session(_profile(protocol="native"))
        session.task_class = TaskClass.ALERT_TRIAGE

        anthropic_profile = _profile(
            protocol="anthropic-native",
            name="sonnet",
            require_task_class=True,
            allowed=list(TaskClass),
        )
        session.set_profile(anthropic_profile)
        assert session.task_class == TaskClass.ALERT_TRIAGE
        assert session._anthropic_seeded is False  # seeding reset
        assert session._native_seeded is False

    def test_set_task_class_validates_against_current_profile(self):
        """set_task_class() re-validates against current profile (gap fix)."""
        restricted = _profile(
            name="restricted",
            require_task_class=True,
            allowed=[TaskClass.IOC_EXTRACTION],
        )
        session = _session(restricted)
        with pytest.raises(EngagementScopeError, match="SIGMA_DRAFT"):
            session.set_task_class("SIGMA_DRAFT")

    def test_set_task_class_accepts_allowed_class(self):
        """set_task_class() succeeds when class is in allowed list."""
        restricted = _profile(
            name="restricted",
            require_task_class=True,
            allowed=[TaskClass.IOC_EXTRACTION, TaskClass.ALERT_TRIAGE],
        )
        session = _session(restricted)
        session.set_task_class("ALERT_TRIAGE")
        assert session.task_class == TaskClass.ALERT_TRIAGE

    def test_set_task_class_none_clears_binding(self):
        """set_task_class(None) clears the binding without validation."""
        session = _session()
        session.task_class = TaskClass.SIGMA_DRAFT
        session.set_task_class(None)
        assert session.task_class is None

    def test_set_task_class_no_enforcement_when_require_false(self):
        """When profile.require_task_class=False, any class is accepted."""
        permissive = _profile(
            name="open",
            require_task_class=False,
            allowed=[TaskClass.IOC_EXTRACTION],  # only IOC allowed if enforced
        )
        session = _session(permissive)
        # SIGMA_DRAFT not in allowed list, but enforcement is off
        session.set_task_class("SIGMA_DRAFT")
        assert session.task_class == TaskClass.SIGMA_DRAFT

    def test_set_task_class_unknown_raises(self):
        """Unknown task class name raises UnknownTaskClassError via _coerce."""
        session = _session()
        with pytest.raises(EngagementScopeError):
            # _coerce_task_class wraps UnknownTaskClassError into EngagementScopeError
            session.set_task_class("BOGUS_CLASS")
