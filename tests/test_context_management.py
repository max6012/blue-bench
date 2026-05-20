"""Unit tests for the analyst CLI's context-management surface.

Exercises pure functions only — no live model calls, no MCP server.
The model + REPL paths are validated end-to-end via manual smoke runs
(see plandb history for t-aah8, t-mjok, t-5gls, t-yixq, etc.) since
mocking the streaming + tool dispatch faithfully would be a brittle
test investment.

Surface under test:
  blue_bench_cli._sessions       SessionState + save/load/list/auto_id
  blue_bench_cli.analyst         compact_history_heuristic,
                                 _top_context_contributors,
                                 _parse_categories,
                                 _categories_to_tools,
                                 _truncate,
                                 _format_args_oneline
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

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
    _categories_to_tools,
    _format_args_oneline,
    _parse_categories,
    _top_context_contributors,
    _truncate,
    compact_history_heuristic,
)


# ── _sessions ─────────────────────────────────────────────────────────────────

def _make_state(sid: str = "test", **overrides) -> SessionState:
    base = dict(
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


def test_session_save_load_roundtrip(tmp_path: Path) -> None:
    s = _make_state(
        tool_gate=["elastic", "wazuh"],
        messages=[
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "what alerts?"},
            {"role": "assistant", "content": "Found 3."},
        ],
        name="my-investigation",
    )
    path = save_session(s, tmp_path)
    assert path.exists()
    assert not path.with_suffix(".json.tmp").exists()

    loaded = load_session(s.id, tmp_path)
    assert loaded.id == s.id
    assert loaded.profile_name == s.profile_name
    assert loaded.tool_gate == ["elastic", "wazuh"]
    assert loaded.messages == s.messages
    assert loaded.name == "my-investigation"
    assert loaded.schema_version == SCHEMA_VERSION


def test_session_save_is_atomic(tmp_path: Path) -> None:
    """Tmp staging file should not survive a successful save."""
    s = _make_state()
    path = save_session(s, tmp_path)
    assert path.exists()
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


def test_session_save_updates_last_updated(tmp_path: Path) -> None:
    import time

    s = _make_state()
    s.last_updated = 0.0
    save_session(s, tmp_path)
    loaded = load_session(s.id, tmp_path)
    assert loaded.last_updated > 0
    # And that the live state was bumped too (saver mutates in place)
    assert s.last_updated > 0


def test_session_path_rejects_unsafe_ids(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        session_path("../escape", tmp_path)
    with pytest.raises(ValueError):
        session_path("with/slash", tmp_path)
    # Hyphens, dots, underscores are fine
    session_path("ok.fine_name-2", tmp_path)


def test_load_missing_session_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_session("nope", tmp_path)


def test_load_rejects_old_schema(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "v0", "id": "bad"}))
    with pytest.raises(ValueError, match="schema_version"):
        load_session("bad", tmp_path)


def test_list_sessions_sorted_desc(tmp_path: Path) -> None:
    a = _make_state("a")
    a.last_updated = 100.0
    b = _make_state("b")
    b.last_updated = 200.0
    c = _make_state("c")
    c.last_updated = 50.0
    save_session(a, tmp_path)
    save_session(b, tmp_path)
    save_session(c, tmp_path)
    listed = list_sessions(tmp_path)
    # save_session bumps last_updated; their order should reflect save order.
    # We only assert: descending and all present.
    assert {s.id for s in listed} == {"a", "b", "c"}
    for x, y in zip(listed, listed[1:]):
        assert x.last_updated >= y.last_updated


def test_list_sessions_skips_corrupt(tmp_path: Path) -> None:
    save_session(_make_state("good"), tmp_path)
    (tmp_path / "broken.json").write_text("not json{{")
    (tmp_path / "wrong-schema.json").write_text(json.dumps({"schema_version": "v0"}))
    listed = list_sessions(tmp_path)
    assert {s.id for s in listed} == {"good"}


def test_list_sessions_empty_dir(tmp_path: Path) -> None:
    assert list_sessions(tmp_path) == []
    assert list_sessions(tmp_path / "does-not-exist") == []


def test_session_exists(tmp_path: Path) -> None:
    save_session(_make_state("yes"), tmp_path)
    assert session_exists("yes", tmp_path) is True
    assert session_exists("no", tmp_path) is False
    # Bad chars don't blow up the existence check
    assert session_exists("../bad", tmp_path) is False


def test_auto_session_id_format() -> None:
    sid = auto_session_id("gemma4-e4b")
    parts = sid.split("-")
    # Format: YYYYMMDD-HHMMSS-<profile>
    assert len(parts) >= 3
    assert len(parts[0]) == 8 and parts[0].isdigit()
    assert len(parts[1]) == 6 and parts[1].isdigit()


def test_auto_session_id_sanitizes_profile() -> None:
    sid = auto_session_id("weird/profile name")
    assert "/" not in sid
    assert " " not in sid


# ── compact_history_heuristic ────────────────────────────────────────────────

def test_compact_native_drops_old_tool_results() -> None:
    """Native protocol: role=tool messages older than the last 2 user turns."""
    big = "X" * 10_000
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "...", "tool_calls": [{"name": "search_alerts"}]},
        {"role": "tool", "content": big},
        {"role": "assistant", "content": "first answer"},
        {"role": "user", "content": "second"},
        {"role": "assistant", "content": "...", "tool_calls": [{"name": "get_connections"}]},
        {"role": "tool", "content": "Y" * 5_000},
        {"role": "assistant", "content": "second answer"},
        {"role": "user", "content": "third"},
        {"role": "tool", "content": "Z" * 4_000},
    ]
    new, stats = compact_history_heuristic(msgs)
    assert stats["compacted"] == 1
    assert stats["tokens_freed"] > 0

    tool_msgs = [m for m in new if m.get("role") == "tool"]
    # Oldest is shrunk; the last two stay.
    assert tool_msgs[0]["content"].startswith("[tool result")
    assert tool_msgs[1]["content"] == "Y" * 5_000
    assert tool_msgs[2]["content"] == "Z" * 4_000


def test_compact_anthropic_shrinks_tool_result_blocks() -> None:
    """Anthropic: tool_result blocks inside user messages."""
    msgs = [
        {"role": "user", "content": "first"},
        {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "1", "name": "search_alerts", "input": {}}],
        },
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "1", "content": "X" * 8000}],
        },
        {"role": "user", "content": "second"},
        {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "2", "name": "get_connections", "input": {}}],
        },
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "2", "content": "Y" * 6000}],
        },
        {"role": "user", "content": "third"},
    ]
    new, stats = compact_history_heuristic(msgs)
    assert stats["compacted"] == 1
    # Find the (now-summarized) older tool_result block:
    early = new[2]["content"][0]
    assert early["type"] == "tool_result"
    assert early["content"].startswith("[tool result")
    # Recent tool_result block is unchanged.
    recent = new[5]["content"][0]
    assert recent["content"] == "Y" * 6000


def test_compact_text_embedded_wraps() -> None:
    """text-embedded protocol: tool results live in <tool_result>...</tool_result>."""
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "<tool_result>" + "X" * 5000 + "</tool_result>"},
        {"role": "user", "content": "second"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "<tool_result>" + "Y" * 4000 + "</tool_result>"},
        {"role": "user", "content": "third"},
    ]
    new, stats = compact_history_heuristic(msgs)
    assert stats["compacted"] == 1
    # Old tool_result wrapper got shortened; recent one untouched.
    assert new[3]["content"] == "<tool_result>[compacted]</tool_result>"
    assert new[6]["content"] == "<tool_result>" + "Y" * 4000 + "</tool_result>"


def test_compact_no_op_when_too_few_turns() -> None:
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "only"},
        {"role": "tool", "content": "X" * 5000},
        {"role": "assistant", "content": "answer"},
    ]
    new, stats = compact_history_heuristic(msgs)
    assert stats["compacted"] == 0
    assert new == msgs


def test_compact_idempotent() -> None:
    """Running /compact twice should not re-compact already-compacted results."""
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "a"},
        {"role": "tool", "content": "X" * 8000},
        {"role": "user", "content": "b"},
        {"role": "tool", "content": "Y" * 8000},
        {"role": "user", "content": "c"},
    ]
    once, stats1 = compact_history_heuristic(msgs)
    twice, stats2 = compact_history_heuristic(once)
    assert stats1["compacted"] == 1
    assert stats2["compacted"] == 0
    assert once == twice


# ── _top_context_contributors ─────────────────────────────────────────────────

def test_top_contributors_native() -> None:
    msgs = [
        {"role": "system", "content": "S" * 4000},
        {"role": "user", "content": "u"},
        {"role": "tool", "content": "T" * 12000},
        {"role": "assistant", "content": "a"},
    ]
    out = _top_context_contributors(msgs, top_n=3)
    assert len(out) == 3
    # tool result is the biggest at 12000c / 4 = 3000 tokens
    label, tokens, _ = out[0]
    assert label == "tool"
    assert tokens == 3000


def test_top_contributors_anthropic_tool_result() -> None:
    msgs = [
        {"role": "user", "content": "first"},
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "1", "content": "Z" * 4000}],
        },
    ]
    out = _top_context_contributors(msgs, top_n=2)
    # The tool_result-bearing user message should be labeled distinctly.
    labels = [r[0] for r in out]
    assert "tool result" in labels


# ── flag parsing helpers ──────────────────────────────────────────────────────

def test_parse_categories_valid() -> None:
    assert _parse_categories("elastic,wazuh") == ["elastic", "wazuh"]
    assert _parse_categories("elastic, wazuh ,elastic") == ["elastic", "wazuh"]  # dedup, trim


def test_parse_categories_empty_returns_none() -> None:
    assert _parse_categories(None) is None
    assert _parse_categories("") is None
    assert _parse_categories("  ") is None
    assert _parse_categories(",,") is None


def test_parse_categories_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown"):
        _parse_categories("elastic,bogus")


def test_categories_to_tools() -> None:
    out = _categories_to_tools(["elastic"])
    assert out is not None
    assert "search_alerts" in out
    assert "wazuh_list_agents" not in out
    # None → unrestricted
    assert _categories_to_tools(None) is None
    assert _categories_to_tools([]) is None


# ── small text helpers ───────────────────────────────────────────────────────

def test_truncate() -> None:
    assert _truncate("short", 10) == "short"
    assert _truncate("x" * 50, 10).endswith("…")
    assert len(_truncate("x" * 50, 10)) == 10
    # Newlines flatten
    assert _truncate("a\nb\nc", 10) == "a b c"


def test_format_args_oneline() -> None:
    assert _format_args_oneline({}) == "(no args)"
    assert _format_args_oneline({"x": 1}) == "x=1"
    assert _format_args_oneline({"x": "abc"}) == 'x="abc"'
    # Long string args truncated
    out = _format_args_oneline({"x": "y" * 100})
    assert "…" in out
