"""Unit tests for the anthropic-cli transport's pure helpers — no live CLI.

The stream-json parser needs no model; these cover the tool-result unwrap, the
mcp__ prefix strip, and the OAuth env shaping that the CLI path relies on.
"""

from blue_bench_client.runner import (
    _MCP_TOOL_PREFIX,
    _cli_oauth_env,
    _cli_tool_result_text,
    _strip_mcp_prefix,
)


def test_strip_mcp_prefix():
    assert _strip_mcp_prefix(f"{_MCP_TOOL_PREFIX}search_alerts") == "search_alerts"
    # A name without the prefix passes through unchanged.
    assert _strip_mcp_prefix("search_alerts") == "search_alerts"


def test_cli_tool_result_text_unwraps_result_wrapper():
    # MCPServer wraps a bare-string tool return as {"result": "..."} — the CLI
    # path must unwrap it so the judge sees the same payload as the SDK paths.
    assert _cli_tool_result_text('{"result": "42 alerts"}') == "42 alerts"


def test_cli_tool_result_text_passes_through_plain_string():
    assert _cli_tool_result_text("plain text") == "plain text"


def test_cli_tool_result_text_flattens_block_list():
    blocks = [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]
    assert _cli_tool_result_text(blocks) == "ab"


def test_cli_oauth_env_strips_metered_keys(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oat-token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api-key")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-oat-other")
    env = _cli_oauth_env()
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "oat-token"
    assert "ANTHROPIC_API_KEY" not in env
    assert "ANTHROPIC_AUTH_TOKEN" not in env


def test_cli_oauth_env_promotes_oat_key(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-oat-promoted")
    env = _cli_oauth_env()
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "sk-ant-oat-promoted"


def test_cli_oauth_env_disables_the_silent_legacy_model_remap(monkeypatch):
    # Without this the CLI answers a retired id with the latest model.
    monkeypatch.delenv("CLAUDE_CODE_DISABLE_LEGACY_MODEL_REMAP", raising=False)
    assert _cli_oauth_env()["CLAUDE_CODE_DISABLE_LEGACY_MODEL_REMAP"] == "1"


def test_cli_run_records_the_served_model(monkeypatch):
    import asyncio
    import json
    import subprocess

    from blue_bench_client import runner
    from blue_bench_client.trace import Trace
    from blue_bench_mcp.profiles import load_profile
    from pathlib import Path

    lines = [
        {"type": "assistant", "message": {"model": "claude-opus-4-5-20251101",
                                          "content": [{"type": "text", "text": "hi"}]}},
        {"type": "assistant", "message": {"model": "claude-opus-4-5-20251101",
                                          "content": [{"type": "text", "text": "done"}]}},
        {"type": "result", "result": "done"},
    ]
    out = "\n".join(json.dumps(x) for x in lines)
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=out, stderr=""))
    profile = load_profile(Path(runner.__file__).parents[1] / "blue_bench_mcp/profiles/claude-opus-4-5.yaml")
    trace = Trace(prompt_id="p", profile_name=profile.name, model_id=profile.model_id,
                  tool_protocol="anthropic-cli", question="q", composed_system_prompt="s",
                  tools_available=[])
    asyncio.run(runner._run_anthropic_cli(profile, "s", "q", [], ["srv"], 5, trace))
    assert trace.served_models == ["claude-opus-4-5-20251101"]
    assert trace.final_answer == "done"
