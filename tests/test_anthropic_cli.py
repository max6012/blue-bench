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
