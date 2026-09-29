"""The OpenCode worker's pure parts: the generated config and the event parser."""
from pathlib import Path

from blue_bench_client.fanout import opencode_worker as ow
from blue_bench_client.trace import Trace


def test_config_disables_every_builtin_and_binds_the_slice_server():
    cfg = ow.opencode_config("ollama-cloud/gpt-oss:120b", 131072, Path("/p.md"),
                             ["py", "-m", "blue_bench_mcp.server", "--slice", "s.json"],
                             steps=18, temperature=0.3, top_p=0.9)
    agent = cfg["agent"]["bbworker"]
    assert all(v is False for v in agent["tools"].values()) and "skill" in agent["tools"]
    assert agent["steps"] == 18 and agent["prompt"] == "{file:/p.md}"
    assert cfg["mcp"][ow.MCP_NAME]["command"][-2:] == ["--slice", "s.json"]
    assert "gpt-oss:120b" in cfg["provider"]["ollama-cloud"]["models"]


def test_events_become_trace_turns_with_the_server_prefix_stripped():
    t = Trace(prompt_id="p", profile_name="x", model_id="m", tool_protocol="openai-native",
              question="q", composed_system_prompt="s", tools_available=[])
    ev = [{"type": "tool_use", "part": {"tool": f"{ow.MCP_NAME}_count_by_field",
                                        "state": {"input": {"field": "Image"}, "output": "Top 20"}}},
          {"type": "text", "part": {"text": "done"}},
          {"type": "step_finish", "part": {"reason": "stop"}}]
    ow.events_to_trace(ev, t)
    assert t.turns[0].tool_calls[0].name == "count_by_field" and t.turns[1].content == "Top 20"
    assert t.turns_used == 1 and t.final_answer.startswith("done")
    assert ow._terminal_reason(ev) == "stop"
