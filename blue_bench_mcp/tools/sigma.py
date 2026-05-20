"""MCP register wrapper for SigmaTool.validate_rule."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.sigma import SigmaTool


def register(server: FastMCP, cfg: ServerConfig) -> None:
    tool = SigmaTool(cfg)

    @server.tool()
    async def validate_sigma_rule(rule_yaml: str) -> str:
        """Validate a Sigma rule's YAML syntax + required fields. Returns VALID or INVALID with reasons."""
        return await tool.validate_rule(rule_yaml=rule_yaml)
