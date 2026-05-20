"""MCP register wrappers for WazuhTool commands."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.wazuh import WazuhTool


def register(server: FastMCP, cfg: ServerConfig) -> None:
    tool = WazuhTool(cfg)

    @server.tool()
    async def wazuh_list_agents(status: str = "") -> str:
        """List Wazuh HIDS agents.

        Arguments:
          status: optional filter — 'active' / 'disconnected' / 'pending' /
            'never_connected'. Omit for all agents.
        Returns a formatted table of agent id, name, IP, OS, and status.
        NOTE: requires Wazuh API credentials; if auth fails, returns an error.
        """
        return await tool.list_agents(status=status)

    @server.tool()
    async def get_agent_alerts(
        agent_id: str, level_min: int = 0, limit: int = 50
    ) -> str:
        """Get recent alerts for a specific Wazuh agent.

        Arguments:
          agent_id: Wazuh agent id (a short numeric string like '003'), NOT
            a hostname or IP. Use wazuh_list_agents first if you don't know it.
          level_min: integer 0-15; filter out alerts below this level. Default 0.
          limit: max alerts to return, default 50.
        Primary path queries the Wazuh API; on auth failure, falls back to
        querying the ES wazuh-alerts index for the same agent.
        """
        return await tool.get_agent_alerts(
            agent_id=agent_id, level_min=level_min, limit=limit
        )
