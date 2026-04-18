"""MCP register wrappers for OpenEDRTool commands."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.openedr import OpenEDRTool


def register(server: FastMCP, cfg: ServerConfig) -> None:
    tool = OpenEDRTool(cfg)

    @server.tool()
    async def list_endpoints(status: str = "") -> str:
        """List managed endpoints. Status: online|offline|isolated."""
        return await tool.list_endpoints(status=status)

    @server.tool()
    async def get_detections(
        hostname: str = "",
        severity: str = "",
        timerange_minutes: int = 60,
    ) -> str:
        """Get EDR behavioral detections and IOC matches.

        Arguments:
          hostname: endpoint hostname to filter by; omit for all hosts.
          severity: string filter — 'critical' / 'high' / 'medium' / 'low'.
            NOTE: severity is a STRING here (not an integer like Suricata).
            Omit for no filter.
          timerange_minutes: lookback window, default 60.
        Returns a formatted list of detections with timestamp, hostname,
        rule name, and description.
        """
        return await tool.get_detections(
            hostname=hostname, severity=severity, timerange_minutes=timerange_minutes
        )
