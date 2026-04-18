"""MCP register wrappers for NmapTool commands."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.nmap import NmapTool


def register(server: FastMCP, cfg: ServerConfig) -> None:
    try:
        tool = NmapTool(cfg)
    except RuntimeError as e:
        # nmap missing — skip registration silently; tests will catch this in smoke.
        # TODO(blue-bench): surface a startup log via a structured logger.
        return

    @server.tool()
    async def nmap_scan(
        target: str,
        ports: str = "",
        scan_type: str = "-sT",
        extra_flags: str = "",
    ) -> str:
        """Run an nmap scan against a target IP or CIDR inside the configured allowed ranges.

        Arguments:
          target: IPv4 address or CIDR. Hostnames are rejected. Must be inside
            one of the configured allowed_ranges or the call errors out.
          ports: port specification (e.g., '22,80,443' or '1-65535'). Empty =
            nmap default (top 1000).
          scan_type: scan-type flag (default '-sT' TCP connect). Some scan
            types are blocked by policy (see error message if rejected).
          extra_flags: additional nmap flags. Some flags are blocked by policy.
        Returns raw nmap output. Scans outside the allowed range, with blocked
        flags, or that time out return an error string starting with 'Error:'.
        """
        return await tool.scan(
            target=target, ports=ports, scan_type=scan_type, extra_flags=extra_flags
        )

    @server.tool()
    async def nmap_quick_scan(target: str) -> str:
        """Fast service-detection scan (-sV --top-ports 100 --open)."""
        return await tool.quick_scan(target=target)
