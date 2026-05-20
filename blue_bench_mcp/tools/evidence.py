"""MCP register wrappers for EvidenceTool — four forensic-triage commands.

Names align with archive convention (list_evidence, file_hash, file_metadata,
strings_extract) so Phase 2 prompts can use their archive wording unchanged.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.evidence import EvidenceTool


def register(server: FastMCP, cfg: ServerConfig) -> None:
    tool = EvidenceTool(cfg)

    @server.tool()
    async def list_evidence() -> str:
        """List evidence files with size, mtime, and file type detection."""
        return await tool.list_evidence()

    @server.tool()
    async def file_hash(filename: str, algorithm: str = "sha256") -> str:
        """Compute a hash of an evidence file. Algorithms: md5, sha1, sha256, sha512, or 'all'."""
        return await tool.file_hash(filename=filename, algorithm=algorithm)

    @server.tool()
    async def file_metadata(filename: str) -> str:
        """Identify file type via magic bytes + stat metadata."""
        return await tool.file_metadata(filename=filename)

    @server.tool()
    async def strings_extract(
        filename: str, min_length: int = 4, max_strings: int = 200
    ) -> str:
        """Extract readable ASCII strings from a binary (IOC hunting, URL discovery)."""
        return await tool.strings_extract(
            filename=filename, min_length=min_length, max_strings=max_strings
        )
