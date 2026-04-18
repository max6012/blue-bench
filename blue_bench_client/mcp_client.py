"""Thin stdio MCP client — wraps the mcp SDK for use by runner.

Connects to a server launched as a subprocess via `python -m blue_bench_mcp.server`.
Exposes list_tools() and call_tool() as async methods. Connection is a context
manager (the underlying SDK sessions are all async contexts).
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


class MCPStdioClient:
    def __init__(self, server_cmd: list[str]) -> None:
        self.server_cmd = server_cmd
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "MCPStdioClient":
        self._stack = AsyncExitStack()
        params = StdioServerParameters(command=self.server_cmd[0], args=self.server_cmd[1:])
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        assert self._stack is not None
        await self._stack.aclose()
        self._stack = None
        self._session = None

    async def list_tools(self) -> list[ToolSpec]:
        assert self._session is not None
        resp = await self._session.list_tools()
        return [
            ToolSpec(name=t.name, description=t.description or "", input_schema=t.inputSchema or {})
            for t in resp.tools
        ]

    async def call_tool(self, name: str, args: dict[str, Any]) -> str:
        assert self._session is not None
        resp = await self._session.call_tool(name, args)
        # MCP returns content blocks; concatenate text blocks.
        parts: list[str] = []
        for block in resp.content:
            text = getattr(block, "text", None)
            if text is not None:
                parts.append(text)
        return "\n".join(parts)
