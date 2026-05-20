"""SSE transport integration test.

Spins up the Blue-Bench MCP server over SSE on an ephemeral port in a
background thread, connects a real MCP SSE client, calls list_tools, and
asserts the expected tool surface is present. Also verifies the CORS
preflight response advertises an allowed origin.
"""
from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from typing import Iterator

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.sse import sse_client

from blue_bench_mcp.server import create_server
from blue_bench_mcp.transport_sse import build_sse_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def _sse_server(origins: list[str] | None = None) -> Iterator[int]:
    """Start the SSE server in a background thread; yield its port."""
    port = _free_port()
    server = create_server()
    app = build_sse_app(server, origins or ["http://localhost:*", "http://127.0.0.1:*"])
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    uv = uvicorn.Server(config)

    t = threading.Thread(target=uv.run, daemon=True)
    t.start()

    # Wait for the server to accept connections.
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                break
        except OSError:
            time.sleep(0.05)
    else:
        uv.should_exit = True
        raise RuntimeError("SSE server did not start in time")

    try:
        yield port
    finally:
        uv.should_exit = True
        t.join(timeout=5.0)


# Tool module names the register loop emits; these map 1:1 to blue_bench_mcp/tools/*.py.
# The client-visible tool names are different (e.g. search_alerts, nmap_scan, ...).
# We assert on a representative subset of client-facing tool names.
EXPECTED_TOOLS = {
    "search_alerts",
    "nmap_scan",
    "list_evidence",
    "validate_sigma_rule",
}


@pytest.mark.asyncio
async def test_sse_list_tools_and_cors():
    with _sse_server() as port:
        url = f"http://127.0.0.1:{port}/sse"

        # CORS preflight from an allowed origin should return allow-origin.
        async with httpx.AsyncClient() as http:
            preflight = await http.options(
                url,
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "GET",
                },
                timeout=5.0,
            )
        assert preflight.status_code in (200, 204), preflight.text
        allow = preflight.headers.get("access-control-allow-origin", "")
        assert "localhost:5173" in allow or allow == "*", (
            f"unexpected CORS allow-origin header: {allow!r}"
        )

        # Real MCP client round-trip.
        async with sse_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                tool_names = {t.name for t in result.tools}

        missing = EXPECTED_TOOLS - tool_names
        assert not missing, (
            f"SSE surface missing expected tools: {missing}; got {sorted(tool_names)}"
        )
