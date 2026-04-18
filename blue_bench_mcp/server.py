"""Blue-Bench MCP server entry point.

Supports two transports:
    * stdio (default) — for local MCP clients (Claude Code, reference runner).
    * sse            — for browser-based MCP clients over HTTP/SSE.

Every module in blue_bench_mcp.tools is auto-imported; any module that exposes
a `register(server, cfg)` function is wired into the server at startup. Adding
a tool is add-a-file, no server.py edit required. Tool registration happens
once in create_server(); both transports see the same surface.
"""
from __future__ import annotations

import argparse
import importlib
import pkgutil
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig, load_config


def register_all(server: FastMCP, cfg: ServerConfig) -> list[str]:
    import blue_bench_mcp.tools as tools_pkg
    registered: list[str] = []
    for mod_info in pkgutil.iter_modules(tools_pkg.__path__):
        if mod_info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"blue_bench_mcp.tools.{mod_info.name}")
        if hasattr(mod, "register"):
            mod.register(server, cfg)
            registered.append(mod_info.name)
    return registered


def create_server(cfg: ServerConfig | None = None) -> FastMCP:
    cfg = cfg or ServerConfig()
    server = FastMCP("blue-bench")
    register_all(server, cfg)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Blue-Bench MCP server")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config.yaml (defaults used if omitted)",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse"),
        default="stdio",
        help="Transport to use (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="SSE bind host (overrides config.transport.sse.host)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="SSE bind port (overrides config.transport.sse.port)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config) if args.config else ServerConfig()
    server = create_server(cfg)

    if args.transport == "stdio":
        server.run(transport="stdio")
        return

    # SSE transport — import lazily so stdio users don't pay for starlette.
    from blue_bench_mcp.transport_sse import run_sse

    host = args.host or cfg.transport.sse.host
    port = args.port if args.port is not None else cfg.transport.sse.port
    run_sse(server, host=host, port=port, origins=cfg.transport.sse.origins)


if __name__ == "__main__":
    main()
