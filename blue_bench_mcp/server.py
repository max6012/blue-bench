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

from mcp.server import MCPServer

from blue_bench_mcp.config import ServerConfig, load_config


def register_all(server: MCPServer, cfg: ServerConfig) -> list[str]:
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


def create_server(
    cfg: ServerConfig | None = None,
    *,
    slice_path: Path | None = None,
    slice_log: Path | None = None,
) -> MCPServer:
    """The registered tool surface, optionally hard-bound to one fan-out slice.

    ``slice_path`` is a serialized ``Slice``; when given, every ``tools/call``
    runs through :class:`~blue_bench_mcp.fanout_bind.SliceBindingMiddleware`
    first. Enforcement sits here rather than in the reference client because
    the ``anthropic-cli`` transport (and OpenCode, and Hermes) reach this
    server without passing through any of our client code — a client-side
    proxy would bind one harness and leave the rest unscoped.
    """
    cfg = cfg or ServerConfig()
    server = MCPServer("blue-bench")
    register_all(server, cfg)
    if slice_path is not None:
        # Imported here so a plain server never pays for the fan-out schema.
        from blue_bench_mcp.fanout_bind import SliceBindingMiddleware, load_slice

        SliceBindingMiddleware(server, load_slice(slice_path), slice_log)
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
    parser.add_argument(
        "--slice",
        type=Path,
        default=None,
        dest="slice_path",
        help="Path to a serialized fan-out Slice; hard-binds every tool call to it",
    )
    parser.add_argument(
        "--slice-log",
        type=Path,
        default=None,
        help="Path to append one JSONL line per bound tool call (requires --slice)",
    )
    args = parser.parse_args()
    if args.slice_log is not None and args.slice_path is None:
        parser.error("--slice-log requires --slice")

    cfg = load_config(args.config) if args.config else ServerConfig()
    server = create_server(cfg, slice_path=args.slice_path, slice_log=args.slice_log)

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
