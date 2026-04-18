"""SSE transport for the Blue-Bench MCP server.

Wraps FastMCP's Starlette SSE app with a configurable CORS middleware so
browser-based MCP clients can connect directly (no gateway).

CORS origin allowlist priority (first non-empty wins):
    1. Explicit `origins` argument
    2. BLUE_BENCH_CORS_ORIGINS env var (comma-separated; use "*" to allow all)
    3. The `origins` field on ServerConfig.transport.sse (from config.yaml)
    4. Default: ["http://localhost:*", "http://127.0.0.1:*"]

A single "*" entry disables origin checking entirely (dev mode).
"""
from __future__ import annotations

import os
from typing import Iterable

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


DEFAULT_ORIGINS: list[str] = ["http://localhost:*", "http://127.0.0.1:*"]


def resolve_origins(configured: Iterable[str] | None = None) -> list[str]:
    """Resolve the final CORS origin allowlist.

    configured = origins from config.yaml (or None). Env var overrides it.
    """
    env = os.environ.get("BLUE_BENCH_CORS_ORIGINS", "").strip()
    if env:
        return [o.strip() for o in env.split(",") if o.strip()]
    if configured:
        lst = [o for o in configured if o]
        if lst:
            return lst
    return list(DEFAULT_ORIGINS)


def _cors_middleware(origins: list[str]) -> Middleware:
    # CORSMiddleware distinguishes exact origins (allow_origins) from regex
    # (allow_origin_regex). Wildcard patterns like "http://localhost:*" need
    # the regex form. Star "*" means allow any.
    if origins == ["*"]:
        return Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )
    exact: list[str] = []
    regexes: list[str] = []
    for o in origins:
        if "*" in o:
            # Convert glob-style wildcard to a regex.
            regexes.append(o.replace(".", r"\.").replace("*", r".*"))
        else:
            exact.append(o)
    regex = "|".join(f"({r})" for r in regexes) if regexes else None
    return Middleware(
        CORSMiddleware,
        allow_origins=exact,
        allow_origin_regex=regex,
        allow_methods=["*"],
        allow_headers=["*"],
    )


async def _health(_: Request) -> JSONResponse:
    """Liveness endpoint. Returns 200 whenever the SSE app is serving."""
    return JSONResponse({"ok": True, "service": "blue-bench-mcp"})


def build_sse_app(server: FastMCP, origins: list[str]) -> Starlette:
    """Wrap FastMCP.sse_app() with our CORS middleware.

    FastMCP.sse_app() returns a Starlette app; we wrap it so the CORS
    middleware sits in front of every route (including /sse and /messages/).
    Adds a lightweight `/health` route for container healthchecks.
    """
    inner: Starlette = server.sse_app()
    routes = list(inner.routes) + [Route("/health", _health, methods=["GET"])]
    app = Starlette(
        debug=inner.debug,
        routes=routes,
        middleware=[_cors_middleware(origins)],
        lifespan=inner.router.lifespan_context,
    )
    return app


def run_sse(
    server: FastMCP,
    host: str,
    port: int,
    origins: list[str] | None = None,
) -> None:
    """Blocking call: serve the SSE app via uvicorn."""
    app = build_sse_app(server, resolve_origins(origins))
    uvicorn.run(app, host=host, port=port, log_level="info")
