"""Thin HTTP proxy that forwards browser requests to the Anthropic Messages API.

Purpose: browsers cannot safely hold an API key. This minimal FastAPI app
holds ``ANTHROPIC_API_KEY`` server-side and forwards POST bodies verbatim to
``https://api.anthropic.com/v1/messages``, preserving SSE streaming.

No model selection, no caching, no retries, no request/response body logging.

Launch:
    python -m blue_bench_mcp.anthropic_proxy --port 8766
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import os
from typing import Iterable

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse

UPSTREAM_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
# Headers the client must never be able to forward upstream.
# `origin`, `referer`, and `sec-fetch-*` are stripped so Anthropic does not
# treat forwarded requests as direct-from-browser (which would demand the
# `anthropic-dangerous-direct-browser-access` header).
_STRIPPED_CLIENT_HEADERS = {
    "host",
    "content-length",
    "x-api-key",
    "authorization",
    "origin",
    "referer",
    "cookie",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
}
# Upstream response headers we do not pass back to the browser.
_HOP_BY_HOP = {
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

log = logging.getLogger("blue_bench.anthropic_proxy")


def _parse_origins(raw: str | None) -> list[str] | str:
    if not raw:
        # Default: any localhost / 127.0.0.1 port (regex handled by CORSMiddleware).
        return []
    raw = raw.strip()
    if raw == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


def _forward_headers(src: Iterable[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in src:
        lk = k.lower()
        if lk in _STRIPPED_CLIENT_HEADERS:
            continue
        out[k] = v
    return out


def _filter_response_headers(src: Iterable[tuple[bytes, bytes]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for k, v in src:
        ks = k.decode("latin-1") if isinstance(k, bytes) else k
        vs = v.decode("latin-1") if isinstance(v, bytes) else v
        if ks.lower() in _HOP_BY_HOP:
            continue
        out.append((ks, vs))
    return out


def create_app(
    api_key: str | None = None,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Build the FastAPI app.

    ``api_key`` defaults to ``ANTHROPIC_API_KEY`` from the environment; if
    missing the app raises at construction so startup fails loudly.
    ``http_client`` lets tests inject a client backed by ``MockTransport``.
    """
    key = api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Add it to .env or the environment "
            "before starting the Anthropic proxy."
        )

    app = FastAPI(title="Blue-Bench Anthropic Proxy", version="0.1.0")

    origins_env = os.environ.get("FRONTEND_ORIGIN")
    origins = _parse_origins(origins_env)
    cors_kwargs: dict = {
        "allow_methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["*"],
        "allow_credentials": False,
    }
    if origins == ["*"]:
        cors_kwargs["allow_origins"] = ["*"]
    elif origins:
        cors_kwargs["allow_origins"] = origins
    else:
        # Any localhost / 127.0.0.1 port over http.
        cors_kwargs["allow_origins"] = []
        cors_kwargs["allow_origin_regex"] = r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"
    app.add_middleware(CORSMiddleware, **cors_kwargs)

    app.state.api_key = key
    # If a client is injected (tests), use it directly and skip lifecycle.
    if http_client is not None:
        app.state.client = http_client
        app.state.owns_client = False
    else:
        app.state.client = None
        app.state.owns_client = True

    @contextlib.asynccontextmanager
    async def _lifespan(app: FastAPI):  # pragma: no cover - exercised via server
        if app.state.client is None:
            app.state.client = httpx.AsyncClient(
                timeout=httpx.Timeout(600.0, connect=10.0)
            )
        try:
            yield
        finally:
            if app.state.owns_client and app.state.client is not None:
                await app.state.client.aclose()

    app.router.lifespan_context = _lifespan

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True, "upstream": "api.anthropic.com"}

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        body = await request.body()
        headers = _forward_headers(request.headers.items())
        headers["x-api-key"] = app.state.api_key
        headers.setdefault("anthropic-version", DEFAULT_ANTHROPIC_VERSION)
        headers["content-type"] = request.headers.get("content-type", "application/json")

        # Detect streaming without parsing JSON (preserve verbatim forwarding).
        is_stream = b'"stream"' in body and b"true" in body

        client: httpx.AsyncClient = app.state.client

        if is_stream:
            req = client.build_request("POST", UPSTREAM_URL, content=body, headers=headers)
            upstream = await client.send(req, stream=True)
            resp_headers = _filter_response_headers(upstream.headers.raw)

            async def gen():
                try:
                    # aiter_bytes works for both real streaming and buffered
                    # (MockTransport-backed) responses; raw bytes are preserved.
                    async for chunk in upstream.aiter_bytes():
                        yield chunk
                finally:
                    await upstream.aclose()

            return StreamingResponse(
                gen(),
                status_code=upstream.status_code,
                headers=dict(resp_headers),
                media_type=upstream.headers.get("content-type", "text/event-stream"),
            )

        upstream = await client.post(UPSTREAM_URL, content=body, headers=headers)
        resp_headers = _filter_response_headers(upstream.headers.raw)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=dict(resp_headers),
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    @app.exception_handler(httpx.HTTPError)
    async def _upstream_error(_req: Request, exc: httpx.HTTPError) -> JSONResponse:
        # Do not echo exception strings that might include headers.
        log.warning("upstream transport error: %s", type(exc).__name__)
        return JSONResponse(
            {"error": {"type": "upstream_error", "message": "Upstream request failed."}},
            status_code=502,
        )

    return app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Blue-Bench Anthropic proxy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    load_dotenv()
    # Validate key eagerly so misconfiguration fails before the port opens.
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit(
            "error: ANTHROPIC_API_KEY is not set. Add it to .env or the environment."
        )

    import uvicorn

    uvicorn.run(
        "blue_bench_mcp.anthropic_proxy:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
