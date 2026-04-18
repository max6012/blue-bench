"""Unit tests for the thin Anthropic forwarding proxy.

Uses ``httpx.MockTransport`` to avoid any real network calls; FastAPI is
exercised via ``httpx.ASGITransport`` so middleware (CORS) and routing are
covered end-to-end.
"""
from __future__ import annotations

import json
import logging

import httpx
import pytest

from blue_bench_mcp import anthropic_proxy as proxy_mod


async def _build_app(handler, *, env: dict | None = None, monkeypatch=None):
    """Helper: build a proxy app whose upstream is a MockTransport handler."""
    if monkeypatch is not None and env is not None:
        for k, v in env.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    # Run FastAPI startup so app.state.client is populated.
    async with app.router.lifespan_context(app):
        yield app, mock_client
    await mock_client.aclose()


# ---------------------------------------------------------------------------
# Startup behaviour
# ---------------------------------------------------------------------------


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        proxy_mod.create_app()


def test_create_app_reads_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-key")
    app = proxy_mod.create_app()
    assert app.state.api_key == "sk-env-key"


# ---------------------------------------------------------------------------
# Forwarding + auth injection + client-key stripping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_forwards_body_and_injects_auth(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        return httpx.Response(
            200,
            json={"id": "msg_1", "content": [{"type": "text", "text": "hi"}]},
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                body = {
                    "model": "claude-sonnet-4-6",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 10,
                }
                r = await client.post(
                    "/v1/messages",
                    json=body,
                    headers={
                        # Attacker-supplied key must be stripped.
                        "x-api-key": "sk-EVIL",
                        "authorization": "Bearer evil",
                    },
                )
    finally:
        await mock_client.aclose()

    assert r.status_code == 200
    assert r.json()["id"] == "msg_1"
    assert captured["url"] == proxy_mod.UPSTREAM_URL
    # Our key injected.
    assert captured["headers"]["x-api-key"] == "sk-test-key"
    # anthropic-version default applied.
    assert captured["headers"]["anthropic-version"] == proxy_mod.DEFAULT_ANTHROPIC_VERSION
    # Body forwarded verbatim.
    assert json.loads(captured["body"]) == body
    # No leftover authorization header from the client.
    assert "authorization" not in {k.lower() for k in captured["headers"]}


@pytest.mark.asyncio
async def test_client_anthropic_version_override():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"ok": True})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                r = await c.post(
                    "/v1/messages",
                    json={"model": "x", "messages": [], "max_tokens": 1},
                    headers={"anthropic-version": "2099-01-01"},
                )
    finally:
        await mock_client.aclose()

    assert r.status_code == 200
    assert captured["headers"]["anthropic-version"] == "2099-01-01"


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_streaming_preserves_sse():
    sse_payload = (
        b"event: message_start\n"
        b'data: {"type":"message_start"}\n\n'
        b"event: content_block_delta\n"
        b'data: {"type":"content_block_delta","delta":{"text":"hi"}}\n\n'
        b"event: message_stop\n"
        b'data: {"type":"message_stop"}\n\n'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # Stream byte-for-byte.
        return httpx.Response(
            200,
            content=sse_payload,
            headers={"content-type": "text/event-stream"},
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                r = await c.post(
                    "/v1/messages",
                    json={
                        "model": "claude-sonnet-4-6",
                        "messages": [{"role": "user", "content": "hi"}],
                        "max_tokens": 10,
                        "stream": True,
                    },
                )
    finally:
        await mock_client.aclose()

    assert r.status_code == 200
    assert "text/event-stream" in r.headers["content-type"]
    assert r.content == sse_payload


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cors_preflight_allows_localhost(monkeypatch):
    monkeypatch.delenv("FRONTEND_ORIGIN", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                r = await c.options(
                    "/v1/messages",
                    headers={
                        "origin": "http://localhost:5173",
                        "access-control-request-method": "POST",
                        "access-control-request-headers": "content-type",
                    },
                )
    finally:
        await mock_client.aclose()

    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
    allowed = r.headers.get("access-control-allow-methods", "")
    assert "POST" in allowed


@pytest.mark.asyncio
async def test_cors_blocks_unknown_origin(monkeypatch):
    monkeypatch.delenv("FRONTEND_ORIGIN", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                r = await c.options(
                    "/v1/messages",
                    headers={
                        "origin": "http://evil.example.com",
                        "access-control-request-method": "POST",
                    },
                )
    finally:
        await mock_client.aclose()

    # CORSMiddleware returns 400 for disallowed origins on preflight.
    assert "access-control-allow-origin" not in r.headers


# ---------------------------------------------------------------------------
# Upstream error propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upstream_4xx_propagates():
    body = {"error": {"type": "invalid_request_error", "message": "bad model"}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json=body)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                r = await c.post(
                    "/v1/messages",
                    json={"model": "bogus", "messages": [], "max_tokens": 1},
                )
    finally:
        await mock_client.aclose()

    assert r.status_code == 400
    assert r.json() == body


@pytest.mark.asyncio
async def test_upstream_5xx_propagates():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "upstream down"})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                r = await c.post(
                    "/v1/messages",
                    json={"model": "x", "messages": [], "max_tokens": 1},
                )
    finally:
        await mock_client.aclose()

    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_endpoint():
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    app = proxy_mod.create_app(api_key="sk-test-key", http_client=mock_client)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                r = await c.get("/health")
    finally:
        await mock_client.aclose()

    assert r.status_code == 200
    assert r.json() == {"ok": True, "upstream": "api.anthropic.com"}


# ---------------------------------------------------------------------------
# .env is read and API key is never logged
# ---------------------------------------------------------------------------


def test_dotenv_read_and_key_not_logged(monkeypatch, tmp_path, caplog):
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-from-dotenv-SECRET\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    from dotenv import load_dotenv

    caplog.set_level(logging.DEBUG, logger="blue_bench.anthropic_proxy")
    load_dotenv(env_file)
    import os as _os

    assert _os.environ["ANTHROPIC_API_KEY"] == "sk-from-dotenv-SECRET"

    app = proxy_mod.create_app()
    assert app.state.api_key == "sk-from-dotenv-SECRET"

    # The key must not appear in any log record captured during construction.
    for rec in caplog.records:
        assert "sk-from-dotenv-SECRET" not in rec.getMessage()
