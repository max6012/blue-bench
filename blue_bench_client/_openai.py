"""OpenAI-compatible client factory — local, Ollama /v1, or a Cray /v1.

The runner and interactive console talk to any OpenAI-compatible endpoint
through one factory so that pointing the benchmark at a different backend is a
config change, not a code change. This mirrors ``_ollama.py`` but targets the
OpenAI SDK's ``AsyncOpenAI``/``OpenAI`` clients, which speak the wire protocol
that vLLM, TGI, SGLang, and Ollama's ``/v1`` all expose.

Environment:
    OPENAI_BASE_URL   Base URL of the OpenAI-compatible endpoint. Unset -> the
                      SDK's default (https://api.openai.com/v1). For a local
                      Ollama set http://localhost:11434/v1; for a Cray set the
                      inference server's /v1.
    OPENAI_API_KEY    API key. Sent as ``Authorization: Bearer``. Local
                      endpoints usually accept any non-empty value (e.g.
                      "ollama" or "not-needed"); leave unset only when the
                      endpoint requires no auth at all.

So a local Ollama run needs only OPENAI_BASE_URL=http://localhost:11434/v1; a
Cray run needs OPENAI_BASE_URL=<cray>/v1 + OPENAI_API_KEY in the environment and
a profile whose model_id is the served model tag — no runner change.
"""

from __future__ import annotations

import os

from openai import AsyncOpenAI, OpenAI


def _client_kwargs() -> dict:
    kwargs: dict = {}
    base_url = os.environ.get("OPENAI_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url
    # The SDK (>=1.x) refuses to construct a client without credentials. Local
    # OpenAI-compatible endpoints (Ollama /v1, vLLM, TGI, SGLang) usually accept
    # any non-empty value, so default to a placeholder when no key is set.
    kwargs["api_key"] = os.environ.get("OPENAI_API_KEY") or "not-needed"
    return kwargs


def make_async_client() -> "AsyncOpenAI":
    """AsyncOpenAI configured for the endpoint per environment."""
    return AsyncOpenAI(**_client_kwargs())


def make_client() -> "OpenAI":
    """Synchronous peer of make_async_client (for non-async callers)."""
    return OpenAI(**_client_kwargs())


def is_configured() -> bool:
    """True when an OpenAI-compatible endpoint is explicitly configured.

    Requires OPENAI_BASE_URL specifically: with only OPENAI_API_KEY set, the SDK
    resolves base_url to https://api.openai.com/v1/ — silently targeting the
    metered OpenAI API instead of the intended local/Cray endpoint. An API key
    alone is not "configured" for our purposes.
    """
    return bool(os.environ.get("OPENAI_BASE_URL"))
