"""Ollama client factory — local or Ollama Cloud, selected by environment.

The runner and interactive console talk to Ollama through one factory so that
pointing the benchmark at a larger cloud-hosted model is a config change, not a
code change.

Environment:
    OLLAMA_HOST      Ollama endpoint. Unset -> the client's default
                     (http://localhost:11434, local Metal/CUDA). For Ollama
                     Cloud set https://ollama.com.
    OLLAMA_API_KEY   Cloud API key. When set, sent as ``Authorization: Bearer``
                     so a cloud host authenticates. Local runs leave it unset.

So a local Gemma-4-class run needs nothing; a larger cloud model (e.g.
``gpt-oss:120b-cloud``, ``qwen3-coder:480b-cloud``, ``deepseek-v3.1:671b-cloud``)
needs only OLLAMA_HOST=https://ollama.com + OLLAMA_API_KEY in the environment and
a profile whose model_id is the cloud model tag — no runner change.
"""

from __future__ import annotations

import os

import ollama


def _client_kwargs() -> dict:
    kwargs: dict = {}
    host = os.environ.get("OLLAMA_HOST")
    if host:
        kwargs["host"] = host
    api_key = os.environ.get("OLLAMA_API_KEY")
    if api_key:
        # Cloud auth. Merge rather than clobber any caller headers.
        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {api_key}"
    return kwargs


def make_async_client() -> "ollama.AsyncClient":
    """AsyncClient configured for local Ollama or Ollama Cloud per environment."""
    return ollama.AsyncClient(**_client_kwargs())


def make_client() -> "ollama.Client":
    """Synchronous peer of make_async_client (for non-async callers)."""
    return ollama.Client(**_client_kwargs())


def is_cloud() -> bool:
    """True when configured to talk to a remote/cloud Ollama endpoint."""
    return bool(os.environ.get("OLLAMA_API_KEY")) or (
        "ollama.com" in os.environ.get("OLLAMA_HOST", "")
    )
