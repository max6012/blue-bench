"""OpenAI-compatible client factory: local /v1 vs Cray, selected by env."""
import pytest
from blue_bench_client import _openai


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def test_no_config_uses_sdk_defaults():
    kw = _openai._client_kwargs()
    assert "base_url" not in kw
    assert kw["api_key"] == "not-needed"
    assert _openai.is_configured() is False


def test_base_url_sets_endpoint(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
    kw = _openai._client_kwargs()
    assert kw["base_url"] == "http://localhost:11434/v1"
    assert kw["api_key"] == "not-needed"
    assert _openai.is_configured() is True


def test_api_key_sets_bearer(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k-123")
    kw = _openai._client_kwargs()
    assert kw["api_key"] == "k-123"
    # D-K: an API key alone is NOT "configured" — without OPENAI_BASE_URL the SDK
    # would silently target api.openai.com.
    assert _openai.is_configured() is False


def test_cray_full_config(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://cray.example/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-cray")
    kw = _openai._client_kwargs()
    assert kw["base_url"] == "https://cray.example/v1"
    assert kw["api_key"] == "sk-cray"
    assert _openai.is_configured() is True


def test_make_async_client_returns_async_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
    client = _openai.make_async_client()
    assert str(client.base_url) == "http://localhost:11434/v1/"


def test_make_client_returns_sync_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
    client = _openai.make_client()
    assert str(client.base_url) == "http://localhost:11434/v1/"
