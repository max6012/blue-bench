"""Ollama client factory: local default vs Ollama Cloud, selected by env."""
import pytest
from blue_bench_client import _ollama


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)


def test_local_default_no_host_no_auth():
    assert _ollama._client_kwargs() == {}
    assert _ollama.is_cloud() is False


def test_cloud_sets_host_and_bearer(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "https://ollama.com")
    monkeypatch.setenv("OLLAMA_API_KEY", "k-123")
    kw = _ollama._client_kwargs()
    assert kw["host"] == "https://ollama.com"
    assert kw["headers"]["Authorization"] == "Bearer k-123"
    assert _ollama.is_cloud() is True


def test_api_key_alone_marks_cloud(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "k-123")
    assert _ollama.is_cloud() is True
    assert _ollama._client_kwargs()["headers"]["Authorization"] == "Bearer k-123"


def test_host_only_no_auth_header(monkeypatch):
    # a non-default local host (e.g. a LAN GPU box) needs no bearer
    monkeypatch.setenv("OLLAMA_HOST", "http://gpu-box:11434")
    kw = _ollama._client_kwargs()
    assert kw == {"host": "http://gpu-box:11434"}


def test_is_cloud_host_rejects_substring_spoofing(monkeypatch):
    # a hostile URL that merely contains the cloud string is NOT cloud
    assert _ollama._is_cloud_host("https://evil.com/ollama.com") is False
    assert _ollama._is_cloud_host("https://ollama.com.evil.com") is False
    # the genuine host (and subdomains) is
    assert _ollama._is_cloud_host("https://ollama.com") is True
    assert _ollama._is_cloud_host("ollama.com") is True
    assert _ollama._is_cloud_host("https://api.ollama.com:443") is True
    assert _ollama._is_cloud_host("http://localhost:11434") is False
