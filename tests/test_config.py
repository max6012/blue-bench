import os
from pathlib import Path

import pytest

from blue_bench_mcp.config import ServerConfig, load_config


def test_defaults():
    cfg = ServerConfig()
    assert cfg.limits.query_timeout == 30
    assert cfg.limits.max_result_chars == 8000
    assert cfg.evidence.evidence_dir == "data/evidence"


def test_model_validate_json():
    raw = '{"limits": {"query_timeout": 60}, "evidence": {"evidence_dir": "/tmp/ev"}}'
    cfg = ServerConfig.model_validate_json(raw)
    assert cfg.limits.query_timeout == 60
    assert cfg.evidence.evidence_dir == "/tmp/ev"
    assert cfg.limits.max_result_chars == 8000


def test_yaml_roundtrip(tmp_path: Path):
    f = tmp_path / "cfg.yaml"
    f.write_text("limits:\n  query_timeout: 45\nevidence:\n  evidence_dir: /data/ev\n")
    cfg = load_config(f)
    assert cfg.limits.query_timeout == 45
    assert cfg.evidence.evidence_dir == "/data/ev"


def test_env_var_interpolation_default_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # When the env var is unset, the `${VAR:-default}` default is used.
    monkeypatch.delenv("BLUE_BENCH_ES_URL", raising=False)
    f = tmp_path / "cfg.yaml"
    f.write_text("elastic:\n  url: ${BLUE_BENCH_ES_URL:-http://localhost:9200}\n")
    cfg = load_config(f)
    assert cfg.elastic.url == "http://localhost:9200"


def test_env_var_interpolation_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # When the env var is set, its value wins over the default.
    monkeypatch.setenv("BLUE_BENCH_ES_URL", "http://elasticsearch:9200")
    f = tmp_path / "cfg.yaml"
    f.write_text("elastic:\n  url: ${BLUE_BENCH_ES_URL:-http://localhost:9200}\n")
    cfg = load_config(f)
    assert cfg.elastic.url == "http://elasticsearch:9200"


def test_env_var_interpolation_dash_without_colon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # `${VAR-default}` (no colon) → explicit empty env wins, default only when unset.
    # This is what the `mcp` service in compose.tools.yml relies on to disable
    # the scanner-sidecar dispatch path.
    monkeypatch.setenv("BLUE_BENCH_NMAP_SCANNER", "")
    f = tmp_path / "cfg.yaml"
    f.write_text("nmap:\n  scanner_container: ${BLUE_BENCH_NMAP_SCANNER-blue-bench-scanner}\n")
    cfg = load_config(f)
    assert cfg.nmap.scanner_container == ""

    monkeypatch.delenv("BLUE_BENCH_NMAP_SCANNER", raising=False)
    cfg2 = load_config(f)
    assert cfg2.nmap.scanner_container == "blue-bench-scanner"


def test_env_var_literal_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # `$${literal}` is preserved as `${literal}` — not substituted.
    monkeypatch.delenv("LITERAL", raising=False)
    f = tmp_path / "cfg.yaml"
    f.write_text("evidence:\n  evidence_dir: /data/$${LITERAL}\n")
    cfg = load_config(f)
    assert cfg.evidence.evidence_dir == "/data/${LITERAL}"
