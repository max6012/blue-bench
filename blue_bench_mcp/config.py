"""ServerConfig — single typed source of truth for the MCP server.

Tools read from nested Pydantic fields, never dict lookups (see docs/internal/TOOL_CLASS_PATTERN.md).
Secrets layer in from env vars via load_config — never commit credentials.

`load_config` also performs `${VAR:-default}` / `${VAR}` substitution on every
string value in the loaded YAML. This lets the same `config.yaml` work both on
the host (where backends live on `localhost`) and inside the Tier 1 tool-tier
compose (where they live on DNS names like `elasticsearch`). See the `mcp`
service in `docker/compose.tools.yml` for the env vars used.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class LimitsConfig(BaseModel):
    query_timeout: int = 30
    max_result_chars: int = 8000
    max_results: int = 500


class EvidenceConfig(BaseModel):
    evidence_dir: str = "data/evidence"


class ElasticConfig(BaseModel):
    url: str = "http://localhost:9200"
    # Multi-index pattern covering Suricata + Wazuh + Zeek. ES accepts comma-separated.
    # Concrete index names set by scripts/seed_es.py; match them verbatim here.
    index_pattern: str = "logstash-suricata-alerts,wazuh-alerts,zeek-conn"
    verify_ssl: bool = False
    user: str = ""
    password: str = ""


class ZeekConfig(BaseModel):
    """Zeek index settings for get_connections (ES-backed)."""
    index: str = "zeek-conn"
    use_elastic: bool = True


class WazuhConfig(BaseModel):
    api_url: str = "https://localhost:55000"
    user: str = ""
    password: str = ""
    # When Wazuh API is unreachable, fall back to querying ES for wazuh-alerts.
    es_fallback_index: str = "wazuh-alerts"


class OpenEDRConfig(BaseModel):
    url: str = "http://localhost:9443"
    verify_ssl: bool = False
    user: str = ""
    password: str = ""


class NmapConfig(BaseModel):
    allowed_ranges: list[str] = Field(default_factory=lambda: ["10.10.0.0/16"])
    blocked_flags: list[str] = Field(default_factory=lambda: ["--script", "-O"])
    timeout: int = 300
    # When set, the tool dispatches `docker exec <scanner_container> nmap ...`
    # instead of invoking nmap on the host. Required when the targets live on
    # an internal Docker network the host can't reach. Empty string = use host nmap.
    scanner_container: str = ""


class SigmaConfig(BaseModel):
    rules_dir: str = "data/sigma_rules"
    default_backend: str = "es-qs"


class SseTransportConfig(BaseModel):
    """SSE transport knobs for browser-based MCP clients.

    CLI flags (--host, --port) override these; the BLUE_BENCH_CORS_ORIGINS
    env var overrides `origins` (see transport_sse.resolve_origins).
    """
    host: str = "127.0.0.1"
    port: int = 8765
    # Wildcard entries (e.g. "http://localhost:*") are converted to regex;
    # a single "*" disables origin checking entirely (dev mode).
    origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:*", "http://127.0.0.1:*"]
    )


class TransportConfig(BaseModel):
    sse: SseTransportConfig = Field(default_factory=SseTransportConfig)


class ServerConfig(BaseModel):
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    elastic: ElasticConfig = Field(default_factory=ElasticConfig)
    zeek: ZeekConfig = Field(default_factory=ZeekConfig)
    wazuh: WazuhConfig = Field(default_factory=WazuhConfig)
    openedr: OpenEDRConfig = Field(default_factory=OpenEDRConfig)
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    sigma: SigmaConfig = Field(default_factory=SigmaConfig)
    transport: TransportConfig = Field(default_factory=TransportConfig)


# ${VAR}, ${VAR:-default} (unset OR empty → default), or ${VAR-default} (unset only).
# Non-recursive. Escape by doubling: $${literal}.
_ENV_VAR_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([^}]*))?\}"
)


def _interpolate_env(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        name, op, default = m.group(1), m.group(2), m.group(3)
        env = os.environ.get(name)
        if op == ":-":
            # POSIX :- → default when unset OR empty.
            if env is not None and env != "":
                return env
            return default if default is not None else ""
        if op == "-":
            # POSIX - → default only when unset; explicit empty wins.
            if env is not None:
                return env
            return default if default is not None else ""
        # No default branch: empty string if unset.
        return env if env is not None else ""

    # Support `$${literal}` as an escape for a literal `${literal}`.
    if "$${" not in value:
        return _ENV_VAR_RE.sub(repl, value)
    # Two-pass to avoid touching escaped sequences.
    sentinel = "\x00ESC\x00"
    tmp = value.replace("$${", sentinel)
    tmp = _ENV_VAR_RE.sub(repl, tmp)
    return tmp.replace(sentinel, "${")


def _interpolate_tree(obj: Any) -> Any:
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, list):
        return [_interpolate_tree(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _interpolate_tree(v) for k, v in obj.items()}
    return obj


def load_config(path: Path) -> ServerConfig:
    """Load YAML config + overlay env secrets (BLUE_BENCH_* prefix).

    Any `${VAR}` / `${VAR:-default}` tokens inside string values are expanded
    from the environment before model validation. Use `$${literal}` to embed
    a literal `${literal}` without substitution.
    """
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    data = _interpolate_tree(data)
    cfg = ServerConfig.model_validate(data)

    # Overlay secrets from environment (only if not already set in YAML).
    cfg.elastic.user = os.environ.get("BLUE_BENCH_ELASTIC_USER", cfg.elastic.user)
    cfg.elastic.password = os.environ.get("BLUE_BENCH_ELASTIC_PASS", cfg.elastic.password)
    cfg.wazuh.user = os.environ.get("BLUE_BENCH_WAZUH_USER", cfg.wazuh.user)
    cfg.wazuh.password = os.environ.get("BLUE_BENCH_WAZUH_PASS", cfg.wazuh.password)
    cfg.openedr.user = os.environ.get("BLUE_BENCH_OPENEDR_USER", cfg.openedr.user)
    cfg.openedr.password = os.environ.get("BLUE_BENCH_OPENEDR_PASS", cfg.openedr.password)

    return cfg
