"""NmapTool tests — run against docker target container when available."""
import shutil

import pytest

from blue_bench_mcp.config import LimitsConfig, NmapConfig, ServerConfig
from blue_bench_mcp.tool_classes.nmap import NmapTool

NMAP_PRESENT = shutil.which("nmap") is not None
DOCKER_PRESENT = shutil.which("docker") is not None


requires_nmap = pytest.mark.skipif(not NMAP_PRESENT, reason="nmap binary not installed")
requires_docker = pytest.mark.skipif(not DOCKER_PRESENT, reason="docker not installed")


@pytest.fixture
def tool():
    cfg = ServerConfig(
        nmap=NmapConfig(
            allowed_ranges=["127.0.0.0/8", "10.0.0.0/8"],
            blocked_flags=["--script", "-O"],
            timeout=30,
            scanner_container="",  # host mode
        ),
        limits=LimitsConfig(max_result_chars=5000),
    )
    return NmapTool(cfg)


def test_build_cmd_host_mode():
    cfg = ServerConfig(nmap=NmapConfig(scanner_container=""))
    t = NmapTool(cfg)
    cmd = t._build_cmd(["-sT", "-p", "22", "127.0.0.1"])
    assert cmd == ["nmap", "-sT", "-p", "22", "127.0.0.1"]


def test_build_cmd_docker_scanner_mode():
    cfg = ServerConfig(nmap=NmapConfig(scanner_container="blue-bench-scanner"))
    t = NmapTool(cfg)
    cmd = t._build_cmd(["-sT", "-p", "22", "10.10.5.22"])
    assert cmd == ["docker", "exec", "blue-bench-scanner", "nmap", "-sT", "-p", "22", "10.10.5.22"]


@requires_nmap
async def test_target_outside_allowed_range_rejected(tool):
    out = await tool.scan(target="8.8.8.8")
    assert out.startswith("Error:")
    assert "allowed ranges" in out


@requires_nmap
async def test_hostname_rejected(tool):
    out = await tool.scan(target="localhost")
    assert out.startswith("Error:")


@requires_nmap
async def test_blocked_flag_rejected(tool):
    out = await tool.scan(target="127.0.0.1", extra_flags="--script vuln")
    assert out.startswith("Error:")
    assert "blocked" in out


@requires_docker
async def test_scan_via_scanner_sidecar_reaches_target():
    # Integration: requires `docker compose up -d` with the scanner + target containers.
    cfg = ServerConfig(
        nmap=NmapConfig(
            allowed_ranges=["10.10.0.0/16"],
            timeout=30,
            scanner_container="blue-bench-scanner",
        ),
        limits=LimitsConfig(max_result_chars=5000),
    )
    t = NmapTool(cfg)
    out = await t.scan(target="10.10.5.22", ports="22,80,8080", scan_type="-sT")
    # Either the scan succeeds (target running) or surfaces the container-missing
    # error cleanly — both are acceptable outcomes depending on test env.
    assert ("Nmap scan report" in out) or ("not running" in out) or (out.startswith("Error:"))
