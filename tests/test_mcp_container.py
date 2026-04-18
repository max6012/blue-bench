"""Docker image build + run smoke test for the MCP container.

Opt-in: set BLUE_BENCH_RUN_DOCKER_TESTS=1 to enable. Skipped by default because
it requires Docker and builds a fresh image (slow — minutes). When enabled, the
test:

    1. Builds docker/Dockerfile.mcp from the repo root.
    2. Runs the image briefly with its SSE transport listening on an ephemeral
       host port.
    3. Polls `/health` until it returns 200 or the deadline elapses.
    4. Tears the container down even if assertions fail.

The container starts with default config, no backends, no secrets — enough to
prove the SSE server boots and answers health checks. End-to-end MCP-client
and backend integration is left to `docker compose up`.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "docker" / "Dockerfile.mcp"
IMAGE_TAG = "blue-bench-mcp:pytest"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=5
        )
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    os.environ.get("BLUE_BENCH_RUN_DOCKER_TESTS") != "1"
    or not _docker_available()
    or not DOCKERFILE.exists(),
    reason="Docker smoke test is opt-in; set BLUE_BENCH_RUN_DOCKER_TESTS=1 and have docker running",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run(cmd: list[str], *, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, cwd=str(REPO)
    )


def test_mcp_container_builds_and_serves_health() -> None:
    """Build the image, run it, hit /health, shut down."""
    # 1. Build.
    build = _run(
        [
            "docker", "build",
            "-f", str(DOCKERFILE),
            "-t", IMAGE_TAG,
            str(REPO),
        ],
        timeout=900,
    )
    assert build.returncode == 0, (
        f"docker build failed (stdout):\n{build.stdout}\n(stderr):\n{build.stderr}"
    )

    port = _free_port()
    name = f"blue-bench-mcp-pytest-{uuid.uuid4().hex[:8]}"

    # 2. Run (detached, ephemeral port, no backend hookups).
    run = _run(
        [
            "docker", "run", "-d",
            "--rm",
            "--name", name,
            "-p", f"127.0.0.1:{port}:8765",
            IMAGE_TAG,
        ]
    )
    assert run.returncode == 0, f"docker run failed:\n{run.stderr}"

    try:
        import urllib.error
        import urllib.request

        # 3. Poll /health.
        deadline = time.time() + 60.0
        last_err: Exception | None = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/health", timeout=2.0
                ) as resp:
                    if resp.status == 200:
                        break
            except (urllib.error.URLError, OSError) as e:
                last_err = e
                time.sleep(0.5)
        else:
            logs = _run(["docker", "logs", name]).stdout
            raise AssertionError(
                f"/health never returned 200 (last error: {last_err}); container logs:\n{logs}"
            )
    finally:
        # 4. Teardown. `--rm` deletes the container when it exits.
        _run(["docker", "stop", name], timeout=30)
