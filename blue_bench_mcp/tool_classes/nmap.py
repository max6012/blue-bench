"""NmapTool — network recon with allowed-range + blocked-flag safety.

Two dispatch modes:

- Host mode (default): runs `nmap` on PATH. Targets must be reachable from the host.
- Docker-scanner mode: dispatches via `docker exec <scanner_container> nmap ...`.
  Needed when targets live on a Docker-internal network that the host can't
  reach (the common lab case — target container aliased as 10.10.5.22).

Select docker-scanner mode by setting `cfg.nmap.scanner_container` in config.yaml.
"""
from __future__ import annotations

import asyncio
import shutil

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import truncate_results, validate_target_in_range


class NmapTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.allowed_ranges = cfg.nmap.allowed_ranges
        self.blocked_flags = cfg.nmap.blocked_flags
        self.timeout = cfg.nmap.timeout
        self.max_chars = cfg.limits.max_result_chars
        self.scanner_container = cfg.nmap.scanner_container

        if self.scanner_container:
            # Docker-scanner mode: we need `docker` on PATH; we don't verify
            # the container is running at init (transient failures are surfaced
            # per-call so we can fail one scan without taking down the server).
            if not shutil.which("docker"):
                raise RuntimeError(
                    "nmap.scanner_container is set but `docker` binary not found on PATH."
                )
        else:
            if not shutil.which("nmap"):
                raise RuntimeError(
                    "nmap binary not found on PATH. Install nmap, or set "
                    "nmap.scanner_container in config.yaml to use a docker sidecar."
                )

    def _build_cmd(self, nmap_args: list[str]) -> list[str]:
        if self.scanner_container:
            return ["docker", "exec", self.scanner_container, "nmap", *nmap_args]
        return ["nmap", *nmap_args]

    async def scan(
        self,
        target: str,
        ports: str = "",
        scan_type: str = "-sT",
        extra_flags: str = "",
    ) -> str:
        """Run an nmap scan. Target must be inside allowed_ranges.

        Args:
            target: IP or CIDR (must be in allowed_ranges)
            ports: Port spec e.g. '22,80,443' or '1-1024'. Default: nmap default.
            scan_type: Scan type flag (default: -sT TCP connect).
            extra_flags: Additional flags; blocked_flags are rejected.
        """
        if not validate_target_in_range(target, self.allowed_ranges):
            return (
                f"Error: target '{target}' is outside allowed ranges "
                f"{self.allowed_ranges} (hostnames not allowed — use an IP or CIDR)."
            )
        all_flags = f"{scan_type} {extra_flags}"
        for blocked in self.blocked_flags:
            if blocked in all_flags:
                return f"Error: flag '{blocked}' is blocked by policy."
        nmap_args: list[str] = [scan_type]
        # In docker-scanner mode, auto-inject -Pn: containers on the internal
        # network frequently don't reply to ICMP, but their TCP services are
        # up. Without -Pn, nmap's default host-discovery reports "host seems
        # down" and exits with no port results. No-op if -Pn is already set.
        if self.scanner_container and "-Pn" not in all_flags:
            nmap_args.append("-Pn")
        if ports:
            nmap_args.extend(["-p", ports])
        if extra_flags:
            nmap_args.extend(extra_flags.split())
        nmap_args.append(target)
        cmd = self._build_cmd(nmap_args)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            return f"Error: nmap timed out after {self.timeout}s."
        output = stdout.decode()
        if proc.returncode != 0 and stderr:
            stderr_text = stderr.decode()
            if self.scanner_container and "No such container" in stderr_text:
                return (
                    f"Error: scanner container '{self.scanner_container}' not running. "
                    f"Run `docker compose up -d scanner` or set nmap.scanner_container='' to use host nmap."
                )
            output += f"\n\nStderr:\n{stderr_text}"
        return truncate_results(output, self.max_chars)

    async def quick_scan(self, target: str) -> str:
        """Fast service-detection scan (-sV --top-ports 100 --open)."""
        return await self.scan(
            target=target, scan_type="-sT", extra_flags="-sV --top-ports 100 --open"
        )
