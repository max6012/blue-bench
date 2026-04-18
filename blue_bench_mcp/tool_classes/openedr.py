"""OpenEDRTool — endpoint telemetry from the OpenEDR mock (FastAPI).

Only get_detections is used by the Phase 2 10-prompt subset (p2-08), but the
class exposes the full set of endpoint queries for future expansion.
"""
from __future__ import annotations

from typing import Any

import httpx

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import truncate_results


class OpenEDRTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.url = cfg.openedr.url.rstrip("/")
        self.verify_ssl = cfg.openedr.verify_ssl
        self.user = cfg.openedr.user
        self.password = cfg.openedr.password
        self.timeout = cfg.limits.query_timeout
        self.max_chars = cfg.limits.max_result_chars
        self.max_results = cfg.limits.max_results

    def _auth(self) -> tuple[str, str] | None:
        return (self.user, self.password) if self.user and self.password else None

    async def _api_get(self, endpoint: str, params: dict | None = None) -> dict:
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.get(f"{self.url}{endpoint}", params=params or {})
            resp.raise_for_status()
            return resp.json()

    async def list_endpoints(self, status: str = "") -> str:
        """List managed endpoints.

        Args:
            status: Filter by status (online, offline, isolated)
        """
        params: dict[str, Any] = {}
        if status:
            params["status"] = status
        try:
            data = await self._api_get("/api/v1/endpoints", params)
        except httpx.HTTPError as e:
            return f"Error: OpenEDR request failed: {e}"
        endpoints = data.get("data", [])
        if not endpoints:
            return "No endpoints returned."
        lines = ["Managed Endpoints:"]
        for ep in endpoints:
            lines.append(
                f"  [{ep.get('status', '?'):8s}] "
                f"{ep.get('hostname', 'unknown'):25s} "
                f"IP={ep.get('ip', '?'):15s} "
                f"OS={ep.get('os', '?')}"
            )
        return truncate_results("\n".join(lines), self.max_chars)

    async def get_detections(
        self,
        hostname: str = "",
        severity: str = "",
        timerange_minutes: int = 60,
    ) -> str:
        """Get EDR detection events (behavioral detections, IOC matches).

        Args:
            hostname: Filter by hostname (empty = all)
            severity: Filter by severity (critical, high, medium, low)
            timerange_minutes: Lookback window
        """
        params: dict[str, Any] = {
            "timerange": f"{timerange_minutes}m",
            "limit": self.max_results,
        }
        if hostname:
            params["hostname"] = hostname
        if severity:
            params["severity"] = severity
        try:
            data = await self._api_get("/api/v1/detections", params)
        except httpx.HTTPError as e:
            return f"Error: OpenEDR request failed: {e}"
        detections = data.get("data", [])
        if not detections:
            return "No detections found matching criteria."
        lines = ["EDR Detections:"]
        for d in detections:
            lines.append(
                f"  [{d.get('severity', '?'):8s}] "
                f"{d.get('timestamp', '?'):26s} "
                f"{d.get('hostname', '?'):20s} "
                f"{d.get('rule_name', '?')}"
            )
            if d.get("description"):
                lines.append(f"    {d['description'][:150]}")
        return truncate_results("\n".join(lines), self.max_chars)
