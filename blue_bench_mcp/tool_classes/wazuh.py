"""WazuhTool — HIDS agent inventory + alerts with Wazuh API primary, ES fallback.

Archive convention: query Wazuh API first (low dwell time, real-time alerts).
Fall back to ES wazuh-alerts-* on connection error or auth failure. ES-only
is too stale to serve analyst queries during an active incident.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import truncate_result_list, truncate_results


class WazuhTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.api_url = cfg.wazuh.api_url.rstrip("/")
        self.user = cfg.wazuh.user
        self.password = cfg.wazuh.password
        self.es_url = cfg.elastic.url.rstrip("/")
        self.es_fallback_index = cfg.wazuh.es_fallback_index
        self.timeout = cfg.limits.query_timeout
        self.max_chars = cfg.limits.max_result_chars
        self.max_results = cfg.limits.max_results
        self._token: str = ""

    async def _authenticate(self) -> str:
        if self._token:
            return self._token
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.post(
                f"{self.api_url}/security/user/authenticate",
                auth=(self.user, self.password) if self.user else None,
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
        return self._token

    async def _api_get(self, endpoint: str, params: dict | None = None) -> dict:
        token = await self._authenticate()
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(verify=False, timeout=float(self.timeout)) as client:
            resp = await client.get(
                f"{self.api_url}{endpoint}", headers=headers, params=params or {}
            )
            if resp.status_code == 401:
                # Token expired — re-auth and retry once.
                self._token = ""
                token = await self._authenticate()
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.get(
                    f"{self.api_url}{endpoint}", headers=headers, params=params or {}
                )
            resp.raise_for_status()
        return resp.json()

    async def _es_fallback_alerts(self, agent_id: str, limit: int) -> list[dict]:
        body = {
            "query": {"term": {"agent.id": agent_id}},
            "sort": [{"@timestamp": "desc"}],
            "size": limit,
        }
        async with httpx.AsyncClient(verify=False, timeout=float(self.timeout)) as client:
            resp = await client.post(
                f"{self.es_url}/{self.es_fallback_index}/_search", json=body
            )
            resp.raise_for_status()
            data = resp.json()
        return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]

    async def list_agents(self, status: str = "") -> str:
        """List Wazuh agents with status.

        Args:
            status: Filter by status (active, disconnected, pending, never_connected)
        """
        params: dict[str, Any] = {}
        if status:
            params["status"] = status
        try:
            data = await self._api_get("/agents", params)
        except (httpx.HTTPError, KeyError) as e:
            return f"Error: Wazuh API unreachable ({e}); list_agents has no ES fallback."
        agents = data.get("data", {}).get("affected_items", [])
        if not agents:
            return "No Wazuh agents found."
        lines = ["Wazuh Agents:"]
        for a in agents:
            lines.append(
                f"  [{a.get('status', '?'):13s}] "
                f"ID={a.get('id', '?'):4s} "
                f"{a.get('name', 'unknown'):20s} "
                f"IP={a.get('ip', '?'):15s} "
                f"OS={a.get('os', {}).get('name', '?')}"
            )
        return truncate_results("\n".join(lines), self.max_chars)

    async def get_agent_alerts(
        self, agent_id: str, level_min: int = 0, limit: int = 50
    ) -> str:
        """Get recent alerts for a Wazuh agent.

        Tries Wazuh API first; falls back to Elasticsearch wazuh-alerts-* on API failure.

        Args:
            agent_id: Wazuh agent ID (e.g., '001')
            level_min: Minimum alert level (0-15)
            limit: Max alerts to return
        """
        limit = min(limit, self.max_results)
        # Primary: Wazuh API.
        try:
            params: dict[str, Any] = {"limit": limit}
            if level_min:
                params["level"] = f"{level_min}-15"
            data = await self._api_get(f"/agents/{agent_id}/alerts", params)
            alerts = data.get("data", {}).get("affected_items", [])
            if alerts:
                result = json.dumps(alerts, indent=2, default=str)
                return truncate_results(f"[source: Wazuh API]\n{result}", self.max_chars)
        except (httpx.HTTPError, KeyError) as api_err:
            api_error = str(api_err)
        else:
            api_error = "empty result"
        # Fallback: ES.
        try:
            alerts = await self._es_fallback_alerts(agent_id, limit)
        except httpx.HTTPError as es_err:
            return (
                f"Error: Wazuh API failed ({api_error}) and ES fallback failed ({es_err})"
            )
        alerts, _ = truncate_result_list(alerts, limit)
        if not alerts:
            return f"No alerts found for agent {agent_id} (Wazuh API: {api_error}; ES fallback empty)."
        result = json.dumps(alerts, indent=2, default=str)
        return truncate_results(
            f"[source: ES fallback — Wazuh API was {api_error}]\n{result}", self.max_chars
        )
