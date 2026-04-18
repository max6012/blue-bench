"""ElasticTool — three analyst-facing query commands backed by Elasticsearch.

Follows the TOOL_CLASS_PATTERN contract: one class, N methods, shared state in
__init__, guardrails applied consistently.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import truncate_result_list, truncate_results


class ElasticTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.url = cfg.elastic.url.rstrip("/")
        self.index_pattern = cfg.elastic.index_pattern
        self.zeek_index = cfg.zeek.index if cfg.zeek.use_elastic else cfg.elastic.index_pattern
        self.verify_ssl = cfg.elastic.verify_ssl
        self.user = cfg.elastic.user
        self.password = cfg.elastic.password
        self.timeout = cfg.limits.query_timeout
        self.max_chars = cfg.limits.max_result_chars
        self.max_results = cfg.limits.max_results

    def _auth(self) -> tuple[str, str] | None:
        return (self.user, self.password) if self.user and self.password else None

    async def _query(self, body: dict, index: str | None = None) -> list[dict]:
        idx = index or self.index_pattern
        url = f"{self.url}/{idx}/_search"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
        return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]

    async def _agg(self, body: dict, index: str | None = None) -> dict:
        idx = index or self.index_pattern
        url = f"{self.url}/{idx}/_search"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            return resp.json()

    async def search_alerts(
        self,
        src_ip: str = "",
        dest_ip: str = "",
        severity: int = 0,
        timerange_minutes: int = 60,
        query_text: str = "",
    ) -> str:
        """Search security alerts across configured indices.

        Args:
            src_ip: Filter by source IP
            dest_ip: Filter by destination IP
            severity: Filter by severity (1=critical, 2=medium, 3=low). 0=no filter.
            timerange_minutes: Lookback window in minutes
            query_text: Free-text query across alert fields
        """
        must: list[dict[str, Any]] = []
        if src_ip:
            must.append({"term": {"src_ip": src_ip}})
        if dest_ip:
            must.append({"term": {"dest_ip": dest_ip}})
        if severity:
            must.append({"term": {"alert.severity": severity}})
        if query_text:
            must.append({"query_string": {"query": query_text}})
        must.append(
            {"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}}
        )
        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "desc"}],
            "size": self.max_results,
        }
        try:
            hits = await self._query(body)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        hits, truncated = truncate_result_list(hits, self.max_results)
        result = json.dumps(hits, indent=2, default=str)
        if truncated:
            result += f"\n\n--- Showing first {self.max_results} results. Narrow your query. ---"
        return truncate_results(result, self.max_chars)

    async def get_connections(
        self,
        src_ip: str = "",
        dest_ip: str = "",
        dest_port: int = 0,
        proto: str = "",
        timerange_minutes: int = 60,
    ) -> str:
        """Search Zeek conn.log via Elasticsearch for host-to-host traffic.

        Args:
            src_ip: Filter by source IP
            dest_ip: Filter by destination IP
            dest_port: Filter by destination port
            proto: Filter by protocol (tcp, udp, icmp)
            timerange_minutes: Lookback window in minutes
        """
        must: list[dict[str, Any]] = []
        if src_ip:
            must.append({"term": {"id.orig_h": src_ip}})
        if dest_ip:
            must.append({"term": {"id.resp_h": dest_ip}})
        if dest_port:
            must.append({"term": {"id.resp_p": dest_port}})
        if proto:
            must.append({"term": {"proto": proto.lower()}})
        must.append(
            {"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}}
        )
        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "desc"}],
            "size": self.max_results,
        }
        try:
            hits = await self._query(body, index=self.zeek_index)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        hits, truncated = truncate_result_list(hits, self.max_results)
        result = json.dumps(hits, indent=2, default=str)
        if truncated:
            result += f"\n\n--- Showing first {self.max_results} results. Narrow your query. ---"
        return truncate_results(result, self.max_chars)

    async def count_by_field(
        self,
        field: str,
        index: str = "",
        timerange_minutes: int = 60,
        top_n: int = 20,
    ) -> str:
        """Aggregate and count values for a field (top talkers, severity distribution, etc).

        Args:
            field: Field to aggregate on (e.g., src_ip, alert.signature, dest_port)
            index: Index pattern (default: configured pattern)
            timerange_minutes: Lookback window
            top_n: Number of top values to return
        """
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}},
            "aggs": {"top_values": {"terms": {"field": field, "size": top_n}}},
        }
        try:
            data = await self._agg(body, index=index or self.index_pattern)
        except httpx.HTTPError as e:
            return f"Error: ES aggregation failed: {e}"
        buckets = data.get("aggregations", {}).get("top_values", {}).get("buckets", [])
        lines = [f"Top {top_n} values for '{field}' (last {timerange_minutes}m):"]
        if not buckets:
            lines.append("  (no results — check field name, index pattern, or timerange)")
        for b in buckets:
            lines.append(f"  {b['key']}: {b['doc_count']}")
        return truncate_results("\n".join(lines), self.max_chars)
