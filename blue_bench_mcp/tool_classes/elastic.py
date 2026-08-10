"""ElasticTool — three analyst-facing query commands backed by Elasticsearch.

Follows the TOOL_CLASS_PATTERN contract: one class, N methods, shared state in
__init__, guardrails applied consistently.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import statistics
from datetime import datetime
from typing import Any

import httpx

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import truncate_result_list, truncate_results

# RFC1918 / link-local: a "beacon" is internal-host -> external-dest, so these
# are excluded from the destination side of the analysis.
_INTERNAL_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")


def _to_epoch(ts: Any) -> float | None:
    """Parse an ES @timestamp (ISO8601) or Zeek ts (epoch string) to seconds."""
    if ts is None:
        return None
    s = str(ts)
    try:
        return float(s)  # Zeek ts epoch string
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _dest_key(ip: str, granularity: str) -> str:
    """Group a destination IP per the aggregation granularity (rotation handling)."""
    if granularity == "/24":
        try:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        except ValueError:
            return ip
    return ip


class ElasticTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.url = cfg.elastic.url.rstrip("/")
        self.index_pattern = cfg.elastic.index_pattern
        self.zeek_index = (
            f"{cfg.zeek.index},{cfg.zeek.ot_conn_index}"
            if cfg.zeek.use_elastic else cfg.elastic.index_pattern
        )
        self.sysmon_index = cfg.sysmon.index
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
        # tolerate a missing index in a comma-separated pattern (e.g. ot-conn absent
        # in an IT-only deployment) instead of 404-ing the whole query.
        url = f"{self.url}/{idx}/_search?ignore_unavailable=true&allow_no_indices=true"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
        return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]

    async def _agg(self, body: dict, index: str | None = None) -> dict:
        idx = index or self.index_pattern
        url = f"{self.url}/{idx}/_search?ignore_unavailable=true&allow_no_indices=true"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            return resp.json()

    async def search_alerts(
        self,
        host_ip: str = "",
        src_ip: str = "",
        dest_ip: str = "",
        severity: int = 0,
        timerange_minutes: int = 60,
        query_text: str = "",
    ) -> str:
        """Search security alerts across configured indices.

        Args:
            host_ip: Filter by host IP (matches either src or dest — use this when investigating a specific host)
            src_ip: Filter by source IP only
            dest_ip: Filter by destination IP only
            severity: Filter by severity (1=critical, 2=medium, 3=low). 0=no filter.
            timerange_minutes: Lookback window in minutes
            query_text: Free-text query across alert fields
        """
        must: list[dict[str, Any]] = []
        if host_ip:
            must.append({"bool": {"should": [{"term": {"src_ip": host_ip}}, {"term": {"dest_ip": host_ip}}], "minimum_should_match": 1}})
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
        host_ip: str = "",
        src_ip: str = "",
        dest_ip: str = "",
        dest_port: int = 0,
        proto: str = "",
        timerange_minutes: int = 60,
    ) -> str:
        """Search Zeek conn.log via Elasticsearch for host-to-host traffic.

        Args:
            host_ip: Filter by host IP (matches either src or dest — use this when investigating a specific host)
            src_ip: Filter by source IP only
            dest_ip: Filter by destination IP only
            dest_port: Filter by destination port
            proto: Filter by protocol (tcp, udp, icmp)
            timerange_minutes: Lookback window in minutes
        """
        must: list[dict[str, Any]] = []
        if host_ip:
            must.append({"bool": {"should": [{"term": {"id.orig_h": host_ip}}, {"term": {"id.resp_h": host_ip}}], "minimum_should_match": 1}})
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
        idx = index or self.index_pattern

        async def _agg_on(f: str) -> list[dict]:
            body = {
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}},
                "aggs": {"top_values": {"terms": {"field": f, "size": top_n}}},
            }
            data = await self._agg(body, index=idx)
            return data.get("aggregations", {}).get("top_values", {}).get("buckets", [])

        # Dynamic string fields (src_ip, dest_ip, dest_port, …) are text-mapped and
        # not aggregatable — a raw terms agg 400s. ES auto-creates a `.keyword`
        # subfield for them, so fall back to it when the raw field errors or is empty.
        used = field
        buckets: list[dict] = []
        last_err: Exception | None = None
        for cand in (field, f"{field}.keyword"):
            try:
                buckets = await _agg_on(cand)
            except httpx.HTTPError as e:
                last_err = e
                continue
            used = cand
            if buckets:
                break
        if not buckets and last_err is not None and used == field:
            return f"Error: ES aggregation failed for '{field}' (also tried '{field}.keyword'): {last_err}"
        field = used
        lines = [f"Top {top_n} values for '{field}' (last {timerange_minutes}m):"]
        if not buckets:
            lines.append("  (no results — check field name, index pattern, or timerange)")
        for b in buckets:
            lines.append(f"  {b['key']}: {b['doc_count']}")
        return truncate_results("\n".join(lines), self.max_chars)

    async def detect_beaconing(
        self,
        timerange_minutes: int = 0,
        min_connections: int = 0,
        max_jitter: float = 0.0,
        aggregation: str = "",
        src_ip: str = "",
        dest_ip: str = "",
    ) -> str:
        """Rank internal->external (src,dest) pairs by how beacon-like they are.

        Interval-regularity analytic (RITA/Zeek-style). Returns a coverage
        envelope + ranked candidates. A negative is ALWAYS bounded — the
        envelope reports what was analyzed, excluded, and NOT visible, so an
        empty candidate list is never a bare "nothing here".
        """
        bc = self.cfg.beaconing
        window = timerange_minutes or bc.default_window_minutes
        minc = max(min_connections or bc.default_min_connections, bc.min_connections_floor)
        jitter = min(max_jitter or bc.default_max_jitter, bc.max_jitter_ceiling)
        gran = aggregation or bc.agg_granularity
        if gran not in ("ip", "/24", "domain"):
            gran = "ip"

        blind = [
            f"beacons with fewer than {minc} callbacks in the window (below min_connections)",
            f"beacons with interval jitter above CV {jitter:g} (looks irregular)",
            f"activity outside the {window/1440:.1f}-day lookback window",
        ]
        if gran == "ip":
            blind.append("rotated / multi-IP C2 — aggregation is per exact-IP; "
                         "retry with aggregation='/24' to catch same-subnet rotation")
        if gran == "domain":
            blind.append("domain-level grouping not yet available; falling back to per-IP")
            gran = "ip"

        # --- step 1: candidate (src -> external dest) pairs by connection count ---
        # src_ip is NOT applied here: rarity (distinct internal hosts per dest)
        # must be computed corpus-wide, else scoping to one host makes every dest
        # rarity-1 and the ranking collapses. src_ip filters the OUTPUT below.
        rng = {"range": {"@timestamp": {"gte": f"now-{window}m", "lte": "now"}}}
        must: list[dict] = [rng]
        must_not = [{"term": {"id.resp_h": c}} for c in _INTERNAL_CIDRS]
        if dest_ip:
            must.append({"term": {"id.resp_h": dest_ip}})
            must_not = []  # explicit dest overrides the external-only filter
        body = {
            "size": 0,
            "query": {"bool": {"must": must, "must_not": must_not}},
            "aggs": {"dest": {"terms": {"field": "id.resp_h", "size": 2000},
                              "aggs": {"src": {"terms": {"field": "id.orig_h", "size": 200}}}}},
        }
        try:
            data = await self._agg(body, index=self.zeek_index)
        except httpx.HTTPError as e:
            return f"Error: ES aggregation failed: {e}"

        # Flatten to (src, dest_key) counts + distinct-src rarity per dest_key.
        pair_counts: dict[tuple[str, str], int] = {}
        dest_srcs: dict[str, set] = {}
        for db in data.get("aggregations", {}).get("dest", {}).get("buckets", []):
            dest = db["key"]
            dk = _dest_key(dest, gran)
            for sb in db.get("src", {}).get("buckets", []):
                s = sb["key"]
                pair_counts[(s, dk)] = pair_counts.get((s, dk), 0) + sb["doc_count"]
                dest_srcs.setdefault(dk, set()).add(s)

        candidates = [(s, dk, n) for (s, dk), n in pair_counts.items()
                      if n >= minc and (not src_ip or s == src_ip)]
        excluded_below = sum(1 for (s, _dk), n in pair_counts.items()
                             if n < minc and (not src_ip or s == src_ip))
        # Cadence-check is one focused query per pair, so it is budget-bounded.
        # Prioritize by destination RARITY (few internal hosts = dedicated infra,
        # the beacon signature) then by count — a low-and-slow beacon has FEWER
        # connections than chatty benign services, so a count-first budget would
        # skip it entirely.
        candidates.sort(key=lambda x: (len(dest_srcs.get(x[1], ())), -x[2]))
        deep = candidates[: bc.top_n]
        not_analyzed = len(candidates) - len(deep)

        # --- step 2: per-candidate cadence (interval CV) from focused fetches ---
        async def _cadence(s: str, dk: str, n: int) -> dict | None:
            m: list[dict] = [rng, {"term": {"id.orig_h": s}}]
            if gran == "/24":
                m.append({"term": {"id.resp_h": dk}})           # CIDR term on ip field
            else:
                m.append({"term": {"id.resp_h": dk}})
            q = {"size": min(5000, max(1000, n * 2)),
                 "_source": ["@timestamp", "orig_bytes", "id.resp_p"],
                 "query": {"bool": {"must": m}}, "sort": [{"@timestamp": "asc"}]}
            try:
                hits = await self._query(q, index=self.zeek_index)
            except httpx.HTTPError:
                return None
            ts = sorted(t for t in (_to_epoch(h.get("@timestamp")) for h in hits) if t is not None)
            if len(ts) < 3:
                return None
            gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
            mean = statistics.mean(gaps)
            cv = (statistics.pstdev(gaps) / mean) if mean > 0 else 99.0
            obytes = [float(h["orig_bytes"]) for h in hits
                      if str(h.get("orig_bytes", "")).replace(".", "", 1).isdigit()]
            ports = sorted({str(h.get("id.resp_p")) for h in hits if h.get("id.resp_p")})
            return {
                "src_ip": s, "dest": dk, "dest_ports": ports,
                "connections": len(ts),
                "mean_interval_s": round(mean, 1),
                "interval_cv": round(cv, 3),
                "regularity_score": round(max(0.0, 1.0 - cv), 3),
                "distinct_src_hosts": len(dest_srcs.get(dk, ())),
                "span_hours": round((ts[-1] - ts[0]) / 3600.0, 1),
                "mean_orig_bytes": round(statistics.mean(obytes), 0) if obytes else None,
            }

        rows = [r for r in await asyncio.gather(*(_cadence(*c) for c in deep)) if r]
        # a beacon is regular: keep pairs whose jitter is under the cutoff
        surfaced = [r for r in rows if r["interval_cv"] <= jitter]
        surfaced.sort(key=lambda r: (-r["regularity_score"], r["interval_cv"]))
        if not_analyzed > 0:
            blind.append(
                f"{not_analyzed} candidate pairs exceeded the deep-analysis budget "
                f"(top {bc.top_n}, prioritized by destination rarity) and were NOT "
                f"cadence-checked — narrow with src_ip/dest_ip or raise min_connections")
        blind.append("a regular beacon to popular shared infrastructure (contacted by "
                     "many internal hosts) is deprioritized by the rarity ranking")

        out = {
            "analysis": {
                "method": "internal->external per-destination interval-regularity (Zeek conn)",
                "window_days": round(window / 1440, 1),
                "min_connections": minc,
                "max_jitter_cv": jitter,
                "aggregation": gran,
                "pairs_analyzed": len(pair_counts),
                "candidate_pairs_at_or_above_min": len(candidates),
                "pairs_excluded_below_min_connections": excluded_below,
                "candidates_deep_analyzed": len(deep),
                "blind_spots": blind,
            },
            "candidates": surfaced,
        }
        return truncate_results(json.dumps(out, indent=2, default=str), self.max_chars)

    # --- Sysmon host telemetry -------------------------------------------------
    # Sysmon string fields are dynamically mapped (text + a `.keyword` subfield),
    # so exact filters use `<field>.keyword`; EventID is numeric so it takes a
    # plain `term`; CommandLine substring search uses a case-insensitive wildcard.

    def _build_process_events_query(
        self,
        host: str,
        image: str,
        parent_image: str,
        command_line_contains: str,
        event_id: int,
        timerange_minutes: int,
    ) -> dict:
        must: list[dict[str, Any]] = []
        if host:
            must.append({"term": {"Computer.keyword": host}})
        if image:
            must.append({"term": {"Image.keyword": image}})
        if parent_image:
            must.append({"term": {"ParentImage.keyword": parent_image}})
        if event_id:
            must.append({"term": {"EventID": event_id}})
        if command_line_contains:
            must.append({
                "wildcard": {
                    "CommandLine.keyword": {
                        "value": f"*{command_line_contains}*",
                        "case_insensitive": True,
                    }
                }
            })
        must.append(
            {"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}}
        )
        return {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "desc"}],
            "size": self.max_results,
        }

    async def get_process_events(
        self,
        host: str = "",
        image: str = "",
        parent_image: str = "",
        command_line_contains: str = "",
        event_id: int = 0,
        timerange_minutes: int = 240,
    ) -> str:
        """Search Sysmon host telemetry (windows-sysmon) for process / host events.

        Args:
            host: Filter by Computer (FQDN, e.g. wkst-01.corp.example.invalid)
            image: Filter by Image (full process path, exact match)
            parent_image: Filter by ParentImage (full parent process path, exact match)
            command_line_contains: Case-insensitive substring match on CommandLine
            event_id: Sysmon EventID (1=process-create, 3=network, 5=process-term,
                7=image-load, 8=create-remote-thread, 10=process-access,
                11=file-create, 12/13=registry, 22=dns). 0=no filter.
            timerange_minutes: Lookback window in minutes
        """
        body = self._build_process_events_query(
            host, image, parent_image, command_line_contains, event_id, timerange_minutes
        )
        try:
            hits = await self._query(body, index=self.sysmon_index)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        hits, truncated = truncate_result_list(hits, self.max_results)
        result = json.dumps(hits, indent=2, default=str)
        if truncated:
            result += f"\n\n--- Showing first {self.max_results} results. Narrow your query. ---"
        return truncate_results(result, self.max_chars)

    def _build_process_tree_self_query(
        self, process_guid: str, host: str, timerange_minutes: int
    ) -> dict:
        # The process itself + its parent: any event carrying this ProcessGuid, or
        # any event whose ChildProcessGuid is this guid (the parent's create event).
        should: list[dict[str, Any]] = [
            {"term": {"ProcessGuid.keyword": process_guid}},
            {"term": {"ParentProcessGuid.keyword": process_guid}},
        ]
        must: list[dict[str, Any]] = [
            {"bool": {"should": should, "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}},
        ]
        if host:
            must.append({"term": {"Computer.keyword": host}})
        return {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "asc"}],
            "size": self.max_results,
        }

    def _build_process_tree_children_query(
        self, process_guid: str, host: str, timerange_minutes: int
    ) -> dict:
        # Children: events whose ParentProcessGuid == this guid.
        must: list[dict[str, Any]] = [
            {"term": {"ParentProcessGuid.keyword": process_guid}},
            {"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}},
        ]
        if host:
            must.append({"term": {"Computer.keyword": host}})
        return {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "asc"}],
            "size": self.max_results,
        }

    async def get_process_tree(
        self,
        process_guid: str = "",
        host: str = "",
        timerange_minutes: int = 240,
    ) -> str:
        """Walk the Sysmon process subtree for a ProcessGuid (self + parent + children).

        Args:
            process_guid: The Sysmon ProcessGuid to anchor on (required)
            host: Optional Computer (FQDN) filter to scope the walk
            timerange_minutes: Lookback window in minutes
        """
        if not process_guid:
            return "Error: process_guid is required."
        self_body = self._build_process_tree_self_query(process_guid, host, timerange_minutes)
        child_body = self._build_process_tree_children_query(process_guid, host, timerange_minutes)
        try:
            self_hits = await self._query(self_body, index=self.sysmon_index)
            child_hits = await self._query(child_body, index=self.sysmon_index)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        self_hits, self_trunc = truncate_result_list(self_hits, self.max_results)
        child_hits, child_trunc = truncate_result_list(child_hits, self.max_results)
        tree = {
            "process_guid": process_guid,
            "self_and_parent": self_hits,
            "children": child_hits,
        }
        result = json.dumps(tree, indent=2, default=str)
        if self_trunc or child_trunc:
            result += f"\n\n--- Some result sets truncated to first {self.max_results}. Narrow your query. ---"
        return truncate_results(result, self.max_chars)
