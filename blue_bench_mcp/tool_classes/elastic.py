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
from blue_bench_mcp.es_queries import _is_ip, host_ip_clauses, host_name_clause, host_name_clauses
from blue_bench_mcp.es_records import with_identity
from blue_bench_mcp.shard_check import note_shards
from blue_bench_mcp.guardrails import (
    FOOTER_RESERVE,
    result_footer,
    json_dump_within,
    truncate_result_list,
    truncate_results,
)
from blue_bench_mcp.timerange import TimeRangeError, timestamp_range

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

    async def _search(self, body: dict, index: str | None = None, *,
                      count: bool = True) -> tuple[list[dict], int]:
        """Run ``body`` and return ``(hits, total)``.

        With ``count`` on, ``total`` is the TRUE match count. Every list tool
        fetches a page of ``size=max_results`` off a much larger match, and
        the footer has to say how much larger (issue #43). ES 8 stops counting
        at 10,000 unless asked, so ``track_total_hits`` is set -- the
        alternative is a footer that says 10,000 for a 192,624-record match,
        which is wrong in a more plausible way than the old page-size number.
        Callers that never show the total (``_query``) leave ``count`` off:
        the beaconing analytic issues one fetch per candidate and should not
        pay for an exact count it discards.
        """
        idx = index or self.index_pattern
        # tolerate a missing index in a comma-separated pattern (e.g. ot-conn absent
        # in an IT-only deployment) instead of 404-ing the whole query.
        url = f"{self.url}/{idx}/_search?ignore_unavailable=true&allow_no_indices=true"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.post(
                url, json={**body, "track_total_hits": True} if count else body)
            resp.raise_for_status()
            data = resp.json()
        note_shards(data, idx)
        hits = [with_identity(hit) for hit in data.get("hits", {}).get("hits", [])]
        total = data.get("hits", {}).get("total", {})
        total = total.get("value", len(hits)) if isinstance(total, dict) else int(total or len(hits))
        return hits, total

    async def _query(self, body: dict, index: str | None = None) -> list[dict]:
        """Hits only, uncounted, for callers that page or aggregate themselves."""
        hits, _ = await self._search(body, index, count=False)
        return hits

    async def _agg(self, body: dict, index: str | None = None) -> dict:
        idx = index or self.index_pattern
        url = f"{self.url}/{idx}/_search?ignore_unavailable=true&allow_no_indices=true"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
        note_shards(data, idx)
        return data

    async def search_alerts(
        self,
        host_ip: str = "",
        src_ip: str = "",
        dest_ip: str = "",
        severity: int = 0,
        timerange_minutes: int = 60,
        query_text: str = "",
        since: str = "",
        until: str = "",
    ) -> str:
        """Search security alerts across configured indices.

        Args:
            host_ip: Filter by host IP (matches either src or dest — use this when investigating a specific host)
            src_ip: Filter by source IP only
            dest_ip: Filter by destination IP only
            severity: Filter by severity (1=critical, 2=medium, 3=low). 0=no filter.
            timerange_minutes: Lookback window in minutes
            query_text: Free-text query across alert fields
            since, until: absolute UTC bounds (ISO-8601); either replaces timerange_minutes
        """
        try:
            rng = timestamp_range(timerange_minutes, since, until)
        except TimeRangeError as e:
            return str(e)
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
        must.append(rng.clause)
        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "desc"}],
            "size": self.max_results,
        }
        try:
            hits, total = await self._search(body)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        fetched = len(hits)
        hits, capped = truncate_result_list(hits, self.max_results)
        # Drop whole RECORDS rather than slicing the serialized string (issue
        # #41), reserve the worst-case footer, then say what actually happened:
        # true match count, page fetched, records shown (issue #43).
        body, dropped = json_dump_within(hits, self.max_chars - FOOTER_RESERVE)
        return body + result_footer(
            total=total, fetched=fetched, capped=capped, shown=len(hits) - dropped,
            max_results=self.max_results)

    async def get_connections(
        self,
        host_ip: str = "",
        src_ip: str = "",
        dest_ip: str = "",
        dest_port: int = 0,
        proto: str = "",
        timerange_minutes: int = 60,
        since: str = "",
        until: str = "",
    ) -> str:
        """Search Zeek conn.log via Elasticsearch for host-to-host traffic.

        Args:
            host_ip: Filter by host IP (matches either src or dest — use this when investigating a specific host)
            src_ip: Filter by source IP only
            dest_ip: Filter by destination IP only
            dest_port: Filter by destination port
            proto: Filter by protocol (tcp, udp, icmp)
            timerange_minutes: Lookback window in minutes
            since, until: absolute UTC bounds (ISO-8601); either replaces timerange_minutes
        """
        try:
            rng = timestamp_range(timerange_minutes, since, until)
        except TimeRangeError as e:
            return str(e)
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
        must.append(rng.clause)
        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "desc"}],
            "size": self.max_results,
        }
        try:
            hits, total = await self._search(body, index=self.zeek_index)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        fetched = len(hits)
        hits, capped = truncate_result_list(hits, self.max_results)
        # Drop whole RECORDS rather than slicing the serialized string (issue
        # #41), reserve the worst-case footer, then say what actually happened:
        # true match count, page fetched, records shown (issue #43).
        body, dropped = json_dump_within(hits, self.max_chars - FOOTER_RESERVE)
        return body + result_footer(
            total=total, fetched=fetched, capped=capped, shown=len(hits) - dropped,
            max_results=self.max_results)

    async def _index_exists(self, index: str) -> bool:
        """Whether ``index`` is present in the cluster.

        Needed because every query here sets ``ignore_unavailable``, which makes
        a missing index look exactly like a query that matched nothing. For the
        asset inventory those are different answers: "this deployment has no
        inventory" and "no asset matches your filters" lead an analyst to
        different next steps.
        """
        url = f"{self.url}/{index}"
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
            ) as client:
                return (await client.head(url)).status_code == 200
        except httpx.HTTPError:
            return False

    async def list_assets(
        self,
        segment: str = "",
        role: str = "",
        ip: str = "",
        name: str = "",
    ) -> str:
        """Read the OT asset inventory: which device a plant address belongs to.

        Args:
            segment: 'OT' to restrict to the plant segment; empty = every asset
            role: device role (controller, rtu, hmi, historian,
                engineering-workstation, safety-controller, ot-firewall)
            ip: exact address; the "what is this address?" lookup
            name: device name or FQDN; the "what address does it have?" lookup
        """
        index = self.cfg.elastic.asset_index
        must: list[dict[str, Any]] = []
        if segment:
            must.append({"term": {"segment.keyword": segment.strip().upper()}})
        if role:
            must.append({"term": {"role.keyword": role.strip().lower()}})
        if ip:
            must.append({"term": {"ip.keyword": ip.strip()}})
        if name:
            n = name.strip().rstrip(".").lower()
            # Either spelling: an analyst reading an ot-hosts record has the
            # FQDN, one reading a diagram has the short label.
            spellings = list(dict.fromkeys([n, n.split(".")[0]]))
            must.append({"bool": {"should": [
                {"terms": {"name.keyword": spellings}},
                {"terms": {"fqdn.keyword": spellings}},
            ], "minimum_should_match": 1}})
        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"name.keyword": "asc"}],
            "size": self.max_results,
        }
        try:
            hits, total = await self._search(body, index=index)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        if not hits:
            # Say which of the two emptinesses this is. A corpus built before
            # the inventory existed has no index at all, and the honest answer
            # there is that this deployment cannot tell you -- not that the
            # device does not exist.
            if not await self._index_exists(index):
                return (
                    f"No asset inventory in this deployment: the index '{index}' does not "
                    f"exist, so there is no record of which device an OT address belongs "
                    f"to. This corpus was built before the inventory was added. Device "
                    f"names still appear in ot-hosts and addresses in the OT protocol "
                    f"indices, but nothing joins the two."
                )
            return "[]"
        fetched = len(hits)
        hits, capped = truncate_result_list(hits, self.max_results)
        # Drop whole RECORDS rather than slicing the serialized string (issue
        # #41), reserve the worst-case footer, then say what actually happened:
        # true match count, page fetched, records shown (issue #43).
        body_text, dropped = json_dump_within(hits, self.max_chars - FOOTER_RESERVE)
        return body_text + result_footer(
            total=total, fetched=fetched, capped=capped, shown=len(hits) - dropped,
            max_results=self.max_results)

    async def _agg_field_plan(self, field: str, index: str) -> dict[str, list[str]]:
        """Aggregatable field name -> the concrete indices to aggregate it in.

        Per index: the field itself when it is aggregatable there, else its
        ``.keyword`` subfield when that is, else the index is left out (the
        field is not mapped there, so it has nothing to count).
        """
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.get(
                f"{self.url}/{index}/_field_caps",
                params={"fields": f"{field},{field}.keyword", "include_unmapped": "true",
                        "ignore_unavailable": "true", "allow_no_indices": "true"})
            resp.raise_for_status()
            caps = resp.json()
        all_indices = caps.get("indices") or []

        def agg_indices(name: str) -> set[str]:
            out: set[str] = set()
            for _type, c in (caps.get("fields", {}).get(name) or {}).items():
                if c.get("aggregatable"):
                    # 'indices' is omitted when the capability holds for all of them.
                    out |= set(c.get("indices") or all_indices)
            return out

        raw, kw = agg_indices(field), agg_indices(f"{field}.keyword")
        plan: dict[str, list[str]] = {}
        for ix in all_indices:
            if ix in raw:
                plan.setdefault(field, []).append(ix)
            elif ix in kw:
                plan.setdefault(f"{field}.keyword", []).append(ix)
        return plan

    async def count_by_field(
        self,
        field: str,
        index: str = "",
        timerange_minutes: int = 60,
        top_n: int = 20,
        since: str = "",
        until: str = "",
        host: str = "",
        host_ip: str = "",
    ) -> str:
        """Aggregate and count values for a field (top talkers, severity distribution, etc).

        Args:
            field: Field to aggregate on (e.g., src_ip, alert.signature, dest_port)
            index: Index pattern (default: configured pattern)
            timerange_minutes: Lookback window
            top_n: Number of top values to return
            since, until: absolute UTC bounds (ISO-8601); either replaces timerange_minutes
            host: host name (FQDN or short label) on the host-log name fields
            host_ip: address at either end of a network record
            Given both, a record matching EITHER counts: they name one host,
            and a Sysmon record carries only the name while a Zeek record
            carries only the addresses, so ANDing them would match neither.
        """
        try:
            rng = timestamp_range(timerange_minutes, since, until)
        except TimeRangeError as e:
            return str(e)
        idx = index or self.index_pattern
        query: dict[str, Any] = rng.clause
        should: list[dict[str, Any]] = []
        if host:
            should += [c for f in ("Computer", "host") for c in host_name_clauses(host, f)]
        if host_ip:
            should += host_ip_clauses(host_ip)
        if should:
            query = {"bool": {"must": [rng.clause],
                              "filter": [{"bool": {"should": should, "minimum_should_match": 1}}]}}

        # A field can be aggregatable in one index and text-only in another
        # (dest_port is numeric in ot-conn, text in zeek-conn). One terms agg
        # over both fails the text-mapped index's shards and ES returns the
        # rest as a partial result -- the survey silently loses that index.
        # So the field is resolved PER INDEX (the raw field where it is
        # aggregatable, else its .keyword subfield), one agg runs per resolved
        # field, and the buckets are merged.
        try:
            plan = await self._agg_field_plan(field, idx)
        except httpx.HTTPError as e:
            return f"Error: could not read the mapping of '{field}' in {idx}: {e}"
        if not plan:
            return (f"Top {top_n} values for '{field}' ({rng.label}):\n"
                    f"  (no results — '{field}' is not an aggregatable field in {idx}; "
                    "check the field name as it appears in tool output)")
        merged: dict[str, int] = {}
        for agg_field, indices in plan.items():
            body = {
                "size": 0,
                "query": query,
                # Over-fetch per group so the merged top_n is right when the
                # groups' top lists interleave.
                "aggs": {"top_values": {"terms": {"field": agg_field, "size": top_n * 3}}},
            }
            try:
                data = await self._agg(body, index=",".join(indices))
            except httpx.HTTPError as e:
                return f"Error: ES aggregation failed for '{agg_field}' in {','.join(indices)}: {e}"
            for b in data.get("aggregations", {}).get("top_values", {}).get("buckets", []):
                key = str(b.get("key_as_string", b["key"]))
                merged[key] = merged.get(key, 0) + b["doc_count"]
        buckets = sorted(merged.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]
        used = " / ".join(sorted(plan))
        lines = [f"Top {top_n} values for '{used}' ({rng.label}):"]
        if not buckets:
            lines.append("  (no results — check field name, index pattern, or timerange)")
        for k, n in buckets:
            lines.append(f"  {k}: {n}")
        return truncate_results("\n".join(lines), self.max_chars)

    # date_histogram intervals the survey tool accepts. All are sub-week, so a
    # uniform `fixed_interval` is correct (ES 8 dropped the bare `interval`
    # key, and `calendar_interval` rejects multiples such as 6h / 15m).
    _TIME_INTERVALS = ("15m", "1h", "6h", "1d")

    async def count_by_time(
        self,
        interval: str = "1h",
        index: str = "",
        timerange_minutes: int = 60,
        host: str = "",
        event_id: int = 0,
        query_text: str = "",
        top_n_hosts: int = 0,
        since: str = "",
        until: str = "",
        host_ip: str = "",
    ) -> str:
        """Histogram of document counts over @timestamp (activity over time).

        The survey instrument for partitioning a large window: find the time
        bands with unusual volume before slicing. Only non-empty buckets are
        returned, so a quiet corpus stays a short answer.

        Args:
            interval: Bucket width — one of 15m, 1h, 6h, 1d
            index: Index pattern (default: configured pattern); comma lists accepted
            timerange_minutes: Lookback window
            host: Optional host filter (Sysmon Computer, Zeek orig/resp IP, auth Computer/host)
            event_id: Optional Windows EventID filter (matches either spelling)
            query_text: Optional free-text (query_string) filter
            top_n_hosts: If >0, list the top N hosts (Computer.keyword) driving each bucket
            since, until: absolute UTC bounds (ISO-8601); either replaces timerange_minutes
        """
        if interval not in self._TIME_INTERVALS:
            return (f"Error: interval must be one of {', '.join(self._TIME_INTERVALS)} "
                    f"(got '{interval}')")
        try:
            rng = timestamp_range(timerange_minutes, since, until)
        except TimeRangeError as e:
            return str(e)
        idx = index or self.index_pattern

        must: list[dict[str, Any]] = []
        if host:
            # One host may be named differently per source: Sysmon writes the
            # FQDN to Computer, linux-syslog the short name to host, and the
            # Zeek/OT conn logs carry IPs in id.orig_h / id.resp_h. A should
            # across all of them lets one call survey a host across a
            # comma-list of indices. The name clauses come from the one shared
            # definition (es_queries) so this filter cannot drift from the
            # host tools' -- it is the copy that used to be a bare `match` and
            # returned the whole index (issue #46).
            # The address fields get the value only when it IS an address:
            # id.orig_h / id.resp_h are ip-typed, and a term there with a name
            # fails that index's shards -- which ES reports as a partial result,
            # so a name over 'zeek-conn,windows-sysmon' silently counted Sysmon
            # alone. host_ip (below) is the way to put the address in.
            must.append(host_name_clause(host, "Computer", "host",
                                         extra=host_ip_clauses(host_ip or host) if (host_ip or _is_ip(host)) else ()))
        elif host_ip:
            must.append({"bool": {"should": host_ip_clauses(host_ip), "minimum_should_match": 1}})
        if event_id:
            # Both spellings, same reason as _build_process_events_query (issue #37).
            must.append({"bool": {"should": [
                {"term": {"EventID": event_id}},
                {"term": {"event_id": event_id}},
            ], "minimum_should_match": 1}})
        if query_text:
            must.append({"query_string": {"query": query_text}})
        must.append(rng.clause)

        # date_histogram defaults min_doc_count to 0 (unlike terms), which would
        # emit every empty bucket between first and last match; pin it to 1.
        hist: dict[str, Any] = {
            "date_histogram": {"field": "@timestamp", "fixed_interval": interval,
                               "min_doc_count": 1},
        }
        if top_n_hosts > 0:
            # Computer.keyword only exists on the Windows indices; on Zeek/OT
            # indices the sub-agg simply returns no host buckets (no error).
            hist["aggs"] = {"hosts": {"terms": {"field": "Computer.keyword", "size": top_n_hosts}}}
        body = {"size": 0, "query": {"bool": {"must": must}}, "aggs": {"over_time": hist}}

        try:
            data = await self._agg(body, index=idx)
        except httpx.HTTPError as e:
            return f"Error: ES aggregation failed: {e}"
        buckets = data.get("aggregations", {}).get("over_time", {}).get("buckets", [])
        # Total is the sum of what is shown, not hits.total: _agg does not ask
        # for an exact count (ES 8 caps at 10,000), and a doc with no
        # @timestamp lands in no bucket, so the two can legitimately differ.
        total = sum(b.get("doc_count", 0) for b in buckets)
        filters = [f"host={host}" if host else "", f"host_ip={host_ip}" if host_ip else "",
                   f"event_id={event_id}" if event_id else "",
                   f"query_text={query_text!r}" if query_text else ""]
        filt = " ".join(f for f in filters if f)
        # Header first so truncation (15m over weeks is thousands of lines)
        # drops trailing buckets, never the summary.
        lines = [f"Docs over time — index {idx}, interval {interval}, {rng.label}"
                 f"{', ' + filt if filt else ''}: {total} docs in {len(buckets)} buckets"]
        if not buckets:
            lines.append("  (no results — check index pattern, filters, or timerange)")
        for b in buckets:
            lines.append(f"  {b.get('key_as_string', b.get('key'))}  {b.get('doc_count', 0)}")
            for h in b.get("hosts", {}).get("buckets", []):
                lines.append(f"      {h['key']}: {h['doc_count']}")
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
        # The coverage block is the point of this tool (it reports its own blind
        # spots), so only `candidates` shrinks.
        body, dropped = json_dump_within(out, self.max_chars, shrink=("candidates",))
        if dropped:
            # A silently dropped candidate is a blind spot, and this tool exists
            # to declare its blind spots rather than hide them. Record it where
            # the model already looks, then re-fit (the note itself costs bytes).
            out["analysis"]["blind_spots"].append(
                f"{dropped} lower-ranked candidate(s) were cadence-checked but "
                f"OMITTED from this response to fit the {self.max_chars}-character "
                f"limit — raise min_connections or filter by src_ip/dest_ip to see them")
            body, _ = json_dump_within(out, self.max_chars, shrink=("candidates",))
        return body

    # --- Sysmon host telemetry -------------------------------------------------
    # Sysmon string fields are dynamically mapped (text + a `.keyword` subfield),
    # so exact filters use `<field>.keyword`; EventID is numeric so it takes a
    # plain `term`; CommandLine substring search uses a case-insensitive wildcard.
    # The host filter is the shared host_name_clause: short name or FQDN, either
    # way it has to reach the FQDN Sysmon stores.

    def _build_process_events_query(
        self,
        host: str,
        image: str,
        parent_image: str,
        command_line_contains: str,
        event_id: int,
        timerange_minutes: int,
        since: str = "",
        until: str = "",
    ) -> dict:
        # Raises TimeRangeError for a bad bound; the public method turns that
        # into the Error string before any ES call.
        rng = timestamp_range(timerange_minutes, since, until)
        must: list[dict[str, Any]] = []
        if host:
            # Not a bare term on Computer.keyword: that is exact on the stored
            # FQDN, so a short name matched nothing and read as a clean host
            # (the mirror image of issue #46; see es_queries).
            must.append(host_name_clause(host, "Computer"))
        if image:
            must.append({"term": {"Image.keyword": image}})
        if parent_image:
            must.append({"term": {"ParentImage.keyword": parent_image}})
        if event_id:
            # Match either spelling: the EVTX ingest path writes `EventID`, the
            # NDJSON path historically wrote only lowercase `event_id`, and a
            # corpus ingested before that was canonicalised carries both. A
            # single-field term query silently missed one whole population --
            # the injected adversary events (issue #37).
            must.append({"bool": {"should": [
                {"term": {"EventID": event_id}},
                {"term": {"event_id": event_id}},
            ], "minimum_should_match": 1}})
        if command_line_contains:
            must.append({
                "wildcard": {
                    "CommandLine.keyword": {
                        "value": f"*{command_line_contains}*",
                        "case_insensitive": True,
                    }
                }
            })
        must.append(rng.clause)
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
        since: str = "",
        until: str = "",
    ) -> str:
        """Search Sysmon host telemetry (windows-sysmon) for process / host events.

        Args:
            host: Filter by Computer (FQDN or short name, e.g. wkst-01.corp.example.invalid or wkst-01)
            image: Filter by Image (full process path, exact match)
            parent_image: Filter by ParentImage (full parent process path, exact match)
            command_line_contains: Case-insensitive substring match on CommandLine
            event_id: Sysmon EventID (1=process-create, 3=network, 5=process-term,
                7=image-load, 8=create-remote-thread, 10=process-access,
                11=file-create, 12/13=registry, 22=dns). 0=no filter.
            timerange_minutes: Lookback window in minutes
            since, until: absolute UTC bounds (ISO-8601); either replaces timerange_minutes
        """
        try:
            body = self._build_process_events_query(
                host, image, parent_image, command_line_contains, event_id,
                timerange_minutes, since=since, until=until,
            )
        except TimeRangeError as e:
            return str(e)
        try:
            hits, total = await self._search(body, index=self.sysmon_index)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        fetched = len(hits)
        hits, capped = truncate_result_list(hits, self.max_results)
        # Drop whole RECORDS rather than slicing the serialized string (issue
        # #41), reserve the worst-case footer, then say what actually happened:
        # true match count, page fetched, records shown (issue #43).
        body, dropped = json_dump_within(hits, self.max_chars - FOOTER_RESERVE)
        return body + result_footer(
            total=total, fetched=fetched, capped=capped, shown=len(hits) - dropped,
            max_results=self.max_results)

    def _build_process_tree_self_query(
        self, process_guid: str, host: str, timerange_minutes: int,
        since: str = "", until: str = "",
    ) -> dict:
        # The process itself + its parent: any event carrying this ProcessGuid, or
        # any event whose ChildProcessGuid is this guid (the parent's create event).
        should: list[dict[str, Any]] = [
            {"term": {"ProcessGuid.keyword": process_guid}},
            {"term": {"ParentProcessGuid.keyword": process_guid}},
        ]
        must: list[dict[str, Any]] = [
            {"bool": {"should": should, "minimum_should_match": 1}},
            timestamp_range(timerange_minutes, since, until).clause,
        ]
        if host:
            must.append(host_name_clause(host, "Computer"))
        return {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "asc"}],
            "size": self.max_results,
        }

    def _build_process_tree_children_query(
        self, process_guid: str, host: str, timerange_minutes: int,
        since: str = "", until: str = "",
    ) -> dict:
        # Children: events whose ParentProcessGuid == this guid.
        must: list[dict[str, Any]] = [
            {"term": {"ParentProcessGuid.keyword": process_guid}},
            timestamp_range(timerange_minutes, since, until).clause,
        ]
        if host:
            must.append(host_name_clause(host, "Computer"))
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
        since: str = "",
        until: str = "",
    ) -> str:
        """Walk the Sysmon process subtree for a ProcessGuid (self + parent + children).

        Args:
            process_guid: The Sysmon ProcessGuid to anchor on (required)
            host: Optional Computer filter (FQDN or short name) to scope the walk
            timerange_minutes: Lookback window in minutes
            since, until: absolute UTC bounds (ISO-8601); either replaces timerange_minutes
        """
        if not process_guid:
            return "Error: process_guid is required."
        try:
            self_body = self._build_process_tree_self_query(
                process_guid, host, timerange_minutes, since=since, until=until)
            child_body = self._build_process_tree_children_query(
                process_guid, host, timerange_minutes, since=since, until=until)
        except TimeRangeError as e:
            return str(e)
        try:
            self_hits, self_total = await self._search(self_body, index=self.sysmon_index)
            child_hits, child_total = await self._search(child_body, index=self.sysmon_index)
        except httpx.HTTPError as e:
            return f"Error: ES query failed: {e}"
        fetched = len(self_hits) + len(child_hits)
        self_hits, self_trunc = truncate_result_list(self_hits, self.max_results)
        child_hits, child_trunc = truncate_result_list(child_hits, self.max_results)
        tree = {
            "process_guid": process_guid,
            "self_and_parent": self_hits,
            "children": child_hits,
        }
        # Shrink the two record lists; process_guid and the object shape survive.
        # Reserve the worst-case footer, then report what actually happened --
        # `if dropped and not footer` hid the size-limit truncation whenever the
        # per-list cap had also fired, which is when it matters most.
        body, dropped = json_dump_within(
            tree, self.max_chars - FOOTER_RESERVE, shrink=("self_and_parent", "children"))
        notes = []
        if self_total + child_total > fetched:
            notes.append(f"matched {self_total + child_total:,}; fetched the newest {fetched}")
        if self_trunc or child_trunc:
            notes.append(f"result sets capped at first {self.max_results}")
        if dropped:
            notes.append(f"{dropped} further record(s) omitted for the size limit")
        footer = f"\n\n--- {'; '.join(notes)}. Narrow your query. ---" if notes else ""
        return body + footer
