"""AuthTool — analyst-facing search over authentication logs.

The other tools cover Suricata/Wazuh alerts (ElasticTool.search_alerts), Zeek
connections (get_connections), and Sysmon process telemetry
(get_process_events). NONE of them read the authentication substrates, so
credential-abuse tradecraft (brute force, password spraying, dormant-credential
use, pass-the-hash, impossible travel) is invisible without this tool.

Two heterogeneous indices, queried together:
  - windows-security  : Windows Security EventLog auth records (EventID int).
  - linux-syslog      : sshd/auth syslog lines (outcome + source in `message`).

Follows the TOOL_CLASS_PATTERN contract: one class, shared state in __init__,
guardrails applied consistently.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import json_dump_within, truncate_result_list


class AuthTool:
    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.url = cfg.elastic.url.rstrip("/")
        # Query both auth indices in one request; ES accepts comma-separated.
        self.index = f"{cfg.auth.windows_security_index},{cfg.auth.linux_syslog_index}"
        self.verify_ssl = cfg.elastic.verify_ssl
        self.user = cfg.elastic.user
        self.password = cfg.elastic.password
        self.timeout = cfg.limits.query_timeout
        # Auth queries surface a few injected anomalies among thousands of benign
        # logons; a tighter cap truncates the needle away even on a filtered query.
        # Give this tool a larger budget (aggregation via count_by_field is the
        # primary pattern-finder; this is the raw-record backstop).
        self.max_chars = cfg.limits.max_result_chars * 2
        self.max_results = cfg.limits.max_results

    def _auth(self) -> tuple[str, str] | None:
        return (self.user, self.password) if self.user and self.password else None

    async def _query(self, body: dict) -> list[dict]:
        url = f"{self.url}/{self.index}/_search"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            # ignore_unavailable so a missing auth index degrades to "no data"
            # rather than a 404 that masks the real (empty) answer.
            resp = await client.post(
                url, json=body, params={"ignore_unavailable": "true", "allow_no_indices": "true"}
            )
            resp.raise_for_status()
            data = resp.json()
        return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]

    async def search_auth_events(
        self,
        account: str = "",
        src_ip: str = "",
        event_id: int = 0,
        logon_type: int = -1,
        result: str = "",
        host: str = "",
        timerange_minutes: int = 240,
    ) -> str:
        """Search authentication events across Windows Security and Linux auth logs.

        Spans two substrates at once (field names differ by source, so a filter
        matches whichever representation applies):
          - Windows Security EventLog: EventID (int) 4624 logon / 4625 FAILED
            logon / 4768 Kerberos TGT / 4769 TGS / 4771 Kerberos pre-auth FAIL /
            4776 NTLM validation. Fields: Computer, SubjectUserName,
            TargetUserName, TargetDomainName, LogonType (2 interactive, 3 network,
            4 batch, 5 service, 10 remote-interactive/RDP), IpAddress,
            WorkstationName, Status, FailureReason.
          - Linux sshd/auth syslog: outcome ("Failed password" / "Accepted") and
            the source IP are in the `message` text.

        Arguments (all optional):
          account: user account — matches Windows SubjectUserName/TargetUserName
            and the Linux syslog message. Empty = no filter.
          src_ip: source IP of the auth attempt — Windows IpAddress and the Linux
            message text. Useful for "one source hitting many accounts" (spraying)
            or "one account from two sources" (impossible travel).
          event_id: exact Windows Security EventID; 0 = no filter. NOTE a nonzero
            event_id restricts to Windows records (Linux syslog has no EventID).
          logon_type: exact Windows LogonType; -1 = no filter (0 is a real value).
          result: 'success' (4624 / Accepted) or 'failure' (4625 / 4771 / Failed
            password); empty = no filter. Use 'failure' to surface brute-force /
            spray attempts.
          host: target host — Windows Computer or Linux syslog host. Empty = no filter.
          timerange_minutes: lookback window from now, default 240. Auth abuse is
            often low-and-slow — widen this for spraying / dormant-credential use.

        Range-filters on @timestamp (set by ingest for both substrates, so it works
        whether the native clock is TimeCreated, UtcTime, or the syslog timestamp);
        records are returned with their native fields intact. Returns a JSON array
        of matching auth records, newest first. Empty [] on no match. Benign logons
        dominate — a match is a lead to triage, not a verdict.
        """
        must: list[dict[str, Any]] = []
        if account:
            must.append({"bool": {"should": [
                {"match": {"SubjectUserName": account}},
                {"match": {"TargetUserName": account}},
                {"match": {"message": account}},
            ], "minimum_should_match": 1}})
        if src_ip:
            must.append({"bool": {"should": [
                {"term": {"IpAddress": src_ip}},
                {"match_phrase": {"message": src_ip}},
            ], "minimum_should_match": 1}})
        if event_id:
            # Match either spelling. The lowercase form is NOT Sysmon-only:
            # apt_inject's parse_evtx writes `event_id` for EVERY Windows EVTX
            # stream, Security included, and those route to windows-security. A
            # single-field term silently misses that whole population (issue
            # #37, same class as the get_process_events fix).
            must.append({"bool": {"should": [
                {"term": {"EventID": event_id}},
                {"term": {"event_id": event_id}},
            ], "minimum_should_match": 1}})
        if logon_type >= 0:
            # LogonType is stored as a string ("4"); match both forms defensively.
            must.append({"bool": {"should": [
                {"term": {"LogonType": str(logon_type)}},
                {"term": {"LogonType": logon_type}},
            ], "minimum_should_match": 1}})
        r = result.strip().lower()
        if r in ("success", "successful", "accepted"):
            must.append({"bool": {"should": [
                {"term": {"EventID": 4624}},
                {"term": {"event_id": 4624}},
                {"match_phrase": {"message": "Accepted"}},
            ], "minimum_should_match": 1}})
        elif r in ("failure", "failed", "fail"):
            must.append({"bool": {"should": [
                {"term": {"EventID": 4625}},
                {"term": {"event_id": 4625}},
                {"term": {"EventID": 4771}},
                {"term": {"event_id": 4771}},
                {"match_phrase": {"message": "Failed password"}},
            ], "minimum_should_match": 1}})
        if host:
            must.append({"bool": {"should": [
                {"match": {"Computer": host}},
                {"match": {"host": host}},
            ], "minimum_should_match": 1}})
        must.append({"range": {"@timestamp": {"gte": f"now-{timerange_minutes}m", "lte": "now"}}})

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
        # Drop whole records rather than slicing the serialized string:
        # truncate_results would splice a marker through the middle of the JSON
        # and hand the model something unparseable (issue #41).
        # Reserve the WORST-CASE footer length, then report what actually
        # happened. The earlier `if dropped and not truncated` suppressed the
        # accurate count in exactly the case where the response was most
        # truncated -- it reported "showing first N" while returning far fewer.
        reserve = 160
        body, dropped = json_dump_within(hits, self.max_chars - reserve)
        shown = len(hits) - dropped
        notes = []
        if truncated:
            notes.append(f"result set capped at first {self.max_results}")
        if dropped:
            notes.append(f"showing {shown} of those {len(hits)} (size limit)")
        footer = f"\n\n--- {'; '.join(notes)}. Narrow your query. ---" if notes else ""
        return body + footer
