"""MCP register wrappers for ElasticTool commands."""
from __future__ import annotations

from mcp.server import MCPServer

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.elastic import ElasticTool


def register(server: MCPServer, cfg: ServerConfig) -> None:
    tool = ElasticTool(cfg)

    @server.tool()
    async def search_alerts(
        host_ip: str = "",
        src_ip: str = "",
        dest_ip: str = "",
        severity: int = 0,
        timerange_minutes: int = 240,
        query_text: str = "",
        since: str = "",
        until: str = "",
    ) -> str:
        """Search security alerts across all configured index patterns (by default: Suricata alerts + Wazuh HIDS alerts + Zeek connections).

        Arguments:
          host_ip: IPv4/IPv6 string; matches the address at EITHER end of the
            connection (source or destination). This is the filter to reach for
            when you are investigating one host — use src_ip/dest_ip only when
            the direction matters.
          src_ip, dest_ip: IPv4/IPv6 strings; omit for no filter.
          severity: integer 1 (critical) / 2 (medium) / 3 (low); 0 = no filter.
            For Suricata this filters on alert.severity; Wazuh uses a different
            scale (rule.level, 0-15) that this filter does not touch.
          timerange_minutes: lookback window from now, default 240.
          query_text: free-text query (Lucene-style) across all alert fields;
            useful for signature names, rule descriptions, query_text like
            'Cobalt Strike' will match any signature containing that phrase.
          since, until: absolute UTC bounds (ISO-8601, e.g. '2026-08-26T00:00:00Z');
            when either is given they replace timerange_minutes. Use them to pin
            an investigation to one exact time band — a lookback can only bound
            the leading edge. 'Z' and '+00:00' both work; no suffix means UTC.
        Returns JSON-formatted array of matching alert records. Empty [] on no match.
        """
        return await tool.search_alerts(
            host_ip=host_ip,
            src_ip=src_ip,
            dest_ip=dest_ip,
            severity=severity,
            timerange_minutes=timerange_minutes,
            query_text=query_text,
            since=since,
            until=until,
        )

    @server.tool()
    async def get_connections(
        host_ip: str = "",
        src_ip: str = "",
        dest_ip: str = "",
        dest_port: int = 0,
        proto: str = "",
        timerange_minutes: int = 240,
        since: str = "",
        until: str = "",
    ) -> str:
        """Search Zeek conn.log records for host-to-host traffic.

        Arguments:
          host_ip: IPv4/IPv6 string; matches the address at EITHER end of the
            connection (id.orig_h or id.resp_h). This is the filter to reach for
            when you are investigating one host — it catches the traffic it
            initiated and the traffic it received. Use src_ip/dest_ip only when
            the direction matters.
          src_ip, dest_ip: IPv4/IPv6 strings; omit for no filter.
          dest_port: integer port number; 0 = no filter.
          proto: 'tcp', 'udp', or 'icmp'; empty for no filter.
          timerange_minutes: lookback window from now, default 240.
          since, until: absolute UTC bounds (ISO-8601, e.g. '2026-08-26T00:00:00Z');
            when either is given they replace timerange_minutes. Use them to pin
            an investigation to one exact time band — a lookback can only bound
            the leading edge. 'Z' and '+00:00' both work; no suffix means UTC.
        Returns JSON array of Zeek conn records with fields including src_ip,
        dest_ip, dest_port, proto, service, orig_bytes, resp_bytes, duration,
        conn_state. Empty [] on no match.
        """
        return await tool.get_connections(
            host_ip=host_ip,
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            proto=proto,
            timerange_minutes=timerange_minutes,
            since=since,
            until=until,
        )

    @server.tool()
    async def get_process_events(
        host: str = "",
        image: str = "",
        parent_image: str = "",
        command_line_contains: str = "",
        event_id: int = 0,
        timerange_minutes: int = 240,
        since: str = "",
        until: str = "",
    ) -> str:
        """Search Sysmon host telemetry (windows-sysmon index) for process and
        host events — the workhorse for hunting host-side kill-chain activity.

        Field names are Sysmon-specific: Sysmon uses Computer (FQDN host),
        Image / ParentImage (full process paths), CommandLine, EventID (int),
        and ProcessGuid / ParentProcessGuid.

        Arguments:
          host: Computer FQDN, e.g. 'wkst-01.corp.example.invalid'; exact match,
            empty = no filter.
          image: full Image path, exact match (e.g. 'C:\\Windows\\System32\\svchost.exe');
            empty = no filter.
          parent_image: full ParentImage path, exact match; empty = no filter.
          command_line_contains: case-insensitive substring matched anywhere in
            CommandLine; empty = no filter. Use for LotL hunting
            (e.g. 'powershell', '-enc', 'rundll32').
          event_id: Sysmon EventID — 1 process-create, 3 network-connect,
            5 process-terminate, 7 image-load, 8 create-remote-thread,
            10 process-access, 11 file-create, 12/13 registry, 22 dns.
            0 = no filter.
          timerange_minutes: lookback window from now, default 240.
          since, until: absolute UTC bounds (ISO-8601, e.g. '2026-08-26T00:00:00Z');
            when either is given they replace timerange_minutes. Use them to pin
            an investigation to one exact time band — a lookback can only bound
            the leading edge. 'Z' and '+00:00' both work; no suffix means UTC.
        Returns a JSON array of matching Sysmon records (fields include EventID,
        Computer, UtcTime, Image, CommandLine, ParentImage, ParentCommandLine,
        ProcessGuid, ParentProcessGuid, User, TargetFilename, TargetObject).
        Empty [] on no match.
        """
        return await tool.get_process_events(
            host=host,
            image=image,
            parent_image=parent_image,
            command_line_contains=command_line_contains,
            event_id=event_id,
            timerange_minutes=timerange_minutes,
            since=since,
            until=until,
        )

    @server.tool()
    async def get_process_tree(
        process_guid: str = "",
        host: str = "",
        timerange_minutes: int = 240,
        since: str = "",
        until: str = "",
    ) -> str:
        """Walk the Sysmon process subtree around a ProcessGuid — returns the
        process itself, its parent, and its direct children so you can trace an
        attack chain up and down from a single pivot point.

        Field names are Sysmon-specific: the anchor is a ProcessGuid; children
        are events whose ParentProcessGuid equals that guid.

        Arguments:
          process_guid: the Sysmon ProcessGuid to anchor on (required). Get one
            from get_process_events output.
          host: optional Computer FQDN to scope the walk; empty = all hosts.
          timerange_minutes: lookback window from now, default 240.
          since, until: absolute UTC bounds (ISO-8601, e.g. '2026-08-26T00:00:00Z');
            when either is given they replace timerange_minutes. Use them to pin
            an investigation to one exact time band — a lookback can only bound
            the leading edge. 'Z' and '+00:00' both work; no suffix means UTC.
        Returns a JSON object with keys: 'process_guid' (the anchor),
        'self_and_parent' (events carrying this ProcessGuid plus the parent's
        create event), and 'children' (events whose ParentProcessGuid is this
        guid). Each list is [] on no match.
        """
        return await tool.get_process_tree(
            process_guid=process_guid,
            host=host,
            timerange_minutes=timerange_minutes,
            since=since,
            until=until,
        )

    @server.tool()
    async def count_by_field(
        field: str,
        index: str = "",
        timerange_minutes: int = 240,
        top_n: int = 20,
        since: str = "",
        until: str = "",
    ) -> str:
        """Aggregate and count top values for a field — use for 'top-N',
        'distribution', 'most common' style questions.

        Arguments:
          field: the exact field path to aggregate on. Field names are
            source-specific: Suricata nests severity at 'alert.severity',
            signatures at 'alert.signature'; Wazuh uses 'rule.level',
            'rule.description'; Zeek uses top-level 'src_ip', 'dest_ip',
            'dest_port'. Pass the field path exactly as it appears in tool
            output, not a shortened form.
          index: optional ES index pattern override. Leave empty to search the
            default alert/Zeek pattern (logstash-suricata-alerts,wazuh-alerts,
            zeek-conn). To aggregate over a source OUTSIDE that default, pass
            its index explicitly: 'windows-sysmon' (Sysmon host telemetry),
            'windows-security,linux-syslog' (authentication logs), or 'ot-conn'
            (OT/plant connection logs).
          timerange_minutes: lookback window, default 240.
          top_n: max number of top values to return, default 20.
          since, until: absolute UTC bounds (ISO-8601, e.g. '2026-08-26T00:00:00Z');
            when either is given they replace timerange_minutes. Use them to pin
            an investigation to one exact time band — a lookback can only bound
            the leading edge. 'Z' and '+00:00' both work; no suffix means UTC.
        Returns a human-readable ranked list of (value, count) pairs.
        """
        return await tool.count_by_field(
            field=field,
            index=index,
            timerange_minutes=timerange_minutes,
            top_n=top_n,
            since=since,
            until=until,
        )

    @server.tool()
    async def count_by_time(
        interval: str = "1h",
        index: str = "",
        timerange_minutes: int = 240,
        host: str = "",
        event_id: int = 0,
        query_text: str = "",
        top_n_hosts: int = 0,
        since: str = "",
        until: str = "",
    ) -> str:
        """Histogram of document counts over time — use to SURVEY a window
        before digging in: find the hours or days with unusual volume, then
        narrow other tools to those bands. Returns only non-empty buckets.

        Arguments:
          interval: bucket width, one of '15m', '1h', '6h', '1d'. Start wide
            ('1d' over the whole corpus), then re-run with '1h' or '15m' on
            the band that stands out.
          index: optional ES index pattern override. Leave empty to survey the
            default alert/Zeek pattern (logstash-suricata-alerts,wazuh-alerts,
            zeek-conn). To survey a source OUTSIDE that default, pass its index
            explicitly: 'windows-sysmon' (Sysmon host telemetry),
            'windows-security,linux-syslog' (authentication logs), 'zeek-dns',
            'zeek-http', or 'ot-conn' (OT/plant connection logs). Comma lists
            are accepted.
          timerange_minutes: lookback window, default 240. The corpus spans
            weeks — pass a large value (e.g. 43200 = 30 days) to see all of it.
          host: optional host filter, matched against Sysmon 'Computer', Zeek
            'id.orig_h' / 'id.resp_h', and auth 'Computer' / 'host'. Use the
            FQDN for Windows sources and the IP for Zeek.
          event_id: optional Windows EventID filter (Sysmon 1, 3, 11...;
            Security 4624, 4625, 4688...). 0 = no filter.
          query_text: optional free-text (Lucene-style) filter.
          top_n_hosts: if > 0, list the top N hosts (Computer) inside each
            bucket so you can see which machines drive a spike. Only Windows
            indices carry that field.
          since, until: absolute UTC bounds (ISO-8601, e.g. '2026-08-26T00:00:00Z');
            when either is given they replace timerange_minutes. Use them to pin
            an investigation to one exact time band — a lookback can only bound
            the leading edge. 'Z' and '+00:00' both work; no suffix means UTC.
        Returns a header line (index, interval, window, total docs, bucket
        count) then one line per bucket: '<bucket start ISO>  <count>', with
        an indented 'host: count' list when top_n_hosts is set.
        """
        return await tool.count_by_time(
            interval=interval,
            index=index,
            timerange_minutes=timerange_minutes,
            host=host,
            event_id=event_id,
            query_text=query_text,
            top_n_hosts=top_n_hosts,
            since=since,
            until=until,
        )

    async def detect_beaconing(
        timerange_minutes: int = 0,
        min_connections: int = 0,
        max_jitter: float = 0.0,
        aggregation: str = "",
        src_ip: str = "",
        dest_ip: str = "",
    ) -> str:
        """Rank internal->external (src,dest) pairs by how BEACON-LIKE they are —
        the interval-regularity analytic for finding low-and-slow C2 that raw
        connection listings bury in benign volume.

        Returns a JSON object with two parts:
          - "analysis": a COVERAGE envelope — the method, the thresholds used,
            how many pairs were analyzed / excluded / deep-checked, and a
            "blind_spots" list. READ THIS: an empty "candidates" list is NOT
            proof of "no C2" — it is bounded by these blind spots. If you need
            to rule C2 out, address the blind spots (widen the window, lower
            min_connections toward the floor, retry aggregation='/24' for
            rotated C2) or corroborate on host telemetry — do not treat a bare
            negative as a true negative.
          - "candidates": ranked (src->dest) pairs with connections,
            mean_interval_s, interval_cv (lower = more regular), regularity_score,
            distinct_src_hosts (1 = dedicated infra), span_hours, mean_orig_bytes.

        Arguments (all optional; omitted values use the configured envelope):
          timerange_minutes: lookback (beacons need days — default is wide).
          min_connections: min callbacks to qualify (floored by config; a
            slower beacon needs a lower value to be seen).
          max_jitter: interval-CV cutoff for "regular" (attackers add jitter to
            evade; raise this to catch jittered beacons, at the cost of FPs).
          aggregation: 'ip' (exact dest) or '/24' (merge a rotated subnet).
          src_ip / dest_ip: scope to one host or destination.

        Benign automation (updates, NTP, telemetry) also beacons — a high rank
        is a lead to triage, not a verdict.
        """
        return await tool.detect_beaconing(
            timerange_minutes=timerange_minutes,
            min_connections=min_connections,
            max_jitter=max_jitter,
            aggregation=aggregation,
            src_ip=src_ip,
            dest_ip=dest_ip,
        )

    # Off by default — beacons are not meant to be network-findable, so this
    # beacon-finder stays out of the measurement tool surface unless a config
    # explicitly sets beaconing.enabled.
    if cfg.beaconing.enabled:
        server.tool()(detect_beaconing)
