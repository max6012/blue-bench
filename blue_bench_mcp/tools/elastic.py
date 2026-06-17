"""MCP register wrappers for ElasticTool commands."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.elastic import ElasticTool


def register(server: FastMCP, cfg: ServerConfig) -> None:
    tool = ElasticTool(cfg)

    @server.tool()
    async def search_alerts(
        src_ip: str = "",
        dest_ip: str = "",
        severity: int = 0,
        timerange_minutes: int = 240,
        query_text: str = "",
    ) -> str:
        """Search security alerts across all configured index patterns (by default: Suricata alerts + Wazuh HIDS alerts + Zeek connections).

        Arguments:
          src_ip, dest_ip: IPv4/IPv6 strings; omit for no filter.
          severity: integer 1 (critical) / 2 (medium) / 3 (low); 0 = no filter.
            For Suricata this filters on alert.severity; Wazuh uses a different
            scale (rule.level, 0-15) that this filter does not touch.
          timerange_minutes: lookback window from now, default 240.
          query_text: free-text query (Lucene-style) across all alert fields;
            useful for signature names, rule descriptions, query_text like
            'Cobalt Strike' will match any signature containing that phrase.
        Returns JSON-formatted array of matching alert records. Empty [] on no match.
        """
        return await tool.search_alerts(
            src_ip=src_ip,
            dest_ip=dest_ip,
            severity=severity,
            timerange_minutes=timerange_minutes,
            query_text=query_text,
        )

    @server.tool()
    async def get_connections(
        src_ip: str = "",
        dest_ip: str = "",
        dest_port: int = 0,
        proto: str = "",
        timerange_minutes: int = 240,
    ) -> str:
        """Search Zeek conn.log records for host-to-host traffic.

        Arguments:
          src_ip, dest_ip: IPv4/IPv6 strings; omit for no filter.
          dest_port: integer port number; 0 = no filter.
          proto: 'tcp', 'udp', or 'icmp'; empty for no filter.
          timerange_minutes: lookback window from now, default 240.
        Returns JSON array of Zeek conn records with fields including src_ip,
        dest_ip, dest_port, proto, service, orig_bytes, resp_bytes, duration,
        conn_state. Empty [] on no match.
        """
        return await tool.get_connections(
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            proto=proto,
            timerange_minutes=timerange_minutes,
        )

    @server.tool()
    async def get_process_events(
        host: str = "",
        image: str = "",
        parent_image: str = "",
        command_line_contains: str = "",
        event_id: int = 0,
        timerange_minutes: int = 240,
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
        )

    @server.tool()
    async def get_process_tree(
        process_guid: str = "",
        host: str = "",
        timerange_minutes: int = 240,
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
        Returns a JSON object with keys: 'process_guid' (the anchor),
        'self_and_parent' (events carrying this ProcessGuid plus the parent's
        create event), and 'children' (events whose ParentProcessGuid is this
        guid). Each list is [] on no match.
        """
        return await tool.get_process_tree(
            process_guid=process_guid,
            host=host,
            timerange_minutes=timerange_minutes,
        )

    @server.tool()
    async def count_by_field(
        field: str,
        index: str = "",
        timerange_minutes: int = 240,
        top_n: int = 20,
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
          index: optional ES index pattern override (e.g., to scope an
            aggregation to a single data source). Leave empty to search the
            default multi-index pattern.
          timerange_minutes: lookback window, default 240.
          top_n: max number of top values to return, default 20.
        Returns a human-readable ranked list of (value, count) pairs.
        """
        return await tool.count_by_field(
            field=field,
            index=index,
            timerange_minutes=timerange_minutes,
            top_n=top_n,
        )
