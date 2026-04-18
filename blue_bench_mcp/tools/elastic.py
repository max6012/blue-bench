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
        timerange_minutes: int = 60,
        query_text: str = "",
    ) -> str:
        """Search security alerts across all configured index patterns (by default: Suricata alerts + Wazuh HIDS alerts + Zeek connections).

        Arguments:
          src_ip, dest_ip: IPv4/IPv6 strings; omit for no filter.
          severity: integer 1 (critical) / 2 (medium) / 3 (low); 0 = no filter.
            For Suricata this filters on alert.severity; Wazuh uses a different
            scale (rule.level, 0-15) that this filter does not touch.
          timerange_minutes: lookback window from now, default 60.
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
        timerange_minutes: int = 60,
    ) -> str:
        """Search Zeek conn.log records for host-to-host traffic.

        Arguments:
          src_ip, dest_ip: IPv4/IPv6 strings; omit for no filter.
          dest_port: integer port number; 0 = no filter.
          proto: 'tcp', 'udp', or 'icmp'; empty for no filter.
          timerange_minutes: lookback window from now, default 60.
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
    async def count_by_field(
        field: str,
        index: str = "",
        timerange_minutes: int = 60,
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
          timerange_minutes: lookback window, default 60.
          top_n: max number of top values to return, default 20.
        Returns a human-readable ranked list of (value, count) pairs.
        """
        return await tool.count_by_field(
            field=field,
            index=index,
            timerange_minutes=timerange_minutes,
            top_n=top_n,
        )
