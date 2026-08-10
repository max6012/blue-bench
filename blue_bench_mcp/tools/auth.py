"""MCP register wrapper for AuthTool (authentication-log search)."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.tool_classes.auth import AuthTool


def register(server: FastMCP, cfg: ServerConfig) -> None:
    tool = AuthTool(cfg)

    @server.tool()
    async def search_auth_events(
        account: str = "",
        src_ip: str = "",
        event_id: int = 0,
        logon_type: int = -1,
        result: str = "",
        host: str = "",
        timerange_minutes: int = 240,
    ) -> str:
        """Search authentication events across Windows Security and Linux auth logs
        — the only tool that reads the auth substrate, and the workhorse for
        credential-abuse hunting (brute force, password spraying, dormant-credential
        use, pass-the-hash, impossible travel).

        Covers two sources at once (field names differ; a filter matches whichever
        applies):
          - Windows Security EventLog: EventID (int) 4624 logon / 4625 FAILED logon /
            4768 Kerberos TGT / 4769 TGS / 4771 Kerberos pre-auth FAIL / 4776 NTLM
            validation. Fields include Computer, SubjectUserName, TargetUserName,
            TargetDomainName, LogonType (2 interactive / 3 network / 4 batch /
            5 service / 10 remote-interactive-RDP), IpAddress, WorkstationName,
            Status, FailureReason.
          - Linux sshd/auth syslog: the outcome ("Failed password" / "Accepted") and
            the source IP live in the `message` text.

        Arguments (all optional):
          account: user account — Windows SubjectUserName/TargetUserName + Linux message.
          src_ip: source IP of the attempt — Windows IpAddress + Linux message. Use to
            spot one source hitting many accounts (spray) or one account from two
            sources (impossible travel).
          event_id: exact Windows Security EventID; 0 = no filter. A nonzero value
            restricts to Windows records (Linux syslog has no EventID).
          logon_type: exact Windows LogonType; -1 = no filter (0 is a valid value).
          result: 'success' (4624 / Accepted) or 'failure' (4625 / 4771 / Failed
            password); empty = no filter. Use 'failure' for brute-force / spray leads.
          host: target host — Windows Computer or Linux syslog host.
          timerange_minutes: lookback from now, default 240. Credential abuse is often
            low-and-slow — widen this for spraying / dormant-credential use.

        Returns a JSON array of matching auth records (native fields preserved),
        newest first. Empty [] on no match. Benign logons dominate — a match is a
        lead to triage, not a verdict.
        """
        return await tool.search_auth_events(
            account=account,
            src_ip=src_ip,
            event_id=event_id,
            logon_type=logon_type,
            result=result,
            host=host,
            timerange_minutes=timerange_minutes,
        )
