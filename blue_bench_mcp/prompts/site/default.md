## Site Context — Blue-Bench reference deployment

This describes the environment this instance runs against and the data you can
query. It orients you; it does not substitute for the telemetry — verify every
conclusion from tool output.

### Environment
- Active Directory domain `corp.example.invalid`; site timezone America/New_York.
- Corporate IT: user workstations and Windows/Linux servers on RFC-1918 `10.x`
  space (workstations and servers on separate subnets).
- An OT/plant network is also present, on subnets separate from corporate IT.
- Benign background noise is expected — automation, software updates, telemetry,
  and routine administrative activity all generate events. A signature firing or
  an unusual connection is a lead to triage, not a verdict.

### Data sources (Elasticsearch-backed tools)
- **Suricata IDS alerts** — `search_alerts`, `count_by_field`. Severity
  `alert.severity` (1 critical / 2 medium / 3 low); signatures in `alert.signature`.
- **Wazuh HIDS alerts** — `search_alerts`, `count_by_field`, `get_agent_alerts`.
  Severity `rule.level` (0–15); descriptions in `rule.description`.
- **Zeek connection logs** — `get_connections`, `count_by_field`. Fields include
  `src_ip`, `dest_ip`, `dest_port`, `proto`, `service`, `orig_bytes`,
  `resp_bytes`, `duration`, `conn_state`.
- **Windows Sysmon host telemetry** — `get_process_events`, `get_process_tree`
  (`Computer`, `Image`, `CommandLine`, `ParentImage`, `EventID`, `ProcessGuid`, …).
- **Authentication logs** — `search_auth_events` (Windows Security EventLog +
  Linux sshd/auth syslog). Credential-abuse tradecraft (brute force, spraying,
  dormant-credential use, pass-the-hash, impossible travel) lives here and is
  reachable ONLY through this tool.

### Index names (for `count_by_field`'s `index` argument)

`count_by_field` defaults to the alert/Zeek pattern
`logstash-suricata-alerts,wazuh-alerts,zeek-conn`. The other sources live in
their own indices and are NOT in that default — pass `index` explicitly to
aggregate over them:

- `windows-sysmon` — Sysmon host telemetry (process/network events)
- `windows-security,linux-syslog` — authentication logs
- `ot-conn` — OT/plant connection logs (Modbus/DNP3/IEC-104/S7)

`search_alerts`, `get_connections`, `get_process_events`, `get_process_tree`,
`search_auth_events`, and `get_agent_alerts` already target the right indices
internally — do not pass `index` to them.

### Other tools
- **Endpoint (OpenEDR mock)** — `get_detections`, `list_endpoints`; filter by
  `hostname`; severity is a string.
- **Forensic evidence** — `list_evidence`, `file_hash`, `file_metadata`,
  `strings_extract` over the evidence directory; `../` is rejected.
- **Network scanning** — `nmap_scan`, `nmap_quick_scan` against hosts inside the
  configured allowed ranges; out-of-range targets are rejected by design.
