## Site Context — Blue-Bench reference deployment

This section describes the specific environment this Blue-Bench instance is running against. Site operators replace this file with their own when deploying elsewhere.

### Data sources available via Elasticsearch tools

- **Suricata IDS alerts.** Accessible through `search_alerts` and `count_by_field`. Severity field is `alert.severity` with integer values `1` (critical) / `2` (medium) / `3` (low). Signature names are in `alert.signature`.
- **Wazuh HIDS alerts.** Accessible through `search_alerts`, `count_by_field`, and `get_agent_alerts` (with Wazuh API fallback to ES). Severity field is `rule.level` with integer values `0`–`15`. Rule descriptions are in `rule.description`.
- **Zeek network connection logs.** Accessible through `get_connections` and `count_by_field`. Relevant fields include `src_ip`, `dest_ip`, `dest_port`, `proto`, `service`, `orig_bytes`, `resp_bytes`, `duration`, `conn_state`.

All three data sources live in the default index pattern configured on the tool side — you do not normally need to pass an `index` argument. If you do specify one, use the exact pattern shown in the tool's description.

### Endpoint telemetry (OpenEDR mock)

`get_detections`, `list_endpoints` query a FastAPI-hosted OpenEDR mock. Use `hostname` arguments to filter — the severity field is a string (`critical`/`high`/`medium`/`low`).

### Forensic evidence directory

`list_evidence`, `file_hash`, `file_metadata`, `strings_extract` operate on files under the configured evidence directory. Filenames are relative to that directory. Path traversal (`../`) is rejected.

### Network scanning

`nmap_scan` and `nmap_quick_scan` target hosts inside the allowed ranges declared in the tool's configuration. Targets outside that range are rejected — those are safety guardrails, not data errors.

### Known scenarios in this dataset

This reference deployment is seeded with a synthetic Cobalt-Strike-style incident plus realistic background telemetry (AIT-ADS, Brim). Expect to encounter:

- HTTPS C2 beacon activity on common ports
- DNS tunneling via TXT record abuse
- Large outbound data transfers indicating exfiltration
- SSH brute force + privilege escalation patterns on Linux hosts

When an analyst asks about a host or alert, these scenarios are probable sources for findings — but always verify from tool output rather than assuming.
