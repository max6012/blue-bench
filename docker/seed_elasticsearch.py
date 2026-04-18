#!/usr/bin/env python3
"""Seed Elasticsearch with CU27 synthetic data.

Loads Suricata alerts (eve.json) and Zeek connections (conn.log) into
Elasticsearch indices matching the MCP server's expected patterns.

Usage:
    python seed_elasticsearch.py --data-dir /data --es-url http://elasticsearch:9200
"""

import json
import os
import sys
import time
from pathlib import Path

import httpx

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))

# Index names matching config.local.yaml patterns
ALERTS_INDEX = "logstash-suricata-alerts"
ZEEK_INDEX = "zeek-conn"
WAZUH_INDEX = "wazuh-alerts"


def wait_for_es(url: str, max_retries: int = 30):
    """Wait until Elasticsearch is ready."""
    for i in range(max_retries):
        try:
            r = httpx.get(f"{url}/_cluster/health", timeout=5)
            if r.status_code == 200:
                health = r.json()
                print(f"ES cluster '{health['cluster_name']}' status: {health['status']}")
                return True
        except Exception:
            pass
        print(f"Waiting for Elasticsearch... ({i+1}/{max_retries})")
        time.sleep(2)
    print("ERROR: Elasticsearch not available")
    sys.exit(1)


def create_index(url: str, index: str, mappings: dict = None):
    """Create index if it doesn't exist."""
    r = httpx.head(f"{url}/{index}", timeout=5)
    if r.status_code == 200:
        print(f"  Index '{index}' already exists, deleting...")
        httpx.delete(f"{url}/{index}", timeout=10)

    body = {}
    if mappings:
        body["mappings"] = mappings

    r = httpx.put(f"{url}/{index}", json=body, timeout=10)
    if r.status_code in (200, 201):
        print(f"  Created index '{index}'")
    else:
        print(f"  ERROR creating '{index}': {r.text}")
        sys.exit(1)


def bulk_index(url: str, index: str, docs: list[dict]):
    """Bulk-index documents into Elasticsearch."""
    if not docs:
        print(f"  No documents to index into '{index}'")
        return

    lines = []
    for i, doc in enumerate(docs):
        lines.append(json.dumps({"index": {"_index": index, "_id": str(i)}}))
        lines.append(json.dumps(doc))

    body = "\n".join(lines) + "\n"
    r = httpx.post(
        f"{url}/_bulk",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=30,
    )
    result = r.json()
    if result.get("errors"):
        errors = [item for item in result["items"] if "error" in item.get("index", {})]
        print(f"  WARNING: {len(errors)} indexing errors")
    print(f"  Indexed {len(docs)} documents into '{index}'")


def parse_zeek_conn_log(path: Path) -> list[dict]:
    """Parse Zeek conn.log TSV into list of dicts with ES-friendly field names."""
    lines = path.read_text().strip().split("\n")
    fields = None
    records = []
    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue
        values = line.split("\t")
        record = {}
        for i, f in enumerate(fields):
            val = values[i] if i < len(values) else "-"
            record[f] = val
        # Add ES-friendly fields
        record["@timestamp"] = record.get("ts", "")
        record["src_ip"] = record.get("id.orig_h", "")
        record["src_port"] = record.get("id.orig_p", "")
        record["dest_ip"] = record.get("id.resp_h", "")
        record["dest_port"] = record.get("id.resp_p", "")
        records.append(record)
    return records


def main():
    print(f"CU27 Elasticsearch Seeder")
    print(f"  ES URL:   {ES_URL}")
    print(f"  Data dir: {DATA_DIR}")
    print()

    wait_for_es(ES_URL)
    print()

    # --- Suricata alerts ---
    eve_path = DATA_DIR / "eve.json"
    if eve_path.exists():
        alerts = [json.loads(line) for line in eve_path.read_text().strip().split("\n") if line.strip()]
        print(f"Loading {len(alerts)} Suricata alerts...")
        create_index(ES_URL, ALERTS_INDEX, {
            "properties": {
                "@timestamp": {"type": "date"},
                "src_ip": {"type": "ip"},
                "dest_ip": {"type": "ip"},
                "alert": {"properties": {
                    "signature": {"type": "text"},
                    "severity": {"type": "integer"},
                    "category": {"type": "keyword"},
                }},
            }
        })
        bulk_index(ES_URL, ALERTS_INDEX, alerts)
    else:
        print(f"WARNING: {eve_path} not found, skipping Suricata alerts")

    print()

    # --- Zeek connections ---
    conn_path = DATA_DIR / "conn.log"
    if conn_path.exists():
        conns = parse_zeek_conn_log(conn_path)
        print(f"Loading {len(conns)} Zeek connections...")
        create_index(ES_URL, ZEEK_INDEX, {
            "properties": {
                "@timestamp": {"type": "date"},
                "src_ip": {"type": "ip"},
                "dest_ip": {"type": "ip"},
                "src_port": {"type": "keyword"},
                "dest_port": {"type": "keyword"},
                "proto": {"type": "keyword"},
                "service": {"type": "keyword"},
            }
        })
        bulk_index(ES_URL, ZEEK_INDEX, conns)
    else:
        print(f"WARNING: {conn_path} not found, skipping Zeek connections")

    print()

    # --- Wazuh alerts (also indexed in ES for cross-correlation) ---
    wazuh_path = DATA_DIR / "wazuh_alerts.json"
    if wazuh_path.exists():
        wazuh_alerts = [json.loads(line) for line in wazuh_path.read_text().strip().split("\n") if line.strip()]
        print(f"Loading {len(wazuh_alerts)} Wazuh alerts...")
        create_index(ES_URL, WAZUH_INDEX)
        bulk_index(ES_URL, WAZUH_INDEX, wazuh_alerts)
    else:
        print(f"WARNING: {wazuh_path} not found, skipping Wazuh alerts")

    print()

    # Refresh all indices
    httpx.post(f"{ES_URL}/_refresh", timeout=10)
    print("All indices refreshed.")

    # Summary
    print("\n--- Seed Summary ---")
    for idx in [ALERTS_INDEX, ZEEK_INDEX, WAZUH_INDEX]:
        r = httpx.get(f"{ES_URL}/{idx}/_count", timeout=5)
        if r.status_code == 200:
            count = r.json().get("count", 0)
            print(f"  {idx}: {count} documents")
        else:
            print(f"  {idx}: not found")

    print("\nDone! Elasticsearch is seeded with CU27 sample data.")


if __name__ == "__main__":
    main()
