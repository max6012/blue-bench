"""Seed Blue-Bench Phase 2 Elasticsearch.

Runs from the host directly (not containerized) — hits http://localhost:9200
and loads data/raw/ into three indices:

  logstash-suricata-alerts   ← data/raw/eve.json
  zeek-conn                  ← data/raw/conn.log
  wazuh-alerts               ← data/raw/wazuh_alerts.json  (used as ES fallback)

Sets @timestamp on each document to spread across the last hour, so the
60-minute default lookback in our tools sees the data.

Usage:
  .venv/bin/python scripts/seed_es.py [--es-url http://localhost:9200]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

DEFAULT_ES = os.environ.get("BLUE_BENCH_ES_URL", "http://localhost:9200")
REPO = Path(__file__).parent.parent
DATA_DIR = REPO / "data" / "raw"

ALERTS_INDEX = "logstash-suricata-alerts"
ZEEK_INDEX = "zeek-conn"
WAZUH_INDEX = "wazuh-alerts"


def _wait_for_es(url: str, retries: int = 10) -> None:
    for i in range(retries):
        try:
            r = httpx.get(f"{url}/_cluster/health", timeout=3)
            if r.status_code == 200:
                health = r.json()
                print(f"ES ready — cluster={health['cluster_name']} status={health['status']}")
                return
        except httpx.HTTPError:
            pass
        print(f"  waiting for ES ({i + 1}/{retries})...")
    print(f"ERROR: ES at {url} did not become ready")
    sys.exit(1)


def _recreate_index(url: str, index: str, mappings: dict | None = None) -> None:
    httpx.delete(f"{url}/{index}", timeout=10)  # Ignore errors — might not exist.
    body = {"mappings": mappings} if mappings else {}
    r = httpx.put(f"{url}/{index}", json=body, timeout=15)
    if r.status_code not in (200, 201):
        print(f"  ERROR creating '{index}': {r.text}")
        sys.exit(1)
    print(f"  created index: {index}")


def _bulk_index(url: str, index: str, docs: list[dict]) -> None:
    if not docs:
        print(f"  (no docs for '{index}' — skipping)")
        return
    lines: list[str] = []
    for i, doc in enumerate(docs):
        lines.append(json.dumps({"index": {"_index": index, "_id": str(i)}}))
        lines.append(json.dumps(doc, default=str))
    body = "\n".join(lines) + "\n"
    r = httpx.post(
        f"{url}/_bulk",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=30,
    )
    r.raise_for_status()
    result = r.json()
    errors = [item for item in result.get("items", []) if "error" in item.get("index", {})]
    if errors:
        print(f"  WARN: {len(errors)} indexing errors in '{index}'; first: {errors[0]}")
    print(f"  indexed {len(docs)} docs → {index}")


def _ts_window(count: int, now: datetime | None = None, span_minutes: int = 45) -> list[str]:
    """Return `count` ISO-8601 timestamps spread over the last `span_minutes`, oldest first.

    Default span is 45 minutes — chosen so that ALL seeded data fits inside the
    tools' default 60-minute lookback window at run time (with 15 minutes of
    slack for drift between seed and run). Widening the span (e.g., to 24h) to
    "outlast long sessions" has the opposite effect: 60-min lookback then sees
    only a sparse slice of the data and queries come back empty in ways that
    look like model regressions but are actually seed-time-vs-lookback
    mismatch.

    Re-seed before each benchmark run to keep the data inside the tools'
    default lookback. The runner does NOT auto-re-seed — it's your job.
    """
    now = now or datetime.now(timezone.utc)
    if count <= 1:
        return [now.isoformat()]
    span = timedelta(minutes=span_minutes)
    step = span / max(count - 1, 1)
    return [(now - span + i * step).isoformat() for i in range(count)]


def _load_suricata(path: Path) -> list[dict]:
    docs = [json.loads(line) for line in path.read_text().strip().split("\n") if line.strip()]
    ts = _ts_window(len(docs))
    for d, t in zip(docs, ts):
        d["@timestamp"] = t
    return docs


def _load_zeek_conn(path: Path) -> list[dict]:
    lines = path.read_text().strip().split("\n")
    fields: list[str] | None = None
    docs: list[dict] = []
    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not fields:
            continue
        values = line.split("\t")
        record: dict = {}
        for i, f in enumerate(fields):
            val = values[i] if i < len(values) else "-"
            record[f] = val
        # Duplicate to ES-friendly field names so both our tools and archive prompts work.
        record["src_ip"] = record.get("id.orig_h", "")
        record["src_port"] = record.get("id.orig_p", "")
        record["dest_ip"] = record.get("id.resp_h", "")
        record["dest_port"] = record.get("id.resp_p", "")
        docs.append(record)
    ts = _ts_window(len(docs))
    for d, t in zip(docs, ts):
        d["@timestamp"] = t
    return docs


def _load_wazuh(path: Path) -> list[dict]:
    docs = [json.loads(line) for line in path.read_text().strip().split("\n") if line.strip()]
    ts = _ts_window(len(docs))
    for d, t in zip(docs, ts):
        d["@timestamp"] = t
    return docs


def _combine(real: list[dict], synthetic: list[dict]) -> list[dict]:
    """Merge real + synthetic docs and re-timestamp the combined set."""
    combined = list(real) + list(synthetic)
    ts = _ts_window(len(combined))
    for d, t in zip(combined, ts):
        d["@timestamp"] = t
    return combined


def seed(es_url: str) -> None:
    print(f"Blue-Bench ES seeder — url={es_url} data_dir={DATA_DIR}")
    _wait_for_es(es_url)
    synthetic_dir = DATA_DIR / "synthetic"

    # Suricata (real AIT-ADS + synthetic Cobalt Strike scenario)
    real_eve = DATA_DIR / "eve.json"
    syn_eve = synthetic_dir / "eve.json"
    if real_eve.exists() or syn_eve.exists():
        real_docs = _load_suricata(real_eve) if real_eve.exists() else []
        syn_docs = _load_suricata(syn_eve) if syn_eve.exists() else []
        combined = _combine(real_docs, syn_docs)
        print(f"\nSuricata: {len(real_docs)} real + {len(syn_docs)} synthetic = {len(combined)}")
        _recreate_index(
            es_url,
            ALERTS_INDEX,
            {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "src_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "alert": {
                        "properties": {
                            "signature": {"type": "text"},
                            "severity": {"type": "integer"},
                            "category": {"type": "keyword"},
                        }
                    },
                }
            },
        )
        _bulk_index(es_url, ALERTS_INDEX, combined)

    # Zeek conn (real Brim + synthetic Cobalt Strike beacons)
    real_conn = DATA_DIR / "conn.log"
    syn_conn = synthetic_dir / "conn.log"
    if real_conn.exists() or syn_conn.exists():
        real_docs = _load_zeek_conn(real_conn) if real_conn.exists() else []
        syn_docs = _load_zeek_conn(syn_conn) if syn_conn.exists() else []
        combined = _combine(real_docs, syn_docs)
        print(f"\nZeek conn: {len(real_docs)} real + {len(syn_docs)} synthetic = {len(combined)}")
        _recreate_index(
            es_url,
            ZEEK_INDEX,
            {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "src_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "id.orig_h": {"type": "ip"},
                    "id.resp_h": {"type": "ip"},
                    "id.orig_p": {"type": "keyword"},
                    "id.resp_p": {"type": "keyword"},
                    "proto": {"type": "keyword"},
                    "service": {"type": "keyword"},
                }
            },
        )
        _bulk_index(es_url, ZEEK_INDEX, combined)

    # Wazuh (real AIT-ADS + synthetic SSH brute force / priv esc scenario)
    real_wazuh = DATA_DIR / "wazuh_alerts.json"
    syn_wazuh = synthetic_dir / "wazuh_alerts.json"
    if real_wazuh.exists() or syn_wazuh.exists():
        real_docs = _load_wazuh(real_wazuh) if real_wazuh.exists() else []
        syn_docs = _load_wazuh(syn_wazuh) if syn_wazuh.exists() else []
        combined = _combine(real_docs, syn_docs)
        print(f"\nWazuh (ES fallback): {len(real_docs)} real + {len(syn_docs)} synthetic = {len(combined)}")
        _recreate_index(es_url, WAZUH_INDEX)
        _bulk_index(es_url, WAZUH_INDEX, combined)

    httpx.post(f"{es_url}/_refresh", timeout=10)
    print("\nRefreshed. Counts:")
    for idx in (ALERTS_INDEX, ZEEK_INDEX, WAZUH_INDEX):
        r = httpx.get(f"{es_url}/{idx}/_count", timeout=5)
        if r.status_code == 200:
            print(f"  {idx}: {r.json().get('count', 0)}")
        else:
            print(f"  {idx}: MISSING")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--es-url", default=DEFAULT_ES)
    args = p.parse_args()
    seed(args.es_url)


if __name__ == "__main__":
    main()
