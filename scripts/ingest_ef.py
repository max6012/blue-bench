"""Ingest an EvidenceForge output directory into Blue-Bench Elasticsearch.

EvidenceForge (EF) is Blue-Bench's adopted benign IT-telemetry generator
(see docs/internal/heavy-telemetry/evidenceforge-migration-plan.md). EF writes
per-host directories under ``<out>/data/<host>/`` plus shared sensor dirs; this
adapter parses every format into one ES index per log-type, mirroring the
existing ``scripts/seed_es.py`` naming (``zeek-conn``, ``logstash-suricata-alerts``,
``wazuh-alerts``) and extending it (``zeek-dns``, ``windows-sysmon``,
``ecar-edr``, ...). ``count_by_field`` reaches any of them via its index
override; ``get_connections`` reads ``zeek-conn`` unchanged.

Two contracts this adapter MUST honour (advisor 2026-06-10):

1. **doc ``_id`` is content-derived, never positional.** ``seed_es.py`` uses
   ``_id=str(i)``; that breaks the injection orchestrator (t-9pwe / EF-P5),
   which must repoint ground-truth ``where`` to ES doc ids computed from the
   event itself. We key ``_id`` on the source's native id (Zeek ``uid``,
   Sysmon ``EventRecordID``, eCAR ``id``) and fall back to
   ``sha256(canonical record)`` for line formats. Deterministic re-seed for
   free.

2. **``@timestamp`` preserves the corpus window.** ``seed_es.py`` compresses
   everything into "the last 45 minutes" so a 60-minute lookback sees it; for a
   real S/M/L corpus that destroys RQ2 (APT dwell is measured in days, C2
   beacons on a fixed interval). We apply a SINGLE global shift to every event
   across every source, preserving all relative inter-event spacing. Default:
   real EF times untouched. ``--anchor-end-to-now`` shifts the whole window so
   the corpus ends ~now (one delta, spacing intact) for demo lookbacks.

Usage::

    .venv/bin/python scripts/ingest_ef.py --ef-dir /tmp/ef-out [--es-url ...]
                                          [--anchor-end-to-now] [--prefix ""]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import httpx

log = logging.getLogger("ingest_ef")

EVTX_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# --- index taxonomy: one index per log-type, existing names mirrored ----------

ZEEK_LOGTYPES = (
    "conn", "dns", "http", "ssl", "files", "x509",
    "dhcp", "ntp", "ocsp", "pe", "weird", "packet_filter", "reporter",
)


def zeek_index(logtype: str) -> str:
    return f"zeek-{logtype}"


WINDOWS_SYSMON_INDEX = "windows-sysmon"
WINDOWS_SECURITY_INDEX = "windows-security"
ECAR_INDEX = "ecar-edr"
SYSLOG_INDEX = "linux-syslog"
SNORT_INDEX = "snort-alerts"
ASA_INDEX = "firewall-asa"
WEB_INDEX = "web-access"
PROXY_INDEX = "proxy-access"

# Merged OT / IT-OT-bridge telemetry (EF-P4 merger output, NDJSON).
OT_HOSTS_INDEX = "ot-hosts"
# Bridge events are written per (source, log); route by source so the IT-side
# of a bridge session lands in the IT index and the OT-side in an OT index.
_BRIDGE_INDEX = {
    "zeek": "zeek-conn",       # IT-side network leg
    "ot": "ot-conn",           # OT-side network leg
    "linux": SYSLOG_INDEX,     # IT/jump-host auth
    "ot_hosts": OT_HOSTS_INDEX,  # OT host auth
}

# ip-typed fields per the seed_es.py zeek-conn mapping; everything else dynamic.
_IP_FIELDS = ("id.orig_h", "id.resp_h")
_KEYWORD_FIELDS = ("id.orig_p", "id.resp_p", "proto", "service", "uid")


def _index_mappings(sample_keys: Iterable[str]) -> dict:
    props: dict[str, dict] = {"@timestamp": {"type": "date"}}
    keys = set(sample_keys)
    for f in _IP_FIELDS:
        if f in keys:
            props[f] = {"type": "ip"}
    for f in _KEYWORD_FIELDS:
        if f in keys:
            props[f] = {"type": "keyword"}
    return {"mappings": {"properties": props}}


# --- per-format parsers: each yields (record, native_ts, native_id|None) ------
#
# native_ts: a tz-aware UTC datetime (the event's real time).
# native_id: stable id string, or None to fall back to sha256(record).


def _sha_id(rec: dict) -> str:
    blob = json.dumps(rec, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def parse_zeek(path: Path) -> Iterable[tuple[dict, datetime, str | None]]:
    """Zeek NDJSON (any log-type). ``ts`` = epoch float, ``uid`` = native id."""
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rec = json.loads(line)
            ts = rec.get("ts")
            when = datetime.fromtimestamp(float(ts), tz=timezone.utc) if ts is not None else None
            # convenience aliases so count_by_field on src/dest works like seed_es
            rec.setdefault("src_ip", rec.get("id.orig_h", ""))
            rec.setdefault("dest_ip", rec.get("id.resp_h", ""))
            rec.setdefault("dest_port", rec.get("id.resp_p", ""))
            rec.setdefault("src_port", rec.get("id.orig_p", ""))
            yield rec, when, rec.get("uid")


def _evtx_records(path: Path) -> Iterable[dict]:
    # Stream with iterparse and clear each <Event> after use — constant memory.
    # ET.fromstring(read_text()) loads the whole tree and OOMs on L-scale logs
    # (18 days x 30 hosts -> hundreds of MB of Windows Security XML).
    ev_tag = f"{EVTX_NS}Event"
    for _evt, elem in ET.iterparse(str(path), events=("end",)):
        if elem.tag != ev_tag:
            continue
        rec: dict[str, Any] = {}
        sysd = elem.find(f"{EVTX_NS}System")
        if sysd is not None:
            for child in sysd:
                tag = child.tag.replace(EVTX_NS, "")
                if tag == "EventID":
                    rec["EventID"] = int(child.text) if child.text else None
                elif tag == "TimeCreated":
                    rec["TimeCreated"] = child.get("SystemTime")
                elif tag == "Provider":
                    rec["Provider"] = child.get("Name")
                elif tag in ("Computer", "Channel", "EventRecordID"):
                    rec[tag] = child.text
                elif tag == "Execution":
                    rec["ProcessID"] = child.get("ProcessID")
                    rec["ThreadID"] = child.get("ThreadID")
        data = elem.find(f"{EVTX_NS}EventData")
        if data is not None:
            for d in data.findall(f"{EVTX_NS}Data"):
                name = d.get("Name")
                if name:
                    rec[name] = d.text
        yield rec
        elem.clear()  # free the processed <Event> to keep memory flat


def parse_evtx(path: Path) -> Iterable[tuple[dict, datetime, str | None]]:
    """Windows Security / Sysmon EventLog XML. TimeCreated ISO, EventRecordID id."""
    for rec in _evtx_records(path):
        tc = rec.get("TimeCreated")
        when = _parse_iso(tc) if tc else None
        yield rec, when, rec.get("EventRecordID")


def parse_ecar(path: Path) -> Iterable[tuple[dict, datetime, str | None]]:
    """eCAR EDR NDJSON. ``timestamp_ms`` epoch-ms, ``id`` native id."""
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            ms = rec.get("timestamp_ms")
            when = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc) if ms else None
            yield rec, when, rec.get("id") or rec.get("objectID")


_SYSLOG_RE = re.compile(r"^<\d+>\d?\s*(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(.*)$")


def parse_syslog(path: Path) -> Iterable[tuple[dict, datetime, str | None]]:
    """RFC5424 syslog lines carry a full ISO timestamp."""
    for raw in path.read_text().splitlines():
        if not raw.strip():
            continue
        m = _SYSLOG_RE.match(raw)
        if m:
            when = _parse_iso(m.group(1))
            rec = {"timestamp": m.group(1), "host": m.group(2), "process": m.group(3),
                   "pid": m.group(4), "message": m.group(5), "raw": raw}
        else:
            when, rec = None, {"raw": raw}
        yield rec, when, None


_WEB_RE = re.compile(r"^(\S+).*\[([^\]]+)\]\s+\"([^\"]*)\"\s+(\d{3})\s+(\S+)\s+\"([^\"]*)\"\s+\"([^\"]*)\"")


def parse_web(path: Path) -> Iterable[tuple[dict, datetime, str | None]]:
    """Apache combined log: [14/May/2024:12:01:55 +0000]."""
    for raw in path.read_text().splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        m = _WEB_RE.match(raw)
        if m:
            when = _parse_apache(m.group(2))
            rec = {"client_ip": m.group(1), "time": m.group(2), "request": m.group(3),
                   "status": int(m.group(4)), "bytes": m.group(5), "referrer": m.group(6),
                   "user_agent": m.group(7), "raw": raw}
        else:
            when, rec = None, {"raw": raw}
        yield rec, when, None


def parse_lines_passthrough(path: Path) -> Iterable[tuple[dict, datetime | None, str | None]]:
    """ASA / snort / proxy: keep the raw line; timestamp parsed best-effort."""
    for raw in path.read_text().splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        yield {"raw": raw}, _line_time_best_effort(raw), None


def parse_ot_ndjson(path: Path) -> Iterable[tuple[dict, datetime | None, str | None]]:
    """Merged OT / bridge NDJSON. ``ts`` (epoch) or ``timestamp`` (ISO); ``uid``
    is the native id. Conn-like records get src/dest aliases like Zeek."""
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            ts = rec.get("ts")
            if ts not in (None, ""):
                when = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            elif rec.get("timestamp"):
                when = _parse_iso(str(rec["timestamp"]))
            elif rec.get("UtcTime"):
                # Sysmon-shaped events (e.g. injected adversary) carry UtcTime
                # ("2026-03-02 10:24:01.141"), space-separated and tz-naive=UTC.
                when = _parse_iso(str(rec["UtcTime"]).replace(" ", "T"))
            else:
                when = None
            if "id.orig_h" in rec:
                rec.setdefault("src_ip", rec.get("id.orig_h", ""))
                rec.setdefault("dest_ip", rec.get("id.resp_h", ""))
                rec.setdefault("dest_port", rec.get("id.resp_p", ""))
            yield rec, when, rec.get("uid")


# --- timestamp helpers --------------------------------------------------------

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_iso(s: str) -> datetime | None:
    try:
        s = s.replace("Z", "+00:00")
        # python fromisoformat handles 6-digit fractions; trim 7-digit (EVTX)
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_apache(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None


_SNORT_RE = re.compile(r"^(\d{2})/(\d{2})-(\d{2}):(\d{2}):(\d{2}\.\d+)")
_ASA_RE = re.compile(r"^<\d+>([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")

# Year is absent from snort/ASA lines; inferred from the corpus once it's known.
_CORPUS_YEAR = {"y": None}


def _line_time_best_effort(raw: str) -> datetime | None:
    y = _CORPUS_YEAR["y"]
    if y is None:
        return None
    m = _SNORT_RE.match(raw)
    if m:
        mo, da, hh, mm, ss = m.groups()
        sec = float(ss)
        return datetime(y, int(mo), int(da), int(hh), int(mm), int(sec),
                        int((sec % 1) * 1e6), tzinfo=timezone.utc)
    m = _ASA_RE.match(raw)
    if m:
        mon, da, hh, mm, ss = m.groups()
        return datetime(y, _MONTHS[mon], int(da), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    return None


# --- source routing -----------------------------------------------------------

ParserFn = Callable[[Path], Iterable[tuple[dict, datetime | None, str | None]]]


def route(relpath: str) -> tuple[str, ParserFn] | None:
    """Map a corpus-relative path to (index, parser). None = skip.

    EF telemetry lives under ``data/`` (routed by filename); the EF-P4 merger
    writes OT/bridge NDJSON under ``ot/`` / ``ot_hosts/`` / ``bridge/``.
    """
    rel = relpath.replace("\\", "/")
    parts = rel.split("/")
    top = parts[0].lower()
    name = parts[-1].lower()

    # --- merged OT / bridge NDJSON (EF-P4) ---
    if top == "ot" and name.endswith(".ndjson"):
        return f"ot-{name[:-7]}", parse_ot_ndjson            # ot/modbus.ndjson -> ot-modbus
    if top == "ot_hosts" and name.endswith(".ndjson"):
        return OT_HOSTS_INDEX, parse_ot_ndjson
    if top == "bridge" and name.endswith(".ndjson"):
        source = name.split(".", 1)[0]                       # "<source>.<log>.ndjson"
        return _BRIDGE_INDEX.get(source, f"bridge-{source}"), parse_ot_ndjson

    # --- injected adversary NDJSON (EF-P5): "<incident>.<stream>.<log>.ndjson" ---
    # Host-remapped adversary events, routed into the SAME index as the matching
    # benign telemetry so the signal is a needle in the real haystack. Split by
    # log so Zeek http (which shares its conn's uid) lands in zeek-http, not
    # colliding under the uid-keyed zeek-conn.
    if top == "injected" and name.endswith(".ndjson"):
        tokens = name[:-7].split(".")                        # incident.stream.log
        stream, log = (tokens[-2], tokens[-1]) if len(tokens) >= 2 else ("", "")
        if stream == "sysmon":
            return WINDOWS_SYSMON_INDEX, parse_ot_ndjson
        if stream == "zeek":
            return zeek_index(log), parse_ot_ndjson          # zeek-conn / zeek-http / ...
        return None

    # --- EF telemetry under data/ (routed by filename) ---
    if name.endswith(".json") and name[:-5] in ZEEK_LOGTYPES:
        return zeek_index(name[:-5]), parse_zeek
    if name == "windows_event_sysmon.xml":
        return WINDOWS_SYSMON_INDEX, parse_evtx
    if name == "windows_event_security.xml":
        return WINDOWS_SECURITY_INDEX, parse_evtx
    if name == "ecar.json":
        return ECAR_INDEX, parse_ecar
    if name == "syslog.log":
        return SYSLOG_INDEX, parse_syslog
    if name == "web_access.log":
        return WEB_INDEX, parse_web
    if name == "snort_alert.log":
        return SNORT_INDEX, parse_lines_passthrough
    if name == "cisco_asa.log":
        return ASA_INDEX, parse_lines_passthrough
    if name == "proxy_access.log":
        return PROXY_INDEX, parse_lines_passthrough
    return None  # bash_history + anything else: not an ES stream


# --- ES plumbing --------------------------------------------------------------


def _wait_for_es(url: str, retries: int = 30) -> None:
    for i in range(retries):
        try:
            if httpx.get(f"{url}/_cluster/health", timeout=3).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        log.info("waiting for ES (%d/%d)...", i + 1, retries)
        import time
        time.sleep(2)
    log.error("ES at %s never became ready", url)
    sys.exit(1)


def _recreate_index(url: str, index: str, mappings: dict) -> None:
    httpx.delete(f"{url}/{index}", timeout=10)
    r = httpx.put(f"{url}/{index}", json=mappings, timeout=15)
    if r.status_code not in (200, 201):
        log.error("create %s failed: %s", index, r.text)
        sys.exit(1)


def _bulk(url: str, index: str, docs: list[tuple[str, dict]], *, batch: int = 2000) -> int:
    """Bulk-index in batches with 429 backoff.

    One request per index overruns ES's write queue on real S/M/L corpora
    (a 165 MB tier indexes fine in ~2k-doc batches but 429s as a single body).
    Each batch retries on 429 with exponential backoff so a transient queue-full
    doesn't drop documents.
    """
    import time
    ok = 0
    for start in range(0, len(docs), batch):
        chunk = docs[start:start + batch]
        lines: list[str] = []
        for _id, doc in chunk:
            lines.append(json.dumps({"index": {"_index": index, "_id": _id}}))
            lines.append(json.dumps(doc, default=str))
        body = "\n".join(lines) + "\n"
        for attempt in range(6):
            r = httpx.post(f"{url}/_bulk", content=body,
                           headers={"Content-Type": "application/x-ndjson"}, timeout=120)
            if r.status_code == 429:
                time.sleep(min(2 ** attempt, 16))
                continue
            r.raise_for_status()
            errs = [it for it in r.json().get("items", []) if "error" in it.get("index", {})]
            if errs:
                log.warning("%d index errors in %s; first: %s", len(errs), index, errs[0])
            ok += len(chunk) - len(errs)
            break
        else:
            log.error("bulk into %s still 429 after retries; %d docs dropped", index, len(chunk))
    return ok


# --- main ingest --------------------------------------------------------------


def _corpus_window(ef_dir: Path) -> tuple[datetime | None, datetime | None]:
    """The corpus collection window (UTC), read from GROUND_TRUTH.json (EF) or
    the merge manifest — NOT by scanning events. Used to anchor timestamps and
    infer the year for line-format logs without holding the corpus in memory."""
    def _p(s):
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    gt = ef_dir / "GROUND_TRUTH.json"
    if gt.is_file():
        cw = json.loads(gt.read_text()).get("collection_window", {})
        return _p(cw.get("start")), _p(cw.get("end"))
    man = ef_dir / "corpus-manifest.yaml"
    if man.is_file():
        import yaml
        w = (yaml.safe_load(man.read_text()) or {}).get("window", {})
        return _p(w.get("start")), _p(w.get("end"))
    return None, None


def ingest(ef_dir: Path, es_url: str, *, anchor_end_to_now: bool, batch: int = 2000) -> dict[str, int]:
    """Stream the corpus into ES with constant memory.

    The parsers are per-file generators; we flush each index's docs to ES in
    batches as they're produced rather than accumulating the whole corpus in a
    dict first (which OOMs on an L-scale ~17 GB-of-OT corpus). The time anchor
    + year are derived from the corpus WINDOW (GROUND_TRUTH / manifest), not by
    scanning every event, so a single streaming pass suffices.
    """
    walk_root = ef_dir
    win_start, win_end = _corpus_window(ef_dir)
    if win_end is not None:
        _CORPUS_YEAR["y"] = win_end.year  # for snort/ASA line-format year inference
    # Shift the whole window so it ends ~now (relative spacing preserved). Anchor
    # on the declared window end rather than the max event — same semantics,
    # no full-corpus scan.
    delta = (datetime.now(timezone.utc) - win_end) if (anchor_end_to_now and win_end) else None

    from collections import defaultdict
    counts: dict[str, int] = defaultdict(int)
    buffers: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    created: set[str] = set()

    def _flush(index: str) -> None:
        docs = buffers[index]
        if not docs:
            return
        if index not in created:
            _recreate_index(es_url, index, _index_mappings(docs[0][1].keys()))
            created.add(index)
        counts[index] += _bulk(es_url, index, docs)
        buffers[index] = []

    for path in sorted(walk_root.rglob("*")):
        if not path.is_file():
            continue
        routed = route(str(path.relative_to(walk_root)))
        if routed is None:
            continue
        index, parser = routed
        for rec, when, native_id in parser(path):
            doc = dict(rec)
            eff = (when + delta) if (delta and when) else when
            if eff is not None:
                doc["@timestamp"] = eff.isoformat()
            buffers[index].append((native_id or _sha_id(rec), doc))
            if len(buffers[index]) >= batch:
                _flush(index)
    for index in list(buffers):
        _flush(index)
    for index in created:
        httpx.post(f"{es_url}/{index}/_refresh", timeout=30)
        log.info("ingested %d -> %s", counts[index], index)
    if win_start and win_end:
        log.info("corpus window: %s .. %s (shift=%s)", win_start.isoformat(), win_end.isoformat(),
                 "end->now" if delta else "none")
    return dict(counts)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Ingest an EvidenceForge output dir into Blue-Bench ES")
    p.add_argument("--ef-dir", required=True, type=Path, help="EF output dir (containing data/)")
    p.add_argument("--es-url", default="http://localhost:9200")
    p.add_argument("--anchor-end-to-now", action="store_true",
                   help="shift the whole corpus window so it ends ~now (spacing preserved)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    _wait_for_es(args.es_url)
    counts = ingest(args.ef_dir, args.es_url, anchor_end_to_now=args.anchor_end_to_now)
    total = sum(counts.values())
    print(f"ingested {total} docs across {len(counts)} indices:")
    for idx, n in sorted(counts.items()):
        print(f"  {idx:24s} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
