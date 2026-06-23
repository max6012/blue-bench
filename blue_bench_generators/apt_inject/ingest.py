"""Ingest sandbox kill-chain captures (EVTX + Zeek) into event dicts.

A capture directory (``data/raw/sandbox/<run>/``) holds::

    windows/Sysmon.evtx     Microsoft-Windows-Sysmon/Operational
    windows/Security.evtx   Security channel
    windows/System.evtx     System channel
    windows/PowerShell.evtx Windows PowerShell channel
    zeek/conn.log           Zeek TSV (one file per log)
    zeek/http.log  ...

``parse_capture_dir`` returns a flat list of event dicts. Each dict
carries routing metadata the orchestrator (``t-9pwe``) uses to place the
event into the corpus, plus a parsed ``_capture_ts`` for the scheduler:

    _stream      "sysmon" | "evtx" | "zeek"      (corpus source subdir)
    _log         "sysmon" | "winevtx" | "conn"|"dns"|"http"|...
    _capture_ts  datetime (UTC, tz-aware) — original capture time
    event_id     int (Windows only)
    channel      str (evtx stream only: "Security"|"System"|...)
    Computer     str (Windows hostname)
    ... native EventData / Zeek fields ...

The native field names are PRESERVED verbatim (Sysmon ``UtcTime``,
``Image``, ``CommandLine``; Zeek ``ts``, ``uid``, ``id.orig_h``) so the
rewrite step can target them by the same names ``cybercrime_foil`` uses.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

log = logging.getLogger(__name__)

# EVTX channel → corpus routing. Sysmon gets its own corpus stream
# ("sysmon"); the other Windows channels share the "evtx" stream and are
# split by their ``channel`` field (matching the composer's
# jsonl_by_channel writer).
_EVTX_FILES: dict[str, tuple[str, str]] = {
    # filename stem        (_stream, channel-label)
    "Sysmon": ("sysmon", "Microsoft-Windows-Sysmon/Operational"),
    "Security": ("evtx", "Security"),
    "System": ("evtx", "System"),
    "PowerShell": ("evtx", "Windows PowerShell"),
}

_WIN_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_evtx_ts(system: dict, eventdata: dict) -> datetime | None:
    """Best-effort UTC timestamp from Sysmon UtcTime or System TimeCreated."""
    # Sysmon EventData carries a precise UtcTime ("2026-06-09 22:23:45.894").
    raw = eventdata.get("UtcTime")
    if raw:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    # System/Security/PowerShell: TimeCreated SystemTime attribute.
    raw = system.get("TimeCreated")
    if raw:
        # python-evtx renders "2026-06-09 22:23:45.899967+00:00".
        s = raw.replace(" ", "T", 1)
        try:
            return datetime.fromisoformat(s).astimezone(timezone.utc)
        except ValueError:
            pass
    return None


def parse_evtx_record_xml(xml: str) -> tuple[dict, dict]:
    """Parse one EVTX record XML into (system_fields, eventdata_fields).

    Public so callers/tests can exercise the XML→dict mapping without a
    binary ``.evtx`` file (the captures themselves are gitignored).
    """
    return _parse_evtx_record_xml(xml)


def _parse_evtx_record_xml(xml: str) -> tuple[dict, dict]:
    """Parse one EVTX record XML into (system_fields, eventdata_fields)."""
    root = ET.fromstring(xml)
    system: dict = {}
    eventdata: dict = {}
    for child in root:
        tag = _strip_ns(child.tag)
        if tag == "System":
            for sc in child:
                stag = _strip_ns(sc.tag)
                if stag == "TimeCreated":
                    system["TimeCreated"] = sc.get("SystemTime", "")
                elif stag == "EventID":
                    system["EventID"] = (sc.text or "").strip()
                elif stag == "Channel":
                    system["Channel"] = (sc.text or "").strip()
                elif stag == "Computer":
                    system["Computer"] = (sc.text or "").strip()
                elif stag == "Provider":
                    system["Provider"] = sc.get("Name", "")
        elif tag == "EventData":
            for dc in child:
                name = dc.get("Name")
                if name:
                    eventdata[name] = (dc.text or "").strip() if dc.text else ""
    return system, eventdata


def parse_evtx(path: Path, stream: str, default_channel: str) -> list[dict]:
    """Parse one EVTX file into event dicts (native fields preserved)."""
    events: list[dict] = []
    with Evtx(str(path)) as evtx:
        for rec in evtx.records():
            try:
                system, eventdata = _parse_evtx_record_xml(rec.xml())
            except ET.ParseError as exc:
                log.warning("evtx parse error in %s: %s", path.name, exc)
                continue
            try:
                event_id = int(system.get("EventID", "0") or "0")
            except ValueError:
                event_id = 0
            ts = _parse_evtx_ts(system, eventdata)
            ev: dict = {
                "_stream": stream,
                "_log": "sysmon" if stream == "sysmon" else "winevtx",
                "_capture_ts": ts,
                "event_id": event_id,
                "channel": system.get("Channel", default_channel),
                "Computer": system.get("Computer", ""),
            }
            ev.update(eventdata)
            events.append(ev)
    return events


# --- Zeek TSV ---------------------------------------------------------

def _zeek_unescape(v: str) -> str:
    # Zeek TSV escapes tab/newline/backslash; we only need to undo the
    # common ones for faithful round-trip. "-" stays "-" (unset).
    return v.replace("\\x09", "\t").replace("\\x0a", "\n")


def parse_zeek_log(path: Path) -> list[dict]:
    """Parse one Zeek TSV (.log) file into event dicts."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return parse_zeek_log_text(fh.read(), default_log=path.stem)


def parse_zeek_log_text(text: str, *, default_log: str = "conn") -> list[dict]:
    """Parse Zeek TSV text into event dicts keyed by the #fields header.

    Text-based twin of ``parse_zeek_log`` so callers (and tests) can parse
    without a file on disk — mirrors ``cybercrime_foil.zeek_replay``.
    """
    fields: list[str] = []
    log_name = default_log
    events: list[dict] = []
    sep = "\t"
    for line in text.splitlines():
        if True:
            line = line.rstrip("\n")
            if line.startswith("#"):
                if line.startswith("#separator"):
                    # e.g. "#separator \x09"
                    tok = line.split(" ", 1)[1].strip()
                    sep = tok.replace("\\x09", "\t")
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                elif line.startswith("#path"):
                    log_name = line.split(sep, 1)[1].strip()
                continue
            if not fields or not line:
                continue
            vals = line.split(sep)
            ev: dict = {"_stream": "zeek", "_log": log_name}
            for k, v in zip(fields, vals):
                ev[k] = _zeek_unescape(v)
            ts = ev.get("ts")
            if ts and ts != "-":
                try:
                    ev["_capture_ts"] = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                except (TypeError, ValueError):
                    ev["_capture_ts"] = None
            else:
                ev["_capture_ts"] = None
            events.append(ev)
    return events


# --- capture dir ------------------------------------------------------

def parse_capture_dir(run_dir: Path) -> list[dict]:
    """Parse all EVTX + Zeek under one capture dir into a flat event list."""
    run_dir = Path(run_dir)
    out: list[dict] = []

    win = run_dir / "windows"
    if win.is_dir():
        for stem, (stream, channel) in _EVTX_FILES.items():
            p = win / f"{stem}.evtx"
            if p.is_file():
                out.extend(parse_evtx(p, stream, channel))

    zeek = run_dir / "zeek"
    if zeek.is_dir():
        for p in sorted(zeek.glob("*.log")):
            out.extend(parse_zeek_log(p))

    return out


def summarize(events: list[dict]) -> dict:
    """Count events by (_stream, _log/event_id) for quick verification."""
    by_stream: dict[str, int] = {}
    sysmon_eids: dict[int, int] = {}
    zeek_logs: dict[str, int] = {}
    n_ts = 0
    for ev in events:
        by_stream[ev["_stream"]] = by_stream.get(ev["_stream"], 0) + 1
        if ev.get("_capture_ts") is not None:
            n_ts += 1
        if ev["_stream"] == "sysmon":
            eid = ev.get("event_id", 0)
            sysmon_eids[eid] = sysmon_eids.get(eid, 0) + 1
        elif ev["_stream"] == "zeek":
            zeek_logs[ev["_log"]] = zeek_logs.get(ev["_log"], 0) + 1
    return {
        "total": len(events),
        "with_ts": n_ts,
        "by_stream": by_stream,
        "sysmon_event_ids": dict(sorted(sysmon_eids.items())),
        "zeek_logs": dict(sorted(zeek_logs.items())),
    }
