"""Host + time rewrite for scheduled APT campaign events.

Takes the ``CampaignPlan`` from ``schedule`` and produces injection-ready
event dicts:

  * time-shift — every event's native timestamp field is set to its
    scheduled ``campaign_ts`` (Sysmon ``UtcTime``; EVTX ``timestamp``;
    Zeek ``ts``), so the event lands at its low-and-slow campaign moment
    rather than its capture moment;
  * host-rewrite — the capture host identity (hostname ``EC2AMAZ-…`` +
    private IP ``10.20.1.210``) is remapped to a target corpus host
    (name / fqdn / ip), in the Sysmon ``Computer`` field, any field that
    embeds the capture hostname, and Zeek address fields.

Determinism: the rewrite is a pure function of the plan + host map; no RNG
of its own (the schedule already consumed the campaign seed).

v1 limit: a single patient-zero target host. Lateral-movement events are
host-rewritten to the SAME target host (source-side capture on one box);
a true second-host destination is a follow-up once multi-host capture
exists. This is recorded in the bundle notes, not silently dropped.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime

from blue_bench_generators.apt_inject.schedule import CampaignPlan, ScheduledEvent

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class HostMap:
    """Capture-host identity → target corpus host identity."""

    capture_name: str  # e.g. "EC2AMAZ-VU9QJAP"
    capture_ip: str  # e.g. "10.20.1.210"
    target_name: str  # e.g. "WS-FIN-014"
    target_fqdn: str  # e.g. "ws-fin-014.corp.example"
    target_ip: str  # e.g. "10.10.4.37"


# Zeek address fields to remap (same set cybercrime_foil rewrites).
_ZEEK_IP_FIELDS = ("id.orig_h", "id.resp_h", "tx_hosts", "rx_hosts")


def _sysmon_utc(ts: datetime) -> str:
    """Sysmon UtcTime format: 'YYYY-MM-DD HH:MM:SS.mmm' (millis)."""
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


def _evtx_ts(ts: datetime) -> str:
    """EVTX/composer 'timestamp' ISO-8601 (matches it_baseline.evtx)."""
    base = ts.strftime("%Y-%m-%dT%H:%M:%S")
    # naive or aware both render without offset here to match the
    # baseline generators' naive convention.
    return base


def _zeek_ts(ts: datetime) -> str:
    """Zeek ts: epoch seconds with microsecond precision."""
    return f"{ts.timestamp():.6f}"


def _rewrite_host_in_str(value: str, hmap: HostMap) -> str:
    """Replace capture hostname/IP occurrences inside a string field."""
    if not value:
        return value
    out = value
    if hmap.capture_name and hmap.capture_name in out:
        out = out.replace(hmap.capture_name, hmap.target_name)
    if hmap.capture_ip and hmap.capture_ip in out:
        out = out.replace(hmap.capture_ip, hmap.target_ip)
    return out


def _rewrite_event(se: ScheduledEvent, hmap: HostMap) -> dict:
    """Return a NEW rewritten event dict (input untouched)."""
    ev = dict(se.event)  # shallow copy; values are scalars
    ts = se.campaign_ts
    stream = ev.get("_stream")

    # --- time-shift: write the canonical timestamp field per stream ---
    if stream == "sysmon":
        ev["UtcTime"] = _sysmon_utc(ts)
    elif stream == "evtx":
        ev["timestamp"] = _evtx_ts(ts)
    elif stream == "zeek":
        if "ts" in ev:
            ev["ts"] = _zeek_ts(ts)

    # --- host-rewrite ---
    if stream in ("sysmon", "evtx"):
        if ev.get("Computer"):
            # Computer was the bare capture hostname; target gets the fqdn.
            ev["Computer"] = hmap.target_fqdn
        # Sweep EVERY string field for embedded capture hostname / IP. A
        # hardcoded field list missed User / ParentUser / SourceUser
        # (Sysmon embeds "HOSTNAME\\user"), leaking the capture identity.
        # The markers (EC2AMAZ-… / 10.20.1.210) are distinctive enough that
        # a blanket replace is safe and leak-proof. Skip our own _-prefixed
        # metadata keys and the already-handled Computer field.
        for f, v in list(ev.items()):
            if f == "Computer" or f.startswith("_"):
                continue
            if isinstance(v, str):
                ev[f] = _rewrite_host_in_str(v, hmap)
    elif stream == "zeek":
        for f in _ZEEK_IP_FIELDS:
            v = ev.get(f)
            if not v or v == "-":
                continue
            ev[f] = re.sub(re.escape(hmap.capture_ip), hmap.target_ip, str(v))

    # carry campaign metadata for the bundle's per-event annotations.
    ev["_stage"] = se.stage
    ev["_technique"] = se.technique
    ev["_campaign_ts"] = ts.isoformat()
    # drop the non-serialisable capture datetime.
    ev.pop("_capture_ts", None)
    return ev


def rewrite_plan(plan: CampaignPlan, hmap: HostMap) -> list[dict]:
    """Rewrite every scheduled event; returns a NEW list in timeline order."""
    out = [_rewrite_event(se, hmap) for se in plan.scheduled]
    log.info(
        "rewrite: %d events, host %s/%s -> %s/%s, window %s..%s",
        len(out), hmap.capture_name, hmap.capture_ip,
        hmap.target_fqdn, hmap.target_ip,
        plan.dwell_start, plan.dwell_end,
    )
    return out
