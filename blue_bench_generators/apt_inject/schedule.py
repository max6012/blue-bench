"""Signal selection + low-and-slow campaign scheduling.

Two jobs, both deterministic:

1. SELECT the attack-attributable events from each ~8-10k-event stage
   capture. A kill-chain capture is mostly ambient Windows OS baseline
   (boot-time process churn, benign svchost LSASS reads, periodic DNS);
   only a thin slice is the atomic's signal. Injecting everything would
   mislabel benign noise as APT and flood the corpus (the corpus already
   HAS baseline). We anchor on the atomic's distinctive command line, then
   follow the Sysmon process-GUID subtree — every event whose acting
   process is in that subtree is attributable; everything else is dropped.

2. SCHEDULE the selected per-stage signal into one campaign timeline with
   realistic dwell: initial-access early, lateral spread across days, C2
   as sparse beacons throughout, exfil near the end. Each stage's internal
   relative timing is preserved around its scheduled anchor.

The corpus baseline supplies the haystack; this module produces the
needle, sized and paced so hunting is required.
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


# --- per-stage signal signatures --------------------------------------
#
# anchor_cmdline: regex matched (case-insensitive) against Sysmon EID1
#   CommandLine to find the atomic's launching process(es). The process
#   GUID subtree rooted at those anchors defines the attributable host
#   events.
# extra_eids: Sysmon EIDs to include for an anchor-subtree process even
#   when the event itself isn't a process-create (10 ProcessAccess, 11
#   FileCreate, 13 RegistryValueSet, 22 DNSQuery, 3 NetworkConnect).
# zeek: include the atomic's network egress from these Zeek logs
#   (the SSH control channel is filtered out separately).

@dataclass(frozen=True)
class TechniqueSignature:
    technique: str
    anchor_cmdline: str
    zeek_logs: tuple[str, ...] = ()
    c2_spread: bool = False  # spread this technique's events as sparse beacons


# Signatures keyed by ATT&CK TECHNIQUE, not by stage. The build reads the
# technique for each captured stage from the kill-chain manifest, so a foil
# with different techniques per stage (and >1 technique in a stage, e.g. a
# stealer doing both T1555 and T1003.001 under credential-access) selects and
# labels each correctly. The APT techniques keep their original anchors, so the
# APT bundle builds byte-identically.
TECHNIQUE_SIGNATURES: dict[str, TechniqueSignature] = {
    "T1566.001": TechniqueSignature(
        "T1566.001", r"invoke-webrequest|\.doc|\.docm|attachment|Outlook",
        zeek_logs=("http", "files", "conn")),
    "T1059.001": TechniqueSignature(
        "T1059.001", r"powershell.*(-enc|-e |downloadstring|iex|invoke-expression|frombase64)"),
    "T1547.001": TechniqueSignature(
        "T1547.001", r"reg(\.exe)?\s+add.*\\run|new-itemproperty.*\\run|set-itemproperty.*\\run"),
    "T1218.005": TechniqueSignature("T1218.005", r"mshta(\.exe)?"),
    "T1003.001": TechniqueSignature(
        "T1003.001", r"comsvcs\.dll.*minidump|procdump.*lsass|mimikatz|sekurlsa|nanodump"),
    "T1057": TechniqueSignature(
        "T1057", r"tasklist|get-process|wmic\s+process|get-wmiobject.*process"),
    "T1021.002": TechniqueSignature(
        "T1021.002", r"net(\.exe)?\s+use.*\\\\|new-smbmapping|admin\$|psexec",
        zeek_logs=("conn",)),
    "T1560.001": TechniqueSignature(
        "T1560.001", r"makecab|rar(\.exe)?\s+a|7z(\.exe)?\s+a|compress-archive"),
    "T1071.001": TechniqueSignature(
        "T1071.001", r"invoke-webrequest|useragent|httpbrowser|wget/|opera/",
        zeek_logs=("http", "ssl", "conn", "dns"), c2_spread=True),
    "T1041": TechniqueSignature(
        "T1041", r"invoke-webrequest|uploadstring|uploadfile|exfil|nslookup",
        zeek_logs=("http", "dns", "conn")),
    # --- commodity-foil techniques (best-effort anchors) ---
    "T1555": TechniqueSignature(
        "T1555", r"vaultcmd|cmdkey|sekurlsa|webbrowserpassview|lazagne|"
                 r"(chrome|edge|firefox).*(login data|passwords)|get-clipboardcontents"),
    "T1082": TechniqueSignature(
        "T1082", r"systeminfo|get-computerinfo|wmic\s+(os|computersystem)|"
                 r"get-wmiobject.*win32_operatingsystem|fsutil\s+fsinfo"),
    "T1005": TechniqueSignature(
        "T1005", r"findstr\s+/s|get-childitem.*-recurse|robocopy|"
                 r"copy.*\\.(docx|xlsx|pdf|txt)|stealfiles"),
}


# Canonical APT stage -> technique (the original 1:1 kill chain). Used only to
# keep the legacy ``schedule_campaign({stage: events})`` call shape working;
# the manifest-driven path passes the technique explicitly.
_APT_STAGE_TECHNIQUE: dict[str, str] = {
    "initial-access": "T1566.001",
    "execution": "T1059.001",
    "persistence": "T1547.001",
    "defense-evasion": "T1218.005",
    "credential-access": "T1003.001",
    "discovery": "T1057",
    "lateral-movement": "T1021.002",
    "collection": "T1560.001",
    "command-and-control": "T1071.001",
    "exfiltration": "T1041",
}


def _technique_for_stage(stage: str) -> str:
    return _APT_STAGE_TECHNIQUE.get(stage, "T0000")


# Sysmon fields naming the acting process GUID, by event id. An event is
# attributable if its acting-process GUID is in the atomic subtree.
_PROC_GUID_FIELD: dict[int, str] = {
    1: "ProcessGuid",
    3: "ProcessGuid",
    5: "ProcessGuid",
    7: "ProcessGuid",
    8: "SourceProcessGuid",
    10: "SourceProcessGUID",  # note casing differs in Sysmon schema
    11: "ProcessGuid",
    12: "ProcessGuid",
    13: "ProcessGuid",
    22: "ProcessGuid",
    23: "ProcessGuid",
    25: "ProcessGuid",
}


def _acting_guid(ev: dict) -> str | None:
    eid = ev.get("event_id")
    fld = _PROC_GUID_FIELD.get(eid)
    if not fld:
        return None
    # Sysmon EID10 uses SourceProcessGUID; tolerate the alt casing.
    return ev.get(fld) or ev.get("SourceProcessGuid") or None


def _is_ssh_control(ev: dict, control_port: str = "22") -> bool:
    """True for the harness's own SSH control channel (not the atomic)."""
    if ev.get("_stream") != "zeek":
        return False
    return ev.get("id.resp_p") == control_port or ev.get("id.orig_p") == control_port


def select_signal(events: list[dict], technique: str) -> list[dict]:
    """Return the attack-attributable subset of one stage's capture.

    Host signal: the Sysmon process-GUID subtree rooted at the atomic's
    anchor process(es). Network signal: the technique's Zeek egress logs,
    excluding the SSH control channel. Keyed by ATT&CK technique so the same
    selector serves the APT and any foil manifest.
    """
    sig = TECHNIQUE_SIGNATURES.get(technique)
    if sig is None:
        raise ValueError(f"no signature for technique {technique!r}")
    anchor_re = re.compile(sig.anchor_cmdline, re.I)

    sysmon = [e for e in events if e.get("_stream") == "sysmon"]

    # 1. anchor process-creates (EID1) whose CommandLine matches.
    anchor_guids: set[str] = set()
    for e in sysmon:
        if e.get("event_id") == 1 and anchor_re.search(str(e.get("CommandLine", ""))):
            g = e.get("ProcessGuid")
            if g:
                anchor_guids.add(g)

    # 2. grow the subtree: add EID1 children whose ParentProcessGuid is in
    #    the set, until it stops growing (bounded by a hard cap).
    guids = set(anchor_guids)
    for _ in range(20):
        added = False
        for e in sysmon:
            if e.get("event_id") == 1:
                g = e.get("ProcessGuid")
                p = e.get("ParentProcessGuid")
                if g and g not in guids and p in guids:
                    guids.add(g)
                    added = True
        if not added:
            break

    # 3. select every Sysmon event whose acting process is in the subtree.
    selected: list[dict] = []
    for e in sysmon:
        g = _acting_guid(e)
        if g and g in guids:
            selected.append(e)

    # 4. network egress for this stage (exclude SSH control channel).
    if sig.zeek_logs:
        wanted = set(sig.zeek_logs)
        for e in events:
            if e.get("_stream") == "zeek" and e.get("_log") in wanted and not _is_ssh_control(e):
                # drop pure-loopback / control noise; keep real egress
                selected.append(e)

    return selected


# --- LotL campaign scheduling -----------------------------------------
#
# Each stage gets an anchor offset within the dwell window. Offsets follow
# kill-chain order with realistic gaps; the campaign seed jitters them so
# the timeline isn't mechanically regular. Stage-internal relative timing
# is preserved: an event captured ``dt`` after its stage's earliest event
# lands at ``anchor + dt`` (optionally compressed).

# Fractional placement of each stage's ANCHOR within the dwell window
# [0.0, 1.0]. Hand-tuned for a plausible intrusion: recon/access early,
# lateral mid, collection/exfil late. C2 is special (spread, see below).
_STAGE_ANCHOR_FRAC: dict[str, float] = {
    "initial-access": 0.00,
    "execution": 0.02,
    "discovery": 0.06,
    "defense-evasion": 0.10,
    "persistence": 0.14,
    "credential-access": 0.25,
    "lateral-movement": 0.45,
    "collection": 0.80,
    "command-and-control": 0.50,  # anchor; events get spread (c2_spread)
    "exfiltration": 0.95,
}


@dataclass
class ScheduledEvent:
    event: dict
    campaign_ts: datetime
    stage: str
    technique: str


@dataclass
class CampaignPlan:
    dwell_start: datetime
    dwell_end: datetime
    seed: int
    scheduled: list[ScheduledEvent] = field(default_factory=list)


def _seed_int(campaign_id: str, seed: int) -> int:
    h = hashlib.sha256(f"{campaign_id}:{seed}".encode()).digest()
    return int.from_bytes(h[:8], "big")


def _stage_relative(events: list[dict]) -> list[tuple[float, dict]]:
    """(seconds-after-stage-earliest, event) for events with a capture ts."""
    ts = [(e["_capture_ts"], e) for e in events if e.get("_capture_ts") is not None]
    if not ts:
        return []
    earliest = min(t for t, _ in ts)
    return [((t - earliest).total_seconds(), e) for t, e in ts]


def schedule_campaign(
    stage_signal,
    *,
    dwell_start: datetime,
    dwell_days: float,
    campaign_id: str,
    seed: int = 0,
    stage_compression: float = 1.0,
) -> CampaignPlan:
    """Place each stage's selected signal onto a dwell-window timeline.

    Args:
        stage_signal: stage -> selected events (from ``select_signal``).
        dwell_start: campaign start within the corpus window (UTC-naive to
            match the baseline generators, or tz-aware; used consistently).
        dwell_days: length of the dwell window in days. Must fit inside the
            corpus time window (S=1, M=7, L=14 days).
        campaign_id: identity for deterministic jitter.
        seed: campaign seed.
        stage_compression: multiply each stage's internal relative offsets
            (1.0 = preserve capture timing; <1 = tighten a stage's burst).

    Returns:
        CampaignPlan with one ScheduledEvent per selected event, sorted by
        campaign_ts.
    """
    rng = random.Random(_seed_int(campaign_id, seed))
    dwell_seconds = dwell_days * 86400.0
    dwell_end = dwell_start + timedelta(days=dwell_days)
    scheduled: list[ScheduledEvent] = []

    # Accept either the legacy ``{stage: events}`` mapping (technique inferred
    # from the technique whose signature the stage's events matched) or the
    # manifest-driven ``[(stage, technique, events), ...]`` rows.
    if isinstance(stage_signal, dict):
        rows = [(stage, _technique_for_stage(stage), events)
                for stage, events in stage_signal.items()]
    else:
        rows = list(stage_signal)

    for stage, technique, events in rows:
        sig = TECHNIQUE_SIGNATURES.get(technique)
        rel = _stage_relative(events)
        if not rel:
            continue
        frac = _STAGE_ANCHOR_FRAC.get(stage, 0.5)
        # jitter the anchor by +/- 3% of the dwell so stages aren't on a
        # mechanically fixed grid.
        jitter = (rng.random() - 0.5) * 0.06
        anchor_off = max(0.0, min(1.0, frac + jitter)) * dwell_seconds
        anchor_ts = dwell_start + timedelta(seconds=anchor_off)

        if sig and sig.c2_spread:
            # C2: spread this stage's events as sparse beacons across the
            # WHOLE dwell instead of clustering at the anchor. Each event
            # is placed at a random point in [0.2, 0.95] of the dwell (the
            # active-intrusion span), with the set sorted so beacon order
            # is preserved.
            n = len(rel)
            points = sorted(0.20 + rng.random() * 0.75 for _ in range(n))
            for (_, ev), p in zip(sorted(rel, key=lambda x: x[0]), points):
                ts = dwell_start + timedelta(seconds=p * dwell_seconds)
                scheduled.append(ScheduledEvent(ev, ts, stage, technique))
        else:
            for rel_s, ev in rel:
                ts = anchor_ts + timedelta(seconds=rel_s * stage_compression)
                # clamp inside the dwell window
                if ts > dwell_end:
                    ts = dwell_end
                scheduled.append(ScheduledEvent(ev, ts, stage, technique))

    scheduled.sort(key=lambda se: se.campaign_ts)
    return CampaignPlan(dwell_start, dwell_end, seed, scheduled)
