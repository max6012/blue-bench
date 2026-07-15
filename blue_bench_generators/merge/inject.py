"""Inject an adversary bundle into a merged EvidenceForge corpus (EF-P5).

An adversary bundle (the APT sandbox capture, or a cybercrime foil) pairs
host-remapped attack telemetry (``<id>.events.ndjson``) with a Blue-Bench
ground-truth annotation (``<id>.ground-truth.yaml``). The bundle was captured on
a sandbox host and previously remapped onto a placeholder identity; this
injector re-remaps it onto a *real* host of the target EF corpus and writes the
events into the corpus tree so the normal ingest path carries them into ES.

Two invariants:

- **No capture-identity leak.** Every reference to the bundle's source host
  (name / NETBIOS / FQDN / internal IP) is rewritten to the target EF host
  across *all* string fields. External C2 / exfil addresses are adversary
  infrastructure and are preserved — they are part of the signal.
- **Ground truth repoints to the injected events.** Each ``events[].where``
  is rewritten to the injected corpus file + a content-derived id (the same id
  the ingest adapter assigns), so the judge can address the exact ES document.

The injected events are written as NDJSON under ``<corpus>/injected/`` and the
repointed ground truth under ``<corpus>/ground-truth/``; both are picked up by
``scripts/ingest_ef.py`` and the build manifest.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

_UTCTIME_FMT = "%Y-%m-%d %H:%M:%S.%f"

# base62 alphabet for Zeek-style uids on synthesized beacon events.
_UID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _event_time(ev: dict) -> datetime | None:
    """Best-effort UTC time for a bundle event (Sysmon UtcTime or Zeek ts)."""
    if ev.get("UtcTime"):
        try:
            return datetime.strptime(str(ev["UtcTime"]), _UTCTIME_FMT).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    ts = ev.get("ts")
    if ts not in (None, ""):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (TypeError, ValueError):
            return None
    return None


def _shift_event_time(ev: dict, delta: timedelta) -> dict:
    """Shift an event's wall-clock time field(s) by ``delta`` (in place-ish)."""
    out = dict(ev)
    if out.get("UtcTime"):
        t = _event_time(ev)
        if t is not None:
            out["UtcTime"] = (t + delta).strftime(_UTCTIME_FMT)[:-3]  # ms precision
    if out.get("ts") not in (None, ""):
        try:
            out["ts"] = f"{float(ev['ts']) + delta.total_seconds():.6f}"
        except (TypeError, ValueError):
            pass
    return out


@dataclass(frozen=True)
class BeaconSpec:
    """A low-and-slow C2 beacon to synthesize into an APT bundle.

    The beacon is the *behavioral* signal (gate 2): regular callbacks across the
    whole campaign window, so ``gap_log`` (inter-event cadence) and ``dwell_frac``
    (window position) separate it from the cybercrime foil's smash-and-grab burst.
    Its *surface* is matched to the foil (same port/proto/service and a byte
    envelope that overlaps benign traffic to the same shared-CDN destination), so
    it stays non-separable on gate 1: only the cadence gives it away, found by
    per-(host->dest) inter-arrival analysis, not by destination reputation.

    ``dest_ips`` (a rotation set) round-robins callbacks across several IPs in a
    single /24 — realistic targeted-actor infra rotation that evades per-IP
    beacon detection (each IP stays under the connection threshold) but is caught
    by /24 aggregation. Leave it empty and set ``dest_ip`` for a single-IP beacon.
    """
    dest_ip: str = ""                         # single dedicated C2 IP
    dest_ips: tuple[str, ...] = ()            # rotation set (round-robin); overrides dest_ip
    dest_port: str = "443"
    proto: str = "tcp"
    service: str = "ssl"
    interval_seconds: float = 10800.0         # ~3h low-and-slow cadence
    jitter_fraction: float = 0.3              # ±30% so it isn't a perfect metronome
    orig_bytes_range: tuple[int, int] = (300, 800)     # small check-in
    resp_bytes_range: tuple[int, int] = (2000, 18000)  # variable tasking
    tasking_every: int = 8                    # 1-in-N callbacks pulls a larger payload
    technique: str = "T1071.001"              # application-layer C2

    def targets(self) -> tuple[str, ...]:
        """The C2 IP(s) to round-robin across (rotation set, else the single IP)."""
        return self.dest_ips or ((self.dest_ip,) if self.dest_ip else ())


def _seed_int(incident_id: str, seed: int) -> int:
    """Deterministic per-incident seed: same (incident, seed) -> same beacon."""
    h = hashlib.sha256(f"{incident_id}:{seed}".encode()).hexdigest()
    return int(h[:8], 16)


def _beacon_uid(rng: random.Random) -> str:
    return "C" + "".join(rng.choice(_UID_ALPHABET) for _ in range(16))


def synthesize_beacon(
    orig_h: str, window_start: datetime, window_end: datetime, spec: BeaconSpec, *, seed: int
) -> list[dict]:
    """Generate cadenced Zeek ``conn`` beacon events across [start, end].

    ``orig_h`` is the bundle's capture source IP (rewritten to the victim by the
    normal remap downstream); the beacon rides ``inject_bundle``'s remap+rebase
    like any other bundle event. Deterministic given ``seed``.
    """
    targets = spec.targets()
    if window_end <= window_start or spec.interval_seconds <= 0 or not targets:
        return []
    rng = random.Random(seed)
    out: list[dict] = []
    t = window_start.timestamp()
    end = window_end.timestamp()
    i = 0
    while t <= end:
        obytes = rng.randint(*spec.orig_bytes_range)
        # occasional larger tasking pull, else a modest check-in response
        if i % spec.tasking_every == 0:
            rbytes = rng.randint(spec.resp_bytes_range[1] // 2, spec.resp_bytes_range[1])
        else:
            rbytes = rng.randint(spec.resp_bytes_range[0], spec.resp_bytes_range[1] // 2)
        opkts = max(4, obytes // 120)
        rpkts = max(4, rbytes // 700)
        dur = round(rng.uniform(0.15, 3.5), 6)
        out.append({
            "_stream": "zeek",
            "_log": "conn",
            "_stage": "command-and-control",
            "_technique": spec.technique,
            "_campaign_ts": datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f"),
            "ts": f"{t:.6f}",
            "uid": _beacon_uid(rng),
            "id.orig_h": orig_h,
            "id.orig_p": str(rng.randint(49152, 65535)),
            "id.resp_h": targets[i % len(targets)],   # round-robin rotation
            "id.resp_p": spec.dest_port,
            "proto": spec.proto,
            "service": spec.service,
            "duration": f"{dur:.6f}",
            "orig_bytes": str(obytes),
            "resp_bytes": str(rbytes),
            "orig_ip_bytes": str(obytes + opkts * 40),
            "resp_ip_bytes": str(rbytes + rpkts * 40),
            "orig_pkts": str(opkts),
            "resp_pkts": str(rpkts),
            "missed_bytes": "0",
            "conn_state": "SF",
            "history": "ShADadFf",
            "local_orig": "T",
            "local_resp": "F",
            "ip_proto": "6",
            "tunnel_parents": "-",
        })
        i += 1
        step = spec.interval_seconds * (1.0 + rng.uniform(-spec.jitter_fraction, spec.jitter_fraction))
        t += max(1.0, step)
    return out


def rebase_campaign(events: list[dict], corpus_start: datetime, *, warmup_frac: float = 0.05) -> tuple[list[dict], datetime, datetime, timedelta]:
    """Shift the whole campaign so its first event lands just after corpus_start.

    A single delta is applied to every event, preserving all relative spacing
    (the low-and-slow dwell and beacon cadence are the signal — they must
    survive). Returns (shifted_events, new_start, new_end, delta).
    """
    times = [t for t in (_event_time(e) for e in events) if t is not None]
    if not times:
        return events, corpus_start, corpus_start, timedelta(0)
    bundle_start, bundle_end = min(times), max(times)
    # nudge the campaign start a little past the corpus start so it doesn't
    # begin exactly at t0 of the benign window.
    span = bundle_end - bundle_start
    offset = span * warmup_frac if span else timedelta(0)
    delta = (corpus_start + offset) - bundle_start
    shifted = [_shift_event_time(e, delta) for e in events]
    return shifted, bundle_start + delta, bundle_end + delta, delta


@dataclass(frozen=True)
class HostRemap:
    """Maps a bundle's captured source identity onto a real EF corpus host."""

    from_name: str        # capture host short/NETBIOS, e.g. "WS-FIN-014"
    from_fqdn: str        # e.g. "ws-fin-014.corp.example"
    from_ip: str          # internal capture IP, e.g. "10.10.4.37"
    to_name: str          # target EF NETBIOS, e.g. "WKST-03"
    to_fqdn: str          # target EF FQDN, e.g. "wkst-03.corp.example.invalid"
    to_ip: str            # target EF IP, e.g. "10.10.0.13"

    def _pairs(self) -> list[tuple[str, str]]:
        # Longest-first so FQDN is replaced before the bare name it contains,
        # and case-insensitively for the NETBIOS name (User = HOST\\user).
        return [
            (self.from_fqdn, self.to_fqdn),
            (self.from_ip, self.to_ip),
            (self.from_name, self.to_name),
        ]

    def apply(self, value: str) -> str:
        out = value
        for src, dst in self._pairs():
            if src:
                out = re.sub(re.escape(src), dst, out, flags=re.IGNORECASE)
        return out


# Zeek conn boolean columns are encoded "T"/"F" in TSV-derived captures but
# JSON true/false in EvidenceForge output. Coerce so the injected events match
# the benign index mapping (else ES rejects them on the boolean field) and are
# not surface-separable on field type.
_ZEEK_BOOL_FIELDS = ("local_orig", "local_resp")


def _coerce_zeek_bools(ev: dict) -> dict:
    out = dict(ev)
    for f in _ZEEK_BOOL_FIELDS:
        v = out.get(f)
        if isinstance(v, str) and v in ("T", "F"):
            out[f] = (v == "T")
    return out


def remap_event(ev: dict, remap: HostRemap) -> dict:
    """Rewrite every string field that mentions the capture identity.

    Recurses into nested lists/dicts. Non-string scalars pass through. External
    addresses (anything not matching the from-identity) are untouched.
    """
    def _walk(v):
        if isinstance(v, str):
            return remap.apply(v)
        if isinstance(v, list):
            return [_walk(x) for x in v]
        if isinstance(v, dict):
            return {k: _walk(x) for k, x in v.items()}
        return v

    return _walk(ev)


def doc_id_for(rec: dict) -> str:
    """The ES ``_id`` the ingest adapter WILL assign to this event.

    Must match scripts/ingest_ef.py exactly: the native id (Zeek ``uid``) if
    present, else sha256 over the public (non-``_``) fields. Keying the
    ground-truth ``doc_id`` on this is what lets the judge address the exact ES
    document — getting it wrong silently orphans the pointer.
    """
    native = rec.get("uid")
    if native:
        return str(native)
    public = {k: v for k, v in rec.items() if not k.startswith("_")}
    blob = json.dumps(public, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


# Bundle ``_stream`` -> (corpus subdir suffix, ES index the ingest routes to).
# The ingest adapter routes ``injected/*.<stream>.ndjson`` by this stream tag.
_STREAM_LOG = {"sysmon": "sysmon", "zeek": "zeek"}


def leak_check(events: list[dict], remap: HostRemap) -> list[str]:
    """Return any capture-identity strings still present (should be empty)."""
    blob = json.dumps(events, default=str, ensure_ascii=False)
    leaks = []
    for needle in (remap.from_fqdn, remap.from_ip, remap.from_name):
        if needle and re.search(re.escape(needle), blob, flags=re.IGNORECASE):
            leaks.append(needle)
    return leaks


def _corpus_window(corpus_dir: Path) -> tuple[datetime | None, datetime | None]:
    """Read the EF corpus collection window from GROUND_TRUTH.json (UTC)."""
    gt_path = corpus_dir / "GROUND_TRUTH.json"
    if not gt_path.is_file():
        return None, None
    cw = json.loads(gt_path.read_text()).get("collection_window", {})

    def _p(s):
        if not s:
            return None
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    return _p(cw.get("start")), _p(cw.get("end"))


def load_bundle(bundle_dir: str | Path, incident_id: str) -> tuple[list[dict], dict]:
    bundle_dir = Path(bundle_dir)
    events = [
        json.loads(line)
        for line in (bundle_dir / f"{incident_id}.events.ndjson").read_text().splitlines()
        if line.strip()
    ]
    gt = yaml.safe_load((bundle_dir / f"{incident_id}.ground-truth.yaml").read_text())
    return events, gt


def inject_bundle(
    corpus_dir: str | Path,
    bundle_dir: str | Path,
    incident_id: str,
    remap: HostRemap,
    *,
    beacon: BeaconSpec | None = None,
    seed: int = 0,
) -> dict:
    """Remap a bundle onto a real EF host, write it into the corpus tree, and
    repoint its ground truth. Returns a summary dict.

    ``beacon`` (APT bundles only) synthesizes a low-and-slow C2 beacon across the
    bundle's own campaign window before remap, so it rides the same remap+rebase
    and lands on the victim with cadence intact — the RQ2 network signal the raw
    capture lacks. ``seed`` makes the beacon deterministic.

    Raises ``ValueError`` if any capture identity leaks past the remap.
    """
    corpus_dir = Path(corpus_dir)
    events, gt = load_bundle(bundle_dir, incident_id)

    if beacon is not None:
        times = [t for t in (_event_time(e) for e in events) if t is not None]
        if times:
            b = synthesize_beacon(remap.from_ip, min(times), max(times), beacon,
                                  seed=_seed_int(incident_id, seed))
            log.info("synthesized %d beacon events across the campaign window, rotating over %s",
                     len(b), ",".join(beacon.targets()))
            events = events + b

    remapped = [_coerce_zeek_bools(remap_event(ev, remap)) for ev in events]
    leaks = leak_check(remapped, remap)
    if leaks:
        raise ValueError(f"capture-identity leak after remap: {leaks}")

    # Rebase the campaign onto the EF corpus window (read from GROUND_TRUTH.json)
    # so the adversary overlays the benign haystack instead of sitting at its
    # original capture dates. A single delta preserves dwell + beacon cadence.
    cstart, cend = _corpus_window(corpus_dir)
    if cstart is not None:
        remapped, new_start, new_end, _ = rebase_campaign(remapped, cstart)
        if cend is not None and new_end > cend:
            log.warning(
                "injected campaign dwell (%s) exceeds corpus window end %s by %s; "
                "the low-and-slow campaign is longer than this tier's window — "
                "use a larger tier (M/L) for full-dwell adversaries",
                new_end - new_start, cend.isoformat(), new_end - cend,
            )
        # reflect the rebased window in the ground truth time_window
        if "time_window" in gt:
            tw = dict(gt["time_window"])
            # Floor to whole seconds so the formatted endpoints and
            # duration_seconds agree exactly (schema rule 9 compares them).
            s0 = new_start.replace(microsecond=0)
            e0 = new_end.replace(microsecond=0)
            tw["injection_start"] = s0.strftime("%Y-%m-%dT%H:%M:%SZ")
            tw["injection_end"] = e0.strftime("%Y-%m-%dT%H:%M:%SZ")
            tw["duration_seconds"] = int((e0 - s0).total_seconds())
            gt["time_window"] = tw

    # Write injected events as NDJSON per (stream, log), filename
    # "<incident>.<stream>.<log>.ndjson", so each lands in the SAME index as
    # the matching benign telemetry (sysmon -> windows-sysmon, zeek conn ->
    # zeek-conn, zeek http -> zeek-http). Splitting by _log matters for Zeek:
    # an http record shares its conn record's uid, so co-indexing them under a
    # uid-keyed zeek-conn would silently collide and orphan a ground-truth
    # pointer.
    inj_dir = corpus_dir / "injected"
    inj_dir.mkdir(parents=True, exist_ok=True)
    by_key: dict[tuple[str, str], list[dict]] = {}
    for ev in remapped:
        stream = str(ev.get("_stream", "sysmon"))
        logname = str(ev.get("_log", stream))
        by_key.setdefault((stream, logname), []).append(ev)
    written: dict[str, int] = {}
    for (stream, logname), evs in sorted(by_key.items()):
        path = inj_dir / f"{incident_id}.{stream}.{logname}.ndjson"
        with path.open("w", encoding="utf-8", newline="") as f:
            for ev in evs:
                doc = {k: v for k, v in ev.items() if not k.startswith("_")}
                f.write(json.dumps(doc, sort_keys=True, default=str) + "\n")
        written[f"{stream}/{logname}"] = len(evs)

    # Repoint ground truth: events[].where -> the ES doc_id the ingest will
    # assign. GT event i (1-based, original bundle order) corresponds to
    # remapped[i-1]; the doc_id is content/uid-derived and independent of which
    # per-stream file the event lands in, so re-grouping by stream above does
    # not affect this mapping.
    #
    # Synthesized beacon events (BeaconSpec) are appended AFTER the captured
    # bundle events, so the GT-aligned prefix remapped[0:len(gt_events)] is
    # unchanged. They are supporting C2 telemetry with no per-event ground-truth
    # pointer, so we repoint only that prefix and allow the extra suffix.
    gt_out = dict(gt)
    gt_events = gt.get("events", [])
    if len(remapped) < len(gt_events):
        raise ValueError(
            f"ground-truth event count {len(gt_events)} > injected event count "
            f"{len(remapped)}; cannot repoint by index"
        )
    new_events = []
    for i, e in enumerate(gt_events):
        e2 = dict(e)
        e2["where"] = {"doc_id": doc_id_for(remapped[i])}
        new_events.append(e2)
    gt_out["events"] = new_events

    gt_dir = corpus_dir / "ground-truth"
    gt_dir.mkdir(parents=True, exist_ok=True)
    gt_path = gt_dir / f"{incident_id}.ground-truth.yaml"
    gt_path.write_text(yaml.safe_dump(gt_out, sort_keys=False), encoding="utf-8", newline="")

    log.info("injected %s onto %s: %s events, GT repointed -> %s",
             incident_id, remap.to_fqdn, written, gt_path)
    return {
        "incident_id": incident_id,
        "source_class": gt.get("source_class"),
        "target_host": remap.to_fqdn,
        "written": written,
        "events": sum(written.values()),
        "ground_truth": str(gt_path),
    }
