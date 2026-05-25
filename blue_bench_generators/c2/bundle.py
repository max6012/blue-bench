"""Bundle emitter for synthetic C2 streams.

Same shape as ``cybercrime_foil/bundle.py``. Produces:

    <incident_id>.events.ndjson     -- one event per line (Zeek + Suricata flavour)
    <incident_id>.ground-truth.yaml -- schema-conformant annotation per v1.0

Schema validation is delegated to the cybercrime_foil validator
(``cybercrime_foil.bundle.validate_bundle``). The 11 rules are
schema-version-level, not profile-family-level -- re-implementing them
here would only invite drift. We import them.

Key per-profile differences from the cybercrime_foil bundle:

    * ``source_class`` is ``cybercrime`` for commodity profiles,
      ``apt`` for stealth profiles (rather than always ``cybercrime``).
    * ``confidence`` defaults from the profile: ``high`` for commodity,
      ``medium`` for stealth.
    * ``source.kind`` is ``synthetic-c2`` (per the schema enum, added
      2026-05-25) -- this telemetry is synthesised, not replayed from a
      captured PCAP, and represents C2 traffic specifically rather than
      generic benign anomaly.
    * ``segment_class`` is fixed to ``IT`` for v1 (OT-APT is handled by
      ``t-ot-apt``).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

# Re-use the schema validator from cybercrime_foil. The 11 rules are
# schema-level, not profile-family-level; duplicating would drift.
from blue_bench_generators.cybercrime_foil.bundle import (  # noqa: F401
    SCHEMA_VERSION,
    SchemaValidationError,
    validate_bundle,
)
from blue_bench_generators.c2.profiles import C2Profile

log = logging.getLogger(__name__)


# --- corpus binding (mirrors cybercrime_foil.bundle.CorpusBinding) ---


@dataclass
class CorpusBinding:
    """Pins the bundle to a particular corpus build."""

    tier: str  # "S" | "M" | "L"
    build_hash: str  # sha256 hex of the produced corpus
    baseline_generator_config: str  # repo-relative path

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "build_hash": self.build_hash,
            "baseline_generator_config": self.baseline_generator_config,
        }


# --- event-id generation (deterministic, same convention as cybercrime_foil) ---


def _event_id(incident_id: str, sequence: int) -> str:
    return f"evt-{incident_id}-{sequence:04d}"


# --- IOC extraction ---


def _extract_iocs(emitted_events: list[dict], profile: C2Profile) -> dict:
    """Populate analyst-relevant IOCs from the emitted synthetic C2 events.

    Unlike real-PCAP replay (where every observed artefact is a candidate
    and curation is the hard part), synthetic C2 lets us populate IOCs
    deterministically from what we know we emitted: callback IPs, the
    SNI / DNS-query / HTTP-host hostnames we generated, and the resulting
    URLs. The DNS-resolver IP is intentionally excluded -- it's benign
    infrastructure from the analyst's perspective.

    Returns a dict shaped to the ``expected_findings.iocs`` block of the
    ground-truth schema. Lists are sorted for determinism.
    """
    ipv4: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()

    for ev in emitted_events:
        log_name = str(ev.get("_log", "")).lower()
        event_type = str(ev.get("event_type", "")).lower()

        # Zeek-flavoured records (`_log` field)
        if log_name == "conn":
            if ev.get("id.resp_h"):
                ipv4.add(str(ev["id.resp_h"]))
        elif log_name == "http":
            if ev.get("id.resp_h"):
                ipv4.add(str(ev["id.resp_h"]))
            host = ev.get("host")
            uri = ev.get("uri")
            if host:
                domains.add(str(host))
                if uri:
                    scheme = "https" if profile.transport == "https" else "http"
                    urls.add(f"{scheme}://{host}{uri}")
        elif log_name == "ssl":
            if ev.get("id.resp_h"):
                ipv4.add(str(ev["id.resp_h"]))
            if ev.get("server_name"):
                domains.add(str(ev["server_name"]))
        elif log_name == "dns":
            # `answers` carries the C2 IP; `id.resp_h` is the resolver
            # (not an IOC).
            if ev.get("answers"):
                ipv4.add(str(ev["answers"]))
            if ev.get("query"):
                domains.add(str(ev["query"]))

        # Suricata eve.json records (`event_type` field)
        elif event_type == "flow":
            if ev.get("dest_ip"):
                ipv4.add(str(ev["dest_ip"]))
        elif event_type == "http":
            if ev.get("dest_ip"):
                ipv4.add(str(ev["dest_ip"]))
            http = ev.get("http") or {}
            hostname = http.get("hostname")
            url = http.get("url")
            if hostname:
                domains.add(str(hostname))
                if url:
                    scheme = "https" if profile.transport == "https" else "http"
                    urls.add(f"{scheme}://{hostname}{url}")
        elif event_type == "tls":
            if ev.get("dest_ip"):
                ipv4.add(str(ev["dest_ip"]))
            tls = ev.get("tls") or {}
            sni = tls.get("sni")
            if sni:
                domains.add(str(sni))
        elif event_type == "dns":
            # Suricata DNS: `dest_ip` is the resolver -- skip it. The
            # corresponding Zeek `dns` record above carries the answer
            # IP via the `answers` field; the IOC for DNS-transport
            # profiles is sourced from there.
            dns = ev.get("dns") or {}
            rrname = dns.get("rrname")
            if rrname:
                domains.add(str(rrname))

    return {
        "sha256": [],
        "sha1": [],
        "md5": [],
        "ipv4": sorted(ipv4),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "file_names": [],
        "process_names": [],
        "email_headers": [],
        "registry_keys": [],
        "mutex_names": [],
    }


# --- role classification ---


def _classify_role(event: dict, profile: C2Profile) -> str:
    """Best-effort mapping from a synthetic C2 event to a schema role.

    For C2 traffic, almost everything is a C2 event by definition. We
    keep the heuristic narrow: DNS -> discovery (name resolution is
    discovery-tactic shaped), files -> delivery, alerts -> other (the
    alert is meta-evidence, not a TTP-evidencing event of its own).
    """
    log_name = str(event.get("_log", "")).lower()
    event_type = str(event.get("event_type", "")).lower()
    if event_type == "alert":
        return "other"
    if log_name == "files" or event_type == "fileinfo":
        return "delivery"
    if log_name == "dns" or event_type == "dns":
        return "discovery"
    # conn / ssl / http / flow / tls all carry the C2 callback itself.
    return "c2"


# --- ground-truth assembly ---


def build_ground_truth(
    *,
    incident_id: str,
    profile: C2Profile,
    events_ndjson_filename: str,
    emitted_events: list[dict],
    corpus: CorpusBinding,
    injection_start: datetime,
    injection_end: datetime,
    ingestion_commit: str = "0" * 40,
    raw_artifact_hash: str = "0" * 64,
    confidence_override: str | None = None,
) -> dict:
    """Build the ground-truth dict for one synthetic C2 incident.

    Args:
        incident_id: stable kebab-case id for the incident.
        profile: the C2Profile this stream was generated from. Drives
            ``source_class``, ``confidence``, ``ttps``, and
            ``ttps_optional``.
        events_ndjson_filename: filename of the events NDJSON file (used
            as the ``where.fixture_line.path`` for each event pointer).
        emitted_events: events already emitted by zeek_emit +
            suricata_emit. Each line gets a pointer.
        corpus: corpus binding (tier, build hash, baseline-gen config).
        injection_start: scheduled start of the window (UTC).
        injection_end: scheduled end of the window (UTC).
        ingestion_commit: git SHA of the ingest pipeline commit.
            40 zeros allowed as a placeholder.
        raw_artifact_hash: sha256 of the upstream artifact (here, the
            generator-config hash); 64 zeros allowed.
        confidence_override: force a confidence value; default from the
            profile.

    Returns:
        Dict ready for YAML dump.
    """
    confidence = confidence_override or profile.confidence

    # Schema rule 9: duration_seconds must equal end-start to second
    # precision. Since the YAML serializes timestamps with %Y-%m-%dT%H:%M:%SZ
    # (no microseconds), we MUST truncate to whole seconds here so the
    # validator's re-parse matches.
    injection_start = injection_start.replace(microsecond=0)
    injection_end = injection_end.replace(microsecond=0)

    events_block: list[dict] = []
    for i, ev in enumerate(emitted_events, start=1):
        events_block.append({
            "id": _event_id(incident_id, i),
            "where": {
                "fixture_line": {
                    "path": events_ndjson_filename,
                    "line": i,
                },
            },
            "role": _classify_role(ev, profile),
            # Per-event TTP linking: synthetic C2 evidences the same set
            # the profile declares. The orchestrator can refine per-event
            # later if needed; v1 attributes the whole profile TTP set.
            "ttp_links": [profile.ttps[0]] if profile.ttps else [],
        })

    duration_seconds = int((injection_end - injection_start).total_seconds())

    # attribution_required: pick the LotL / encrypted-channel TTPs as
    # the required set for commodity (they're the high-confidence ones
    # for a discriminator); for stealth use the first two TTPs which
    # are the protocol + encryption tactic anchors.
    attribution_required = list(profile.ttps[: min(2, len(profile.ttps))])

    accepted_alternates: dict[str, list[str]] = {}
    for ttp in attribution_required:
        if "." in ttp:
            accepted_alternates[ttp] = [ttp.split(".")[0]]

    # Scoring defaults: commodity uses cybercrime defaults (attribution
    # weight 0.5); stealth uses apt defaults (attribution weight 0.4)
    # per the schema doc. Both keep discrimination required (RQ3).
    attribution_weight = 0.5 if profile.source_class == "cybercrime" else 0.4

    gt: dict = {
        "schema_version": SCHEMA_VERSION,
        "incident_id": incident_id,
        "source_class": profile.source_class,
        "segment_class": "IT",
        "source": {
            # synthetic-c2: generator output representing C2 traffic.
            # Added to schema enum 2026-05-25; supersedes earlier use of
            # synthetic-anomaly, which is now reserved for benign-anomaly
            # source-class samples.
            "kind": "synthetic-c2",
            "reference": f"blue_bench_generators.c2:preset:{profile.name}",
            "ingestion_commit": ingestion_commit,
            "raw_artifact_hash": raw_artifact_hash,
        },
        "corpus": corpus.to_dict(),
        "time_window": {
            "injection_start": injection_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "injection_end": injection_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": duration_seconds,
        },
        "ttps": list(profile.ttps),
        "ttps_optional": list(profile.ttps_optional),
        "confidence": confidence,
        "events": events_block,
        "expected_findings": {
            "iocs": _extract_iocs(emitted_events, profile),
            "ttp_attribution": {
                "required": attribution_required,
                "accepted_alternates": accepted_alternates,
            },
            "narrative_facts": [
                f"Traffic shape matches the {profile.family} profile "
                f"(transport={profile.transport}).",
                f"Beacon cadence mean is {profile.beacon_interval_seconds:.0f}s "
                f"with jitter +-{int(profile.beacon_jitter_fraction * 100)}%.",
                (
                    "Commodity-class C2: signature-based detection fires; "
                    "discriminating signal is high-confidence and family-specific."
                    if profile.source_class == "cybercrime"
                    else
                    "LotL-class C2: signature-based detection does not fire; "
                    "discriminating signal is cadence + endpoint shape + JA3."
                ),
            ],
        },
        "scoring": {
            "detection": {
                "found_threshold": 0.7,
                "partial_threshold": 0.3,
            },
            "attribution": {
                "weight": attribution_weight,
            },
            "discrimination": {
                "required": True,
            },
        },
        "notes": (
            f"Synthetic C2 stream from preset {profile.name!r} "
            f"({profile.family}). Profile kind: {profile.kind()}. "
            f"Payloads are random-data of profile-sized length; "
            f"no real malicious bytes."
        ),
    }
    return gt


# --- writer ---


def write_bundle(
    *,
    incident_id: str,
    profile: C2Profile,
    emitted_events: list[dict],
    corpus: CorpusBinding,
    injection_start: datetime,
    injection_end: datetime,
    bundle_dir: Path,
    ingestion_commit: str = "0" * 40,
    raw_artifact_hash: str = "0" * 64,
    confidence_override: str | None = None,
) -> tuple[Path, Path]:
    """Write NDJSON + YAML into ``bundle_dir``. Validate before writing.

    Returns:
        ``(ndjson_path, yaml_path)``.

    Raises:
        SchemaValidationError if the generated ground-truth fails any
        of the 11 rules (rule 8 skipped at emit time).
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    ndjson_name = f"{incident_id}.events.ndjson"
    yaml_name = f"{incident_id}.ground-truth.yaml"

    gt = build_ground_truth(
        incident_id=incident_id,
        profile=profile,
        events_ndjson_filename=ndjson_name,
        emitted_events=emitted_events,
        corpus=corpus,
        injection_start=injection_start,
        injection_end=injection_end,
        ingestion_commit=ingestion_commit,
        raw_artifact_hash=raw_artifact_hash,
        confidence_override=confidence_override,
    )

    # Validate BEFORE writing -- fail loud, leave no half-written artefacts.
    validate_bundle(gt)

    ndjson_path = bundle_dir / ndjson_name
    yaml_path = bundle_dir / yaml_name

    with ndjson_path.open("w", encoding="utf-8") as f:
        for i, ev in enumerate(emitted_events, start=1):
            obj = dict(ev)
            obj["event_id"] = _event_id(incident_id, i)
            f.write(json.dumps(obj, default=str) + "\n")

    with yaml_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(gt, f, sort_keys=False, allow_unicode=True)

    log.info(
        "wrote c2 bundle: %s, %s (%d events, profile=%s)",
        ndjson_path,
        yaml_path,
        len(emitted_events),
        profile.name,
    )
    return ndjson_path, yaml_path


def load_ground_truth(path: Path) -> dict:
    """Convenience: load + parse a ground-truth YAML."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_events_ndjson(path: Path) -> list[dict]:
    """Convenience: load an events NDJSON file fully."""
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
