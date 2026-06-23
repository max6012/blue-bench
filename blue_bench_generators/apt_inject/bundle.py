"""Bundle emitter for the APT injection harness.

Emits, into a bundle directory::

    <campaign_id>.events.ndjson        one rewritten event per line
    <campaign_id>.ground-truth.yaml    annotation, source_class=apt

Reuses ``cybercrime_foil.bundle`` for the shared ground-truth contract —
``CorpusBinding``, ``validate_bundle`` (the 11 schema rules), and
``SchemaValidationError``. Only the ground-truth *construction* differs:
this is an APT campaign stitched from kill-chain stages, not a single
cybercrime incident, so ``source_class=apt`` and the per-event role /
ttp_links come from the stage each event was selected for.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import yaml

from blue_bench_generators.cybercrime_foil.bundle import (
    SCHEMA_VERSION,
    CorpusBinding,
    SchemaValidationError,
    validate_bundle,
)

log = logging.getLogger(__name__)

# Kill-chain stage → schema event-role enum. Stages with no exact enum
# member map to "other"; the real technique is preserved in ttp_links, so
# attribution is never lost to the coarse role.
_STAGE_ROLE: dict[str, str] = {
    "initial-access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "defense-evasion": "other",
    "credential-access": "other",
    "discovery": "discovery",
    "lateral-movement": "lateral",
    "collection": "other",
    "command-and-control": "c2",
    "exfiltration": "exfil",
}


def _event_id(campaign_id: str, seq: int) -> str:
    return f"evt-{campaign_id}-{seq:04d}"


def build_apt_ground_truth(
    *,
    campaign_id: str,
    rewritten_events: list[dict],
    corpus: CorpusBinding,
    injection_start: datetime,
    injection_end: datetime,
    segment_class: str = "IT",
    confidence: str = "high",
    ingestion_commit: str = "0" * 40,
    raw_artifact_hash: str = "0" * 64,
    notes: str = "",
) -> dict:
    """Build the source_class=apt ground-truth dict for one campaign."""
    events_ndjson = f"{campaign_id}.events.ndjson"

    # ttps = the distinct techniques across all stages, in first-seen order.
    ttps: list[str] = []
    for ev in rewritten_events:
        t = ev.get("_technique")
        if t and t not in ttps:
            ttps.append(t)

    events_block: list[dict] = []
    for i, ev in enumerate(rewritten_events, start=1):
        stage = ev.get("_stage", "other")
        events_block.append({
            "id": _event_id(campaign_id, i),
            "where": {"fixture_line": {"path": events_ndjson, "line": i}},
            "role": _STAGE_ROLE.get(stage, "other"),
            "ttp_links": [ev["_technique"]] if ev.get("_technique") else [],
        })

    duration_seconds = int((injection_end - injection_start).total_seconds())

    gt: dict = {
        "schema_version": SCHEMA_VERSION,
        "incident_id": campaign_id,
        "source_class": "apt",
        "segment_class": segment_class,
        "source": {
            "kind": "sandbox-atomic",
            "reference": "sandbox/vm/capture-killchain.sh + generators/apt_inject/killchain.tsv",
            "ingestion_commit": ingestion_commit,
            "raw_artifact_hash": raw_artifact_hash,
        },
        "corpus": corpus.to_dict(),
        "time_window": {
            "injection_start": injection_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "injection_end": injection_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": duration_seconds,
        },
        "ttps": ttps,
        "ttps_optional": [],
        "confidence": confidence,
        "events": events_block,
        "expected_findings": {
            "iocs": {
                "sha256": [], "sha1": [], "md5": [],
                "ipv4": [], "domains": [], "urls": [],
                "file_names": [], "process_names": [],
                "email_headers": [], "registry_keys": [], "mutex_names": [],
            },
            "ttp_attribution": {
                "required": list(ttps),
                "accepted_alternates": {},
            },
            "narrative_facts": [
                "Single-host APT kill chain captured from Atomic Red Team in an "
                "isolated AWS sandbox, then time-shifted into a low-and-slow campaign "
                "and host-remapped onto a baseline corpus host.",
                "Dwell is measured in days: initial access and execution land early, "
                "lateral movement spreads across the middle of the window, and "
                "collection/exfiltration occur near the end.",
                "C2 appears as sparse web beacons distributed across the dwell window "
                "rather than a single burst.",
                "Lateral movement is source-side only (single-host capture); the "
                "destination host is not represented in this bundle.",
            ],
        },
        "scoring": {
            "detection": {"found_threshold": 0.7, "partial_threshold": 0.3},
            "attribution": {"weight": 0.5},
            # APT is RQ2 (detect low-and-slow). Discrimination (RQ3) is the
            # cybercrime foil's job; an APT campaign that the model labels
            # APT is correct, so discrimination is not required here.
            "discrimination": {"required": False},
        },
        "notes": notes or (
            "APT campaign stitched from a 10-stage Atomic Red Team kill chain "
            "(initial-access → exfil) captured in the AWS sandbox substrate. "
            "Signal selected by Sysmon process-GUID subtree per stage; injected "
            "as a thin needle at low-and-slow pacing. Per-event role is the "
            "coarse kill-chain phase; the precise technique is in ttp_links."
        ),
    }
    return gt


def write_apt_bundle(
    *,
    campaign_id: str,
    rewritten_events: list[dict],
    corpus: CorpusBinding,
    injection_start: datetime,
    injection_end: datetime,
    bundle_dir: Path,
    segment_class: str = "IT",
    confidence: str = "high",
) -> tuple[Path, Path]:
    """Validate then write NDJSON + ground-truth YAML. Returns the paths."""
    bundle_dir = Path(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    gt = build_apt_ground_truth(
        campaign_id=campaign_id,
        rewritten_events=rewritten_events,
        corpus=corpus,
        injection_start=injection_start,
        injection_end=injection_end,
        segment_class=segment_class,
        confidence=confidence,
    )
    # Fail loud before writing — leave no half-written artefacts.
    validate_bundle(gt)

    ndjson_path = bundle_dir / f"{campaign_id}.events.ndjson"
    yaml_path = bundle_dir / f"{campaign_id}.ground-truth.yaml"

    with ndjson_path.open("w", encoding="utf-8") as fh:
        for ev in rewritten_events:
            fh.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
    yaml_path.write_text(
        yaml.safe_dump(gt, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    log.info("wrote apt bundle: %s + %s (%d events)",
             ndjson_path.name, yaml_path.name, len(rewritten_events))
    return ndjson_path, yaml_path


__all__ = [
    "build_apt_ground_truth",
    "write_apt_bundle",
    "validate_bundle",
    "SchemaValidationError",
    "CorpusBinding",
]
