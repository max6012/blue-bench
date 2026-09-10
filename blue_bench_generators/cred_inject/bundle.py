"""Emit a credential-abuse bundle to disk and validate it.

Writes, into ``<out_root>/<subdir>/``::

    <incident_id>.events.ndjson        one synthetic event per line
    <incident_id>.ground-truth.yaml    annotation (validated against the 11-rule
                                        contract shared with cybercrime_foil)

The ground-truth is constructed from the builder's per-event role + technique;
``validate_bundle`` enforces the schema (single where-locator, role enum, ttp
regex, threshold ordering, ttp_attribution ⊆ ttps, …) before the file is written.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import yaml

from blue_bench_generators.cred_inject.events import BundleSpec
from blue_bench_generators.cybercrime_foil.bundle import validate_bundle

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "data" / "bundles"
_ZERO40 = "0" * 40
_ZERO64 = "0" * 64
_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"


def _iso_z(utc_str: str) -> tuple[str, datetime]:
    dt = datetime.strptime(utc_str, _TS_FMT)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), dt


def build_ground_truth(spec: BundleSpec) -> dict:
    """Assemble (and validate) the ground-truth dict for a bundle spec."""
    times = [datetime.strptime(ev["UtcTime"], _TS_FMT) for ev, _ in spec.events]
    start, end = min(times), max(times)
    gt_events = []
    for i, (ev, role) in enumerate(spec.events, start=1):
        gt_events.append({
            "id": f"evt-{spec.incident_id}-{i:04d}",
            "where": {"fixture_line": {"path": f"{spec.incident_id}.events.ndjson", "line": i}},
            "role": role,
            "ttp_links": [ev["_technique"]],
        })
    gt = {
        "schema_version": "1.0",
        "incident_id": spec.incident_id,
        "source_class": spec.source_class,
        "segment_class": "IT",
        "source": {
            "kind": "generated",
            "reference": "blue_bench_generators/cred_inject",
            "ingestion_commit": _ZERO40,
            "raw_artifact_hash": _ZERO64,
        },
        "corpus": {
            "tier": "L",
            "build_hash": _ZERO64,
            "baseline_generator_config": "blue_bench_generators/it_baseline",
        },
        "time_window": {
            "injection_start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "injection_end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": int((end - start).total_seconds()),
        },
        "ttps": list(spec.ttps),
        "ttps_optional": [],
        "confidence": "high",
        "events": gt_events,
        "expected_findings": {
            "ttp_attribution": {"required": list(spec.ttps), "accepted_alternates": {}},
            "narrative_facts": list(spec.narrative_facts),
        },
        "scoring": {
            "detection": {"found_threshold": 0.7, "partial_threshold": 0.3},
            "attribution": {"weight": 0.5},
            "discrimination": {"required": False},
        },
        "notes": spec.notes,
    }
    validate_bundle(gt)
    return gt


def write_bundle(spec: BundleSpec, out_root: Path = DEFAULT_OUT) -> Path:
    """Write events.ndjson + ground-truth.yaml for one bundle; return its dir."""
    gt = build_ground_truth(spec)
    out_dir = out_root / spec.subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    events_path = out_dir / f"{spec.incident_id}.events.ndjson"
    events_path.write_text(
        "".join(json.dumps(ev, ensure_ascii=False) + "\n" for ev, _ in spec.events)
    )
    (out_dir / f"{spec.incident_id}.ground-truth.yaml").write_text(
        yaml.safe_dump(gt, sort_keys=False, default_flow_style=False, width=100)
    )
    log.info("wrote %s (%d events) -> %s", spec.incident_id, len(spec.events), out_dir)
    return out_dir
