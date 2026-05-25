"""Bundle emitter + ground-truth schema validator.

Takes (incident_id, rewritten events, catalogue entry, corpus binding) and
emits two files into a bundle directory:

    <incident_id>.events.ndjson           one event per line, with stable event_id
    <incident_id>.ground-truth.yaml       annotation per ground-truth-schema.md v1.0

Pointer convention (decided 2026-05-25 with the advisor): events use
``where: {fixture_line: {path: <incident_id>.events.ndjson, line: N}}`` because
the bundle is the corpus subset for this incident — Elasticsearch indexing
happens downstream in the orchestrator (``t-9pwe``), not here.

Validator: runs all 11 rules from the schema doc except rule 8 (build-hash
matches produced corpus). Rule 8 cannot be checked at emit time because the
emitter takes the build_hash as INPUT and has no access to the assembled
corpus. The orchestrator enforces rule 8 when it stitches bundles into a
corpus build. We document this skip explicitly in code; the validator
exposes rule 8 as a no-op so callers that want to be paranoid still get a
positive return.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml

from blue_bench_generators.cybercrime_foil.catalogue import CatalogueEntry

log = logging.getLogger(__name__)


SCHEMA_VERSION = "1.0"
KNOWN_SCHEMA_VERSIONS = {"1.0"}
SOURCE_CLASS_ENUM = {"apt", "cybercrime", "benign-anomaly"}
SEGMENT_CLASS_ENUM = {"IT", "OT", "IT-OT-bridge"}
EVENT_ROLE_ENUM = {
    "c2",
    "exfil",
    "lateral",
    "execution",
    "persistence",
    "discovery",
    "initial-access",
    "delivery",
    "impact",
    "other",
}
TTP_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")


class SchemaValidationError(ValueError):
    """Raised when an emitted ground-truth bundle fails any of rules 1-11."""


# --- role mapping from event log + content to schema enum ---


def _classify_role(event: dict) -> str:
    """Best-effort mapping from a Zeek/Suricata event to a schema role.

    This is a coarse heuristic — the orchestrator will refine when it
    cross-references against the catalogue's per-incident chain knowledge.
    For v1 we map by log name + obvious port hints.
    """
    log_name = str(event.get("_log", "")).lower()
    event_type = str(event.get("event_type", "")).lower()  # Suricata field
    if event_type == "alert":
        return "other"
    if log_name in {"http", "files"} or event_type in {"http", "fileinfo"}:
        return "delivery"
    if log_name == "ssl" or event_type == "tls":
        return "c2"
    if log_name == "dns" or event_type == "dns":
        return "discovery"
    if log_name == "conn" or event_type == "flow":
        return "c2"
    return "other"


# --- event-id generation (deterministic) ---


def _event_id(incident_id: str, sequence: int) -> str:
    return f"evt-{incident_id}-{sequence:04d}"


# --- bundle construction ---


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


def build_ground_truth(
    *,
    entry: CatalogueEntry,
    events_ndjson_filename: str,
    rewritten_events: list[dict],
    corpus: CorpusBinding,
    injection_start: datetime,
    injection_end: datetime,
    ingestion_commit: str = "0" * 40,
    raw_artifact_hash: str = "0" * 64,
    confidence_override: str | None = None,
) -> dict:
    """Build the ground-truth dict for one incident.

    Args:
        entry: catalogue entry being annotated.
        events_ndjson_filename: filename of the events NDJSON file (used as
            the ``where.fixture_line.path`` for each event pointer).
        rewritten_events: events that have ALREADY been time/IP-rewritten.
            Each entry gets one event annotation with role + ttp_links.
        corpus: corpus binding (tier, build hash, baseline-gen config).
        injection_start: scheduled start of the splice window (UTC).
        injection_end: scheduled end of the splice window (UTC).
        ingestion_commit: git SHA of the ingest pipeline commit; 40 zeros
            allowed as a placeholder for v1 (matches the example file).
        raw_artifact_hash: sha256 of the upstream zip; 64 zeros allowed.
        confidence_override: force a confidence value; default maps H/M/L
            from the catalogue.

    Returns:
        Dict ready for YAML dump. Run ``validate_bundle`` on it before
        writing.
    """
    fidelity_to_confidence = {"H": "high", "M": "medium", "L": "low"}
    confidence = confidence_override or fidelity_to_confidence[entry.attribution_fidelity]

    # Per-event annotations. For each rewritten event we attach a stable
    # event_id (matching the NDJSON sequence) and best-effort role +
    # ttp_links. ttp_links default to all the catalogue's required TTPs
    # the orchestrator will refine these per-event later.
    events_block: list[dict] = []
    for i, ev in enumerate(rewritten_events, start=1):
        events_block.append({
            "id": _event_id(entry.incident_id, i),
            "where": {
                "fixture_line": {
                    "path": events_ndjson_filename,
                    "line": i,
                },
            },
            "role": _classify_role(ev),
            "ttp_links": list(entry.ttps_required[:1]) or list(entry.attribution_required[:1]),
        })

    # If there are no events (shouldn't happen in practice), emit a single
    # synthetic pointer to keep rule 6 happy — actually, better to FAIL.
    # Rule 6: events[] empty -> invalid. We let it fail in validation.

    duration_seconds = int((injection_end - injection_start).total_seconds())

    all_ttps = list(entry.all_ttps)
    accepted_alts = {k: list(v) for k, v in entry.accepted_alternates.items()}

    gt: dict = {
        "schema_version": SCHEMA_VERSION,
        "incident_id": entry.incident_id,
        "source_class": "cybercrime",
        "segment_class": "IT",
        "source": {
            "kind": "mta-pcap",
            "reference": entry.url,
            "ingestion_commit": ingestion_commit,
            "raw_artifact_hash": raw_artifact_hash,
        },
        "corpus": corpus.to_dict(),
        "time_window": {
            "injection_start": injection_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "injection_end": injection_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": duration_seconds,
        },
        "ttps": all_ttps,
        "ttps_optional": list(entry.ttps_optional),
        "confidence": confidence,
        "events": events_block,
        "expected_findings": {
            # IOCs are deferred to follow-up (per advisor): populating
            # them requires real PCAP parsing or hand-authoring per family.
            # Schema does NOT require any IOC subkey to be populated; the
            # subkeys we list here are documented as empty for v1.
            "iocs": {
                "sha256": [],
                "sha1": [],
                "md5": [],
                "ipv4": [],
                "domains": [],
                "urls": [],
                "file_names": [],
                "process_names": [],
                "email_headers": [],
                "registry_keys": [],
                "mutex_names": [],
            },
            "ttp_attribution": {
                "required": list(entry.attribution_required),
                "accepted_alternates": accepted_alts,
            },
            "narrative_facts": list(entry.narrative_facts),
        },
        "scoring": {
            "detection": {
                "found_threshold": 0.7,
                "partial_threshold": 0.3,
            },
            "attribution": {
                "weight": 0.5,
            },
            "discrimination": {
                "required": True,
            },
        },
        "notes": (
            f"Cybercrime-foil splice from MTA capture {entry.date} ({entry.family}). "
            "IOCs deferred to follow-up authoring pass; per-event role + ttp_links "
            "may be refined by the injection orchestrator."
        ),
    }
    return gt


# --- validator ---


def _check_one_of(where: dict) -> str:
    """Rule 7: events[i].where must have exactly one of doc_id / fixture_line."""
    populated = [k for k in ("doc_id", "fixture_line") if k in where and where[k]]
    if len(populated) != 1:
        raise SchemaValidationError(
            f"rule 7: events[].where must have exactly one of doc_id/fixture_line, "
            f"got {populated}"
        )
    return populated[0]


def validate_bundle(gt: dict, *, expected_build_hash: str | None = None) -> None:
    """Run all 11 schema validation rules; raise on first failure.

    Args:
        gt: the ground-truth dict (post-YAML-load or pre-YAML-dump).
        expected_build_hash: if provided, rule 8 is checked against this
            value (i.e. the orchestrator passes the hash of the produced
            corpus). If None, rule 8 is skipped (emit-time default).
    """
    # 1. schema_version known
    if gt.get("schema_version") not in KNOWN_SCHEMA_VERSIONS:
        raise SchemaValidationError(
            f"rule 1: unknown schema_version {gt.get('schema_version')!r}"
        )

    # 2. source_class in enum
    sc = gt.get("source_class")
    if sc not in SOURCE_CLASS_ENUM:
        raise SchemaValidationError(f"rule 2: invalid source_class {sc!r}")

    # 3. segment_class in enum
    segc = gt.get("segment_class")
    if segc not in SEGMENT_CLASS_ENUM:
        raise SchemaValidationError(f"rule 3: invalid segment_class {segc!r}")

    # 4. ttps non-empty for apt + cybercrime
    ttps = gt.get("ttps") or []
    if sc in {"apt", "cybercrime"} and len(ttps) < 1:
        raise SchemaValidationError(
            f"rule 4: ttps must be non-empty for source_class={sc!r}"
        )

    # 5. every ttp matches the regex
    all_ttps_to_check: list[str] = list(ttps) + list(gt.get("ttps_optional") or [])
    for t in all_ttps_to_check:
        if not TTP_REGEX.match(str(t)):
            raise SchemaValidationError(
                f"rule 5: ttp {t!r} does not match ^T\\d{{4}}(\\.\\d{{3}})?$"
            )

    # 6. events non-empty
    events = gt.get("events") or []
    if not events:
        raise SchemaValidationError("rule 6: events[] must be non-empty")

    # 7. each event.where has exactly one of doc_id/fixture_line populated
    for i, ev in enumerate(events):
        where = ev.get("where") or {}
        _check_one_of(where)
        # validate event role
        if ev.get("role") not in EVENT_ROLE_ENUM:
            raise SchemaValidationError(
                f"events[{i}].role {ev.get('role')!r} not in {sorted(EVENT_ROLE_ENUM)}"
            )

    # 8. corpus.build_hash matches produced corpus
    #    Skipped at emit time; the orchestrator passes expected_build_hash.
    if expected_build_hash is not None:
        actual = (gt.get("corpus") or {}).get("build_hash")
        if actual != expected_build_hash:
            raise SchemaValidationError(
                f"rule 8: corpus.build_hash {actual!r} != expected {expected_build_hash!r}"
            )

    # 9. duration_seconds == end - start
    tw = gt.get("time_window") or {}
    try:
        start = _parse_iso(tw["injection_start"])
        end = _parse_iso(tw["injection_end"])
    except (KeyError, ValueError) as exc:
        raise SchemaValidationError(f"rule 9: time_window parse error: {exc}") from exc
    actual_duration = int((end - start).total_seconds())
    if actual_duration != tw.get("duration_seconds"):
        raise SchemaValidationError(
            f"rule 9: duration_seconds {tw.get('duration_seconds')} != "
            f"end-start {actual_duration}"
        )

    # 10. found_threshold >= partial_threshold
    sd = (gt.get("scoring") or {}).get("detection") or {}
    if sd.get("found_threshold", 0) < sd.get("partial_threshold", 0):
        raise SchemaValidationError(
            f"rule 10: found_threshold {sd.get('found_threshold')} < "
            f"partial_threshold {sd.get('partial_threshold')}"
        )

    # 11. ttp_attribution.required subset of ttps
    required_attr = (
        (gt.get("expected_findings") or {})
        .get("ttp_attribution", {})
        .get("required", [])
    )
    ttps_set = set(ttps)
    extra = [t for t in required_attr if t not in ttps_set]
    if extra:
        raise SchemaValidationError(
            f"rule 11: ttp_attribution.required {extra} not a subset of ttps {sorted(ttps_set)}"
        )


def _parse_iso(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


# --- writer ---


def write_bundle(
    *,
    entry: CatalogueEntry,
    rewritten_events: list[dict],
    corpus: CorpusBinding,
    injection_start: datetime,
    injection_end: datetime,
    bundle_dir: Path,
    ingestion_commit: str = "0" * 40,
    raw_artifact_hash: str = "0" * 64,
    confidence_override: str | None = None,
) -> tuple[Path, Path]:
    """Write NDJSON + YAML to ``bundle_dir``. Validate before writing.

    Returns:
        ``(ndjson_path, yaml_path)``.

    Raises:
        SchemaValidationError if the generated ground-truth fails any rule.
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    ndjson_name = f"{entry.incident_id}.events.ndjson"
    yaml_name = f"{entry.incident_id}.ground-truth.yaml"

    gt = build_ground_truth(
        entry=entry,
        events_ndjson_filename=ndjson_name,
        rewritten_events=rewritten_events,
        corpus=corpus,
        injection_start=injection_start,
        injection_end=injection_end,
        ingestion_commit=ingestion_commit,
        raw_artifact_hash=raw_artifact_hash,
        confidence_override=confidence_override,
    )

    # Validate BEFORE writing — fail loud, leave no half-written artefacts.
    validate_bundle(gt)  # rule 8 skipped at emit time

    ndjson_path = bundle_dir / ndjson_name
    yaml_path = bundle_dir / yaml_name

    with ndjson_path.open("w", encoding="utf-8") as f:
        for i, ev in enumerate(rewritten_events, start=1):
            obj = dict(ev)
            obj["event_id"] = _event_id(entry.incident_id, i)
            f.write(json.dumps(obj, default=str) + "\n")

    with yaml_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(gt, f, sort_keys=False, allow_unicode=True)

    log.info("wrote bundle: %s, %s (%d events)", ndjson_path, yaml_path, len(rewritten_events))
    return ndjson_path, yaml_path


def load_ground_truth(path: Path) -> dict:
    """Convenience: load + parse a ground-truth YAML."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_events_ndjson(path: Path) -> Iterable[dict]:
    """Convenience: stream-parse an events NDJSON file."""
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)
