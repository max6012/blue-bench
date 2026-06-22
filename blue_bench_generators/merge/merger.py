"""Merge OT + IT/OT-bridge telemetry into an EvidenceForge corpus (EF-P4b).

EvidenceForge generates the benign IT telemetry under ``<ef_dir>/data/<host>/``.
This merger drives the unchanged Blue-Bench OT generators (``ot_protocols``,
``ot_hosts``) and the IT/OT bridge over the *same* time window EF used (read
from ``GROUND_TRUTH.json``) and the *same* host inventory (via the scenario
shim), writing their events as NDJSON into the corpus tree:

    <ef_dir>/ot/<log>.ndjson          modbus/dnp3/iec104/s7comm/conn (OT protocols)
    <ef_dir>/ot_hosts/<log>.ndjson    hmi/historian/eng-ws/ot-auth host logs
    <ef_dir>/bridge/<source>.<log>.ndjson   IT/OT bridge sessions, by routed source

A ``corpus-manifest.yaml`` records the build with a content ``build_hash`` over
every telemetry file (EF + OT + bridge), excluding the EF metadata files whose
``generated_at`` stamp would otherwise make the hash non-deterministic. Same
(ef_dir, scenario, tier, seed) -> identical OT/bridge bytes and identical hash.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from blue_bench_generators import it_ot_bridge, ot_hosts, ot_protocols
from blue_bench_generators.it_baseline.composer import _sha256_file
from blue_bench_generators.merge.scenario_topology import shim_from_scenario

log = logging.getLogger(__name__)

# EF metadata files: excluded from build_hash (generated_at varies) and never
# treated as telemetry.
_EF_META = {"GROUND_TRUTH.json", "GROUND_TRUTH.md", "OUTPUT_TARGET.txt",
            "OBSERVATION_MANIFEST.json", "corpus-manifest.yaml"}

# Managed subdirs this merger writes — wiped before write so a re-merge leaves
# no orphan OT/bridge files.
_MANAGED = ("ot", "ot_hosts", "bridge")


def _ndjson_sort_key(ev: dict) -> tuple:
    """Stable order: epoch ts (or ISO timestamp) then uid/bridge_session_uid."""
    ts = ev.get("ts")
    try:
        tk = float(ts) if ts not in (None, "") else 0.0
    except (TypeError, ValueError):
        tk = 0.0
    return (tk, str(ev.get("timestamp", "")), str(ev.get("uid", "")),
            str(ev.get("bridge_session_uid", "")))


def _write_ndjson_by_log(events: list[dict], out_dir: Path, *, prefix: str = "") -> int:
    """Group events by ``_log``, strip internal ``_``-fields, write one NDJSON
    per log type. Returns the number of events written."""
    by_log: dict[str, list[dict]] = {}
    for ev in events:
        by_log.setdefault(str(ev.get("_log", "events")), []).append(ev)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for logname, evs in sorted(by_log.items()):
        evs = sorted(evs, key=_ndjson_sort_key)
        name = f"{prefix}{logname}.ndjson" if prefix else f"{logname}.ndjson"
        path = out_dir / name
        with path.open("w", encoding="utf-8", newline="") as f:
            for ev in evs:
                doc = {k: v for k, v in ev.items() if not k.startswith("_")}
                f.write(json.dumps(doc, sort_keys=True, default=str) + "\n")
        written += len(evs)
    return written


def _parse_window(ef_dir: Path) -> tuple[datetime, datetime]:
    gt = json.loads((ef_dir / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    cw = gt["collection_window"]

    def _naive(s: str) -> datetime:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).replace(tzinfo=None)

    return _naive(cw["start"]), _naive(cw["end"])


def _content_hash(ef_dir: Path) -> tuple[str, list[dict[str, Any]]]:
    """sha256 over (relpath, sha256) of every telemetry file, sorted by path.
    Excludes EF metadata files (``generated_at`` would break determinism)."""
    files: list[dict[str, Any]] = []
    for p in sorted(ef_dir.rglob("*")):
        if not p.is_file() or p.name in _EF_META:
            continue
        rel = str(p.relative_to(ef_dir))
        files.append({"path": rel, "sha256": _sha256_file(p), "bytes": p.stat().st_size})
    blob = "\n".join(f"{f['path']}\t{f['sha256']}" for f in files)
    return hashlib.sha256(blob.encode()).hexdigest(), files


def merge_corpus(
    ef_dir: str | Path,
    scenario_path: str | Path,
    *,
    tier: str,
    seed: int = 0,
) -> dict[str, Any]:
    """Drive OT + bridge over the EF window/inventory and write them into the
    EF corpus tree, then emit ``corpus-manifest.yaml``. Returns the manifest."""
    ef_dir = Path(ef_dir)
    if not (ef_dir / "GROUND_TRUTH.json").is_file():
        raise FileNotFoundError(f"{ef_dir} is not an EF corpus (no GROUND_TRUTH.json)")

    # Wipe managed subdirs so a re-merge is clean.
    for name in _MANAGED:
        d = ef_dir / name
        if d.is_dir():
            for f in d.rglob("*"):
                if f.is_file():
                    f.unlink()

    start, end = _parse_window(ef_dir)
    shim = shim_from_scenario(scenario_path, tier=tier, seed=seed)
    log.info("merge: tier=%s seed=%d window=%s..%s hosts=%d",
             tier, seed, start, end, len(shim.hosts))

    ot_events = list(ot_protocols.generate(shim, None, start, end, seed=seed))
    oth_events = list(ot_hosts.generate(shim, None, start, end, seed=seed))
    bridge_events = list(it_ot_bridge.generate(shim, None, start, end, seed=seed))

    n_ot = _write_ndjson_by_log(ot_events, ef_dir / "ot")
    n_oth = _write_ndjson_by_log(oth_events, ef_dir / "ot_hosts")

    # Bridge events fan across routed sources; write one NDJSON per (source, log).
    by_source: dict[str, list[dict]] = {}
    for ev in bridge_events:
        by_source.setdefault(str(ev.get("_source", "other")), []).append(ev)
    n_bridge = 0
    for source, evs in sorted(by_source.items()):
        n_bridge += _write_ndjson_by_log(evs, ef_dir / "bridge", prefix=f"{source}.")

    build_hash, files = _content_hash(ef_dir)
    manifest = {
        "schema_version": 1,
        "tier": tier,
        "ot_seed": seed,
        "build_hash": build_hash,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "scenario": str(scenario_path),
        "segments": {
            "ef_it": "data/",
            "ot_protocols": {"events": n_ot},
            "ot_hosts": {"events": n_oth},
            "bridge": {"events": n_bridge, "sources": sorted(by_source)},
        },
        "file_count": len(files),
        "total_bytes": sum(f["bytes"] for f in files),
    }
    (ef_dir / "corpus-manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8", newline="")
    log.info("merge: ot=%d ot_hosts=%d bridge=%d build_hash=%s",
             n_ot, n_oth, n_bridge, build_hash[:12])
    return manifest
