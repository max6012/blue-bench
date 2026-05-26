"""IT-baseline corpus composer + tier scaling + corpus output.

Orchestrates the seven per-source telemetry generators into a unified corpus
build under ``<output_dir>/{zeek,suricata,sysmon,evtx,linux,identity,services}/``
plus a top-level ``corpus-manifest.yaml``. The tier knob drives only
topology population size and time-window length (S=1 day, M=7 days,
L=14 days) per the ``t-s0jw`` decision; host populations, services, and the
behavior model are tier-invariant.

Determinism contract: ``build_corpus(tier, output_dir, seed=N)`` produces a
byte-identical corpus across runs for the same ``(tier, seed, start,
duration_days)`` tuple. Per-source streams are sorted by ``(ts, uid)`` (or
``(timestamp, host)``) before write so reordering inside a generator does
not leak into output bytes.

Vendor-neutral. No exercise vocabulary in any emitted artefact.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Literal

import yaml

from blue_bench_generators.it_baseline import (
    behavior,
    evtx,
    identity,
    linux_logs,
    network_zeek,
    services,
    suricata_noise,
    sysmon,
    topology as topo_mod,
)

log = logging.getLogger(__name__)

Tier = Literal["S", "M", "L"]

# Per-tier corpus duration. S/M/L are downscalings of the same topology;
# scale (host count + time window) is the only variable across tiers.
TIER_DURATION_DAYS: dict[str, int] = {"S": 1, "M": 7, "L": 14}

# Default time-window anchor: Monday 2026-01-05 00:00 (naive — generators
# use naive datetimes throughout, see tests/test_it_baseline_*). Fixed so
# that ``(tier, seed)`` alone determines the corpus. Anchored on a Monday so
# S (1 day) lands on a weekday and exercises the time-of-day weekday
# multiplier rather than the weekend baseline floor.
DEFAULT_START = datetime(2026, 1, 5, 0, 0, 0)


def build_corpus(
    tier: Tier,
    output_dir: Path,
    *,
    seed: int = 0,
    start: datetime | None = None,
    duration_days: int | None = None,
) -> dict[str, Any]:
    """Build a complete IT-baseline corpus.

    Args:
        tier: "S", "M", or "L". Drives topology population + default duration.
        output_dir: target directory. Created if missing. Existing source
            directories are overwritten file-by-file but no other files are
            removed.
        seed: deterministic seed threaded through topology, behavior, and
            every per-source generator.
        start: UTC window start. Defaults to ``DEFAULT_START``.
        duration_days: override for per-tier duration.

    Returns:
        The manifest dict that was also written to
        ``<output_dir>/corpus-manifest.yaml``.
    """
    if tier not in TIER_DURATION_DAYS:
        raise ValueError(f"unknown tier {tier!r}; expected one of {list(TIER_DURATION_DAYS)}")
    start = start or DEFAULT_START
    if start.tzinfo is not None:
        # Generators assume naive datetimes; reduce a tz-aware ``--start``
        # to its UTC wall-clock value so the per-source comparators
        # (e.g. services.py:348) don't trip on offset-naive-vs-aware.
        from datetime import timezone as _tz
        start = start.astimezone(_tz.utc).replace(tzinfo=None)
    days = duration_days if duration_days is not None else TIER_DURATION_DAYS[tier]
    if days < 1:
        raise ValueError(f"duration_days must be >= 1, got {days}")
    end = start + timedelta(days=days)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info(
        "composer: tier=%s seed=%d window=%s..%s output=%s",
        tier, seed, start.isoformat(), end.isoformat(), output_dir,
    )

    topology = topo_mod.build_topology(tier=tier, seed=seed)
    activity_model = behavior.build_activity_model(topology, seed=seed)

    # (source_name, module, format_kind). Order is stable so manifest
    # iteration order is deterministic.
    source_specs: tuple[tuple[str, Any, str], ...] = (
        ("zeek", network_zeek, "zeek_tsv"),
        ("suricata", suricata_noise, "jsonl_eve"),
        ("sysmon", sysmon, "jsonl_one"),
        ("evtx", evtx, "jsonl_by_channel"),
        ("linux", linux_logs, "linux_mixed"),
        ("identity", identity, "jsonl_one"),
        ("services", services, "jsonl_by_log"),
    )

    sources_meta: list[dict[str, Any]] = []
    for source_name, module, format_kind in source_specs:
        events = list(module.generate(topology, activity_model, start, end, seed=seed))
        source_dir = output_dir / source_name
        source_dir.mkdir(exist_ok=True)
        files_meta = _write_source(source_name, format_kind, events, source_dir, output_dir)
        sources_meta.append(
            {
                "source": source_name,
                "event_count": len(events),
                "files": files_meta,
            }
        )
        log.info("composer: %s emitted %d events across %d files", source_name, len(events), len(files_meta))

    manifest = _build_manifest(
        tier=tier,
        seed=seed,
        start=start,
        end=end,
        topology=topology,
        sources_meta=sources_meta,
    )
    manifest_path = output_dir / "corpus-manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    log.info("composer: wrote manifest %s build_hash=%s", manifest_path, manifest["build_hash"][:12])
    return manifest


# --- per-source writers ----------------------------------------------------


def _write_source(
    name: str,
    kind: str,
    events: list[dict],
    source_dir: Path,
    output_root: Path,
) -> list[dict[str, Any]]:
    if kind == "zeek_tsv":
        return _write_zeek_tsv(events, source_dir, output_root)
    if kind == "jsonl_eve":
        return _write_jsonl(events, source_dir / "eve.json", output_root)
    if kind == "jsonl_one":
        return _write_jsonl(events, source_dir / f"{name}.jsonl", output_root)
    if kind == "jsonl_by_channel":
        return _write_jsonl_by_field(events, source_dir, output_root, field="channel", suffix=".jsonl")
    if kind == "jsonl_by_log":
        return _write_jsonl_by_field(events, source_dir, output_root, field="_log", suffix=".jsonl")
    if kind == "linux_mixed":
        return _write_linux(events, source_dir, output_root)
    raise ValueError(f"unknown format kind: {kind!r}")


def _write_zeek_tsv(events: list[dict], source_dir: Path, output_root: Path) -> list[dict]:
    """Emit Zeek TSV — one file per ``_log`` value (conn/dns/http/ssl/files).

    Header matches the existing ``data/raw/conn.log`` fixture so the
    ``scripts/seed_es.py`` parser (which reads ``#fields``) ingests unchanged.
    """
    by_log: dict[str, list[dict]] = {}
    for ev in events:
        by_log.setdefault(ev["_log"], []).append(ev)

    files_meta: list[dict] = []
    for log_name, recs in sorted(by_log.items()):
        recs_sorted = sorted(recs, key=lambda r: (str(r.get("ts", "")), str(r.get("uid", r.get("fuid", "")))))
        fields = _zeek_field_order(recs_sorted)
        path = source_dir / f"{log_name}.log"
        lines = [
            "#separator \\x09",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            f"#path\t{log_name}",
            "#fields\t" + "\t".join(fields),
        ]
        for r in recs_sorted:
            row = [_zeek_value(r.get(k)) for k in fields]
            lines.append("\t".join(row))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        files_meta.append(_file_meta(path, output_root, len(recs_sorted)))
    return files_meta


def _zeek_field_order(records: list[dict]) -> list[str]:
    """Stable field order: priority columns first, remainder sorted."""
    keys: set[str] = set()
    for r in records:
        keys.update(k for k in r.keys() if k != "_log")
    priority = ("ts", "uid", "fuid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service")
    head = [k for k in priority if k in keys]
    tail = sorted(k for k in keys if k not in priority)
    return head + tail


def _zeek_value(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, (list, tuple)):
        return ",".join(_zeek_value(x) for x in v) if v else "(empty)"
    return str(v)


def _write_jsonl(events: list[dict], path: Path, output_root: Path) -> list[dict]:
    sorted_events = sorted(events, key=_event_sort_key)
    with path.open("w", encoding="utf-8") as f:
        for ev in sorted_events:
            f.write(json.dumps(ev, sort_keys=True, default=str) + "\n")
    return [_file_meta(path, output_root, len(sorted_events))]


def _write_jsonl_by_field(
    events: list[dict],
    source_dir: Path,
    output_root: Path,
    *,
    field: str,
    suffix: str,
) -> list[dict]:
    by_value: dict[str, list[dict]] = {}
    for ev in events:
        raw = ev.get(field, "other")
        key = str(raw).lower().replace("/", "_").replace(" ", "_")
        by_value.setdefault(key, []).append(ev)
    files_meta: list[dict] = []
    for value, recs in sorted(by_value.items()):
        files_meta.extend(_write_jsonl(recs, source_dir / f"{value}{suffix}", output_root))
    return files_meta


def _write_linux(events: list[dict], source_dir: Path, output_root: Path) -> list[dict]:
    """Linux outputs: auditd → JSONL (auditd text format is messy);
    ``auth_log`` and ``syslog`` → text (the canonical syslog wire form)."""
    by_log: dict[str, list[dict]] = {}
    for ev in events:
        by_log.setdefault(ev["_log"], []).append(ev)
    files_meta: list[dict] = []
    if "auditd" in by_log:
        files_meta.extend(_write_jsonl(by_log["auditd"], source_dir / "auditd.jsonl", output_root))
    if "auth_log" in by_log:
        files_meta.extend(_write_syslog_text(by_log["auth_log"], source_dir / "auth.log", output_root))
    if "syslog" in by_log:
        files_meta.extend(_write_syslog_text(by_log["syslog"], source_dir / "syslog", output_root))
    return files_meta


def _write_syslog_text(events: list[dict], path: Path, output_root: Path) -> list[dict]:
    sorted_events = sorted(events, key=_event_sort_key)
    lines: list[str] = []
    for ev in sorted_events:
        ts = ev.get("timestamp", "")
        host = ev.get("hostname", "")
        proc = ev.get("process", "")
        pid = ev.get("pid", "")
        msg = ev.get("message", "")
        if proc:
            line = f"{ts} {host} {proc}[{pid}]: {msg}"
        else:
            line = f"{ts} {host} {msg}"
        lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [_file_meta(path, output_root, len(sorted_events))]


def _event_sort_key(ev: dict) -> tuple:
    """Sort key tolerant of both Zeek (``ts`` = epoch string) and ISO
    (``timestamp``) generators. Tie-break on uid / msg_id / host."""
    return (
        str(ev.get("ts", "")),
        str(ev.get("timestamp", "")),
        str(ev.get("uid", "")),
        str(ev.get("msg_id", "")),
        str(ev.get("host", ev.get("hostname", ""))),
    )


# --- manifest --------------------------------------------------------------


def _file_meta(path: Path, output_root: Path, event_count: int) -> dict[str, Any]:
    return {
        "path": str(path.relative_to(output_root)),
        "events": event_count,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _build_manifest(
    *,
    tier: str,
    seed: int,
    start: datetime,
    end: datetime,
    topology: topo_mod.Topology,
    sources_meta: list[dict[str, Any]],
) -> dict[str, Any]:
    # build_hash = sha256 over (source_path, sha256) pairs sorted by path.
    # Per-file hashes already cover every byte of every file; aggregating the
    # path-hash pairs is enough to detect any change to any file or any
    # rename.
    pairs: list[str] = []
    total_events = 0
    total_bytes = 0
    for source in sources_meta:
        for f in source["files"]:
            pairs.append(f"{f['path']}\t{f['sha256']}")
            total_bytes += f["bytes"]
        total_events += source["event_count"]
    build_hash = hashlib.sha256("\n".join(sorted(pairs)).encode()).hexdigest()
    return {
        "schema_version": 1,
        "tier": tier,
        "seed": seed,
        "build_hash": build_hash,
        "window": {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "duration_days": (end - start).days,
        },
        "topology": {
            "hosts": len(topology.hosts),
            "users": len(topology.users),
            "services": len(topology.services),
            "vlans": len(topology.vlans),
        },
        "totals": {
            "events": total_events,
            "bytes": total_bytes,
            "source_files": sum(len(s["files"]) for s in sources_meta),
        },
        "sources": sources_meta,
    }
