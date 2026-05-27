"""IT-baseline corpus composer + tier scaling + corpus output.

Orchestrates the seven per-source telemetry generators into a unified corpus
build under ``<output_dir>/{zeek,suricata,sysmon,evtx,linux,identity,services}/``
plus a top-level ``corpus-manifest.yaml``. The tier knob drives only
topology population size and time-window length (S=1 day, M=7 days,
L=14 days) per the ``t-s0jw`` decision; host populations, services, and the
behavior model are tier-invariant.

Determinism contract: ``build_corpus(tier, output_dir, seed=N)`` produces a
byte-identical corpus across runs for the same ``(tier, seed, start,
duration_days)`` tuple. Per-source streams are pre-sorted by a key composed
of timestamp + a per-source unique id (Zeek ``uid``/``fuid``, Suricata
``flow_id``, Sysmon / EVTX ``EventID`` / ``RecordID``, identity ``event_id``,
Linux ``msg_id``) so collisions on the timestamp do not silently fall
through to generator-emission-order. Generator emission order is itself
deterministic, so the sort is belt-and-suspenders, not load-bearing.

Vendor-neutral. No exercise vocabulary in any emitted artefact.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

import yaml

from blue_bench_generators import ot_hosts, ot_protocols
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
from blue_bench_generators.ot_protocols.topology import build_ot_network

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

# Managed source subdirectories. ``corpus-manifest.yaml`` at the root of an
# output dir identifies it as composer-produced and authorises wipe-before-write
# of these subdirs; anything else is left untouched.
_MANAGED_SOURCE_DIRS: tuple[str, ...] = (
    "zeek", "suricata", "sysmon", "evtx", "linux", "identity", "services", "ot", "ot_hosts",
)


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
        output_dir: target directory. Created if missing. Files inside the
            seven managed source subdirectories (``zeek``, ``suricata``,
            ``sysmon``, ``evtx``, ``linux``, ``identity``, ``services``) are
            deleted before write so a re-build of a smaller tier into the
            same directory leaves no orphans. Files at the output root and
            in unmanaged subdirectories are left alone.
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
        start = start.astimezone(timezone.utc).replace(tzinfo=None)
    days = duration_days if duration_days is not None else TIER_DURATION_DAYS[tier]
    if days < 1:
        raise ValueError(f"duration_days must be >= 1, got {days}")
    end = start + timedelta(days=days)

    output_dir = Path(output_dir)
    # Guard rail: if the output dir already exists and contains managed
    # subdirectories WITHOUT a corpus-manifest.yaml, this is almost
    # certainly not a previous composer build -- refuse rather than
    # silently wipe whatever's there. A composer-produced directory always
    # has a manifest at its root, so its presence is a reliable
    # provenance marker.
    manifest_path = output_dir / "corpus-manifest.yaml"
    if output_dir.exists() and not manifest_path.exists():
        existing_managed = [
            name for name in _MANAGED_SOURCE_DIRS
            if (output_dir / name).is_dir() and any((output_dir / name).iterdir())
        ]
        if existing_managed:
            raise ValueError(
                f"refusing to overwrite non-composer subdirectories in {output_dir}: "
                f"{existing_managed}. Either delete the directory manually or pick a "
                f"fresh --output path."
            )
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info(
        "composer: tier=%s seed=%d window=%s..%s output=%s",
        tier, seed, start.isoformat(), end.isoformat(), output_dir,
    )

    topology = topo_mod.build_topology(tier=tier, seed=seed)
    activity_model = behavior.build_activity_model(topology, seed=seed)
    # OT plant-network is built here so its device count flows into the
    # manifest. The per-protocol generators re-build it internally from
    # the IT topology's tier/seed -- duplicate builds are cheap and
    # cross-process determinism is preserved.
    ot_network = build_ot_network(tier=tier, seed=seed)

    # (source_name, module, format_kind). Order is stable so manifest
    # iteration order is deterministic. ``ot`` uses the same Zeek-TSV
    # writer as ``zeek`` -- its events carry ``_log`` ∈ {conn, modbus,
    # dnp3, iec104, s7comm} and route into per-log files under ``ot/``.
    source_specs: tuple[tuple[str, Any, str], ...] = (
        ("zeek", network_zeek, "zeek_tsv"),
        ("suricata", suricata_noise, "jsonl_eve"),
        ("sysmon", sysmon, "jsonl_one"),
        ("evtx", evtx, "jsonl_by_channel"),
        ("linux", linux_logs, "linux_mixed"),
        ("identity", identity, "jsonl_one"),
        ("services", services, "jsonl_by_log"),
        ("ot", ot_protocols, "zeek_tsv"),
        ("ot_hosts", ot_hosts, "jsonl_by_log"),
    )

    sources_meta: list[dict[str, Any]] = []
    for source_name, module, format_kind in source_specs:
        events = list(module.generate(topology, activity_model, start, end, seed=seed))
        source_dir = output_dir / source_name
        # Wipe stale files from any prior build into the same directory.
        # Without this, re-building a smaller tier (e.g. S over a previous M)
        # would leave orphan files on disk that aren't in the new manifest
        # and don't affect ``build_hash`` -- silent staleness for consumers
        # that glob the directory.
        if source_dir.exists():
            for stale in source_dir.iterdir():
                if stale.is_file():
                    stale.unlink()
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
        ot_network=ot_network,
        sources_meta=sources_meta,
    )
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
        newline="",
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
        # ``newline=""`` disables platform newline translation so the file
        # is byte-identical across Linux / macOS / Windows for the same
        # ``(tier, seed)`` -- the determinism contract requires it.
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
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


_ZEEK_ESCAPES = str.maketrans({"\t": "\\x09", "\n": "\\x0a", "\r": "\\x0d", "\\": "\\\\"})


def _zeek_value(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        # Canonical Zeek bool encoding (matches data/raw/conn.log fixture).
        # Listed BEFORE ``int`` because bool is a subclass of int in Python.
        return "T" if v else "F"
    if isinstance(v, (list, tuple)):
        return ",".join(_zeek_value(x) for x in v) if v else "(empty)"
    if isinstance(v, dict):
        # ``str(dict)`` produces invalid TSV that no column-count check
        # would catch -- surface the bug at build time instead.
        raise TypeError(
            f"unsupported Zeek value type {type(v).__name__}: {v!r}; "
            f"nested dicts cannot be flattened into a TSV column"
        )
    return str(v).translate(_ZEEK_ESCAPES)


def _json_strict(v: Any) -> str:
    """``json.dumps(default=...)`` hook that refuses to silently coerce
    unexpected types via ``str()``. A ``datetime`` slipping through, for
    example, would otherwise become ``"2026-01-05 00:00:00"`` -- not
    ISO-8601 -- and tests downstream of JSON-parsing wouldn't catch it.
    Generators are expected to emit JSON-native types only."""
    raise TypeError(
        f"non-serialisable value of type {type(v).__name__}: {v!r}; "
        f"generators must emit JSON-native types (no datetime / Path / set)"
    )


def _write_jsonl(events: list[dict], path: Path, output_root: Path) -> list[dict]:
    """Write JSONL. ``_log`` is a generator-internal routing field and is
    stripped from each record before serialisation -- real Suricata
    ``eve.json`` / Sysmon / auditd telemetry has no such field, and any
    phantom column would surface to MCP consumers."""
    sorted_events = sorted(events, key=_event_sort_key)
    # ``newline=""`` disables platform newline translation so the file is
    # byte-identical across OSes for the same (tier, seed) -- determinism
    # contract requirement.
    with path.open("w", encoding="utf-8", newline="") as f:
        for ev in sorted_events:
            payload = {k: v for k, v in ev.items() if k != "_log"}
            f.write(json.dumps(payload, sort_keys=True, default=_json_strict) + "\n")
    return [_file_meta(path, output_root, len(sorted_events))]


def _write_jsonl_by_field(
    events: list[dict],
    source_dir: Path,
    output_root: Path,
    *,
    field: str,
    suffix: str,
) -> list[dict]:
    """Partition events into one JSONL per distinct value of ``field`` and
    write each. Missing-routing-field is a generator-contract violation
    and raises -- previously such records would silently bucket into
    ``other.jsonl`` and a routing bug would slip past every test."""
    by_value: dict[str, list[dict]] = {}
    for ev in events:
        if field not in ev:
            raise ValueError(
                f"event missing routing field {field!r}: {ev!r}; "
                f"generator-contract violation -- every emitted event must "
                f"carry the partition key the composer routes on"
            )
        key = str(ev[field]).lower().replace("/", "_").replace(" ", "_")
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
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
    return [_file_meta(path, output_root, len(sorted_events))]


def _event_sort_key(ev: dict) -> tuple:
    """Sort key tolerant of both Zeek (``ts`` = epoch-seconds string) and
    ISO (``timestamp``) generators. ``ts`` is parsed as float so the sort
    is numeric -- lex sort happens to match numeric order only while the
    epoch has 10 digits (i.e. dates from 2001-09-09 onward), and the
    default window is comfortably inside that, but a tier-time-machine
    override could land on the wrong side.

    Tie-breakers cover the per-source unique id field so two records
    emitted at the same timestamp are ordered independently of
    generator emission order: Zeek ``uid`` / ``fuid``, Suricata
    ``flow_id``, Sysmon / EVTX ``EventID`` / ``RecordID``, identity
    ``event_id``, Linux ``msg_id``, then host/hostname."""
    ts_raw = ev.get("ts")
    try:
        ts_key = float(ts_raw) if ts_raw not in (None, "") else 0.0
    except (TypeError, ValueError):
        ts_key = 0.0
    return (
        ts_key,
        str(ev.get("timestamp", "")),
        str(ev.get("uid", ev.get("fuid", ""))),
        str(ev.get("flow_id", "")),
        str(ev.get("EventID", ev.get("event_id", ""))),
        str(ev.get("RecordID", "")),
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
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_manifest(
    *,
    tier: str,
    seed: int,
    start: datetime,
    end: datetime,
    topology: topo_mod.Topology,
    ot_network,
    sources_meta: list[dict[str, Any]],
) -> dict[str, Any]:
    # build_hash = sha256 over (source_path, sha256) pairs sorted by path.
    # This is a CONTENT hash: it detects any change to any file or any
    # rename, but it does NOT cover metadata (``tier``, ``seed``, ``window``,
    # topology counts). Two builds with identical file contents but different
    # metadata labels would share a build_hash -- intentional, but callers
    # treating build_hash as a corpus-identity primary key should combine it
    # with ``(tier, seed, window.start, window.end)`` themselves.
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
            "ot_devices": len(ot_network.devices),
            "ot_vlans": len(ot_network.vlans),
            "ot_links": len(ot_network.links),
            # Per-protocol link counts so consumers can tell at a glance
            # which protocols this corpus covers without grepping the
            # OT log files.
            "ot_protocols": {
                proto: sum(1 for l in ot_network.links if l.protocol == proto)
                for proto in ("modbus", "dnp3", "iec104", "s7comm")
            },
            # Per-role count of OT hosts that emit application-level
            # logs (the ``ot_hosts`` source). Embedded RTOS roles
            # (controller/safety/rtu) are excluded -- they have no host
            # log surface.
            "ot_logging_hosts": {
                role: sum(1 for d in ot_network.devices if d.role == role)
                for role in ("hmi", "engineering-workstation", "historian", "ot-firewall")
            },
        },
        "totals": {
            "events": total_events,
            "bytes": total_bytes,
            "source_files": sum(len(s["files"]) for s in sources_meta),
        },
        "sources": sources_meta,
    }
