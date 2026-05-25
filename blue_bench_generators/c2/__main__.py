"""CLI driver for the synthetic C2 generator.

Subcommands::

    profiles list
        Print the preset library (commodity + stealth).

    beacon <preset-name> --target <ip> --callbacks <csv>
                         --start <iso8601> --duration <sec> --seed <int>
        Generate a beacon stream and dump it to stdout as NDJSON, one
        BeaconEvent per line. For inspection / debugging only -- no
        Zeek / Suricata records emitted.

    bundle <preset-name> --incident-id <id> --target <ip>
                         --callbacks <csv> --start <iso8601>
                         --duration <sec> --corpus-build-hash <sha>
                         --out <dir> --seed <int>
                         [--corpus-tier S|M|L]
                         [--baseline-config <path>]
        Generate beacons, emit Zeek + Suricata records, and write a full
        annotated bundle to ``<out>/<incident-id>/``.

Style: argparse, stdlib logging, no Click / Typer (matches
``scripts/seed_es.py`` and the cybercrime_foil CLI).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from blue_bench_generators.c2 import profiles
from blue_bench_generators.c2.beacon import generate_beacons
from blue_bench_generators.c2.bundle import (
    CorpusBinding,
    SchemaValidationError,
    write_bundle,
)
from blue_bench_generators.c2.suricata_emit import (
    emit_for_profile as suricata_emit_for_profile,
)
from blue_bench_generators.c2.zeek_emit import (
    emit_for_profile as zeek_emit_for_profile,
)

log = logging.getLogger("blue_bench_generators.c2")


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BUNDLE_DIR = REPO_ROOT / "data" / "bundles" / "c2"


# Default callback IPs use TEST-NET-3 documentation range (RFC 5737)
# to avoid leaking real infrastructure into demo bundles.
DEFAULT_CALLBACKS = ("203.0.113.42", "203.0.113.99")


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_callbacks(s: str | None) -> list[str]:
    if not s:
        return list(DEFAULT_CALLBACKS)
    return [tok.strip() for tok in s.split(",") if tok.strip()]


# --- subcommands ---


def cmd_profiles_list(args: argparse.Namespace) -> int:
    for p in profiles.COMMODITY_PRESETS:
        print(
            f"{p.name}\t[commodity]\tttps={','.join(p.ttps)}\t"
            f"interval={p.beacon_interval_seconds:.0f}s\t{p.family}"
        )
    for p in profiles.STEALTH_PRESETS:
        print(
            f"{p.name}\t[stealth]  \tttps={','.join(p.ttps)}\t"
            f"interval={p.beacon_interval_seconds:.0f}s\t{p.family}"
        )
    return 0


def cmd_beacon(args: argparse.Namespace) -> int:
    profile = profiles.get_preset(args.preset)
    callbacks = _parse_callbacks(args.callbacks)
    start = _parse_iso(args.start)
    beacons = generate_beacons(
        profile=profile,
        target_host_ip=args.target,
        callback_targets=callbacks,
        start_time=start,
        duration_seconds=args.duration,
        seed=args.seed,
    )
    for b in beacons:
        d = dataclasses.asdict(b)
        d["timestamp"] = b.timestamp.isoformat()
        sys.stdout.write(json.dumps(d) + "\n")
    log.info("emitted %d beacons (profile=%s)", len(beacons), profile.name)
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    profile = profiles.get_preset(args.preset)
    callbacks = _parse_callbacks(args.callbacks)
    start = _parse_iso(args.start)
    end = start.replace() + (start - start)  # placeholder, recomputed below

    beacons = generate_beacons(
        profile=profile,
        target_host_ip=args.target,
        callback_targets=callbacks,
        start_time=start,
        duration_seconds=args.duration,
        seed=args.seed,
    )
    if not beacons:
        log.error(
            "no beacons generated; duration %ss too short for profile %s "
            "(interval mean %ss)",
            args.duration,
            profile.name,
            profile.beacon_interval_seconds,
        )
        return 2

    zeek_events = zeek_emit_for_profile(beacons=beacons, profile=profile, seed=args.seed)
    suri_events = suricata_emit_for_profile(beacons=beacons, profile=profile, seed=args.seed)
    emitted = zeek_events + suri_events

    # Pin injection window to the actual generated event timestamps.
    injection_start = beacons[0].timestamp
    injection_end = beacons[-1].timestamp

    corpus = CorpusBinding(
        tier=args.corpus_tier,
        build_hash=args.corpus_build_hash,
        baseline_generator_config=args.baseline_config,
    )
    out_dir = Path(args.out) / args.incident_id
    try:
        ndjson_path, yaml_path = write_bundle(
            incident_id=args.incident_id,
            profile=profile,
            emitted_events=emitted,
            corpus=corpus,
            injection_start=injection_start,
            injection_end=injection_end,
            bundle_dir=out_dir,
        )
    except SchemaValidationError as exc:
        log.error("c2 bundle validation failed: %s", exc)
        return 3
    print(str(ndjson_path))
    print(str(yaml_path))
    return 0


# --- parser ---


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="c2")
    p.add_argument("-v", "--verbose", action="count", default=0)
    sp = p.add_subparsers(dest="cmd", required=True)

    p_prof = sp.add_parser("profiles", help="preset inspection")
    sp_prof = p_prof.add_subparsers(dest="sub", required=True)
    sp_prof.add_parser("list").set_defaults(func=cmd_profiles_list)

    p_bc = sp.add_parser("beacon", help="generate a beacon stream to stdout")
    p_bc.add_argument("preset")
    p_bc.add_argument("--target", required=True, help="internal host IP (RFC1918)")
    p_bc.add_argument("--callbacks", help="comma-separated callback IPs")
    p_bc.add_argument("--start", required=True, help="ISO 8601 UTC")
    p_bc.add_argument("--duration", type=int, required=True, help="seconds")
    p_bc.add_argument("--seed", type=int, default=0)
    p_bc.set_defaults(func=cmd_beacon)

    p_bn = sp.add_parser("bundle", help="emit a full annotated bundle")
    p_bn.add_argument("preset")
    p_bn.add_argument("--incident-id", required=True)
    p_bn.add_argument("--target", required=True)
    p_bn.add_argument("--callbacks")
    p_bn.add_argument("--start", required=True)
    p_bn.add_argument("--duration", type=int, required=True)
    p_bn.add_argument("--seed", type=int, default=0)
    p_bn.add_argument("--corpus-build-hash", required=True)
    p_bn.add_argument("--out", default=str(DEFAULT_BUNDLE_DIR))
    p_bn.add_argument("--corpus-tier", default="M", choices=["S", "M", "L"])
    p_bn.add_argument(
        "--baseline-config",
        default="generators/it_baseline/configs/m_tier_v1.yaml",
    )
    p_bn.set_defaults(func=cmd_bundle)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    level = logging.WARNING - 10 * args.verbose
    logging.basicConfig(
        level=max(level, logging.DEBUG),
        format="%(levelname)s %(name)s: %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
