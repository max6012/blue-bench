"""CLI: build an APT injection bundle from the sandbox kill-chain captures.

    python -m blue_bench_generators.apt_inject build \
        --index data/raw/sandbox/killchain-index.tsv \
        --captures-root data/raw/sandbox \
        --tier L --dwell-days 10 \
        --target-name WS-FIN-014 --target-fqdn ws-fin-014.corp.example \
        --target-ip 10.10.4.37 \
        --campaign-id apt-bb-001 --seed 0

Reads the kill-chain index (stage → capture run dir), ingests + selects +
schedules + rewrites, and writes the bundle to
``data/bundles/apt_inject/<campaign_id>.{events.ndjson,ground-truth.yaml}``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

from blue_bench_generators.apt_inject.bundle import CorpusBinding, write_apt_bundle
from blue_bench_generators.apt_inject.ingest import parse_capture_dir
from blue_bench_generators.apt_inject.rewrite import HostMap, rewrite_plan
from blue_bench_generators.apt_inject.schedule import schedule_campaign, select_signal

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INDEX = REPO_ROOT / "data" / "raw" / "sandbox" / "killchain-index.tsv"
DEFAULT_CAPTURES = REPO_ROOT / "data" / "raw" / "sandbox"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "data" / "bundles" / "apt_inject"

# Per-tier corpus window (days), mirrors it_baseline composer TIER_DURATION_DAYS.
TIER_DAYS = {"S": 1, "M": 7, "L": 14}
# Corpus anchor, mirrors it_baseline composer DEFAULT_START.
CORPUS_START = datetime(2026, 1, 5, 0, 0, 0)


def _load_index(index_path: Path) -> dict[str, str]:
    """stage -> capture run-dir basename (OK rows only)."""
    stage_run: dict[str, str] = {}
    for line in index_path.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        stage, _tech, _test, run, status = cols[:5]
        if status.strip() == "OK":
            stage_run[stage] = run
    return stage_run


def cmd_build(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    index_path = Path(args.index)
    captures_root = Path(args.captures_root)
    stage_run = _load_index(index_path)
    if not stage_run:
        print(f"ABORT: no OK rows in {index_path}", file=sys.stderr)
        return 1

    if args.tier not in TIER_DAYS:
        print(f"ABORT: unknown tier {args.tier!r}", file=sys.stderr)
        return 2
    window_days = TIER_DAYS[args.tier]
    if args.dwell_days > window_days:
        print(
            f"ABORT: dwell {args.dwell_days}d exceeds tier-{args.tier} window "
            f"{window_days}d", file=sys.stderr,
        )
        return 2

    # dwell starts one day into the window so initial-access isn't at t=0.
    dwell_start = args.start or (CORPUS_START.replace(hour=9))
    if isinstance(dwell_start, str):
        dwell_start = datetime.fromisoformat(dwell_start)

    # ingest + select per stage
    stage_signal: dict[str, list[dict]] = {}
    for stage, run in stage_run.items():
        events = parse_capture_dir(captures_root / run)
        sel = select_signal(events, stage)
        stage_signal[stage] = sel
        logging.info("  %-20s %5d selected / %6d captured", stage, len(sel), len(events))

    plan = schedule_campaign(
        stage_signal,
        dwell_start=dwell_start,
        dwell_days=args.dwell_days,
        campaign_id=args.campaign_id,
        seed=args.seed,
    )
    if not plan.scheduled:
        print("ABORT: no events scheduled (empty selection)", file=sys.stderr)
        return 1

    hmap = HostMap(
        capture_name=args.capture_name,
        capture_ip=args.capture_ip,
        target_name=args.target_name,
        target_fqdn=args.target_fqdn,
        target_ip=args.target_ip,
    )
    rewritten = rewrite_plan(plan, hmap)

    corpus = CorpusBinding(
        tier=args.tier,
        build_hash=args.corpus_build_hash,
        baseline_generator_config=args.baseline_config,
    )
    ndjson_path, yaml_path = write_apt_bundle(
        campaign_id=args.campaign_id,
        rewritten_events=rewritten,
        corpus=corpus,
        injection_start=plan.dwell_start,
        injection_end=plan.dwell_end,
        bundle_dir=Path(args.bundle_dir),
        segment_class=args.segment_class,
    )
    print(f"OK: {len(rewritten)} events")
    print(f"  {ndjson_path}")
    print(f"  {yaml_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m blue_bench_generators.apt_inject")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build an APT injection bundle")
    b.add_argument("--index", default=str(DEFAULT_INDEX))
    b.add_argument("--captures-root", default=str(DEFAULT_CAPTURES))
    b.add_argument("--bundle-dir", default=str(DEFAULT_BUNDLE_DIR))
    b.add_argument("--tier", default="L", choices=list(TIER_DAYS))
    b.add_argument("--dwell-days", type=float, default=10.0)
    b.add_argument("--start", default=None, help="ISO dwell start (default: corpus day 1 09:00)")
    b.add_argument("--campaign-id", default="apt-bb-001")
    b.add_argument("--seed", type=int, default=0)
    b.add_argument("--segment-class", default="IT", choices=["IT", "OT", "IT-OT-bridge"])
    # host map
    b.add_argument("--capture-name", default="EC2AMAZ-VU9QJAP")
    b.add_argument("--capture-ip", default="10.20.1.210")
    b.add_argument("--target-name", default="WS-FIN-014")
    b.add_argument("--target-fqdn", default="ws-fin-014.corp.example")
    b.add_argument("--target-ip", default="10.10.4.37")
    # corpus binding
    b.add_argument("--corpus-build-hash", default="0" * 64)
    b.add_argument("--baseline-config", default="blue_bench_generators/it_baseline")
    b.set_defaults(func=cmd_build)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
