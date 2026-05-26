"""CLI driver for the IT-baseline corpus composer.

Subcommands::

    build --tier S|M|L --output <dir> [--seed N] [--start ISO]
          [--duration-days N]
        Produce a complete IT-baseline corpus to ``<dir>``. Default time
        window: S=1d, M=7d, L=14d, anchored at 2026-01-05T00:00:00Z.

Style: argparse, stdlib logging, no Click/Typer (matches ``scripts/seed_es.py``
and the existing ``cybercrime_foil`` / ``c2`` CLI drivers).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from blue_bench_generators._isotime import parse_iso
from blue_bench_generators.it_baseline.composer import (
    DEFAULT_START,
    TIER_DURATION_DAYS,
    build_corpus,
)

log = logging.getLogger("blue_bench_generators.it_baseline")


def _add_build_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tier", choices=["S", "M", "L"], required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument(
        "--start",
        default=None,
        help=f"ISO-8601 window start (UTC). Default {DEFAULT_START.isoformat()}.",
    )
    p.add_argument(
        "--duration-days",
        type=int,
        default=None,
        help=f"Override duration. Defaults per tier: {TIER_DURATION_DAYS}.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blue_bench_generators.it_baseline")
    subs = parser.add_subparsers(dest="cmd", required=True)
    build = subs.add_parser("build", help="Build an IT-baseline corpus.")
    _add_build_args(build)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )

    if args.cmd == "build":
        start = parse_iso(args.start) if args.start else DEFAULT_START
        manifest = build_corpus(
            tier=args.tier,
            output_dir=args.output,
            seed=args.seed,
            start=start,
            duration_days=args.duration_days,
        )
        print(
            f"corpus built: tier={args.tier} "
            f"hosts={manifest['topology']['hosts']} "
            f"events={manifest['totals']['events']} "
            f"bytes={manifest['totals']['bytes']} "
            f"build_hash={manifest['build_hash'][:12]}"
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
