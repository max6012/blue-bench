"""CLI: synthesize the credential-abuse injection bundles.

    python -m blue_bench_generators.cred_inject build [--out data/bundles] [--seed 0]

Deterministically writes all six bundles (brute force, password spray, dormant
service-account misuse, pass-the-hash, impossible travel, noisy commodity) to
``<out>/<subdir>/<incident_id>.{events.ndjson,ground-truth.yaml}`` — the on-disk
contract the merge/inject pipeline reads. Generation takes no external captures
(unlike apt_inject); ``--seed`` is accepted for parity with the other generators
but the emitted telemetry is a fixed function of the builders (byte-stable).
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from blue_bench_generators.cred_inject.bundle import DEFAULT_OUT, write_bundle
from blue_bench_generators.cred_inject.events import BUILDERS


def cmd_build(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    out_root = Path(args.out)
    only = set(args.only) if args.only else None
    n = 0
    for incident_id, builder in BUILDERS.items():
        if only and incident_id not in only:
            continue
        write_bundle(builder(), out_root)
        n += 1
    logging.info("cred_inject: wrote %d bundle(s) -> %s", n, out_root)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m blue_bench_generators.cred_inject")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="synthesize the credential-abuse bundles")
    b.add_argument("--out", default=str(DEFAULT_OUT), help="bundle root (default: data/bundles)")
    b.add_argument("--seed", type=int, default=0, help="accepted for parity; output is deterministic")
    b.add_argument("--only", nargs="*", default=None, help="restrict to specific incident ids")
    b.set_defaults(func=cmd_build)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
