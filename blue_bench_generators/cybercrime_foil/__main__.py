"""CLI driver for the cybercrime-foil splice pipeline.

Subcommands:
    catalogue list
        Print the v1 16-PCAP catalogue (incident_id, fidelity, family).

    download <incident_id> --zip-url <url> [--raw-dir <dir>]
        Fetch one PCAP archive into data/raw/mta/<incident_id>/.

    replay <incident_id> [--raw-dir <dir>] [--processed-dir <dir>]
        Run Zeek + Suricata against the previously-downloaded PCAP(s) and
        write parsed events as NDJSON under data/processed/<incident_id>/.

    bundle <incident_id> --corpus-build-hash <sha256> --target-epoch <iso>
                         --target-subnet <cidr> [--bundle-dir <dir>]
                         [--corpus-tier S|M|L]
                         [--baseline-config <path>]
        Read parsed events from data/processed/<incident_id>/, rewrite time
        + IPs, and emit the bundle.

    bundle-all  (same flags as bundle, applied to every catalogue entry that
                 has a parsed event stream on disk).

Style: argparse, stdlib logging, no Click/Typer (matches scripts/seed_es.py).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from blue_bench_generators.cybercrime_foil import catalogue
from blue_bench_generators.cybercrime_foil.bundle import (
    CorpusBinding,
    SchemaValidationError,
    write_bundle,
)
from blue_bench_generators.cybercrime_foil.download import (
    DEFAULT_RAW_DIR,
    DownloadError,
    download,
    unzip_archive,
)
from blue_bench_generators.cybercrime_foil.rewrite import rewrite_events
from blue_bench_generators.cybercrime_foil.suricata_replay import (
    SuricataError,
    parse_eve,
    run_suricata,
)
from blue_bench_generators.cybercrime_foil.zeek_replay import (
    ZeekError,
    parse_all,
    run_zeek,
)

log = logging.getLogger("blue_bench_generators.cybercrime_foil")


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROCESSED_DIR = REPO_ROOT / "data" / "processed" / "mta"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "data" / "bundles" / "cybercrime_foil"


# --- subcommands ---


def cmd_catalogue_list(args: argparse.Namespace) -> int:
    for e in catalogue.CATALOGUE:
        print(f"{e.incident_id}\t[{e.attribution_fidelity}]\t{e.date}\t{e.family}")
    return 0


def cmd_download(args: argparse.Namespace) -> int:
    raw_dir = Path(args.raw_dir) if args.raw_dir else DEFAULT_RAW_DIR
    try:
        entry = catalogue.get(args.incident_id)
        archive = download(entry, args.zip_url, raw_dir=raw_dir)
        log.info("downloaded archive: %s", archive)
        files = unzip_archive(entry, archive, raw_dir=raw_dir)
        log.info("unzipped %d files into %s", len(files), archive.parent / "extracted")
    except DownloadError as exc:
        log.error("download failed: %s", exc)
        return 2
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    raw_dir = Path(args.raw_dir) if args.raw_dir else DEFAULT_RAW_DIR
    processed_dir = Path(args.processed_dir) if args.processed_dir else DEFAULT_PROCESSED_DIR
    entry = catalogue.get(args.incident_id)
    extracted = raw_dir / entry.incident_id / "extracted"
    pcaps = sorted(extracted.glob("*.pcap")) if extracted.is_dir() else []
    if not pcaps:
        log.error("no .pcap files found under %s; run `download` first", extracted)
        return 2
    incident_processed = processed_dir / entry.incident_id
    zeek_out = incident_processed / "zeek"
    suricata_out = incident_processed / "suricata"
    incident_processed.mkdir(parents=True, exist_ok=True)

    events: list[dict] = []
    for pcap in pcaps:
        log.info("replay pcap: %s", pcap)
        try:
            run_zeek(pcap, zeek_out)
        except ZeekError as exc:
            log.error("zeek replay failed: %s", exc)
            return 3
        try:
            run_suricata(pcap, suricata_out)
        except SuricataError as exc:
            log.error("suricata replay failed: %s", exc)
            return 4
        events.extend(parse_all(zeek_out))
        events.extend(parse_eve(suricata_out / "eve.json"))

    raw_events_path = incident_processed / "events.raw.ndjson"
    with raw_events_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, default=str) + "\n")
    log.info("wrote %d raw events -> %s", len(events), raw_events_path)
    return 0


def _load_processed_events(processed_dir: Path, incident_id: str) -> list[dict]:
    path = processed_dir / incident_id / "events.raw.ndjson"
    if not path.is_file():
        raise FileNotFoundError(
            f"no parsed events at {path}; run `replay {incident_id}` first"
        )
    events: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _parse_target_epoch(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def cmd_bundle(args: argparse.Namespace) -> int:
    processed_dir = Path(args.processed_dir) if args.processed_dir else DEFAULT_PROCESSED_DIR
    bundle_dir = Path(args.bundle_dir) if args.bundle_dir else DEFAULT_BUNDLE_DIR
    entry = catalogue.get(args.incident_id)
    try:
        raw_events = _load_processed_events(processed_dir, entry.incident_id)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2

    target_epoch = _parse_target_epoch(args.target_epoch)
    rewritten = rewrite_events(
        raw_events,
        incident_id=entry.incident_id,
        target_epoch=target_epoch,
        target_subnet=args.target_subnet,
    )
    # Synthesize injection_end from the latest rewritten event timestamp.
    from blue_bench_generators.cybercrime_foil.rewrite import _earliest_ts, _parse_event_ts

    latest = None
    for ev in rewritten:
        ts = _parse_event_ts(ev)
        if ts is not None and (latest is None or ts > latest):
            latest = ts
    injection_start = _earliest_ts(rewritten) or target_epoch
    injection_end = latest or target_epoch

    corpus = CorpusBinding(
        tier=args.corpus_tier,
        build_hash=args.corpus_build_hash,
        baseline_generator_config=args.baseline_config,
    )
    try:
        ndjson_path, yaml_path = write_bundle(
            entry=entry,
            rewritten_events=rewritten,
            corpus=corpus,
            injection_start=injection_start,
            injection_end=injection_end,
            bundle_dir=bundle_dir / entry.incident_id,
        )
    except SchemaValidationError as exc:
        log.error("bundle validation failed: %s", exc)
        return 5
    print(str(ndjson_path))
    print(str(yaml_path))
    return 0


def cmd_bundle_all(args: argparse.Namespace) -> int:
    processed_dir = Path(args.processed_dir) if args.processed_dir else DEFAULT_PROCESSED_DIR
    failures: list[str] = []
    for entry in catalogue.CATALOGUE:
        raw = processed_dir / entry.incident_id / "events.raw.ndjson"
        if not raw.is_file():
            log.info("skip %s (no processed events at %s)", entry.incident_id, raw)
            continue
        sub_args = argparse.Namespace(**vars(args), incident_id=entry.incident_id)
        rc = cmd_bundle(sub_args)
        if rc != 0:
            failures.append(entry.incident_id)
    if failures:
        log.error("bundle-all: %d failures: %s", len(failures), failures)
        return 6
    return 0


# --- parser ---


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cybercrime_foil")
    p.add_argument("-v", "--verbose", action="count", default=0)
    sp = p.add_subparsers(dest="cmd", required=True)

    # catalogue list
    p_cat = sp.add_parser("catalogue", help="catalogue inspection")
    sp_cat = p_cat.add_subparsers(dest="sub", required=True)
    sp_cat.add_parser("list").set_defaults(func=cmd_catalogue_list)

    # download
    p_dl = sp.add_parser("download", help="fetch one PCAP archive")
    p_dl.add_argument("incident_id")
    p_dl.add_argument("--zip-url", required=True, help="explicit zip URL")
    p_dl.add_argument("--raw-dir")
    p_dl.set_defaults(func=cmd_download)

    # replay
    p_rp = sp.add_parser("replay", help="run zeek + suricata on a downloaded PCAP")
    p_rp.add_argument("incident_id")
    p_rp.add_argument("--raw-dir")
    p_rp.add_argument("--processed-dir")
    p_rp.set_defaults(func=cmd_replay)

    # bundle
    def add_bundle_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--corpus-build-hash", required=True)
        parser.add_argument("--target-epoch", required=True, help="ISO 8601 UTC")
        parser.add_argument("--target-subnet", required=True, help="e.g. 10.42.0.0/16")
        parser.add_argument("--corpus-tier", default="M", choices=["S", "M", "L"])
        parser.add_argument(
            "--baseline-config",
            default="generators/it_baseline/configs/m_tier_v1.yaml",
        )
        parser.add_argument("--processed-dir")
        parser.add_argument("--bundle-dir")

    p_b = sp.add_parser("bundle", help="emit annotated bundle for one incident")
    p_b.add_argument("incident_id")
    add_bundle_args(p_b)
    p_b.set_defaults(func=cmd_bundle)

    p_ba = sp.add_parser("bundle-all", help="emit bundles for every processed incident")
    add_bundle_args(p_ba)
    p_ba.set_defaults(func=cmd_bundle_all)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    level = logging.WARNING - 10 * args.verbose
    logging.basicConfig(level=max(level, logging.DEBUG), format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
