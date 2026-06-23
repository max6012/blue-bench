"""Corpus build orchestrator (EF-P5) — one command produces a tiered corpus.

    python -m blue_bench_generators.merge build --tier S --out <dir>

Composes the tested pieces into one deterministic build:

  1. EvidenceForge benign IT generation  (``eforge generate`` the tier scenario)
  2. OT + IT/OT-bridge merge              (``merger.merge_corpus``)
  3. adversary injection                  (``inject.inject_bundle`` per bundle:
     APT and/or cybercrime foil, each host-remapped onto a real corpus host)
  4. a single content ``build_hash`` over the whole corpus (EF + OT + bridge +
     injected, excluding ground-truth and EF metadata), stamped into every
     ground-truth bundle and validated (schema rule 8).

Tier -> adversary mapping (the dwell must fit the window): the cybercrime foil
(~2 h hands-on-keyboard burst, ~7 h total telemetry footprint once the C2/exfil
Zeek tail is counted) fits every tier; the low-and-slow APT (~10-day dwell) only
fits L. Defaults follow this; override with ``--inject``.

Determinism: same (tier, seed, scenario, bundles) -> byte-identical corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from blue_bench_generators.cybercrime_foil.bundle import SchemaValidationError, validate_bundle
from blue_bench_generators.merge.inject import HostRemap, inject_bundle
from blue_bench_generators.merge.merger import _EF_META, merge_corpus
from blue_bench_generators.merge.scenario_topology import shim_from_scenario

log = logging.getLogger("merge.build")

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIOS = REPO / "scenarios" / "heavy-telemetry"
DEFAULT_BUNDLES = REPO / "data" / "bundles"

# The bundle's captured source identity (placeholder host from apt_inject's
# rewrite). The injector re-remaps this onto a real corpus host.
_CAPTURE = HostRemap(
    from_name="WS-FIN-014", from_fqdn="ws-fin-014.corp.example", from_ip="10.10.4.37",
    to_name="", to_fqdn="", to_ip="",  # target filled per-injection
)

# tier -> [(incident_id, bundle_subdir, target_host_short), ...].
# Foil fits all tiers; the APT's 10-day dwell only fits L (see module docstring).
_DEFAULT_ADVERSARIES: dict[str, list[tuple[str, str, str]]] = {
    "S": [("cybercrime-bb-001", "cybercrime_foil", "wkst-03")],
    "M": [("cybercrime-bb-001", "cybercrime_foil", "wkst-03")],
    "L": [("apt-bb-001", "apt_inject", "wkst-03"),
          ("cybercrime-bb-001", "cybercrime_foil", "wkst-07")],
}

# Files/dirs excluded from the corpus build_hash: EF metadata (generated_at
# varies) and the ground-truth dir (it CONTAINS the hash — would be circular).
_HASH_EXCLUDE_DIRS = {"ground-truth"}


def _remap_for_host(scenario: Path, tier: str, host_short: str) -> HostRemap:
    """Build a HostRemap targeting a real corpus host, resolved from the scenario."""
    shim = shim_from_scenario(scenario, tier=tier, seed=0)
    match = next((h for h in shim.hosts if h.name == host_short or h.fqdn.startswith(host_short + ".")), None)
    if match is None:
        raise SystemExit(f"ABORT: target host {host_short!r} not in scenario {scenario.name}")
    return HostRemap(
        from_name=_CAPTURE.from_name, from_fqdn=_CAPTURE.from_fqdn, from_ip=_CAPTURE.from_ip,
        to_name=host_short.upper(), to_fqdn=match.fqdn, to_ip=match.ip,
    )


def _corpus_build_hash(corpus_dir: Path) -> str:
    """sha256 over (relpath, sha256) of every telemetry file, sorted by path.

    Includes EF + OT + bridge + injected; excludes EF metadata and the
    ground-truth dir (which embeds this hash)."""
    pairs: list[str] = []
    for p in sorted(corpus_dir.rglob("*")):
        if not p.is_file() or p.name in _EF_META:
            continue
        rel = p.relative_to(corpus_dir)
        if rel.parts and rel.parts[0] in _HASH_EXCLUDE_DIRS:
            continue
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        pairs.append(f"{rel.as_posix()}\t{h.hexdigest()}")
    return hashlib.sha256("\n".join(sorted(pairs)).encode()).hexdigest()


def _stamp_ground_truth(corpus_dir: Path, build_hash: str) -> list[str]:
    """Set corpus.build_hash in every ground-truth bundle and validate (rule 8)."""
    gt_dir = corpus_dir / "ground-truth"
    stamped: list[str] = []
    for gt_path in sorted(gt_dir.glob("*.ground-truth.yaml")):
        gt = yaml.safe_load(gt_path.read_text())
        gt.setdefault("corpus", {})["build_hash"] = build_hash
        validate_bundle(gt, expected_build_hash=build_hash)
        gt_path.write_text(yaml.safe_dump(gt, sort_keys=False), encoding="utf-8")
        stamped.append(gt_path.name)
    return stamped


def build_corpus(
    *,
    tier: str,
    out: Path,
    scenario: Path,
    seed: int,
    adversaries: list[tuple[str, str, str]],
    eforge: str,
    ef_dir: Path | None,
) -> dict:
    out = Path(out)

    # 1. EvidenceForge benign IT telemetry.
    if ef_dir is not None:
        if out.resolve() != Path(ef_dir).resolve():
            shutil.copytree(ef_dir, out, dirs_exist_ok=True)
        log.info("using pre-generated EF output: %s", out)
    else:
        if not shutil.which(eforge) and not Path(eforge).exists():
            raise SystemExit(f"ABORT: eforge not found at {eforge!r} (pass --eforge or --ef-dir)")
        log.info("eforge generate %s -> %s", scenario.name, out)
        subprocess.run([eforge, "generate", str(scenario), "-o", str(out)], check=True)

    # 2. OT + IT/OT-bridge merge.
    merge_corpus(out, scenario, tier=tier, seed=seed)

    # 3. adversary injection (each onto a real corpus host).
    injected = []
    for incident, subdir, host in adversaries:
        remap = _remap_for_host(scenario, tier, host)
        summary = inject_bundle(out, DEFAULT_BUNDLES / subdir, incident, remap)
        injected.append({"incident": incident, "source_class": summary["source_class"],
                         "host": remap.to_fqdn, "events": summary["events"]})
        log.info("injected %s (%s) -> %s: %d events",
                 incident, summary["source_class"], remap.to_fqdn, summary["events"])

    # 4. final content hash over the assembled corpus; stamp + validate GTs.
    build_hash = _corpus_build_hash(out)
    stamped = _stamp_ground_truth(out, build_hash)

    # reflect the final hash + injected set in the manifest.
    man_path = out / "corpus-manifest.yaml"
    manifest = yaml.safe_load(man_path.read_text()) if man_path.exists() else {}
    manifest["build_hash"] = build_hash
    manifest["injected"] = injected
    man_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    return {"tier": tier, "out": str(out), "build_hash": build_hash,
            "injected": injected, "ground_truth": stamped}


def cmd_build(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    tier = args.tier
    scenario = Path(args.scenario) if args.scenario else DEFAULT_SCENARIOS / f"bb-benign-{tier.lower()}.yaml"
    if not scenario.is_file():
        print(f"ABORT: scenario not found: {scenario}", file=sys.stderr)
        return 2

    if args.inject:
        adversaries = []
        for spec in args.inject:  # "<incident>:<bundle_subdir>:<host>"
            parts = spec.split(":")
            if len(parts) != 3:
                print(f"ABORT: --inject expects <incident>:<bundle_subdir>:<host>, got {spec!r}",
                      file=sys.stderr)
                return 2
            adversaries.append((parts[0], parts[1], parts[2]))
    else:
        adversaries = _DEFAULT_ADVERSARIES.get(tier, [])

    try:
        result = build_corpus(
            tier=tier, out=Path(args.out), scenario=scenario, seed=args.seed,
            adversaries=adversaries, eforge=args.eforge,
            ef_dir=Path(args.ef_dir) if args.ef_dir else None,
        )
    except (SchemaValidationError, subprocess.CalledProcessError) as exc:
        print(f"ABORT: build failed: {exc}", file=sys.stderr)
        return 1

    print(f"\ncorpus built: tier={result['tier']} build_hash={result['build_hash'][:12]}")
    for inj in result["injected"]:
        print(f"  injected {inj['incident']:18s} {inj['source_class']:11s} {inj['host']:32s} {inj['events']} events")
    print(f"  ground-truth: {', '.join(result['ground_truth']) or '(none)'}")
    print(f"  out: {result['out']}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blue_bench_generators.merge")
    sp = p.add_subparsers(dest="cmd", required=True)
    b = sp.add_parser("build", help="build a tiered corpus (EF-IT + OT + bridge + injected adversary)")
    b.add_argument("--tier", required=True, choices=["S", "M", "L"])
    b.add_argument("--out", required=True, help="corpus output directory")
    b.add_argument("--scenario", default=None, help="EF scenario YAML (default: scenarios/heavy-telemetry/bb-benign-<tier>.yaml)")
    b.add_argument("--seed", type=int, default=0)
    b.add_argument("--ef-dir", default=None, help="use a pre-generated EF output dir instead of running eforge")
    b.add_argument("--eforge", default=str(Path.home() / "ef-venv" / "bin" / "eforge"), help="path to the eforge CLI")
    b.add_argument("--inject", action="append", default=None,
                   help="override adversaries: <incident>:<bundle_subdir>:<host> (repeatable)")
    b.set_defaults(func=cmd_build)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
