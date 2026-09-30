"""OT asset inventory — the join between OT device NAMES and OT ADDRESSES.

The corpus records the two halves of every OT device in different places and
joins them nowhere: ``ot-hosts`` carries the device names of the ~10 OT hosts
that emit host logs (``hmi-03.plant.example.invalid``, ``ews-01…``), while the
protocol indices (``ot-conn``, ``ot-modbus``, ``ot-dnp3``, ``ot-iec104``,
``ot-s7comm``) carry only addresses. ``ot-hosts.source_ip`` does not close it:
that field is the PEER that connected, not the subject host.

Two things break without the join. A fan-out slice scoped to an OT device
cannot be bound on any network tool, because the network tools filter on an
address the harness has no way to derive. And a model investigating OT traffic
has no legitimate way to learn which device an address is -- which is load
bearing, because one of Blue-Bench's three research questions is whether a
model can tell IT from OT.

A real OT analyst has an asset inventory, so the corpus now ships one. The
mapping is already deterministic: ``build_ot_network(tier, seed)`` is a pure
function, the manifest records the ``tier`` and ``ot_seed`` a corpus was built
with, and the addresses it yields are the addresses that are live in ES today
(verified by :func:`verify_against_es`). That means an already-built corpus can
be backfilled without a rebuild.

Records carry NO ``@timestamp``. An inventory is a standing fact about the
plant, not an observation inside a time band: stamping it would make it subject
to ``--anchor-end-to-now`` shifting and would hide it from any slice whose
window does not contain the stamp.

Command line (backfill an already-built corpus into a live ES)::

    .venv/bin/python -m blue_bench_generators.merge.asset_inventory \\
        --ef-dir /private/tmp/bb-corpus-l --es-url http://localhost:9200
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable

import httpx
import yaml

from blue_bench_generators.ot_protocols.topology import build_ot_network

log = logging.getLogger(__name__)

# The corpus subdir and filename. ``ot_assets/`` is its own top-level tree
# rather than another file under ``ot/``: everything under ``ot/`` is a stream
# of protocol events counted as ``ot_protocols.events`` in the manifest, and the
# inventory is neither a stream nor an event.
ASSETS_DIR = "ot_assets"
ASSETS_FILE = "assets.ndjson"

# The ES index the ingest routes this file to.
ASSETS_INDEX = "ot-assets"

# Segment label on every record. The point of the field is that a model can ask
# "is this an OT address?" and get an answer from a source instead of guessing
# from the subnet.
SEGMENT = "OT"


def asset_records(tier: str, seed: int = 0) -> list[dict[str, Any]]:
    """One record per OT device for ``(tier, seed)``, sorted by name.

    ``protocols`` is the sorted set of protocols the device participates in on
    either side of a master/slave link. The links themselves are deliberately
    NOT expanded into the record: tier L has 142 of them across 40 devices, and
    the tool that serves this index has an 8,000-character result budget -- a
    per-link list would push the inventory past it and the tool would answer
    with a third of the plant. The protocol set is the part an analyst reads.
    """
    net = build_ot_network(tier=tier, seed=seed)  # type: ignore[arg-type]
    vlans = {v.name: v for v in net.vlans}

    protocols: dict[str, set[str]] = {}
    for link in net.links:
        protocols.setdefault(link.master, set()).add(link.protocol)
        protocols.setdefault(link.slave, set()).add(link.protocol)

    records = []
    for d in net.devices:
        vlan = vlans.get(d.vlan)
        records.append({
            "name": d.name,
            "fqdn": d.fqdn,
            "ip": d.ip,
            "role": d.role,
            "os": d.os,
            "vendor": d.vendor,
            "vlan": d.vlan,
            "vlan_id": vlan.vlan_id if vlan else 0,
            "subnet": vlan.subnet if vlan else "",
            "segment": SEGMENT,
            "protocols": sorted(protocols.get(d.name, ())),
        })
    return sorted(records, key=lambda r: r["name"])


def write_inventory(ef_dir: str | Path, tier: str, seed: int = 0) -> int:
    """Write ``<ef_dir>/ot_assets/assets.ndjson``. Returns the record count.

    Same NDJSON conventions as the merger's telemetry writer (``sort_keys`` for
    byte-stable output, one record per line), so a re-merge of the same
    ``(tier, seed)`` produces identical bytes and the manifest's ``build_hash``
    stays deterministic.
    """
    out_dir = Path(ef_dir) / ASSETS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    records = asset_records(tier, seed)
    with (out_dir / ASSETS_FILE).open("w", encoding="utf-8", newline="") as f:
        for rec in records:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
    return len(records)


# --- backfill of an already-built corpus --------------------------------------


def manifest_tier_seed(ef_dir: str | Path) -> tuple[str, int]:
    """``(tier, ot_seed)`` from ``corpus-manifest.yaml``.

    This is what makes a backfill possible without a rebuild: the manifest
    records the exact inputs the OT network was built from, and the builder is
    a pure function of them.
    """
    man = Path(ef_dir) / "corpus-manifest.yaml"
    if not man.is_file():
        raise FileNotFoundError(f"{man} not found; cannot tell which tier/seed to regenerate")
    data = yaml.safe_load(man.read_text(encoding="utf-8")) or {}
    tier = data.get("tier")
    if not tier:
        raise ValueError(f"{man} records no tier")
    return str(tier), int(data.get("ot_seed", 0))


def _ot_subnets(tier: str, seed: int = 0) -> list[ipaddress.IPv4Network]:
    nets = []
    for vlan in build_ot_network(tier=tier, seed=seed).vlans:  # type: ignore[arg-type]
        nets.append(ipaddress.ip_network(vlan.subnet))
    return nets


def _distinct(es_url: str, index: str, field: str, *, timeout: float = 60.0) -> list[str]:
    """Every distinct value of ``field`` in ``index``, or a loud failure.

    A terms aggregation that silently drops the tail would turn "every OT
    address resolves" into a claim about an arbitrary subset, so
    ``sum_other_doc_count`` is asserted rather than trusted.
    """
    body = {"size": 0, "aggs": {"v": {"terms": {"field": f"{field}.keyword", "size": 1000}}}}
    url = f"{es_url.rstrip('/')}/{index}/_search?ignore_unavailable=true&allow_no_indices=true"
    resp = httpx.post(url, json=body, timeout=timeout)
    resp.raise_for_status()
    agg = resp.json().get("aggregations", {}).get("v")
    if agg is None:
        return []
    if agg.get("sum_other_doc_count", 0):
        raise RuntimeError(
            f"terms agg on {index}.{field} was truncated "
            f"(sum_other_doc_count={agg['sum_other_doc_count']}); the verification "
            f"would be a claim about a partial address set"
        )
    return [str(b["key"]) for b in agg.get("buckets", [])]


def verify_against_es(
    es_url: str,
    tier: str,
    seed: int = 0,
    indices: Iterable[str] = ("ot-conn", "ot-modbus"),
) -> dict[str, Any]:
    """Check the regenerated inventory against the addresses that are live in ES.

    The rule: every address inside the OT VLAN subnets that appears as a
    ``src_ip`` or ``dest_ip`` in the OT protocol indices must be a device in the
    regenerated inventory. Addresses OUTSIDE those subnets are not failures --
    ``ot-conn`` also carries the IT leg of every IT/OT bridge session (measured:
    ``10.20.0.20``, ``10.20.0.40-42``), and an IT jump host is legitimately not
    an OT asset. They are counted and returned so the relaxation is visible
    rather than assumed.

    The claim this proves is scoped to Elasticsearch, not to the corpus on disk:
    the OT protocol streams are ingested with ``--ot-sample-rate``, so ES holds
    a sample. ES is what the tool and the resolver read, so it is the right
    surface to verify, but it is not the same claim as "every address in the
    25 GB corpus".

    Returns the tally. ``ok`` is False when any OT-subnet address is unknown to
    the inventory; the caller must index nothing in that case, because an
    inventory that names the wrong device is worse than no inventory at all.
    """
    records = asset_records(tier, seed)
    known = {r["ip"] for r in records}
    subnets = _ot_subnets(tier, seed)

    def _is_ot(addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in net for net in subnets)

    seen: set[str] = set()
    per_index: dict[str, int] = {}
    for index in indices:
        vals: set[str] = set()
        for field in ("src_ip", "dest_ip"):
            vals.update(_distinct(es_url, index, field))
        per_index[index] = len(vals)
        seen |= vals

    ot_addrs = sorted(a for a in seen if _is_ot(a))
    non_ot = sorted(a for a in seen if not _is_ot(a))
    unresolved = sorted(a for a in ot_addrs if a not in known)
    return {
        "ok": not unresolved,
        "devices": len(records),
        "indices": per_index,
        "ot_addresses": len(ot_addrs),
        "ot_addresses_resolved": len(ot_addrs) - len(unresolved),
        "unresolved": unresolved,
        "non_ot_addresses": non_ot,
    }


def index_into_es(es_url: str, tier: str, seed: int = 0) -> int:
    """Recreate ``ot-assets`` from the regenerated inventory. Returns docs indexed.

    Goes through the ingest's own routing, parser and ``doc_id`` rather than a
    private copy of any of them, so a backfilled index is byte-identical to one
    a full ``scripts/ingest_ef.py`` run would produce.

    Nothing is written into the corpus directory: the merger's ``build_hash``
    covers every telemetry file, so dropping a new file into an already-built
    corpus would make a recomputed hash disagree with the recorded one. The
    records go from memory straight to ES.
    """
    # Same loader ``inject.py`` uses for the same script, rather than a second
    # mechanism for reaching the one module that owns ``doc_id``.
    from blue_bench_generators.merge.inject import _ingest_adapter

    ingest_ef = _ingest_adapter()
    records = asset_records(tier, seed)
    relpath = f"{ASSETS_DIR}/{ASSETS_FILE}"
    docs = [
        (ingest_ef.doc_id(rec, relpath, ordinal, rec["fqdn"]), dict(rec))
        for ordinal, rec in enumerate(records)
    ]
    ingest_ef._OVERWRITTEN.clear()
    ingest_ef._recreate_index(es_url, ASSETS_INDEX, ingest_ef._index_mappings(docs[0][1].keys()))
    ok = ingest_ef._bulk(es_url, ASSETS_INDEX, docs)
    httpx.post(f"{es_url.rstrip('/')}/{ASSETS_INDEX}/_refresh", timeout=30)
    if ingest_ef._OVERWRITTEN:
        # The _id is the device FQDN, so one record per device is an invariant
        # by construction. An overwrite means two devices share an FQDN, which
        # means the inventory is not an inventory.
        raise RuntimeError(
            f"{dict(ingest_ef._OVERWRITTEN)} documents overwrote an existing _id in "
            f"{ASSETS_INDEX}: two devices share an FQDN and the inventory is wrong"
        )
    return ok


def backfill(ef_dir: str | Path, es_url: str) -> dict[str, Any]:
    """Regenerate the inventory for a built corpus, verify it, then index it.

    Verification comes first and a failure indexes nothing. A wrong inventory is
    worse than a missing one: with no index the tool says it cannot tell you
    which device an address is, and with a wrong one a model confidently names
    the wrong device.
    """
    tier, seed = manifest_tier_seed(ef_dir)
    report = verify_against_es(es_url, tier, seed)
    report["tier"], report["ot_seed"] = tier, seed
    if not report["ok"]:
        raise RuntimeError(
            f"inventory does not match the live corpus: {len(report['unresolved'])} OT "
            f"address(es) in ES are not a device in the regenerated inventory "
            f"({', '.join(report['unresolved'][:10])}). Nothing indexed."
        )
    report["indexed"] = index_into_es(es_url, tier, seed)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ef-dir", required=True, type=Path, help="built corpus dir (has corpus-manifest.yaml)")
    p.add_argument("--es-url", default="http://localhost:9200")
    p.add_argument("--verify-only", action="store_true", help="check the mapping, index nothing")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    if args.verify_only:
        tier, seed = manifest_tier_seed(args.ef_dir)
        report = verify_against_es(args.es_url, tier, seed)
        report["tier"], report["ot_seed"] = tier, seed
    else:
        report = backfill(args.ef_dir, args.es_url)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
