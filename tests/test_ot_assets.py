"""OT asset inventory: generation, ingest routing, backfill verification.

The inventory is the only record in the corpus that joins an OT device name to
an OT address, so these tests are mostly about it being RIGHT rather than about
it existing: the generated addresses have to be the ones that are live in ES,
and a mismatch has to stop the backfill instead of publishing a plausible lie.

Live paths are skipped when Elasticsearch or the index is not there.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
from pathlib import Path

import pytest

from blue_bench_generators.merge import asset_inventory as ai


_spec = importlib.util.spec_from_file_location(
    "ingest_ef", Path(__file__).resolve().parents[1] / "scripts" / "ingest_ef.py"
)
ingest_ef = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ingest_ef)

ES_URL = "http://localhost:9200"


def _es_reachable() -> bool:
    import httpx
    try:
        return httpx.get(f"{ES_URL}/_cluster/health", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


def _assets_populated() -> bool:
    import httpx
    try:
        r = httpx.get(f"{ES_URL}/{ai.ASSETS_INDEX}/_count", timeout=2.0)
        return r.status_code == 200 and r.json().get("count", 0) > 0
    except (httpx.HTTPError, ValueError):
        return False


# The tier/seed the live corpus was built with. Written out rather than read
# from the corpus manifest so these tests depend on Elasticsearch alone -- the
# 25 GB corpus dir need not be present to check what is in ES.
LIVE_TIER_SEED = ("L", 0)

requires_inventory = pytest.mark.skipif(
    not (_es_reachable() and _assets_populated()),
    reason="Elasticsearch / ot-assets not available",
)


# --- generation ---------------------------------------------------------------

def test_tier_l_seed_0_emits_one_record_per_device():
    recs = ai.asset_records("L", 0)
    assert len(recs) == 40
    assert [r["name"] for r in recs] == sorted(r["name"] for r in recs)
    assert {r["segment"] for r in recs} == {"OT"}
    by_role: dict[str, int] = {}
    for r in recs:
        by_role[r["role"]] = by_role.get(r["role"], 0) + 1
    assert by_role == {
        "hmi": 4, "historian": 2, "engineering-workstation": 4, "ot-firewall": 1,
        "controller": 8, "safety-controller": 1, "rtu": 20,
    }


def test_hmi_03_carries_the_address_the_corpus_uses():
    (hmi,) = [r for r in ai.asset_records("L", 0) if r["name"] == "hmi-03"]
    assert hmi["fqdn"] == "hmi-03.plant.example.invalid"
    assert hmi["ip"] == "10.40.0.18"
    assert hmi["role"] == "hmi" and hmi["os"] == "windows"
    assert hmi["vlan"] == "ot-supervisory" and hmi["vlan_id"] == 40
    assert hmi["subnet"] == "10.40.0.0/24"
    # An HMI is a DNP3/IEC-104 master; it speaks neither Modbus nor S7Comm here.
    assert hmi["protocols"] == ["dnp3", "iec104"]


def test_protocols_cover_both_ends_of_a_link():
    recs = {r["name"]: r for r in ai.asset_records("L", 0)}
    # A controller is polled by HMI/historian (dnp3, iec104), polls RTUs
    # (modbus, dnp3), and vendor-a controllers take S7Comm engineering sessions.
    assert recs["plc-01"]["protocols"] == ["dnp3", "iec104", "modbus", "s7comm"]
    assert recs["rtu-01"]["protocols"] == ["dnp3", "modbus"]
    # The firewall is in the inventory and in no protocol link -- which is why
    # its address never appears in the protocol indices.
    assert recs["ot-fw-01"]["protocols"] == []


def test_every_address_is_inside_an_ot_vlan_and_unique():
    recs = ai.asset_records("L", 0)
    nets = ai._ot_subnets("L", 0)
    assert all(any(ipaddress.ip_address(r["ip"]) in n for n in nets) for r in recs)
    assert len({r["ip"] for r in recs}) == len(recs)
    assert len({r["fqdn"] for r in recs}) == len(recs)


def test_generation_is_deterministic():
    assert ai.asset_records("L", 0) == ai.asset_records("L", 0)
    assert len(ai.asset_records("S", 0)) == 8


def test_write_inventory_is_byte_stable(tmp_path: Path):
    n = ai.write_inventory(tmp_path, "L", 0)
    path = tmp_path / ai.ASSETS_DIR / ai.ASSETS_FILE
    first = path.read_bytes()
    assert n == 40 and len(first.decode().splitlines()) == 40
    assert ai.write_inventory(tmp_path, "L", 0) == 40
    assert path.read_bytes() == first
    rec = json.loads(first.decode().splitlines()[0])
    assert set(rec) == {"name", "fqdn", "ip", "role", "os", "vendor", "vlan",
                        "vlan_id", "subnet", "segment", "protocols"}


def test_manifest_tier_seed_is_what_a_backfill_regenerates_from(tmp_path: Path):
    (tmp_path / "corpus-manifest.yaml").write_text("tier: L\not_seed: 0\n")
    assert ai.manifest_tier_seed(tmp_path) == ("L", 0)
    with pytest.raises(FileNotFoundError):
        ai.manifest_tier_seed(tmp_path / "nope")


# --- ingest -------------------------------------------------------------------

def test_ingest_routes_the_inventory_file():
    index, parser = ingest_ef.route("ot_assets/assets.ndjson")
    assert index == "ot-assets"
    assert parser is ingest_ef.parse_ot_assets
    # The protocol tree is untouched by the new branch.
    assert ingest_ef.route("ot/modbus.ndjson")[0] == "ot-modbus"


def test_ingest_keys_assets_on_the_fqdn_and_gives_them_no_time(tmp_path: Path):
    ai.write_inventory(tmp_path, "L", 0)
    path = tmp_path / ai.ASSETS_DIR / ai.ASSETS_FILE
    parsed = list(ingest_ef.parse_ot_assets(path))
    assert len(parsed) == 40
    rec, when, native = parsed[0]
    assert when is None                      # an inventory is not an observation
    assert native == rec["fqdn"]
    assert ingest_ef.doc_id(rec, "ot_assets/assets.ndjson", 0, native) == rec["fqdn"]
    # One document per device, by construction.
    assert len({n for _r, _w, n in parsed}) == 40


def test_inventory_is_not_one_of_the_subsampled_indices():
    # The protocol streams are thinned to keep a GB-scale corpus ingestable; an
    # inventory missing 49 of every 50 devices would be worse than none.
    assert "ot-assets" not in ingest_ef._OT_SAMPLE_INDICES


# --- backfill verification ----------------------------------------------------

def _stub_distinct(monkeypatch, values: dict[tuple[str, str], list[str]]):
    def fake(es_url, index, field, **kw):
        return values.get((index, field), [])
    monkeypatch.setattr(ai, "_distinct", fake)


def test_verify_passes_when_every_ot_address_is_a_device(monkeypatch):
    ips = [r["ip"] for r in ai.asset_records("L", 0)][:5]
    _stub_distinct(monkeypatch, {("ot-conn", "src_ip"): ips,
                                 ("ot-modbus", "dest_ip"): ips[:2]})
    rep = ai.verify_against_es(ES_URL, "L", 0)
    assert rep["ok"] is True
    assert rep["devices"] == 40
    assert rep["ot_addresses"] == 5 == rep["ot_addresses_resolved"]
    assert rep["unresolved"] == []


def test_verify_reports_it_peers_instead_of_failing_on_them(monkeypatch):
    # ot-conn also carries the IT leg of every bridge session. A jump host is
    # legitimately not an OT asset, so it is counted, not failed on.
    _stub_distinct(monkeypatch, {("ot-conn", "src_ip"): ["10.41.0.10", "10.20.0.20"]})
    rep = ai.verify_against_es(ES_URL, "L", 0)
    assert rep["ok"] is True
    assert rep["ot_addresses"] == 1
    assert rep["non_ot_addresses"] == ["10.20.0.20"]


def test_verify_fails_on_an_ot_address_no_device_claims(monkeypatch):
    _stub_distinct(monkeypatch, {("ot-conn", "dest_ip"): ["10.41.0.10", "10.42.0.99"]})
    rep = ai.verify_against_es(ES_URL, "L", 0)
    assert rep["ok"] is False
    assert rep["unresolved"] == ["10.42.0.99"]
    assert rep["ot_addresses_resolved"] == 1


def test_backfill_indexes_nothing_when_verification_fails(monkeypatch, tmp_path: Path):
    (tmp_path / "corpus-manifest.yaml").write_text("tier: L\not_seed: 0\n")
    _stub_distinct(monkeypatch, {("ot-conn", "dest_ip"): ["10.42.0.99"]})
    indexed: list[str] = []
    monkeypatch.setattr(ai, "index_into_es", lambda *a, **k: indexed.append("wrote"))
    with pytest.raises(RuntimeError, match="10.42.0.99"):
        ai.backfill(tmp_path, ES_URL)
    assert indexed == []


def test_distinct_refuses_a_truncated_aggregation(monkeypatch):
    class _Resp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"aggregations": {"v": {"buckets": [{"key": "10.41.0.10"}],
                                           "sum_other_doc_count": 7}}}
    monkeypatch.setattr(ai.httpx, "post", lambda *a, **k: _Resp())
    with pytest.raises(RuntimeError, match="truncated"):
        ai._distinct(ES_URL, "ot-conn", "src_ip")


# --- live ---------------------------------------------------------------------

@requires_inventory
async def test_live_inventory_holds_every_device():
    import httpx
    n = httpx.get(f"{ES_URL}/{ai.ASSETS_INDEX}/_count", timeout=5.0).json()["count"]
    assert n == len(ai.asset_records(*LIVE_TIER_SEED))


@requires_inventory
def test_live_every_ot_host_name_is_in_the_inventory():
    """The name half of the join, which the address check does not cover.

    ot-hosts is where a model or a lead reads an OT device name. A name that is
    not in the inventory resolves to no address and a slice scoped to it binds
    no network tool -- the exact gap the inventory exists to close, and one the
    address-side check would not notice.
    """
    import httpx
    body = {"size": 0, "aggs": {"v": {"terms": {"field": "host.keyword", "size": 200}}}}
    agg = httpx.post(f"{ES_URL}/ot-hosts/_search", json=body, timeout=30.0).json()
    agg = agg["aggregations"]["v"]
    assert agg["sum_other_doc_count"] == 0
    names = [b["key"] for b in agg["buckets"]]
    recs = ai.asset_records(*LIVE_TIER_SEED)
    known = {r["fqdn"] for r in recs} | {r["name"] for r in recs}
    assert names and [n for n in names if n not in known] == []


@requires_inventory
def test_live_regenerated_inventory_matches_the_corpus():
    rep = ai.verify_against_es(ES_URL, *LIVE_TIER_SEED)
    assert rep["ok"], rep["unresolved"]
    assert rep["ot_addresses"] == rep["ot_addresses_resolved"]
