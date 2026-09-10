"""cred_inject generator — determinism, schema validity, capture-identity, and
alignment with the merge registration."""
from __future__ import annotations

import json
from pathlib import Path

from blue_bench_generators.cred_inject.bundle import build_ground_truth, write_bundle
from blue_bench_generators.cred_inject.events import BUILDERS, CAP_FQDN, CAP_IP, CAP_NAME
from blue_bench_generators.cybercrime_foil.bundle import validate_bundle

CAPTURE = {CAP_NAME, CAP_FQDN, CAP_IP}


def _write_all(root: Path) -> None:
    for builder in BUILDERS.values():
        write_bundle(builder(), root)


def test_all_bundles_validate():
    for incident_id, builder in BUILDERS.items():
        gt = build_ground_truth(builder())          # calls validate_bundle internally
        validate_bundle(gt)                          # explicit, belt-and-suspenders
        assert gt["incident_id"] == incident_id
        assert gt["segment_class"] == "IT"
        assert gt["source_class"] in {"apt", "cybercrime", "benign-anomaly"}


def test_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    _write_all(a)
    _write_all(b)
    files = sorted(p.relative_to(a) for p in a.rglob("*") if p.is_file())
    assert files, "no bundles written"
    for rel in files:
        assert (a / rel).read_bytes() == (b / rel).read_bytes(), f"non-deterministic: {rel}"


def test_capture_identity_present_and_attacker_ips_synthetic(tmp_path):
    _write_all(tmp_path)
    for ev_file in tmp_path.rglob("*.events.ndjson"):
        for line in ev_file.read_text().splitlines():
            blob = json.dumps(json.loads(line))
            # remap needs the capture identity somewhere in every event
            assert any(tok in blob for tok in CAPTURE), f"no capture identity in {ev_file.name}: {line[:80]}"
    # the capture IP is the victim identity, never used as an attacker source field
    for builder in BUILDERS.values():
        for ev, _role in builder().events:
            assert ev.get("IpAddress") != CAP_IP          # winsec attacker source
            assert ev.get("dest_ip") != CAP_IP            # suricata C2 dest
            if ev.get("_stream") == "wazuh":
                assert ev["data"].get("srcip") != CAP_IP  # wazuh alert source


def test_matches_merge_registration():
    from blue_bench_generators.merge.__main__ import _DEFAULT_ADVERSARIES
    registered = {inc: sub for inc, sub, _host in _DEFAULT_ADVERSARIES["L"]}
    for incident_id, builder in BUILDERS.items():
        assert incident_id in registered, f"{incident_id} not registered in _DEFAULT_ADVERSARIES[L]"
        assert builder().subdir == registered[incident_id], f"subdir mismatch for {incident_id}"
