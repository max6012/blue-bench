"""Unit tests for the adversary injector (blue_bench_generators/merge/inject).

Covers host-remap correctness, capture-identity leak detection, external-infra
preservation, the doc_id contract with the ingest adapter (native uid vs sha256
fallback), and ground-truth repoint by original bundle order. No ES needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from blue_bench_generators.merge.inject import (
    HostRemap,
    doc_id_for,
    inject_bundle,
    leak_check,
    remap_event,
)

REMAP = HostRemap(
    from_name="WS-FIN-014", from_fqdn="ws-fin-014.corp.example", from_ip="10.10.4.37",
    to_name="WKST-03", to_fqdn="wkst-03.corp.example.invalid", to_ip="10.10.0.13",
)


def test_remap_rewrites_all_identity_forms():
    ev = {
        "Computer": "ws-fin-014.corp.example",
        "User": "WS-FIN-014\\Administrator",
        "id.orig_h": "10.10.4.37",
        "id.resp_h": "142.251.155.119",   # external C2 — must be preserved
        "nested": {"ParentImage": "C:\\Users\\WS-FIN-014\\x.exe"},
    }
    out = remap_event(ev, REMAP)
    assert out["Computer"] == "wkst-03.corp.example.invalid"
    assert out["User"] == "WKST-03\\Administrator"     # case-insensitive NETBIOS
    assert out["id.orig_h"] == "10.10.0.13"
    assert out["id.resp_h"] == "142.251.155.119"        # external untouched
    assert "WKST-03" in out["nested"]["ParentImage"]    # recurses


def test_leak_check_flags_residual_capture_identity():
    leaked = [{"Computer": "ws-fin-014.corp.example"}]
    assert leak_check(leaked, REMAP)                    # non-empty -> leak
    clean = [remap_event({"Computer": "ws-fin-014.corp.example"}, REMAP)]
    assert not leak_check(clean, REMAP)


def test_doc_id_matches_ingest_contract():
    # Zeek event with uid -> native id (matches ingest's native_id path)
    assert doc_id_for({"uid": "CabC123", "ts": "1.0"}) == "CabC123"
    # Sysmon event (no uid) -> sha256 over public fields, _-fields excluded
    a = doc_id_for({"Image": "x.exe", "_stream": "sysmon"})
    b = doc_id_for({"Image": "x.exe"})
    assert a == b and len(a) == 32


def _make_bundle(tmp: Path) -> Path:
    bd = tmp / "bundle"
    bd.mkdir()
    events = [
        {"_stream": "sysmon", "Computer": "ws-fin-014.corp.example", "Image": "powershell.exe"},
        {"_stream": "zeek", "uid": "CzeekUID1", "id.orig_h": "10.10.4.37",
         "id.resp_h": "142.251.155.119", "ts": "1.0"},
    ]
    (bd / "x.events.ndjson").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    gt = {
        "schema_version": "1.0", "incident_id": "x", "source_class": "apt",
        "segment_class": "IT", "ttps": ["T1059.001"],
        "events": [
            {"id": "evt-x-0001", "where": {"fixture_line": {"path": "x.events.ndjson", "line": 1}},
             "role": "execution", "ttp_links": ["T1059.001"]},
            {"id": "evt-x-0002", "where": {"fixture_line": {"path": "x.events.ndjson", "line": 2}},
             "role": "c2", "ttp_links": ["T1071.001"]},
        ],
    }
    (bd / "x.ground-truth.yaml").write_text(yaml.safe_dump(gt))
    return bd


def test_inject_repoints_gt_to_doc_ids_in_bundle_order(tmp_path: Path):
    bd = _make_bundle(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    summary = inject_bundle(corpus, bd, "x", REMAP)
    assert summary["events"] == 2 and summary["target_host"] == "wkst-03.corp.example.invalid"

    gt = yaml.safe_load((corpus / "ground-truth" / "x.ground-truth.yaml").read_text())
    wheres = [e["where"] for e in gt["events"]]
    assert all("doc_id" in w for w in wheres)            # repointed to doc_id
    # GT event 2 is the zeek event (uid) -> doc_id is that uid, despite the
    # injector grouping sysmon-first on disk (order-independent mapping)
    assert wheres[1]["doc_id"] == "CzeekUID1"
    # GT event 1 is the sysmon event -> sha256 doc_id (32 hex), not a uid
    assert len(wheres[0]["doc_id"]) == 32

    # injected files written per stream, no _-fields, no capture identity
    blob = "".join(p.read_text() for p in (corpus / "injected").glob("*.ndjson"))
    assert "ws-fin-014" not in blob.lower() and "10.10.4.37" not in blob
    assert "wkst-03.corp.example.invalid" in blob
    assert "142.251.155.119" in blob                     # external C2 preserved
    assert "_stream" not in blob                         # internal field stripped


def test_inject_raises_on_count_mismatch(tmp_path: Path):
    bd = _make_bundle(tmp_path)
    # corrupt GT to have a different event count
    gt = yaml.safe_load((bd / "x.ground-truth.yaml").read_text())
    gt["events"] = gt["events"][:1]
    (bd / "x.ground-truth.yaml").write_text(yaml.safe_dump(gt))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    try:
        inject_bundle(corpus, bd, "x", REMAP)
        assert False, "expected ValueError on count mismatch"
    except ValueError as e:
        assert "event count" in str(e)


def test_rebase_shifts_campaign_preserving_dwell():
    from datetime import datetime, timezone
    from blue_bench_generators.merge.inject import rebase_campaign, _event_time
    events = [
        {"_stream": "sysmon", "UtcTime": "2026-01-05 09:00:00.000"},
        {"_stream": "sysmon", "UtcTime": "2026-01-15 09:00:00.000"},  # +10 days
        {"_stream": "zeek", "ts": str(datetime(2026, 1, 10, 9, 0, tzinfo=timezone.utc).timestamp())},
    ]
    corpus_start = datetime(2026, 3, 2, 5, 0, tzinfo=timezone.utc)
    shifted, new_start, new_end, delta = rebase_campaign(events, corpus_start)
    # dwell preserved (10 days), start lands at/after corpus_start
    assert (new_end - new_start).days == 10
    assert new_start >= corpus_start
    # relative spacing intact: middle zeek event still ~5 days after start
    mid = _event_time(shifted[2])
    assert 4 <= (mid - new_start).days <= 6
