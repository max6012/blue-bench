"""Unit tests for the adversary injector (blue_bench_generators/merge/inject).

Covers host-remap correctness, capture-identity leak detection, external-infra
preservation, the doc_id contract with the ingest adapter (agreement between the
ids the ground truth points at and the ids the ingest will actually write), and
ground-truth repoint by original bundle order. No ES needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from blue_bench_generators.merge.inject import (
    HostRemap,
    doc_ids_for_file,
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


def _ingest_module():
    """The real ingest adapter, loaded the way it is actually run."""
    import importlib.util
    path = Path(__file__).resolve().parents[1] / "scripts" / "ingest_ef.py"
    spec = importlib.util.spec_from_file_location("_t_ingest_ef", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ids_the_ingest_will_write(corpus: Path) -> dict[str, list[str]]:
    """Recompute every injected _id by the ingest's own route+parser+doc_id.

    This deliberately does NOT call anything in inject.py — it walks the corpus
    exactly as ``ingest()`` does (``relative_to(ef_dir)``, ``route()``,
    ``enumerate(parser(path))``) so the test compares two independent paths.
    """
    ing = _ingest_module()
    out: dict[str, list[str]] = {}
    for path in sorted(corpus.rglob("*")):
        if not path.is_file():
            continue
        relpath = str(path.relative_to(corpus)).replace("\\", "/")
        routed = ing.route(relpath)
        if routed is None:
            continue
        _index, parser = routed
        out[relpath] = [
            ing.doc_id(rec, relpath, ordinal, native_id)
            for ordinal, (rec, _when, native_id) in enumerate(parser(path))
        ]
    return out


def test_gt_doc_ids_agree_with_the_ids_the_ingest_will_write(tmp_path: Path):
    """The property that matters: AGREEMENT, not uniqueness.

    Both sides could be internally unique and still mutually wrong — that is
    exactly how issue #31 hid. So recompute the ids through the ingest's own
    code path and require set-equality with the ground-truth pointers.
    """
    bd = _make_bundle(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    inject_bundle(corpus, bd, "x", REMAP)

    gt = yaml.safe_load((corpus / "ground-truth" / "x.ground-truth.yaml").read_text())
    pointers = [e["where"]["doc_id"] for e in gt["events"]]

    by_file = _ids_the_ingest_will_write(corpus)
    assert by_file, "the ingest routes none of the injected files"
    will_write = {i for ids in by_file.values() for i in ids}

    orphans = set(pointers) - will_write
    assert not orphans, (
        f"{len(orphans)} ground-truth pointer(s) address a doc_id the ingest will "
        f"never write: {sorted(orphans)}"
    )


def test_each_gt_pointer_addresses_its_own_event_not_just_some_event(tmp_path: Path):
    """Set-equality is necessary but not sufficient — a permutation passes it.

    Pin one known event by content: GT event 1 is the sysmon powershell event,
    so its pointer must be the id of the record whose Image is powershell.exe.
    """
    ing = _ingest_module()
    bd = _make_bundle(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    inject_bundle(corpus, bd, "x", REMAP)

    gt = yaml.safe_load((corpus / "ground-truth" / "x.ground-truth.yaml").read_text())

    want = None
    for path in sorted((corpus / "injected").glob("*.ndjson")):
        relpath = f"injected/{path.name}"
        _index, parser = ing.route(relpath)
        for ordinal, (rec, _when, native_id) in enumerate(parser(path)):
            if rec.get("Image") == "powershell.exe":
                want = ing.doc_id(rec, relpath, ordinal, native_id)
    assert want is not None, "the powershell event was not written to the corpus"
    assert gt["events"][0]["where"]["doc_id"] == want


def test_duplicate_events_get_distinct_ids(tmp_path: Path):
    """Issue #31 repro. Genuinely repeated telemetry is normal (same image, same
    command line, same second); under a bare content hash all N collapsed onto
    one _id and a bulk index reported N successes while writing 1 document.
    """
    bd = tmp_path / "bundle"
    bd.mkdir()
    dupe = {"_stream": "sysmon", "Computer": "ws-fin-014.corp.example",
            "Image": "powershell.exe", "UtcTime": "2026-03-02 10:24:01.141"}
    n = 12
    (bd / "d.events.ndjson").write_text(
        "\n".join(json.dumps(dict(dupe)) for _ in range(n)) + "\n")
    gt = {
        "schema_version": "1.0", "incident_id": "d", "source_class": "apt",
        "segment_class": "IT", "ttps": ["T1059.001"],
        "events": [
            {"id": f"evt-d-{i:04d}",
             "where": {"fixture_line": {"path": "d.events.ndjson", "line": i + 1}},
             "role": "execution", "ttp_links": ["T1059.001"]}
            for i in range(n)
        ],
    }
    (bd / "d.ground-truth.yaml").write_text(yaml.safe_dump(gt))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    inject_bundle(corpus, bd, "d", REMAP)

    ids = doc_ids_for_file(corpus / "injected" / "d.sysmon.sysmon.ndjson")
    assert len(ids) == n, f"wrote {n} records, parser yields {len(ids)}"
    assert len(set(ids)) == n, (
        f"{n - len(set(ids))} of {n} identical records share an _id — they would "
        f"overwrite each other on ingest"
    )

    # ...and the ground truth must address all n distinct documents.
    out = yaml.safe_load((corpus / "ground-truth" / "d.ground-truth.yaml").read_text())
    pointers = [e["where"]["doc_id"] for e in out["events"]]
    assert len(set(pointers)) == n
    assert set(pointers) == set(ids)


def test_several_http_transactions_on_one_uid_do_not_collide(tmp_path: Path):
    """A Zeek ``uid`` identifies a connection, not a record: one connection can
    carry several http transactions, and there is no ``trans_depth`` on these
    records to disambiguate. Keying _id on uid collapsed them (issue #36).
    """
    bd = tmp_path / "bundle"
    bd.mkdir()
    events = [
        {"_stream": "zeek", "_log": "http", "uid": "CsharedUID",
         "id.orig_h": "10.10.4.37", "id.resp_h": "142.251.155.119",
         "ts": str(1.0 + i), "uri": f"/stage{i}"}
        for i in range(3)
    ]
    (bd / "h.events.ndjson").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    gt = {
        "schema_version": "1.0", "incident_id": "h", "source_class": "apt",
        "segment_class": "IT", "ttps": ["T1071.001"],
        "events": [
            {"id": f"evt-h-{i:04d}",
             "where": {"fixture_line": {"path": "h.events.ndjson", "line": i + 1}},
             "role": "c2", "ttp_links": ["T1071.001"]}
            for i in range(3)
        ],
    }
    (bd / "h.ground-truth.yaml").write_text(yaml.safe_dump(gt))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    inject_bundle(corpus, bd, "h", REMAP)

    ids = doc_ids_for_file(corpus / "injected" / "h.zeek.http.ndjson")
    assert len(set(ids)) == 3, f"three http transactions on one uid collapsed to {set(ids)}"


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
    # Both are 32-hex content+position hashes. The zeek event's uid is NOT used
    # as the _id: a uid identifies a connection, not a record, so several http
    # transactions would share one. The mapping stays keyed on original bundle
    # order despite the injector grouping sysmon-first on disk.
    assert all(len(w["doc_id"]) == 32 for w in wheres)
    assert wheres[0]["doc_id"] != wheres[1]["doc_id"]
    assert "CzeekUID1" not in {w["doc_id"] for w in wheres}

    # injected files written per stream, no _-fields, no capture identity
    blob = "".join(p.read_text() for p in (corpus / "injected").glob("*.ndjson"))
    assert "ws-fin-014" not in blob.lower() and "10.10.4.37" not in blob
    assert "wkst-03.corp.example.invalid" in blob
    assert "142.251.155.119" in blob                     # external C2 preserved
    assert "_stream" not in blob                         # internal field stripped


def test_inject_raises_when_gt_exceeds_events(tmp_path: Path):
    # GT with MORE events than the bundle can't be repointed by index (dangling
    # pointer). GT with fewer is fine — the surplus is un-referenced supporting
    # telemetry (e.g. synthesized beacon callbacks).
    bd = _make_bundle(tmp_path)
    gt = yaml.safe_load((bd / "x.ground-truth.yaml").read_text())
    gt["events"] = gt["events"] + gt["events"]  # double -> exceeds bundle events
    (bd / "x.ground-truth.yaml").write_text(yaml.safe_dump(gt))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    try:
        inject_bundle(corpus, bd, "x", REMAP)
        assert False, "expected ValueError when GT exceeds injected events"
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


# --- issue #35: adversary dwell must be reachable with the documented defaults --

# The registered MCP surface (blue_bench_mcp/tools/) documents and passes a
# 240-minute default lookback. detect_beaconing passes 0 and falls back to
# config.default_window_minutes = 10080 (7d). If the campaign's last event is
# older than the shortest of those, a player using nothing but defaults sees an
# empty tail.
MCP_DEFAULT_LOOKBACK_MINUTES = 240


def _make_l_window_corpus(tmp: Path, days: int = 18) -> tuple[Path, datetime, datetime]:
    """A corpus dir whose declared collection window is L-tier sized."""
    from datetime import datetime, timedelta, timezone
    corpus = tmp / "corpus"
    corpus.mkdir()
    end = datetime(2026, 9, 9, 18, 0, tzinfo=timezone.utc)
    start = end - timedelta(days=days)
    (corpus / "GROUND_TRUTH.json").write_text(json.dumps({
        "collection_window": {"start": start.isoformat(), "end": end.isoformat()}
    }))
    return corpus, start, end


def _long_dwell_bundle(tmp: Path, incident_id: str, dwell_days: int = 11) -> Path:
    """A low-and-slow bundle: first and last event `dwell_days` apart."""
    from datetime import datetime, timedelta, timezone
    bd = tmp / f"bundle-{incident_id}"
    bd.mkdir()
    t0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
    stamps = [t0, t0 + timedelta(days=dwell_days // 2), t0 + timedelta(days=dwell_days)]
    events = [
        {"_stream": "sysmon", "Computer": "ws-fin-014.corp.example",
         "Image": f"stage{i}.exe",
         "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.000")}
        for i, t in enumerate(stamps)
    ]
    (bd / f"{incident_id}.events.ndjson").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n")
    gt = {
        "schema_version": "1.0", "incident_id": incident_id, "source_class": "apt",
        "segment_class": "IT", "ttps": ["T1059.001"],
        "time_window": {"injection_start": "", "injection_end": "", "duration_seconds": 0},
        "events": [
            {"id": f"evt-{incident_id}-{i:04d}",
             "where": {"fixture_line": {"path": f"{incident_id}.events.ndjson", "line": i + 1}},
             "role": "execution", "ttp_links": ["T1059.001"]}
            for i in range(len(events))
        ],
    }
    (bd / f"{incident_id}.ground-truth.yaml").write_text(yaml.safe_dump(gt))
    return bd


def _injection_end(corpus: Path, incident_id: str) -> "datetime":
    from datetime import datetime, timezone
    gt = yaml.safe_load(
        (corpus / "ground-truth" / f"{incident_id}.ground-truth.yaml").read_text())
    raw = gt["time_window"]["injection_end"]
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)


def test_injected_campaign_is_reachable_with_the_default_lookback(tmp_path: Path):
    """Issue #35. Start-anchoring left days ~12.5-18 of an 18-day L window empty
    of adversary activity, so the documented default lookbacks searched a tail
    that contained nothing.
    """
    corpus, _cstart, cend = _make_l_window_corpus(tmp_path)
    bd = _long_dwell_bundle(tmp_path, "apt")
    inject_bundle(corpus, bd, "apt", REMAP)

    end = _injection_end(corpus, "apt")
    age_minutes = (cend - end).total_seconds() / 60
    assert 0 < age_minutes <= MCP_DEFAULT_LOOKBACK_MINUTES, (
        f"the campaign's last event is {age_minutes:.0f} min before the corpus "
        f"end; a player using the documented {MCP_DEFAULT_LOOKBACK_MINUTES}-minute "
        f"default sees no adversary activity at all"
    )


def test_rebase_preserves_full_dwell_while_end_anchoring(tmp_path: Path):
    """End-anchoring must not compress the campaign — the dwell IS the RQ2 signal."""
    corpus, cstart, _cend = _make_l_window_corpus(tmp_path)
    bd = _long_dwell_bundle(tmp_path, "apt", dwell_days=11)
    inject_bundle(corpus, bd, "apt", REMAP)

    gt = yaml.safe_load((corpus / "ground-truth" / "apt.ground-truth.yaml").read_text())
    assert gt["time_window"]["duration_seconds"] == 11 * 24 * 3600
    # ...and it still fits inside the corpus window (no events before the haystack)
    from datetime import datetime, timezone
    start = datetime.fromisoformat(
        gt["time_window"]["injection_start"].replace("Z", "+00:00")
    ).replace(tzinfo=timezone.utc)
    assert start >= cstart


def test_campaigns_do_not_all_end_at_the_same_instant(tmp_path: Path):
    """A single constant cooldown would make every campaign co-terminal.

    Identical end times across the APT and the cybercrime foil are a separable
    signal with nothing to do with tradecraft, and they sit directly in RQ3's
    path (APT vs cybercrime discrimination).
    """
    corpus, _cstart, cend = _make_l_window_corpus(tmp_path)
    ends = {}
    for incident_id in ("apt", "cybercrime", "commodity"):
        bd = _long_dwell_bundle(tmp_path, incident_id, dwell_days=6)
        inject_bundle(corpus, bd, incident_id, REMAP)
        ends[incident_id] = _injection_end(corpus, incident_id)

    assert len(set(ends.values())) == len(ends), (
        f"campaigns are co-terminal: {ends}"
    )
    # ...but every one is still inside the default lookback
    for incident_id, end in ends.items():
        age = (cend - end).total_seconds() / 60
        assert 0 < age <= MCP_DEFAULT_LOOKBACK_MINUTES, (incident_id, age)


def test_cooldown_is_deterministic_across_rebuilds():
    from blue_bench_generators.merge.inject import cooldown_for
    assert cooldown_for("apt-2026-03") == cooldown_for("apt-2026-03")
    assert cooldown_for("apt") != cooldown_for("cybercrime")
    for incident_id in ("apt", "cybercrime", "commodity", "ot-intrusion", "x"):
        mins = cooldown_for(incident_id).total_seconds() / 60
        assert 0 < mins <= MCP_DEFAULT_LOOKBACK_MINUTES, (incident_id, mins)
