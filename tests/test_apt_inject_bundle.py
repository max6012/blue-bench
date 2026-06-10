"""Rewrite + bundle tests for the APT injection harness (synthetic events).

End-to-end-ish: synthesize a tiny two-stage selection, schedule, rewrite,
and emit a bundle; assert the host/time rewrite landed, no capture
identity leaks, and the ground-truth passes all 11 schema rules.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from blue_bench_generators.apt_inject.bundle import (
    CorpusBinding,
    build_apt_ground_truth,
    validate_bundle,
    write_apt_bundle,
)
from blue_bench_generators.apt_inject.rewrite import HostMap, rewrite_plan
from blue_bench_generators.apt_inject.schedule import schedule_campaign

HMAP = HostMap(
    capture_name="EC2AMAZ-VU9QJAP",
    capture_ip="10.20.1.210",
    target_name="WS-FIN-014",
    target_fqdn="ws-fin-014.corp.example",
    target_ip="10.10.4.37",
)


def _sysmon(eid, guid, cmdline, ts, **extra):
    ev = {
        "_stream": "sysmon", "_log": "sysmon", "event_id": eid,
        "_capture_ts": ts, "ProcessGuid": guid, "CommandLine": cmdline,
        "Computer": "EC2AMAZ-VU9QJAP", "User": "EC2AMAZ-VU9QJAP\\Administrator",
    }
    ev.update(extra)
    return ev


def _plan():
    cap = datetime(2026, 6, 9, 22, 0, 0, tzinfo=timezone.utc)
    stage_signal = {
        "initial-access": [_sysmon(1, "ia", "invoke-webrequest x.docm", cap)],
        "exfiltration": [
            {"_stream": "zeek", "_log": "http", "_capture_ts": cap,
             "ts": str(cap.timestamp()), "id.orig_h": "10.20.1.210",
             "id.resp_h": "203.0.113.9", "id.resp_p": "80"},
        ],
    }
    return schedule_campaign(stage_signal, dwell_start=datetime(2026, 1, 6, 9, 0, 0),
                             dwell_days=10.0, campaign_id="t", seed=0)


def test_rewrite_applies_host_and_time_no_leak():
    rewritten = rewrite_plan(_plan(), HMAP)
    blob = json.dumps(rewritten)
    # capture identity fully scrubbed (incl. User = HOST\\user)
    assert "EC2AMAZ-VU9QJAP" not in blob
    assert "10.20.1.210" not in blob
    # target identity present
    assert any(e.get("Computer") == "ws-fin-014.corp.example" for e in rewritten)
    assert any(e.get("User") == "WS-FIN-014\\Administrator" for e in rewritten)
    assert any(e.get("id.orig_h") == "10.10.4.37" for e in rewritten if e["_stream"] == "zeek")
    # timestamps shifted into the campaign window (Jan 2026, not Jun)
    for e in rewritten:
        if e["_stream"] == "sysmon":
            assert e["UtcTime"].startswith("2026-01")


def test_bundle_passes_schema_and_pointers_line_up(tmp_path: Path):
    rewritten = rewrite_plan(_plan(), HMAP)
    corpus = CorpusBinding(tier="L", build_hash="0" * 64,
                           baseline_generator_config="blue_bench_generators/it_baseline")
    nd, yml = write_apt_bundle(
        campaign_id="apt-test", rewritten_events=rewritten, corpus=corpus,
        injection_start=datetime(2026, 1, 6, 9, 0, 0),
        injection_end=datetime(2026, 1, 16, 9, 0, 0),
        bundle_dir=tmp_path,
    )
    gt = yaml.safe_load(yml.read_text())
    validate_bundle(gt)  # all 11 rules
    assert gt["source_class"] == "apt"
    # every event pointer's line N resolves to a real NDJSON line
    ndjson_lines = nd.read_text().splitlines()
    for ev in gt["events"]:
        line_no = ev["where"]["fixture_line"]["line"]
        assert 1 <= line_no <= len(ndjson_lines)
        json.loads(ndjson_lines[line_no - 1])  # parses


def test_ttps_required_subset_of_ttps():
    rewritten = rewrite_plan(_plan(), HMAP)
    gt = build_apt_ground_truth(
        campaign_id="x", rewritten_events=rewritten,
        corpus=CorpusBinding("L", "0" * 64, "cfg"),
        injection_start=datetime(2026, 1, 6, 9, 0, 0),
        injection_end=datetime(2026, 1, 16, 9, 0, 0),
    )
    req = set(gt["expected_findings"]["ttp_attribution"]["required"])
    assert req.issubset(set(gt["ttps"]))
    # apt is RQ2, discrimination not required
    assert gt["scoring"]["discrimination"]["required"] is False
