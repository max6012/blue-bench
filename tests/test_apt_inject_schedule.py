"""Signal-selection + campaign-scheduling tests (synthetic events).

Runs without the gitignored captures: a small synthetic process tree
exercises the GUID-subtree selector, and a two-stage signal exercises the
dwell scheduler.
"""

from __future__ import annotations

from datetime import datetime, timezone

from blue_bench_generators.apt_inject.schedule import (
    schedule_campaign,
    select_signal,
)


def _sysmon(eid, guid=None, parent=None, cmdline="", ts=None, **extra):
    ev = {
        "_stream": "sysmon",
        "_log": "sysmon",
        "event_id": eid,
        "_capture_ts": ts,
        "CommandLine": cmdline,
    }
    if guid is not None:
        ev["ProcessGuid"] = guid
    if parent is not None:
        ev["ParentProcessGuid"] = parent
    ev.update(extra)
    return ev


def test_select_anchors_and_walks_subtree():
    t0 = datetime(2026, 6, 9, 22, 0, 0, tzinfo=timezone.utc)
    events = [
        # ambient benign process — must NOT be selected
        _sysmon(1, guid="benign-1", parent="root", cmdline="C:\\Windows\\explorer.exe", ts=t0),
        # the atomic anchor (cred-access comsvcs LSASS dump)
        _sysmon(1, guid="atk-1", parent="shell",
                cmdline="powershell.exe & {rundll32 C:\\windows\\System32\\comsvcs.dll, MiniDump 600 dump.bin full}",
                ts=t0),
        # a child of the anchor — selected via subtree walk
        _sysmon(1, guid="atk-2", parent="atk-1", cmdline="rundll32.exe comsvcs.dll", ts=t0),
        # a registry write BY the child process — selected (acting guid in subtree)
        _sysmon(13, guid="atk-2", ts=t0, TargetObject="HKLM\\...\\Run\\x"),
        # a benign EID10 lsass read by svchost — NOT selected (guid not in subtree)
        _sysmon(10, ts=t0, TargetImage="C:\\Windows\\System32\\lsass.exe",
                SourceImage="svchost.exe", **{"SourceProcessGUID": "benign-svc"}),
        # an EID10 by the atomic child — selected
        _sysmon(10, ts=t0, TargetImage="C:\\Windows\\System32\\lsass.exe",
                SourceImage="rundll32.exe", **{"SourceProcessGUID": "atk-2"}),
    ]
    sel = select_signal(events, "credential-access")
    guids = {e.get("ProcessGuid") for e in sel}
    # anchor + child present
    assert "atk-1" in {e.get("ProcessGuid") for e in sel if e["event_id"] == 1}
    assert "atk-2" in {e.get("ProcessGuid") for e in sel if e["event_id"] == 1}
    # benign process not selected
    assert "benign-1" not in guids
    # the atomic EID10 selected, benign svchost EID10 not
    e10 = [e for e in sel if e["event_id"] == 10]
    assert len(e10) == 1
    assert e10[0]["SourceProcessGUID"] == "atk-2"


def test_select_drops_ssh_control_channel():
    t0 = datetime(2026, 6, 9, 22, 0, 0, tzinfo=timezone.utc)
    events = [
        # atomic web beacon — kept
        {"_stream": "zeek", "_log": "http", "_capture_ts": t0,
         "id.orig_h": "10.20.1.210", "id.resp_p": "80", "user_agent": "HttpBrowser/1.0"},
        # harness SSH control — dropped
        {"_stream": "zeek", "_log": "conn", "_capture_ts": t0,
         "id.orig_h": "108.46.171.121", "id.resp_p": "22"},
    ]
    sel = select_signal(events, "command-and-control")
    assert all(e.get("id.resp_p") != "22" for e in sel)
    assert any(e.get("user_agent") == "HttpBrowser/1.0" for e in sel)


def test_schedule_orders_stages_and_is_deterministic():
    t0 = datetime(2026, 1, 6, 9, 0, 0)
    cap = datetime(2026, 6, 9, 22, 0, 0, tzinfo=timezone.utc)
    stage_signal = {
        "initial-access": [_sysmon(1, guid="ia", cmdline="invoke-webrequest x.docm", ts=cap)],
        "exfiltration": [_sysmon(1, guid="ex", cmdline="invoke-webrequest exfil", ts=cap)],
    }
    plan_a = schedule_campaign(stage_signal, dwell_start=t0, dwell_days=10.0,
                               campaign_id="c1", seed=0)
    plan_b = schedule_campaign(stage_signal, dwell_start=t0, dwell_days=10.0,
                               campaign_id="c1", seed=0)
    # deterministic
    assert [s.campaign_ts for s in plan_a.scheduled] == [s.campaign_ts for s in plan_b.scheduled]
    # initial-access lands before exfiltration on the timeline
    by_stage = {s.stage: s.campaign_ts for s in plan_a.scheduled}
    assert by_stage["initial-access"] < by_stage["exfiltration"]
    # both inside the dwell window
    for s in plan_a.scheduled:
        assert t0 <= s.campaign_ts <= plan_a.dwell_end


def test_schedule_seed_changes_jitter():
    t0 = datetime(2026, 1, 6, 9, 0, 0)
    cap = datetime(2026, 6, 9, 22, 0, 0, tzinfo=timezone.utc)
    sig = {"credential-access": [_sysmon(1, guid="a", cmdline="comsvcs.dll MiniDump", ts=cap)]}
    a = schedule_campaign(sig, dwell_start=t0, dwell_days=10.0, campaign_id="c", seed=0)
    b = schedule_campaign(sig, dwell_start=t0, dwell_days=10.0, campaign_id="c", seed=1)
    assert a.scheduled[0].campaign_ts != b.scheduled[0].campaign_ts
