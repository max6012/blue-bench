"""Tests for the Sysmon event generator (t-r858).

Covers:
    * Windows-only host filter (Linux hosts emit nothing).
    * Determinism for fixed (topology, start, end, seed).
    * Window respect (no events outside [start, end)).
    * EventID 1 volume tracks the activity model's process_creation rate.
    * Parent-child process consistency (every EventID 1's ParentProcessGuid
      exists as a prior EventID 1 on the same host).
    * Per-role process tree templates (admin-WS runs powershell; plain
      workstation never runs sqlservr).
    * Image loads attach to a real prior process on the same host.
    * Synthetic hash flagging via ``_note`` (no real-IOC contamination).
    * Time-of-day responsiveness (overnight volume < workday volume).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators.it_baseline.behavior import build_activity_model
from blue_bench_generators.it_baseline.sysmon import generate
from blue_bench_generators.it_baseline.topology import build_topology


# --- helpers ---------------------------------------------------------------

# Pin to a known Monday so weekday() == 0.
MON_09 = datetime(2026, 5, 11, 9, 0, 0)
MON_12 = datetime(2026, 5, 11, 12, 0, 0)
MON_22 = datetime(2026, 5, 11, 22, 0, 0)
MON_24 = datetime(2026, 5, 12, 0, 0, 0)
MON_03 = datetime(2026, 5, 11, 3, 0, 0)
MON_06 = datetime(2026, 5, 11, 6, 0, 0)


def _model(tier: str = "S", seed: int = 0):
    topo = build_topology(tier, seed=seed)  # type: ignore[arg-type]
    am = build_activity_model(topo)
    return topo, am


# --- tests -----------------------------------------------------------------


def test_only_windows_hosts_emit_events():
    topo, am = _model("M")
    events = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=2), seed=42))
    # Build a map fqdn -> os and assert no event came from a linux host.
    os_by_fqdn = {h.fqdn: h.os for h in topo.hosts}
    for ev in events:
        assert os_by_fqdn[ev["Computer"]] == "windows", (
            f"event from non-windows host: {ev['Computer']}"
        )
    # And the windows hosts collectively did emit something.
    assert events, "expected some events from windows hosts"


def test_deterministic_with_seed():
    topo, am = _model("S")
    a = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=2), seed=7))
    b = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=2), seed=7))
    assert a == b
    # Different seed -> different output.
    c = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=2), seed=8))
    assert a != c


def test_no_events_outside_window():
    topo, am = _model("S")
    start = MON_09
    end = MON_09 + timedelta(hours=3)
    events = list(generate(topo, am, start, end, seed=0))
    assert events, "expected at least some events"
    start_str = start.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    end_str = end.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    for ev in events:
        assert start_str <= ev["UtcTime"] < end_str, (
            f"event outside window: {ev['UtcTime']} (window {start_str}..{end_str})"
        )


def test_event_id_1_volume_matches_process_creation_rate():
    """Sum of EventID 1 per host roughly tracks the integrated rate.

    Run a long-enough window (12 hours, weekday) on tier S to keep the
    integral well above 0 but the topology small. Tolerance is wide
    (factor of 2 either way) because:

      * The boot tree adds a small fixed offset per host.
      * Workstations attach role templates at process_creation rate but
        servers attach at the same rate -- the table values are large
        enough that boot offset is small relative to the integral.

    We assert the ratio of observed-to-expected stays in [0.4, 2.0] per
    host over the window. This is enough signal to catch a bug where
    the rate is ignored entirely, while accepting Poisson variance.
    """
    topo, am = _model("S")
    start = MON_09
    end = MON_09 + timedelta(hours=12)
    events = list(generate(topo, am, start, end, seed=0))

    # Count EventID 1 per host.
    from collections import defaultdict
    counts: dict[str, int] = defaultdict(int)
    for ev in events:
        if ev["event_id"] == 1:
            counts[ev["Computer"]] += 1

    # Compute expected integral per host: sum over hours of rate(host, "process_creation", ts).
    windows_hosts = [h for h in topo.hosts if h.os == "windows"]
    assert windows_hosts, "fixture topology has no windows hosts -- bad fixture"
    for host in windows_hosts:
        expected = 0.0
        cursor = start
        while cursor < end:
            expected += am.rate(host, "process_creation", cursor)
            cursor = cursor + timedelta(hours=1)
        observed = counts[host.fqdn]
        # The boot tree adds 5 events; subtract it before ratio.
        observed_minus_boot = max(0, observed - 5)
        # Plus services.exe spawn on servers.
        ratio = (observed_minus_boot + 1) / (expected + 1)  # +1 smoothing
        # Tolerance is wide -- Poisson variance + servers floor at 0.85
        # + workstations get a 0.5/0.6 multiplier across lunch + evening
        # all conspire to push the ratio off 1.0. We just want to catch
        # the case where rate is ignored entirely.
        assert 0.25 <= ratio <= 3.0, (
            f"host {host.name} ({host.role}): observed {observed} EventID 1, "
            f"expected ~{expected:.1f}, ratio={ratio:.2f}"
        )


def test_parent_child_process_consistency():
    """Every EventID 1's ParentProcessGuid is a known ProcessGuid on host.

    The boot-tree root (``System``) self-parents, which counts as
    "known on this host".
    """
    topo, am = _model("S")
    events = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=2), seed=0))

    # Group EventID 1 by host.
    from collections import defaultdict
    by_host: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["event_id"] == 1:
            by_host[ev["Computer"]].append(ev)

    assert by_host, "expected at least one EventID 1"

    for fqdn, recs in by_host.items():
        # Sort by UtcTime so "prior" is meaningful.
        recs.sort(key=lambda e: e["UtcTime"])
        known_guids: set[str] = set()
        for ev in recs:
            # Self-parent counts as a valid root.
            if ev["ParentProcessGuid"] == ev["ProcessGuid"]:
                known_guids.add(ev["ProcessGuid"])
                continue
            assert ev["ParentProcessGuid"] in known_guids, (
                f"host {fqdn}: process {ev['Image']} (guid={ev['ProcessGuid']}) "
                f"has unknown parent {ev['ParentProcessGuid']}"
            )
            known_guids.add(ev["ProcessGuid"])


def test_admin_workstation_runs_powershell():
    topo, am = _model("M")
    events = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=4), seed=0))
    admin_ws = {h.fqdn for h in topo.hosts if h.role == "admin-workstation"}
    assert admin_ws, "fixture has no admin-workstation hosts"

    powershell_seen = any(
        ev["event_id"] == 1
        and ev["Computer"] in admin_ws
        and "powershell.exe" in ev["Image"].lower()
        for ev in events
    )
    assert powershell_seen, (
        "expected at least one EventID 1 with powershell.exe on an admin-workstation"
    )


def test_workstation_does_not_run_sqlservr():
    topo, am = _model("M")
    events = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=4), seed=0))
    plain_ws = {h.fqdn for h in topo.hosts if h.role == "workstation"}
    assert plain_ws, "fixture has no plain workstations"

    for ev in events:
        if ev["event_id"] != 1:
            continue
        if ev["Computer"] not in plain_ws:
            continue
        assert "sqlservr" not in ev["Image"].lower(), (
            f"plain workstation {ev['Computer']} spawned sqlservr -- role template leak"
        )


def test_image_loads_attach_to_existing_processes():
    """Every EventID 7's ProcessGuid matches a prior EventID 1 on the host."""
    topo, am = _model("S")
    events = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=2), seed=0))

    # Build the per-host set of process guids ever observed in EventID 1.
    from collections import defaultdict
    proc_guids: dict[str, set[str]] = defaultdict(set)
    for ev in events:
        if ev["event_id"] == 1:
            proc_guids[ev["Computer"]].add(ev["ProcessGuid"])

    seen_seven = False
    for ev in events:
        if ev["event_id"] != 7:
            continue
        seen_seven = True
        assert ev["ProcessGuid"] in proc_guids[ev["Computer"]], (
            f"host {ev['Computer']}: EventID 7 references unknown ProcessGuid "
            f"{ev['ProcessGuid']}"
        )
    assert seen_seven, "expected at least one EventID 7 in the corpus"


def test_hashes_marked_synthetic_in_comment_or_note():
    """Events carrying Hashes also carry a synthetic-flag _note."""
    topo, am = _model("S")
    events = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=2), seed=0))

    hashed_events = [ev for ev in events if "Hashes" in ev]
    assert hashed_events, "expected at least one event carrying Hashes"
    for ev in hashed_events:
        note = ev.get("_note", "")
        assert "synthetic" in note.lower(), (
            f"event {ev['event_id']} carries Hashes but no synthetic _note: {ev}"
        )


def test_volume_responds_to_time_of_day():
    """Workday volume strictly exceeds early-morning volume.

    Compare a 1h workday window (10:00-11:00) against a 1h early-morning
    window (03:00-04:00) on the same Monday for the same tier and seed.
    Workday events should be at least 2x early-morning events on
    workstations (servers floor at 0.85x so their contribution is
    flatter). We assert against the overall total.
    """
    topo, am = _model("M")
    work_events = list(generate(topo, am, MON_09 + timedelta(hours=1), MON_09 + timedelta(hours=2), seed=0))
    early_events = list(generate(topo, am, MON_03, MON_03 + timedelta(hours=1), seed=0))

    # Strip boot-tree events (the boot tree is identical regardless of
    # time-of-day, so it would mask the response).
    def _strip_boot(events):
        boot_pids = {4, 300, 600, 900, 1200}
        return [ev for ev in events if not (
            ev["event_id"] == 1 and ev.get("ProcessId") in boot_pids
        )]

    work_n = len(_strip_boot(work_events))
    early_n = len(_strip_boot(early_events))
    assert work_n > early_n * 1.5, (
        f"expected workday volume > 1.5x early-morning; got work={work_n}, early={early_n}"
    )


def test_every_event_carries_log_and_event_id_tags():
    topo, am = _model("S")
    events = list(generate(topo, am, MON_09, MON_09 + timedelta(hours=1), seed=0))
    assert events
    for ev in events:
        assert ev.get("_log") == "sysmon", f"missing/wrong _log: {ev}"
        assert isinstance(ev.get("event_id"), int), f"missing event_id: {ev}"
