"""Unit tests for the RQ3 anti-giveaway gate harness (blue_bench_generators/merge/gates).

Covers the rank-based AUC, surface-feature hygiene (no host/time leak), the
behavioural-vs-surface split on synthetic data, and determinism. The live
measurement on the real bundles is an EF-P5 reference run, not CI.
"""

from __future__ import annotations

from blue_bench_generators.merge import gates


def test_auc_known_cases():
    # perfectly separable (positives score higher)
    assert gates.auc([0.1, 0.2, 0.9, 1.0], [0, 0, 1, 1]) == 1.0
    # perfectly anti-separable
    assert gates.auc([0.9, 1.0, 0.1, 0.2], [0, 0, 1, 1]) == 0.0
    # ties -> 0.5
    assert gates.auc([0.5, 0.5, 0.5, 0.5], [0, 1, 0, 1]) == 0.5
    # single class -> 0.5 (undefined, safe default)
    assert gates.auc([0.1, 0.9], [1, 1]) == 0.5


def test_surface_features_exclude_host_and_time():
    ev = {"_stream": "sysmon", "event_id": 1, "Computer": "wkst-03.corp.example.invalid",
          "User": "WKST-03\\Administrator", "UtcTime": "2026-03-02 09:00:00.000",
          "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "ProcessGuid": "{abc}"}
    f = gates.surface_features(ev)
    blob = " ".join(f.keys())
    # no host / user / time / guid leaks into the feature space
    assert not any(k in blob for k in ("Computer", "User", "UtcTime", "Guid", "host"))
    assert f["img_powershell.exe"] == 1.0 and f["sysmon_eid"] == 1.0


def test_behavioral_separates_low_and_slow_from_smash_and_grab():
    # APT: sparse (1 event/hour over 10h); foil: dense (1 event/10s over ~3min)
    apt = [{"_stream": "sysmon", "event_id": 1, "Computer": "h",
            "UtcTime": f"2026-03-02 {9+i:02d}:00:00.000"} for i in range(10)]
    foil = [{"_stream": "sysmon", "event_id": 1, "Computer": "h",
             "UtcTime": f"2026-03-02 09:{i//6:02d}:{(i*10)%60:02d}.000"} for i in range(10)]
    rep = gates.run_gates(apt, foil, seed=7)
    surf = next(r for r in rep.results if r.name == "surface_non_separability")
    behav = next(r for r in rep.results if r.name == "behavioral_separability")
    # identical surface (same EID/image) -> non-separable; cadence -> separable
    assert surf.value <= 0.65
    assert behav.value >= 0.85


def test_run_gates_deterministic():
    apt = [{"_stream": "sysmon", "event_id": 1, "Computer": "h",
            "UtcTime": f"2026-03-02 {9+i:02d}:00:00.000"} for i in range(8)]
    foil = [{"_stream": "zeek", "_log": "conn", "id.resp_p": 443, "proto": "tcp",
             "id.resp_h": "203.0.113.9", "ts": str(1.0 + i * 5)} for i in range(8)]
    a = gates.run_gates(apt, foil, seed=42)
    b = gates.run_gates(apt, foil, seed=42)
    assert [r.value for r in a.results] == [r.value for r in b.results]


def test_volume_parity_ratio():
    apt = [{"_stream": "sysmon", "event_id": 1, "Computer": "h", "UtcTime": "2026-03-02 09:00:00.000"}] * 10
    foil = [{"_stream": "sysmon", "event_id": 1, "Computer": "h", "UtcTime": "2026-03-02 09:00:00.000"}] * 25
    rep = gates.run_gates(apt, foil, seed=1)
    vol = next(r for r in rep.results if r.name == "volume_parity")
    assert abs(vol.value - 2.5) < 1e-9 and not vol.passed  # 25/10 = 2.5x > 2x
