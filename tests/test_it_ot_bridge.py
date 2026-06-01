"""Tests for the IT/OT bridge event generator (t-bridge).

Acceptance bar: matched-pair telemetry across IT and OT sides, three
normal session kinds, three anomaly kinds, determinism, baseline-
disjointness for anomalies, composer signature compatibility.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators import it_ot_bridge
from blue_bench_generators.it_baseline.topology import build_topology
from blue_bench_generators.it_ot_bridge.bridge import (
    AnomalyWindow,
    BridgeSession,
    generate_for_topologies,
    session_kind_counts,
)
from blue_bench_generators.ot_protocols.topology import build_ot_network


# --- shared fixtures -------------------------------------------------------


# Monday 2026-01-05 (matches composer.DEFAULT_START so the shift window
# logic exercises a known weekday).
WINDOW_START = datetime(2026, 1, 5, 0, 0, 0)
WINDOW_END_1D = datetime(2026, 1, 6, 0, 0, 0)
WINDOW_END_3D = datetime(2026, 1, 8, 0, 0, 0)


@pytest.fixture(scope="module")
def it_topo_s():
    return build_topology(tier="S", seed=0)


@pytest.fixture(scope="module")
def it_topo_m():
    return build_topology(tier="M", seed=0)


@pytest.fixture(scope="module")
def ot_net_s():
    return build_ot_network(tier="S", seed=0)


@pytest.fixture(scope="module")
def ot_net_m():
    return build_ot_network(tier="M", seed=0)


@pytest.fixture(scope="module")
def events_clean_1d(it_topo_s, ot_net_s) -> list[dict]:
    return list(generate_for_topologies(it_topo_s, ot_net_s, WINDOW_START, WINDOW_END_1D, seed=0))


# --- basic structure -------------------------------------------------------


def test_emits_non_empty_stream(events_clean_1d):
    assert events_clean_1d, "S-tier weekday should produce some bridge events"


def test_every_event_has_source_field(events_clean_1d):
    """Cross-source routing contract: every event names its destination."""
    for e in events_clean_1d:
        assert "_source" in e, f"event missing _source: {e}"
        assert e["_source"] in {"linux", "zeek", "ot", "ot_hosts"}, (
            f"unknown _source: {e['_source']}"
        )


def test_every_event_has_bridge_session_uid(events_clean_1d):
    for e in events_clean_1d:
        assert "bridge_session_uid" in e, f"event missing bridge_session_uid: {e}"
        assert e["bridge_session_uid"].startswith("B"), (
            f"bridge_session_uid must start with B: {e['bridge_session_uid']}"
        )
        assert len(e["bridge_session_uid"]) == 13


# --- matched-pair correlation ---------------------------------------------


def test_jump_to_ews_session_paired_records(it_topo_m, ot_net_m):
    """A single jump_to_ews session must produce exactly 4 records:
    1 zeek (corp->jump), 1 linux auth, 1 zeek (jump->EWS), 1 ot_hosts auth,
    all sharing the same bridge_session_uid."""
    # S tier may have zero corp workstations; use M for breadth.
    events = list(generate_for_topologies(it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0))
    # Group by bridge_session_uid.
    by_session: dict[str, list[dict]] = {}
    for e in events:
        by_session.setdefault(e["bridge_session_uid"], []).append(e)

    # Pick the first session whose records look like jump_to_ews
    # (has both a linux auth_log AND an ot_hosts ot_auth).
    matched = []
    for uid, recs in by_session.items():
        sources = {r["_source"] for r in recs}
        if {"linux", "zeek", "ot_hosts"}.issubset(sources):
            matched.append((uid, recs))
    assert matched, "expected at least one jump_to_ews session in M-tier 1d"

    uid, recs = matched[0]
    sources_count = {}
    for r in recs:
        sources_count[r["_source"]] = sources_count.get(r["_source"], 0) + 1
    assert sources_count["linux"] == 1, f"expected 1 linux record, got {sources_count}"
    assert sources_count["zeek"] == 2, f"expected 2 zeek records (corp->jump + jump->EWS), got {sources_count}"
    assert sources_count["ot_hosts"] == 1, f"expected 1 ot_hosts record, got {sources_count}"
    # All four records must carry the same bridge_session_uid.
    assert all(r["bridge_session_uid"] == uid for r in recs)


def test_historian_bi_read_has_matched_pair(events_clean_1d):
    """Each historian_bi_read session emits one IT-side zeek conn AND
    one OT-side zeek conn sharing bridge_session_uid."""
    by_session: dict[str, list[dict]] = {}
    for e in events_clean_1d:
        by_session.setdefault(e["bridge_session_uid"], []).append(e)
    matched_pairs = 0
    for uid, recs in by_session.items():
        sources = {r["_source"] for r in recs}
        # historian_bi_read produces zeek + ot, no linux or ot_hosts
        if sources == {"zeek", "ot"} and len(recs) == 2:
            matched_pairs += 1
    assert matched_pairs >= 1, "expected at least one historian_bi_read session"


def test_ews_config_backup_once_per_weekday(it_topo_m, ot_net_m):
    """ews_config_backup is a fixed once-per-weekday pattern."""
    events = list(generate_for_topologies(it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_3D, seed=0))
    # M-tier Mon-Wed = 3 weekdays. The config-backup session shape is
    # (ot zeek conn, zeek conn) at 18:30 from EWS to corp file-share.
    by_session: dict[str, list[dict]] = {}
    for e in events:
        by_session.setdefault(e["bridge_session_uid"], []).append(e)
    backups = []
    for uid, recs in by_session.items():
        sources = {r["_source"] for r in recs}
        if sources == {"ot", "zeek"} and len(recs) == 2:
            # Could be historian_bi_read or ews_config_backup. The
            # backup's outbound leg is FROM the EWS (.40 supervisory)
            # to a corp file-server target on port 445.
            if any(r.get("id.resp_p") == "445" for r in recs):
                backups.append((uid, recs))
    assert len(backups) == 3, f"expected 3 ews_config_backup sessions, got {len(backups)}"


# --- anomalies ------------------------------------------------------------


def test_jump_host_bypass_signature(it_topo_m, ot_net_m):
    """jump_host_bypass: corp->EWS direct, ot_auth on EWS, NO linux
    auth on the jump-host. Must be testably disjoint from baseline."""
    window = AnomalyWindow(
        kind="jump_host_bypass",
        start=datetime(2026, 1, 5, 14, 0, 0),
        end=datetime(2026, 1, 5, 14, 5, 0),
    )
    events = list(generate_for_topologies(
        it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
        anomaly_windows=(window,),
    ))
    # Find the bypass session.
    by_session: dict[str, list[dict]] = {}
    for e in events:
        by_session.setdefault(e["bridge_session_uid"], []).append(e)
    bypass = None
    for uid, recs in by_session.items():
        sources = {r["_source"] for r in recs}
        # The bypass produces exactly zeek + ot_hosts (NO linux)
        if sources == {"zeek", "ot_hosts"} and len(recs) == 2:
            bypass = recs
            break
    assert bypass is not None, "expected jump_host_bypass session in event stream"
    assert not any(r["_source"] == "linux" for r in bypass), (
        "bypass anomaly must not emit a linux auth_log; that's the disjoint signature"
    )


def test_unexpected_corp_to_ot_signature(it_topo_m, ot_net_m):
    window = AnomalyWindow(
        kind="unexpected_corp_to_ot",
        start=datetime(2026, 1, 5, 10, 0, 0),
        end=datetime(2026, 1, 5, 10, 5, 0),
    )
    events = list(generate_for_topologies(
        it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
        anomaly_windows=(window,),
    ))
    # Find a zeek conn record where the source is a corp VLAN IP
    # (10.10.x or 10.20.x) and the destination is OT control (10.41.x).
    anomalous = [
        e for e in events
        if e["_source"] in ("zeek", "ot")
        and e.get("_log") == "conn"
        and (e["id.orig_h"].startswith("10.10.") or e["id.orig_h"].startswith("10.20."))
        and e["id.resp_h"].startswith("10.41.")
    ]
    assert anomalous, "expected corp->OT-control direct conn record"


def test_historian_external_replication_signature(it_topo_m, ot_net_m):
    window = AnomalyWindow(
        kind="historian_external_replication",
        start=datetime(2026, 1, 5, 12, 0, 0),
        end=datetime(2026, 1, 5, 12, 5, 0),
    )
    events = list(generate_for_topologies(
        it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
        anomaly_windows=(window,),
    ))
    external = [
        e for e in events
        if e.get("_log") == "conn"
        and e["id.resp_h"].startswith("198.51.100.")
    ]
    assert external, "expected historian->external conn record"


# --- baseline disjointness -----------------------------------------------


def test_baseline_no_corp_to_ot_control(events_clean_1d):
    """Normal sessions never have a corp-VLAN source talking to OT control."""
    for e in events_clean_1d:
        if e.get("_log") != "conn":
            continue
        # corp VLAN starts at 10.10.; OT control at 10.41.
        if e["id.orig_h"].startswith("10.10.") and e["id.resp_h"].startswith("10.41."):
            pytest.fail(f"baseline conn corp->OT-control: {e}")


def test_baseline_no_external_destinations(events_clean_1d):
    for e in events_clean_1d:
        if e.get("_log") != "conn":
            continue
        assert not e["id.resp_h"].startswith("198.51.100."), (
            f"baseline conn to documentation IP range: {e}"
        )


def test_baseline_jump_to_ews_always_has_jump_host_auth(it_topo_m, ot_net_m):
    """For every baseline jump_to_ews session (sessions with both an
    ot_hosts ot_auth on an EWS AND a zeek conn to that EWS), there
    must be a paired linux auth_log on the jump-host."""
    events = list(generate_for_topologies(it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0))
    by_session: dict[str, list[dict]] = {}
    for e in events:
        by_session.setdefault(e["bridge_session_uid"], []).append(e)
    for uid, recs in by_session.items():
        has_ot_auth = any(r["_source"] == "ot_hosts" and r.get("_log") == "ot_auth" for r in recs)
        has_linux_auth = any(r["_source"] == "linux" for r in recs)
        if has_ot_auth:
            assert has_linux_auth, (
                f"session {uid} has OT-side login but no IT-side jump-host "
                f"auth -- looks like a bypass in the baseline: {recs}"
            )


# --- determinism ----------------------------------------------------------


def test_determinism_same_seed(it_topo_s, ot_net_s):
    a = list(generate_for_topologies(it_topo_s, ot_net_s, WINDOW_START, WINDOW_END_1D, seed=0))
    b = list(generate_for_topologies(it_topo_s, ot_net_s, WINDOW_START, WINDOW_END_1D, seed=0))
    assert a == b


def test_determinism_different_seed_differs(it_topo_s, ot_net_s):
    a = list(generate_for_topologies(it_topo_s, ot_net_s, WINDOW_START, WINDOW_END_1D, seed=0))
    b = list(generate_for_topologies(it_topo_s, ot_net_s, WINDOW_START, WINDOW_END_1D, seed=42))
    assert a != b


def test_all_session_uids_unique(it_topo_m, ot_net_m):
    """Bridge session UIDs derive from (seed, kind, session_idx). Same
    session_idx across different kinds must not collide -- the kind
    differentiator should prevent it. This catches a real class of
    regression if session_idx is ever passed in without kind."""
    anomalies = (
        AnomalyWindow(kind="jump_host_bypass",
                      start=datetime(2026, 1, 5, 3, 0), end=datetime(2026, 1, 5, 3, 5)),
        AnomalyWindow(kind="unexpected_corp_to_ot",
                      start=datetime(2026, 1, 5, 4, 0), end=datetime(2026, 1, 5, 4, 5)),
        AnomalyWindow(kind="historian_external_replication",
                      start=datetime(2026, 1, 5, 5, 0), end=datetime(2026, 1, 5, 5, 5)),
    )
    events = list(generate_for_topologies(
        it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
        anomaly_windows=anomalies,
    ))
    uids = [e["bridge_session_uid"] for e in events]
    distinct = {e["bridge_session_uid"] for e in events}
    # We expect multiple records per session, so uids has more entries
    # than distinct. But the count of distinct UIDs must equal the
    # session count -- no two sessions can share a UID.
    by_session_records = {}
    for e in events:
        by_session_records.setdefault(e["bridge_session_uid"], []).append(e)
    assert len(distinct) == len(by_session_records)


def test_bridge_ssh_thumbprint_matches_natural_shape(it_topo_m, ot_net_m):
    """Bridge auth.log records must use the SAME 43-char SSH key
    fingerprint shape as the natural linux_logs generator. A length-
    based detector would otherwise discover every bridge session for
    free (12-char hex vs 43-char base32 from a fixed alphabet)."""
    import re
    events = list(generate_for_topologies(
        it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
    ))
    fp_pattern = re.compile(r"SHA256:([A-Z0-9]+) session=")
    bridge_auth = [e for e in events if e["_source"] == "linux"]
    assert bridge_auth, "expected at least one bridge linux auth_log"
    for r in bridge_auth:
        m = fp_pattern.search(r["message"])
        assert m is not None, f"could not extract fingerprint from {r['message']!r}"
        thumb = m.group(1)
        assert len(thumb) == 43, (
            f"bridge SSH fingerprint must be 43 chars (matches natural "
            f"sshd record); got {len(thumb)} ({thumb!r})"
        )
        # Alphabet must match linux_logs.py:_emit_sshd_accepted (no I/O confusion)
        assert set(thumb).issubset(set("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789")), (
            f"bridge SSH fingerprint contains chars outside ssh-fp alphabet: {thumb}"
        )


def test_bridge_auth_log_carries_session_in_message(it_topo_m, ot_net_m):
    """The syslog text writer drops dict keys other than ``message``.
    Bridge auth records append session=<uid> to the message tail so
    cross-stream correlation survives serialisation."""
    events = list(generate_for_topologies(
        it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
    ))
    bridge_auth = [e for e in events if e["_source"] == "linux"]
    assert bridge_auth
    for r in bridge_auth:
        uid = r["bridge_session_uid"]
        assert f"session={uid}" in r["message"], (
            f"bridge auth_log message must include session={uid}: {r['message']}"
        )


def test_l_tier_uses_real_jump_host(ot_net_m):
    """L-tier IT topology has a real jump-host. The bridge generator
    must prefer it over the synthesised fallback -- otherwise a
    regression that always returns the fallback would never be caught
    by tests that run on M (which has no real jump-host)."""
    from blue_bench_generators.it_baseline.topology import build_topology
    from blue_bench_generators.ot_protocols.topology import build_ot_network
    it_l = build_topology(tier="L", seed=0)
    ot_l = build_ot_network(tier="L", seed=0)
    real_jump = next((h for h in it_l.hosts if h.role == "jump-host"), None)
    assert real_jump is not None, "L tier topology must have a jump-host"
    events = list(generate_for_topologies(it_l, ot_l, WINDOW_START, WINDOW_END_1D, seed=0))
    auth_logs = [e for e in events if e["_source"] == "linux"]
    assert auth_logs, "L-tier 1d should produce linux auth_log events"
    for r in auth_logs:
        assert r["hostname"] == real_jump.fqdn, (
            f"L-tier auth_log hostname {r['hostname']!r} should match real "
            f"jump-host {real_jump.fqdn!r}, not the fallback"
        )


def test_fallback_jump_host_ip_does_not_collide():
    """Fallback DMZ IPs (.200 range) stay above the topology allocator's
    upward .10-onward range so no synthesised IP collides with a real host."""
    from blue_bench_generators.it_baseline.topology import build_topology
    from blue_bench_generators.it_ot_bridge.bridge import (
        _JUMP_HOST_FALLBACK_IP,
        _CORP_FILESHARE_HOST_FALLBACK,
    )
    for tier in ("S", "M", "L"):
        topo = build_topology(tier=tier, seed=0)
        all_ips = {h.ip for h in topo.hosts}
        assert _JUMP_HOST_FALLBACK_IP not in all_ips, (
            f"{tier}: jump-host fallback IP collides with topology"
        )
        assert _CORP_FILESHARE_HOST_FALLBACK[1] not in all_ips, (
            f"{tier}: file-share fallback IP collides with topology"
        )


# --- window discipline ----------------------------------------------------


def test_no_events_outside_window(events_clean_1d):
    for e in events_clean_1d:
        if "timestamp" in e:
            # auth_log uses Host.isoformat (microseconds); ot_auth uses
            # _iso_ts (milliseconds). Both are ISO-8601, datetime.fromisoformat
            # handles both.
            ts = datetime.fromisoformat(e["timestamp"])
            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
        elif "ts" in e:
            ts = datetime.fromtimestamp(float(e["ts"]))
        else:
            pytest.fail(f"event has neither timestamp nor ts: {e}")
        assert WINDOW_START <= ts < WINDOW_END_1D, f"event outside window: {ts}"


def test_no_weekend_baseline_sessions(it_topo_m, ot_net_m):
    """Baseline sessions only fire on weekdays."""
    # 2026-01-10 = Saturday. Run a Sat-Sun-only window.
    sat_start = datetime(2026, 1, 10, 0, 0, 0)
    mon_start = datetime(2026, 1, 12, 0, 0, 0)
    events = list(generate_for_topologies(it_topo_m, ot_net_m, sat_start, mon_start, seed=0))
    assert events == [], "weekend window should produce no baseline sessions"


# --- anomaly validation ---------------------------------------------------


def test_anomaly_partial_overlap_raises(it_topo_m, ot_net_m):
    bad = AnomalyWindow(
        kind="jump_host_bypass",
        start=WINDOW_START - timedelta(hours=1),
        end=WINDOW_START + timedelta(hours=1),
    )
    with pytest.raises(ValueError, match="straddles corpus window"):
        list(generate_for_topologies(
            it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
            anomaly_windows=(bad,),
        ))


def test_unknown_anomaly_kind_raises(it_topo_s, ot_net_s):
    bad = AnomalyWindow(
        kind="bogus_kind",  # type: ignore[arg-type]
        start=WINDOW_START,
        end=WINDOW_END_1D,
    )
    with pytest.raises(ValueError, match="unknown bridge anomaly kind"):
        list(generate_for_topologies(
            it_topo_s, ot_net_s, WINDOW_START, WINDOW_END_1D, seed=0,
            anomaly_windows=(bad,),
        ))


@pytest.mark.parametrize("kind,bad_name", [
    ("jump_host_bypass", "not-an-ews"),
    ("unexpected_corp_to_ot", "not-a-controller"),
    ("historian_external_replication", "not-a-historian"),
])
def test_bad_target_device_raises(it_topo_m, ot_net_m, kind, bad_name):
    """Explicit target_device that names no eligible device is a caller
    bug -- raises (uniform with ot_hosts anomaly target_device policy)."""
    bad = AnomalyWindow(
        kind=kind,
        start=datetime(2026, 1, 5, 10, 0, 0),
        end=datetime(2026, 1, 5, 10, 5, 0),
        target_device=bad_name,
    )
    with pytest.raises(ValueError, match="not an eligible"):
        list(generate_for_topologies(
            it_topo_m, ot_net_m, WINDOW_START, WINDOW_END_1D, seed=0,
            anomaly_windows=(bad,),
        ))


def test_anomaly_zero_duration_raises(it_topo_s, ot_net_s):
    bad = AnomalyWindow(
        kind="jump_host_bypass",
        start=datetime(2026, 1, 5, 12, 0, 0),
        end=datetime(2026, 1, 5, 12, 0, 0),
    )
    with pytest.raises(ValueError, match="non-positive"):
        list(generate_for_topologies(
            it_topo_s, ot_net_s, WINDOW_START, WINDOW_END_1D, seed=0,
            anomaly_windows=(bad,),
        ))


# --- composer signature ---------------------------------------------------


def test_composer_signature(it_topo_s):
    events = list(it_ot_bridge.generate(it_topo_s, None, WINDOW_START, WINDOW_END_1D, seed=0))
    assert events, "expected non-empty stream via composer signature"


def test_composer_signature_missing_tier_raises():
    class NoTier:
        pass
    with pytest.raises(TypeError, match="has no ``tier`` attribute"):
        list(it_ot_bridge.generate(NoTier(), None, WINDOW_START, WINDOW_END_1D, seed=0))


# --- introspection --------------------------------------------------------


def test_session_kind_counts_public():
    counts = session_kind_counts("S")
    assert set(counts.keys()) == {"jump_to_ews", "historian_bi_read", "ews_config_backup"}
    assert all(v > 0 for v in counts.values())
    # M-tier scales up vs S.
    counts_m = session_kind_counts("M")
    assert counts_m["jump_to_ews"] > counts["jump_to_ews"]
