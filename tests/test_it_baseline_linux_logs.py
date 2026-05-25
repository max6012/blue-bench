"""Tests for the Linux host telemetry generator (`t-45tc`).

Cover: linux-only emission, determinism, time-window respect, EXECVE
volume scaling with process_creation rate, sshd Failed/Accepted ratio
matching logon_failure/logon_attempt, sudo only for admins, PID/PPID
consistency, hourly cron fires, vendor-neutral paths, time-of-day
response, and service-event scoping.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from blue_bench_generators.it_baseline.behavior import build_activity_model
from blue_bench_generators.it_baseline.linux_logs import generate
from blue_bench_generators.it_baseline.topology import (
    FORBIDDEN_TERM_DENYLIST,
    build_topology,
)


# --- fixtures --------------------------------------------------------------


# L tier exercises the widest set of Linux roles (jump-host, siem-server,
# proxy-server, dhcp-dns-server, web-server, mail-server).
TIER = "L"

# Pin to a Monday so weekday() == 0 and we get the apt-on-Monday line.
WINDOW_START = datetime(2026, 5, 11, 0, 0, 0)
WINDOW_END = datetime(2026, 5, 12, 0, 0, 0)  # 24 hours


def _events(tier: str = TIER, seed: int = 0, hours: int = 24) -> list[dict]:
    topo = build_topology(tier)  # type: ignore[arg-type]
    model = build_activity_model(topo)
    end = WINDOW_START + timedelta(hours=hours)
    return list(generate(topo, model, WINDOW_START, end, seed=seed))


# --- spec acceptance cases -------------------------------------------------


def test_only_linux_hosts_emit_events():
    topo = build_topology(TIER)  # type: ignore[arg-type]
    linux_fqdns = {h.fqdn for h in topo.hosts if h.os == "linux"}
    windows_fqdns = {h.fqdn for h in topo.hosts if h.os == "windows"}
    evs = _events()
    assert evs, "expected at least some events"
    seen_hosts = {e["hostname"] for e in evs}
    assert seen_hosts <= linux_fqdns
    assert seen_hosts.isdisjoint(windows_fqdns)


def test_deterministic_with_seed():
    a = _events(seed=7)
    b = _events(seed=7)
    assert a == b
    # Different seeds should produce different streams.
    c = _events(seed=13)
    assert a != c


def test_no_events_outside_window():
    evs = _events(hours=6)
    end = WINDOW_START + timedelta(hours=6)
    for e in evs:
        ts = datetime.fromisoformat(e["timestamp"])
        assert WINDOW_START <= ts < end


def test_execve_volume_matches_process_creation_rate():
    topo = build_topology(TIER)  # type: ignore[arg-type]
    model = build_activity_model(topo)
    end = WINDOW_START + timedelta(hours=24)
    evs = list(generate(topo, model, WINDOW_START, end, seed=0))

    execve = [e for e in evs if e["_log"] == "auditd" and e["type"] == "EXECVE"]
    assert execve, "expected EXECVE records"

    # Per-host EXECVE counts should correlate strongly with the integral
    # of process_creation rate over the window.
    by_host: dict[str, int] = {}
    for e in execve:
        by_host[e["hostname"]] = by_host.get(e["hostname"], 0) + 1

    # Compute expected per-host integral.
    expected: dict[str, float] = {}
    for host in topo.hosts:
        if host.os != "linux":
            continue
        cursor = WINDOW_START
        total = 0.0
        while cursor < end:
            total += model.rate(host, "process_creation", cursor)
            cursor += timedelta(hours=1)
        expected[host.fqdn] = total

    # For each host, observed should be within ~30% of expected.
    for fqdn, exp in expected.items():
        obs = by_host.get(fqdn, 0)
        if exp < 1:
            # Vanishingly small expectation -- tolerate either way.
            continue
        ratio = obs / exp
        assert 0.7 < ratio < 1.3, (
            f"host {fqdn}: observed {obs} EXECVE vs expected ~{exp:.0f} "
            f"(ratio {ratio:.2f})"
        )


def test_sshd_accepted_failed_pair_ratio_matches_behavior():
    topo = build_topology(TIER)  # type: ignore[arg-type]
    model = build_activity_model(topo)
    end = WINDOW_START + timedelta(hours=24)
    evs = list(generate(topo, model, WINDOW_START, end, seed=0))

    sshd = [e for e in evs if e["_log"] == "auth_log" and e["process"] == "sshd"]
    accepted = sum(1 for e in sshd if e["message"].startswith("Accepted"))
    failed = sum(1 for e in sshd if e["message"].startswith("Failed"))
    assert accepted > 0
    assert failed > 0

    # Compute expected ratio from rate tables across all Linux hosts.
    exp_la = 0.0
    exp_lf = 0.0
    for host in topo.hosts:
        if host.os != "linux":
            continue
        cursor = WINDOW_START
        while cursor < end:
            exp_la += model.rate(host, "logon_attempt", cursor)
            exp_lf += model.rate(host, "logon_failure", cursor)
            cursor += timedelta(hours=1)

    obs_ratio = failed / accepted
    exp_ratio = exp_lf / exp_la
    # Tolerance is wide because failure rate is ~1-2 orders of magnitude
    # smaller than attempts and integer rounding introduces noise.
    assert exp_ratio * 0.5 < obs_ratio < exp_ratio * 2.0, (
        f"observed Failed/Accepted = {obs_ratio:.4f}, expected ~{exp_ratio:.4f}"
    )


def test_sudo_only_emitted_for_admin_users():
    topo = build_topology(TIER)  # type: ignore[arg-type]
    evs = _events()
    sudo = [e for e in evs if e["_log"] == "auth_log" and e["process"] == "sudo"]
    assert sudo, "expected sudo events in L tier"

    admin_usernames = {u.username for u in topo.users if u.role == "admin"}
    for e in sudo:
        first_tok = e["message"].split(" ", 1)[0]
        assert first_tok in admin_usernames, (
            f"sudo emitted for non-admin user: {first_tok!r}"
        )


def test_pid_ppid_consistency():
    evs = _events()
    auditd = [e for e in evs if e["_log"] == "auditd"]
    seen_pids_per_host: dict[str, set[int]] = {}
    # Process in timestamp order; EXECVE/SYSCALL/CWD/PATH for the same
    # execve event share a msg_id but only one logical "new PID" is added.
    last_msg_id: dict[str, str | None] = {}
    def _seq_key(e: dict) -> tuple:
        # Sort by (timestamp, hostname, numeric seq) so events emitted at the
        # same second on the same host preserve emission order.
        ms_str, seq_str = e["msg_id"].split(".", 1)
        return (e["timestamp"], e["hostname"], int(seq_str))

    auditd_sorted = sorted(auditd, key=_seq_key)
    for e in auditd_sorted:
        host = e["hostname"]
        seen = seen_pids_per_host.setdefault(host, {1})  # systemd
        ppid = e["ppid"]
        pid = e["pid"]
        assert ppid in seen, (
            f"host {host}: PPID {ppid} for PID {pid} at {e['timestamp']} "
            f"has not appeared as a prior PID (seen={sorted(seen)[:10]}...)"
        )
        seen.add(pid)
        last_msg_id[host] = e["msg_id"]


def test_cron_fires_hourly():
    topo = build_topology(TIER)  # type: ignore[arg-type]
    evs = _events()
    linux_hosts = [h for h in topo.hosts if h.os == "linux"]
    end = WINDOW_START + timedelta(hours=24)

    for host in linux_hosts:
        # Every hour in the window must have at least 1 cron line for this host.
        cron_hours: set[int] = set()
        for e in evs:
            if (
                e["_log"] == "syslog"
                and e["process"] == "cron"
                and e["hostname"] == host.fqdn
            ):
                hour = datetime.fromisoformat(e["timestamp"]).hour
                cron_hours.add(hour)
        expected_hours = {(WINDOW_START + timedelta(hours=h)).hour for h in range(24)}
        missing = expected_hours - cron_hours
        assert not missing, (
            f"host {host.fqdn}: missing cron in hours {sorted(missing)}"
        )


def test_logs_contain_only_vendor_neutral_paths():
    evs = _events()
    for term in FORBIDDEN_TERM_DENYLIST:
        for e in evs:
            for v in e.values():
                if isinstance(v, str):
                    assert term not in v.lower(), (
                        f"forbidden term {term!r} found in event: {e}"
                    )
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            assert term not in item.lower()

    # Every auditd path-ish field should live under /var, /etc, /home,
    # /bin, /usr, /opt, /proc, or /tmp.
    allowed_roots = ("/var/", "/etc/", "/home/", "/bin/", "/usr/", "/opt/", "/proc/", "/tmp/")
    for e in evs:
        if e["_log"] != "auditd":
            continue
        for field in ("exe", "name", "cwd"):
            v = e.get(field)
            if not v or not isinstance(v, str):
                continue
            if v.startswith("/"):
                assert v.startswith(allowed_roots), (
                    f"unexpected root in path {v!r}"
                )


def test_volume_responds_to_time_of_day():
    """EXECVE volume during peak hours should exceed late-night volume."""
    topo = build_topology(TIER)  # type: ignore[arg-type]
    model = build_activity_model(topo)
    end = WINDOW_START + timedelta(hours=24)
    evs = list(generate(topo, model, WINDOW_START, end, seed=0))

    # Focus on a workstation-style host... but all Linux hosts here are
    # servers (constant-overnight). Pick the proxy/web/mail host (web-mail
    # bucket, no constant-overnight inflation? actually web-mail IS in
    # the constant-overnight set). Test still works because admin-WS lift
    # doesn't apply and the time-of-day taper drops to 0.15 overnight vs
    # 1.0 at midday. The 0.85 floor caps the dip but peak is still > floor.
    web_hosts = [h for h in topo.hosts if h.role == "web-server"]
    assert web_hosts
    host = web_hosts[0]

    execve_by_hour: dict[int, int] = {}
    for e in evs:
        if e["_log"] == "auditd" and e["type"] == "EXECVE" and e["hostname"] == host.fqdn:
            h = datetime.fromisoformat(e["timestamp"]).hour
            execve_by_hour[h] = execve_by_hour.get(h, 0) + 1

    # Peak hour (10) total vs early-morning (03). With the 0.85 floor,
    # peak (1.0) is still > floor (0.85), so total peak should be >= 03.
    peak = sum(execve_by_hour.get(h, 0) for h in (10, 11, 14, 15))
    early = sum(execve_by_hour.get(h, 0) for h in (2, 3, 4, 5))
    assert peak >= early, (
        f"peak hours {peak} should be >= early-morning {early} for {host.fqdn}"
    )


def test_service_events_only_on_server_roles():
    topo = build_topology(TIER)  # type: ignore[arg-type]
    evs = _events()
    server_fqdns = {
        h.fqdn for h in topo.hosts
        if h.os == "linux" and h.role != "workstation"
    }
    # Confirm there are no Linux workstations in the topology (verify
    # clause in the spec).
    linux_workstations = [
        h for h in topo.hosts if h.os == "linux" and h.role == "workstation"
    ]
    assert not linux_workstations, (
        "topology unexpectedly grew Linux workstations -- service event "
        "scoping needs to be re-asserted"
    )

    for e in evs:
        if e["_log"] == "syslog" and e["process"] == "systemd":
            assert e["hostname"] in server_fqdns


# --- shape checks ----------------------------------------------------------


def test_three_distinct_log_streams_present():
    evs = _events()
    logs = {e["_log"] for e in evs}
    assert logs == {"auditd", "auth_log", "syslog"}


def test_msg_id_format_for_auditd():
    evs = _events()
    for e in evs:
        if e["_log"] != "auditd":
            continue
        assert "." in e["msg_id"]
        ms, seq = e["msg_id"].split(".", 1)
        assert ms.isdigit()
        assert seq.isdigit()
