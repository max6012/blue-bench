"""Windows EventLog generator for the IT baseline corpus.

Emits Security- and System-channel events shaped like canonical Windows
EventLog records:

* 4624 — successful logon
* 4625 — failed logon
* 4634 — logoff (paired to the 4624 by ``TargetLogonId``)
* 4672 — special-privileges logon (admin sibling to 4624)
* 4688 — process creation
* 7036 — service state change (System channel)

Vendor-neutral, deterministic, Windows hosts only. Composed against the
``ActivityModel`` rate table -- the per-hour rate determines the event
count per host per hour; events inside an hour are spread uniformly.

Every emitted dict carries::

    {
        "_log": "winevtx",
        "event_id": <int>,
        "channel": "Security" | "System",
        "timestamp": "<iso8601>",
        ...
    }

Design notes
------------

* One ``random.Random(seed)`` instance per ``generate()`` call. No
  reseeding mid-stream; ordering is stabilised at the end.
* ``TargetLogonId`` is a deterministic per-host counter formatted as
  ``0x<host_idx:04x><counter:08x>``. The same id pairs the 4624 with
  its 4634 (and the 4672 sibling for admin logons).
* Failed logons (4625) are generated from the independent
  ``logon_failure`` rate. The 4625/4624 ratio falls out as
  ``failure / attempt`` naturally.
* Logon types: type 2 (interactive) when the target host is a
  workstation, type 3 (network) when the target is a server, with a
  small fraction of type 10 (RDP) on admin-workstations and servers.
* 7036 emits only on server roles (workstation / admin-workstation are
  skipped even though the behavior table assigns them a non-zero
  service_event rate).
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from blue_bench_generators.it_baseline.behavior import ActivityModel
from blue_bench_generators.it_baseline.topology import Host, Topology, User

log = logging.getLogger(__name__)


# --- constants -------------------------------------------------------------


_SECURITY_CHANNEL = "Security"
_SYSTEM_CHANNEL = "System"

_DOMAIN_NETBIOS = "CORP"

# Benign command pool for 4688. Vendor-neutral.
_BENIGN_PROCESSES: tuple[tuple[str, str, str], ...] = (
    # (NewProcessName, CommandLine, ParentProcessName)
    (
        r"C:\Windows\System32\svchost.exe",
        r'"C:\Windows\System32\svchost.exe" -k netsvcs -p',
        r"C:\Windows\System32\services.exe",
    ),
    (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r'"powershell.exe" -NoProfile -Command Get-Service',
        r"C:\Windows\explorer.exe",
    ),
    (
        r"C:\Windows\System32\cmd.exe",
        r'"cmd.exe" /c whoami',
        r"C:\Windows\explorer.exe",
    ),
    (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r'"chrome.exe" --type=renderer',
        r"C:\Windows\explorer.exe",
    ),
    (
        r"C:\Windows\System32\taskhostw.exe",
        r"taskhostw.exe",
        r"C:\Windows\System32\svchost.exe",
    ),
    (
        r"C:\Windows\System32\conhost.exe",
        r'"\??\C:\Windows\system32\conhost.exe" 0xffffffff',
        r"C:\Windows\System32\cmd.exe",
    ),
)


_BENIGN_SERVICES: tuple[str, ...] = (
    "Windows Update",
    "BITS",
    "Windows Defender Antivirus Service",
    "Print Spooler",
    "DHCP Client",
    "Task Scheduler",
    "Windows Time",
    "RPC Endpoint Mapper",
)


_FAILURE_SUBSTATUSES: tuple[tuple[str, str], ...] = (
    # (SubStatus, FailureReason text)
    ("0xC0000064", "User name does not exist."),
    ("0xC000006A", "User name is correct but the password is wrong."),
    ("0xC0000234", "User logon with account locked out."),
    ("0xC0000071", "Passwords expired."),
    ("0xC0000072", "Account currently disabled."),
)


_LOGON_PROCESSES: tuple[str, ...] = ("User32", "Advapi", "NtLmSsp", "Kerberos")
_AUTH_PACKAGES: tuple[str, ...] = ("Kerberos", "NTLM", "Negotiate")


_SERVER_ROLES: frozenset[str] = frozenset(
    {
        "file-server",
        "database-server",
        "web-server",
        "mail-server",
        "domain-controller",
        "dhcp-dns-server",
        "siem-server",
        "jump-host",
        "proxy-server",
    }
)


_WORKSTATION_ROLES: frozenset[str] = frozenset(
    {"workstation", "admin-workstation"}
)


_ADMIN_PRIVILEGE_LIST: str = (
    "SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege "
    "SeTakeOwnershipPrivilege SeDebugPrivilege SeSystemEnvironmentPrivilege "
    "SeLoadDriverPrivilege SeImpersonatePrivilege"
)


# --- helpers ---------------------------------------------------------------


def _make_sid(seed_index: int, kind: str = "user") -> str:
    """Stable SID-like string. Format mirrors real SIDs without claiming RIDs.

    ``kind`` lets system / well-known SIDs read distinctly from user SIDs
    in test output.
    """
    if kind == "system":
        return "S-1-5-18"
    # Mid-range RID 1000+ matches real domain user RIDs.
    rid = 1000 + (seed_index % 50000)
    return f"S-1-5-21-1111111111-2222222222-3333333333-{rid}"


def _is_windows(host: Host) -> bool:
    return host.os == "windows"


def _host_ip(topology: Topology, host_name: str) -> str:
    for h in topology.hosts:
        if h.name == host_name:
            return h.ip
    return "-"


def _host_by_name(topology: Topology, name: str) -> Host | None:
    for h in topology.hosts:
        if h.name == name:
            return h
    return None


def _hour_count(rate_per_hour: float, rng: random.Random) -> int:
    """Convert a fractional events/hour rate to an integer count.

    Floor + Bernoulli on the fractional part keeps the long-run mean equal
    to the input while staying deterministic given a fixed RNG sequence.
    """
    if rate_per_hour <= 0.0:
        return 0
    whole = int(rate_per_hour)
    frac = rate_per_hour - whole
    if frac > 0.0 and rng.random() < frac:
        whole += 1
    return whole


def _spread_timestamps(
    hour_start: datetime, count: int, rng: random.Random
) -> list[datetime]:
    """Uniformly spread ``count`` timestamps over a one-hour window."""
    out: list[datetime] = []
    for _ in range(count):
        offset_s = rng.random() * 3600.0
        out.append(hour_start + timedelta(seconds=offset_s))
    out.sort()
    return out


def _tag(event_id: int, channel: str, ts: datetime) -> dict:
    """Base envelope every emitted dict carries."""
    return {
        "_log": "winevtx",
        "event_id": event_id,
        "channel": channel,
        "timestamp": ts.isoformat(),
    }


# --- session model ---------------------------------------------------------


@dataclass
class _OpenSession:
    target_logon_id: str
    subject_user: User
    subject_host: Host
    target_user: User
    target_host: Host
    logon_type: int
    auth_package: str
    open_ts: datetime
    close_ts: datetime


def _pick_logon_type(target_host: Host, rng: random.Random) -> int:
    """Type 2 on workstations, 3 on servers, small chance of 10 (RDP).

    The choice biases firmly toward the dominant type per host class so
    the ``test_logon_types_distribution`` assertion stays comfortably
    inside its tolerance band.
    """
    if target_host.role in _WORKSTATION_ROLES:
        # Workstations: mostly interactive, small RDP slice on admin-WS.
        if target_host.role == "admin-workstation" and rng.random() < 0.15:
            return 10
        return 2
    # Servers: mostly network logons; rare RDP from an admin.
    if rng.random() < 0.05:
        return 10
    return 3


def _pick_auth_package(logon_type: int, rng: random.Random) -> str:
    if logon_type == 10:
        return "Negotiate"
    if logon_type == 3:
        # Network logons -- typically Kerberos in a healthy AD env.
        return rng.choices(_AUTH_PACKAGES, weights=(0.75, 0.10, 0.15))[0]
    return rng.choices(_AUTH_PACKAGES, weights=(0.55, 0.20, 0.25))[0]


# --- per-event builders ----------------------------------------------------


def _build_4624(
    *,
    session: _OpenSession,
    user_indices: dict[str, int],
    process_id_pool: list[int],
    rng: random.Random,
) -> dict:
    subj_idx = user_indices[session.subject_user.username]
    tgt_idx = user_indices[session.target_user.username]
    record = _tag(4624, _SECURITY_CHANNEL, session.open_ts)
    record.update(
        {
            "SubjectUserSid": _make_sid(subj_idx),
            "SubjectUserName": session.subject_user.username,
            "SubjectDomainName": _DOMAIN_NETBIOS,
            "SubjectLogonId": f"0x{(subj_idx % 0xFFFFFFFF):08x}",
            "TargetUserSid": _make_sid(tgt_idx),
            "TargetUserName": session.target_user.username,
            "TargetDomainName": _DOMAIN_NETBIOS,
            "TargetLogonId": session.target_logon_id,
            "LogonType": session.logon_type,
            "LogonProcessName": rng.choice(_LOGON_PROCESSES),
            "AuthenticationPackageName": session.auth_package,
            "WorkstationName": session.subject_host.name.upper(),
            "ProcessId": f"0x{rng.choice(process_id_pool):x}",
            "ProcessName": r"C:\Windows\System32\lsass.exe",
            "IpAddress": session.subject_host.ip,
            "IpPort": str(rng.randint(49152, 65535)),
            "HostName": session.target_host.name,
        }
    )
    return record


def _build_4625(
    *,
    ts: datetime,
    target_user: User,
    target_host: Host,
    user_indices: dict[str, int],
    rng: random.Random,
) -> dict:
    """Failed-logon record.

    The "subject" here mirrors real 4625s where lsass is the subject
    on the target host. The "target user" carries the rejected creds.
    """
    tgt_idx = user_indices[target_user.username]
    logon_type = _pick_logon_type(target_host, rng)
    substatus, reason = rng.choice(_FAILURE_SUBSTATUSES)
    # Source IP: for a benign failed logon, attribute to the target
    # host's own IP. (Realistic enterprise mix would have a remote
    # source for type-3 failures; the test only constrains the
    # SubStatus enum, so keeping this simple is fine.)
    src_ip = target_host.ip
    record = _tag(4625, _SECURITY_CHANNEL, ts)
    record.update(
        {
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "TargetUserSid": _make_sid(tgt_idx),
            "TargetUserName": target_user.username,
            "TargetDomainName": _DOMAIN_NETBIOS,
            "TargetLogonId": "0x0",
            "LogonType": logon_type,
            "LogonProcessName": rng.choice(_LOGON_PROCESSES),
            "AuthenticationPackageName": _pick_auth_package(logon_type, rng),
            "WorkstationName": target_host.name.upper(),
            "ProcessId": "0x0",
            "ProcessName": "-",
            "IpAddress": src_ip,
            "IpPort": str(rng.randint(49152, 65535)),
            "Status": "0xC000006D",
            "SubStatus": substatus,
            "FailureReason": reason,
            "HostName": target_host.name,
        }
    )
    return record


def _build_4634(session: _OpenSession, user_indices: dict[str, int]) -> dict:
    tgt_idx = user_indices[session.target_user.username]
    record = _tag(4634, _SECURITY_CHANNEL, session.close_ts)
    record.update(
        {
            "TargetUserSid": _make_sid(tgt_idx),
            "TargetUserName": session.target_user.username,
            "TargetDomainName": _DOMAIN_NETBIOS,
            "TargetLogonId": session.target_logon_id,
            "LogonType": session.logon_type,
            "HostName": session.target_host.name,
        }
    )
    return record


def _build_4672(session: _OpenSession, user_indices: dict[str, int]) -> dict:
    tgt_idx = user_indices[session.target_user.username]
    record = _tag(4672, _SECURITY_CHANNEL, session.open_ts)
    record.update(
        {
            "SubjectUserSid": _make_sid(tgt_idx),
            "SubjectUserName": session.target_user.username,
            "SubjectDomainName": _DOMAIN_NETBIOS,
            "SubjectLogonId": session.target_logon_id,
            "PrivilegeList": _ADMIN_PRIVILEGE_LIST,
            "HostName": session.target_host.name,
        }
    )
    return record


def _build_4688(
    *,
    ts: datetime,
    host: Host,
    user: User,
    user_indices: dict[str, int],
    process_id_pool: list[int],
    rng: random.Random,
) -> dict:
    new_proc, command_line, parent_proc = rng.choice(_BENIGN_PROCESSES)
    user_idx = user_indices[user.username]
    elevation = 2 if user.role == "admin" else 1
    record = _tag(4688, _SECURITY_CHANNEL, ts)
    record.update(
        {
            "SubjectUserSid": _make_sid(user_idx),
            "SubjectUserName": user.username,
            "SubjectDomainName": _DOMAIN_NETBIOS,
            "SubjectLogonId": f"0x{(user_idx % 0xFFFFFFFF):08x}",
            "NewProcessId": f"0x{rng.choice(process_id_pool):x}",
            "NewProcessName": new_proc,
            "TokenElevationType": f"%%{1934 + elevation}",
            "ProcessId": f"0x{rng.choice(process_id_pool):x}",
            "CommandLine": command_line,
            "TargetUserSid": "S-1-0-0",
            "TargetUserName": "-",
            "TargetDomainName": "-",
            "TargetLogonId": "0x0",
            "ParentProcessName": parent_proc,
            "MandatoryLabel": "S-1-16-8192",
            "HostName": host.name,
        }
    )
    return record


def _build_7036(*, ts: datetime, host: Host, rng: random.Random) -> dict:
    service = rng.choice(_BENIGN_SERVICES)
    state = rng.choice(("running", "stopped"))
    record = _tag(7036, _SYSTEM_CHANNEL, ts)
    record.update(
        {
            "param1": service,
            "param2": state,
            "HostName": host.name,
        }
    )
    return record


# --- public API ------------------------------------------------------------


def generate(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Yield Windows EventLog event dicts. Windows hosts only.

    Deterministic given ``(topology, start, end, seed)``. Events are
    yielded in ``(timestamp, host, event_id)`` order so iteration is
    stable across Python builds.
    """
    if end <= start:
        log.info("evtx.generate: empty window (end <= start); no events")
        return []

    rng = random.Random(seed)

    # Cache lookup structures up-front so determinism is independent of
    # consumer iteration order.
    windows_hosts: list[Host] = [h for h in topology.hosts if _is_windows(h)]
    if not windows_hosts:
        log.info("evtx.generate: no Windows hosts in topology; no events")
        return []

    host_index: dict[str, int] = {h.name: i for i, h in enumerate(topology.hosts)}
    users_by_host: dict[str, list[User]] = {}
    for u in topology.users:
        users_by_host.setdefault(u.primary_host, []).append(u)
    user_indices: dict[str, int] = {
        u.username: i for i, u in enumerate(topology.users)
    }

    # Stable per-host PID pool. Real Windows recycles PIDs continuously;
    # for a synthetic corpus a fixed pool keeps the schema realistic
    # without leaking RNG calls into the determinism budget.
    process_id_pool: list[int] = list(range(0x100, 0x100 + 256))

    # Cross-host servers list for picking network-logon targets.
    # Windows-only: a 4624 emitted "on" a Linux host would violate the
    # only-Windows contract -- those network logons land in the auth.log
    # generator instead (linux_logs subtask).
    server_hosts: list[Host] = [
        h
        for h in topology.hosts
        if h.role in _SERVER_ROLES and h.os == "windows"
    ]

    open_sessions: list[_OpenSession] = []
    events: list[dict] = []

    # Logon counter per host -- feeds into TargetLogonId so pairing is
    # exact and unique within the corpus.
    logon_counters: dict[str, int] = {h.name: 0 for h in windows_hosts}

    # Walk in 1-hour buckets.
    cursor = start
    one_hour = timedelta(hours=1)
    while cursor < end:
        next_cursor = min(cursor + one_hour, end)
        hour_fraction = (next_cursor - cursor).total_seconds() / 3600.0

        for host in windows_hosts:
            # --- 4624 logons --------------------------------------------
            logon_attempt_rate = activity_model.rate(
                host, "logon_attempt", cursor
            )
            n_logons = _hour_count(logon_attempt_rate * hour_fraction, rng)
            stamps = _spread_timestamps(cursor, n_logons, rng)

            host_users = users_by_host.get(host.name, [])
            for ts in stamps:
                # Subject: a user who logs in here. If host has no users
                # bound (e.g. servers), pick a random topology user.
                if host_users:
                    subject_user = host_users[rng.randrange(len(host_users))]
                else:
                    subject_user = topology.users[
                        rng.randrange(len(topology.users))
                    ]
                subject_host_obj = (
                    _host_by_name(topology, subject_user.primary_host) or host
                )
                # Target: if subject lives on a workstation, ~70% of
                # logons stay local (workstation logon); the remainder
                # are network logons to a server.
                if (
                    subject_host_obj.role in _WORKSTATION_ROLES
                    and server_hosts
                    and rng.random() < 0.3
                ):
                    target_host = server_hosts[
                        rng.randrange(len(server_hosts))
                    ]
                else:
                    target_host = host

                logon_type = _pick_logon_type(target_host, rng)
                auth_pkg = _pick_auth_package(logon_type, rng)

                logon_counters[host.name] = logon_counters[host.name] + 1
                counter = logon_counters[host.name]
                target_logon_id = (
                    f"0x{host_index[host.name]:04x}{counter:08x}"
                )
                # Session duration: deterministic via rng. 15min..4h.
                duration_s = rng.uniform(15 * 60.0, 4 * 3600.0)
                close_ts = ts + timedelta(seconds=duration_s)
                session = _OpenSession(
                    target_logon_id=target_logon_id,
                    subject_user=subject_user,
                    subject_host=subject_host_obj,
                    target_user=subject_user,  # self-logon model
                    target_host=target_host,
                    logon_type=logon_type,
                    auth_package=auth_pkg,
                    open_ts=ts,
                    close_ts=close_ts,
                )
                events.append(
                    _build_4624(
                        session=session,
                        user_indices=user_indices,
                        process_id_pool=process_id_pool,
                        rng=rng,
                    )
                )
                # 4672 sibling for admin logons.
                if subject_user.role == "admin":
                    events.append(_build_4672(session, user_indices))
                # Close 4634 only if it falls inside the window.
                if close_ts < end:
                    events.append(_build_4634(session, user_indices))
                else:
                    open_sessions.append(session)

            # --- 4625 failed logons --------------------------------------
            failure_rate = activity_model.rate(host, "logon_failure", cursor)
            n_failures = _hour_count(failure_rate * hour_fraction, rng)
            failure_stamps = _spread_timestamps(cursor, n_failures, rng)
            for ts in failure_stamps:
                if host_users:
                    target_user = host_users[rng.randrange(len(host_users))]
                else:
                    target_user = topology.users[
                        rng.randrange(len(topology.users))
                    ]
                events.append(
                    _build_4625(
                        ts=ts,
                        target_user=target_user,
                        target_host=host,
                        user_indices=user_indices,
                        rng=rng,
                    )
                )

            # --- 4688 process creation -----------------------------------
            proc_rate = activity_model.rate(host, "process_creation", cursor)
            n_procs = _hour_count(proc_rate * hour_fraction, rng)
            proc_stamps = _spread_timestamps(cursor, n_procs, rng)
            for ts in proc_stamps:
                if host_users:
                    proc_user = host_users[rng.randrange(len(host_users))]
                else:
                    proc_user = topology.users[
                        rng.randrange(len(topology.users))
                    ]
                events.append(
                    _build_4688(
                        ts=ts,
                        host=host,
                        user=proc_user,
                        user_indices=user_indices,
                        process_id_pool=process_id_pool,
                        rng=rng,
                    )
                )

            # --- 7036 service events (servers only) ----------------------
            if host.role in _SERVER_ROLES:
                svc_rate = activity_model.rate(host, "service_event", cursor)
                n_svc = _hour_count(svc_rate * hour_fraction, rng)
                svc_stamps = _spread_timestamps(cursor, n_svc, rng)
                for ts in svc_stamps:
                    events.append(
                        _build_7036(ts=ts, host=host, rng=rng)
                    )

        cursor = next_cursor

    # Stable ordering for cross-build determinism.
    events.sort(
        key=lambda e: (e["timestamp"], e.get("HostName", ""), e["event_id"])
    )
    log.info(
        "evtx.generate: emitted %d events across %d windows hosts (window=%s..%s seed=%d)",
        len(events),
        len(windows_hosts),
        start.isoformat(),
        end.isoformat(),
        seed,
    )
    return events
