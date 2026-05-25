"""Linux host telemetry generator for the IT baseline corpus.

Emits three log streams for Linux hosts in the topology:

* ``auditd``   -- syscall records (EXECVE, SYSCALL open/connect). PID/PPID
                  consistency is maintained within each host (every PPID
                  has appeared earlier as a PID; PID 1 = systemd is the
                  fallback parent).
* ``auth_log`` -- ``/var/log/auth.log`` lines for sshd (Accepted/Failed)
                  and sudo (admin users only).
* ``syslog``   -- ``/var/log/syslog`` lines for cron (hourly fire), systemd
                  service events, and very rare apt package operations.

Benign activity only. Vendor-neutral; no exercise vocabulary. Deterministic
given ``(topology, start, end, seed)``.

Rate composition is delegated to :class:`ActivityModel`. The mapping from
event_class to log stream is:

* ``process_creation``   -> auditd EXECVE (+ companion SYSCALL/PATH/CWD)
* ``logon_attempt``      -> auth_log sshd "Accepted publickey" (+ sudo for admins)
* ``logon_failure``      -> auth_log sshd "Failed password"
* ``network_connection`` -> auditd SYSCALL ``connect`` (sample)
* ``file_access``        -> auditd SYSCALL ``open`` (sample)
* ``service_event``      -> syslog systemd start/stop

Cron is NOT rate-driven: every Linux host fires ``cron`` once per hour
in the window (the standard "session opened for user root" hourly job)
plus a daily fire just after 06:00 local.

Public entry point: :func:`generate`.
"""

from __future__ import annotations

import hashlib
import logging
import random
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from blue_bench_generators.it_baseline.behavior import ActivityModel
from blue_bench_generators.it_baseline.topology import Host, Topology, User

log = logging.getLogger(__name__)


# Roles that run service start/stop events (i.e. servers). All Linux hosts
# in the topology are servers in practice -- there are no Linux workstations
# -- but enforce this explicitly so a future topology with Linux
# workstations does not silently emit systemd noise on user laptops.
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


# Plausible benign EXECVE shapes. (comm, exe, argv, syscall, success).
_EXECVE_CATALOGUE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("bash", "/bin/bash", ("bash", "-c", "test -d /var/log")),
    ("ls", "/bin/ls", ("ls", "-l", "/var/log")),
    ("cat", "/bin/cat", ("cat", "/etc/hostname")),
    ("grep", "/bin/grep", ("grep", "-r", "ERROR", "/var/log")),
    ("awk", "/usr/bin/awk", ("awk", "{print $1}", "/etc/passwd")),
    ("cron", "/usr/sbin/cron", ("cron", "-f")),
    ("logrotate", "/usr/sbin/logrotate", ("logrotate", "/etc/logrotate.conf")),
    ("sshd", "/usr/sbin/sshd", ("sshd", "-D")),
    ("python3", "/usr/bin/python3", ("python3", "/opt/health/check.py")),
    ("curl", "/usr/bin/curl", ("curl", "-sS", "http://10.20.0.10/health")),
)


# Files commonly opened by service processes. Vendor-neutral paths only.
_OPEN_PATHS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/group",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/lib/dpkg/status",
    "/proc/self/status",
    "/proc/loadavg",
    "/proc/meminfo",
)


# Plausible destinations for connect() samples (loopback + RFC1918).
_CONNECT_TARGETS: tuple[tuple[str, int], ...] = (
    ("127.0.0.1", 53),
    ("127.0.0.1", 25),
    ("10.20.0.10", 514),  # SIEM
    ("10.20.0.20", 389),  # DC LDAP
    ("10.30.0.10", 3128),  # proxy
    ("10.20.0.30", 445),  # SMB
)


# Service units that may start / stop on a given hour.
_SYSTEMD_UNITS: tuple[str, ...] = (
    "cron.service",
    "rsyslog.service",
    "ssh.service",
    "systemd-logind.service",
    "systemd-timesyncd.service",
)


# Source IP pool for inbound sshd lines (admin workstations + service hosts).
_SSH_SOURCE_IPS: tuple[str, ...] = (
    "10.10.0.20",
    "10.10.0.21",
    "10.20.0.40",
    "10.30.0.11",
)


_SUDO_COMMANDS: tuple[str, ...] = (
    "/bin/systemctl restart rsyslog",
    "/usr/bin/apt update",
    "/bin/journalctl -xe",
    "/usr/sbin/service ssh status",
    "/bin/cat /var/log/auth.log",
)


def _rate_to_count(rate_per_hour: float, rng: random.Random) -> int:
    """Convert a per-hour rate into an integer event count.

    Uses the deterministic floor + Bernoulli for the fractional part so
    the schedule reproduces exactly under a seeded RNG. Avoids ``random.
    poissonvariate`` because that would amplify variance unnecessarily
    and is also not in stdlib's Random.
    """
    if rate_per_hour <= 0:
        return 0
    base = int(rate_per_hour)
    frac = rate_per_hour - base
    if frac > 0 and rng.random() < frac:
        base += 1
    return base


def _iter_hours(start: datetime, end: datetime) -> Iterator[datetime]:
    """Yield hour-aligned cursors from ``start`` to ``end`` (exclusive).

    For non-hour-aligned starts (e.g. ``start = 09:30``) the first
    cursor is ``start`` itself rather than the hour-floor — otherwise
    the floored cursor would fall before ``start`` and the entire
    ``[start, hour_ceiling)`` partial bucket would emit zero events.
    The convention here matches ``network_zeek`` and ``suricata_noise``:
    partial hours are real buckets, not silently dropped.
    """
    cursor = start.replace(minute=0, second=0, microsecond=0)
    if cursor < start:
        # Use the actual start for the leading partial bucket so it
        # produces events; subsequent cursors step on the hour.
        yield start
        cursor = cursor + timedelta(hours=1)
    while cursor < end:
        yield cursor
        cursor = cursor + timedelta(hours=1)


def _pick_ppid(pid_pool: list[int], rng: random.Random) -> int:
    """Pick a parent PID. ``pid_pool[0]`` is always 1 (systemd).

    Reserves PID 1 as a fallback so the very first EXECVE on a host has
    a valid parent.
    """
    if not pid_pool:
        return 1
    # Bias toward recent PIDs but always allow systemd as a fallback.
    return rng.choice(pid_pool)


def _ssh_user_pool(host: Host, users: tuple[User, ...]) -> list[User]:
    """Users who plausibly SSH into ``host``.

    Pool is: (a) service accounts whose primary host is this host,
    (b) all admin users (admins SSH into Linux servers from their
    Windows admin workstations). Sorted for determinism.
    """
    locals_ = [u for u in users if u.primary_host == host.name]
    admins = [u for u in users if u.role == "admin"]
    seen: set[str] = set()
    pool: list[User] = []
    for u in sorted(locals_ + admins, key=lambda x: x.username):
        if u.username in seen:
            continue
        seen.add(u.username)
        pool.append(u)
    return pool


def _admin_sudo_targets(
    hosts: tuple[Host, ...], users: tuple[User, ...]
) -> dict[str, list[str]]:
    """Map admin username -> sorted list of Linux host names they sudo on.

    Every admin has access to every Linux server (matches the topology's
    flat admin posture). Kept as a function for traceability if the
    posture gets refined later.
    """
    linux_hosts = sorted(
        (h.name for h in hosts if h.os == "linux"),
    )
    return {
        u.username: list(linux_hosts) for u in users if u.role == "admin"
    }


def _emit_execve(
    *,
    host: Host,
    ts: datetime,
    pid: int,
    ppid: int,
    auid: int,
    msg_seq: int,
    rng: random.Random,
) -> Iterable[dict]:
    """Yield (EXECVE, SYSCALL, CWD, PATH) auditd records for one execve."""
    comm, exe, argv = rng.choice(_EXECVE_CATALOGUE)
    msg_id = f"{int(ts.timestamp() * 1000)}.{msg_seq}"
    base = {
        "msg_id": msg_id,
        "timestamp": ts.isoformat(),
        "pid": pid,
        "ppid": ppid,
        "auid": auid,
        "uid": auid,
        "gid": auid,
        "comm": comm,
        "exe": exe,
        "hostname": host.fqdn,
    }
    yield {
        "_log": "auditd",
        "type": "EXECVE",
        **base,
        "argc": len(argv),
        "argv": list(argv),
        "syscall": "execve",
        "success": "yes",
    }
    yield {
        "_log": "auditd",
        "type": "SYSCALL",
        **base,
        "argc": len(argv),
        "argv": list(argv),
        "syscall": "execve",
        "success": "yes",
    }
    yield {
        "_log": "auditd",
        "type": "CWD",
        **base,
        "argc": 0,
        "argv": [],
        "syscall": "execve",
        "success": "yes",
        "cwd": f"/home/{base['auid']}",
    }
    yield {
        "_log": "auditd",
        "type": "PATH",
        **base,
        "argc": 0,
        "argv": [],
        "syscall": "execve",
        "success": "yes",
        "name": exe,
    }


def _emit_open(
    *,
    host: Host,
    ts: datetime,
    pid: int,
    ppid: int,
    auid: int,
    msg_seq: int,
    rng: random.Random,
) -> dict:
    path = rng.choice(_OPEN_PATHS)
    return {
        "_log": "auditd",
        "type": "SYSCALL",
        "msg_id": f"{int(ts.timestamp() * 1000)}.{msg_seq}",
        "timestamp": ts.isoformat(),
        "pid": pid,
        "ppid": ppid,
        "auid": auid,
        "uid": auid,
        "gid": auid,
        "comm": "cat",
        "exe": "/bin/cat",
        "argc": 1,
        "argv": [path],
        "syscall": "open",
        "success": "yes",
        "hostname": host.fqdn,
        "name": path,
    }


def _emit_connect(
    *,
    host: Host,
    ts: datetime,
    pid: int,
    ppid: int,
    auid: int,
    msg_seq: int,
    rng: random.Random,
) -> dict:
    ip, port = rng.choice(_CONNECT_TARGETS)
    return {
        "_log": "auditd",
        "type": "SYSCALL",
        "msg_id": f"{int(ts.timestamp() * 1000)}.{msg_seq}",
        "timestamp": ts.isoformat(),
        "pid": pid,
        "ppid": ppid,
        "auid": auid,
        "uid": auid,
        "gid": auid,
        "comm": "curl",
        "exe": "/usr/bin/curl",
        "argc": 2,
        "argv": ["curl", f"http://{ip}:{port}/"],
        "syscall": "connect",
        "success": "yes",
        "hostname": host.fqdn,
        "remote_ip": ip,
        "remote_port": port,
    }


def _emit_sshd_accepted(
    *, host: Host, ts: datetime, user: User, pid: int, rng: random.Random
) -> dict:
    src = rng.choice(_SSH_SOURCE_IPS)
    port = 32768 + rng.randrange(0, 32000)
    thumb = "".join(rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", k=43))
    msg = (
        f"Accepted publickey for {user.username} from {src} port {port} "
        f"ssh2: ED25519 SHA256:{thumb}"
    )
    return {
        "_log": "auth_log",
        "timestamp": ts.isoformat(),
        "hostname": host.fqdn,
        "facility": "auth",
        "process": "sshd",
        "pid": pid,
        "message": msg,
    }


def _emit_sshd_failed(
    *, host: Host, ts: datetime, user: User, pid: int, rng: random.Random
) -> dict:
    src = rng.choice(_SSH_SOURCE_IPS)
    port = 32768 + rng.randrange(0, 32000)
    msg = (
        f"Failed password for {user.username} from {src} port {port} ssh2"
    )
    return {
        "_log": "auth_log",
        "timestamp": ts.isoformat(),
        "hostname": host.fqdn,
        "facility": "auth",
        "process": "sshd",
        "pid": pid,
        "message": msg,
    }


def _emit_sudo(
    *, host: Host, ts: datetime, user: User, pid: int, rng: random.Random
) -> dict:
    cmd = rng.choice(_SUDO_COMMANDS)
    msg = (
        f"{user.username} : TTY=pts/0 ; PWD=/home/{user.username} ; "
        f"USER=root ; COMMAND={cmd}"
    )
    return {
        "_log": "auth_log",
        "timestamp": ts.isoformat(),
        "hostname": host.fqdn,
        "facility": "auth",
        "process": "sudo",
        "pid": pid,
        "message": msg,
    }


def _emit_cron(*, host: Host, ts: datetime, pid: int, rng: random.Random) -> dict:
    # Standard hourly cron line. Always uses user=root and a benign cmd.
    cmd = "[ -x /usr/sbin/anacron ] || ( cd / && run-parts --report /etc/cron.hourly )"
    msg = f"(root) CMD ({cmd})"
    return {
        "_log": "syslog",
        "timestamp": ts.isoformat(),
        "hostname": host.fqdn,
        "facility": "cron",
        "process": "cron",
        "pid": pid,
        "message": msg,
    }


def _emit_systemd(
    *,
    host: Host,
    ts: datetime,
    pid: int,
    action: str,
    rng: random.Random,
) -> dict:
    unit = rng.choice(_SYSTEMD_UNITS)
    if action == "start":
        text = f"Started {unit}."
    else:
        text = f"Stopped {unit}."
    return {
        "_log": "syslog",
        "timestamp": ts.isoformat(),
        "hostname": host.fqdn,
        "facility": "daemon",
        "process": "systemd",
        "pid": pid,
        "message": text,
    }


def _emit_apt(*, host: Host, ts: datetime, pid: int, rng: random.Random) -> dict:
    text = "Performing automatic upgrade of unattended-upgrades"
    return {
        "_log": "syslog",
        "timestamp": ts.isoformat(),
        "hostname": host.fqdn,
        "facility": "daemon",
        "process": "apt",
        "pid": pid,
        "message": text,
    }


def generate(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Yield Linux host telemetry event dicts (auditd / auth_log / syslog).

    Linux hosts only. Deterministic given ``(topology, start, end, seed)``.
    """
    if end <= start:
        return

    # Sort Linux hosts by name for deterministic iteration order.
    linux_hosts = sorted(
        (h for h in topology.hosts if h.os == "linux"),
        key=lambda h: h.name,
    )
    if not linux_hosts:
        log.info("no linux hosts in topology; nothing to emit")
        return

    users = topology.users
    sudo_targets = _admin_sudo_targets(topology.hosts, users)

    events: list[dict] = []

    for host in linux_hosts:
        # Stable per-host RNG. Mix host name into the seed via blake2b
        # (NOT ``hash()`` — ``hash(str)`` is salted under
        # ``PYTHONHASHSEED=random`` and would shift the host's entire
        # event stream across processes). This RNG drives every Linux
        # event for the host, so non-determinism here is corpus-wide.
        name_hash = int.from_bytes(
            hashlib.blake2b(host.name.encode("utf-8"), digest_size=4).digest(),
            "little",
        )
        host_seed = (seed * 1_000_003) ^ name_hash
        rng = random.Random(host_seed)

        ssh_users = _ssh_user_pool(host, users)
        admin_users_for_host = [
            u for u in users
            if u.role == "admin" and host.name in sudo_targets.get(u.username, [])
        ]

        # PHASE 1: collect (timestamp, kind, payload-rng-state) intents for
        # this host across the whole window. PIDs/PPIDs are assigned in
        # PHASE 2 in strict timestamp order so PPID always references an
        # earlier-emitted PID on the same host.
        # Intent: (ts, kind, payload_dict). For auditd, PID/PPID are filled
        # in phase 2. payload may carry per-event sub-rng draws already.
        intents: list[tuple[datetime, str, dict]] = []

        for hour_ts in _iter_hours(start, end):
            # --- process_creation -> EXECVE ---
            rate_pc = activity_model.rate(host, "process_creation", hour_ts)
            n_pc = _rate_to_count(rate_pc, rng)
            for _ in range(n_pc):
                offset = rng.randrange(0, 3600)
                ts = hour_ts + timedelta(seconds=offset)
                if ts < start or ts >= end:
                    continue
                comm, exe, argv = rng.choice(_EXECVE_CATALOGUE)
                intents.append((ts, "execve", {"comm": comm, "exe": exe, "argv": argv}))

            # --- file_access -> open() syscall (sample) ---
            rate_fa = activity_model.rate(host, "file_access", hour_ts)
            n_fa = _rate_to_count(rate_fa * 0.05, rng)
            for _ in range(n_fa):
                offset = rng.randrange(0, 3600)
                ts = hour_ts + timedelta(seconds=offset)
                if ts < start or ts >= end:
                    continue
                path = rng.choice(_OPEN_PATHS)
                intents.append((ts, "open", {"path": path}))

            # --- network_connection -> connect() (sample) ---
            rate_nc = activity_model.rate(host, "network_connection", hour_ts)
            n_nc = _rate_to_count(rate_nc * 0.10, rng)
            for _ in range(n_nc):
                offset = rng.randrange(0, 3600)
                ts = hour_ts + timedelta(seconds=offset)
                if ts < start or ts >= end:
                    continue
                ip, port = rng.choice(_CONNECT_TARGETS)
                intents.append((ts, "connect", {"ip": ip, "port": port}))

            # --- logon_attempt -> sshd Accepted ---
            rate_la = activity_model.rate(host, "logon_attempt", hour_ts)
            n_la = _rate_to_count(rate_la, rng)
            for _ in range(n_la):
                offset = rng.randrange(0, 3600)
                ts = hour_ts + timedelta(seconds=offset)
                if ts < start or ts >= end:
                    continue
                if not ssh_users:
                    break
                user = rng.choice(ssh_users)
                src = rng.choice(_SSH_SOURCE_IPS)
                port = 32768 + rng.randrange(0, 32000)
                thumb = "".join(
                    rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", k=43)
                )
                sshd_pid = 2000 + rng.randrange(0, 1000)
                intents.append(
                    (
                        ts,
                        "sshd_accepted",
                        {
                            "user": user,
                            "src": src,
                            "port": port,
                            "thumb": thumb,
                            "pid": sshd_pid,
                        },
                    )
                )

            # --- logon_failure -> sshd Failed ---
            rate_lf = activity_model.rate(host, "logon_failure", hour_ts)
            n_lf = _rate_to_count(rate_lf, rng)
            for _ in range(n_lf):
                offset = rng.randrange(0, 3600)
                ts = hour_ts + timedelta(seconds=offset)
                if ts < start or ts >= end:
                    continue
                if not ssh_users:
                    break
                user = rng.choice(ssh_users)
                src = rng.choice(_SSH_SOURCE_IPS)
                port = 32768 + rng.randrange(0, 32000)
                sshd_pid = 2000 + rng.randrange(0, 1000)
                intents.append(
                    (
                        ts,
                        "sshd_failed",
                        {
                            "user": user,
                            "src": src,
                            "port": port,
                            "pid": sshd_pid,
                        },
                    )
                )

            # --- sudo (admin users only) ---
            if admin_users_for_host:
                n_sudo = _rate_to_count(rate_la * 0.2, rng)
                for _ in range(n_sudo):
                    offset = rng.randrange(0, 3600)
                    ts = hour_ts + timedelta(seconds=offset)
                    if ts < start or ts >= end:
                        continue
                    user = rng.choice(admin_users_for_host)
                    cmd = rng.choice(_SUDO_COMMANDS)
                    sudo_pid = 3000 + rng.randrange(0, 1000)
                    intents.append(
                        (
                            ts,
                            "sudo",
                            {"user": user, "cmd": cmd, "pid": sudo_pid},
                        )
                    )

            # --- cron: ALWAYS one hourly fire per Linux host ---
            cron_ts = hour_ts + timedelta(minutes=17)
            if start <= cron_ts < end:
                intents.append((cron_ts, "cron", {"pid": 900}))

            if hour_ts.hour == 6:
                daily_ts = hour_ts + timedelta(minutes=25)
                if start <= daily_ts < end:
                    intents.append((daily_ts, "cron", {"pid": 901}))

            # --- service_event -> systemd start/stop (server roles only) ---
            if host.role in _SERVER_ROLES:
                rate_se = activity_model.rate(host, "service_event", hour_ts)
                n_se = _rate_to_count(rate_se, rng)
                for _ in range(n_se):
                    offset = rng.randrange(0, 3600)
                    ts = hour_ts + timedelta(seconds=offset)
                    if ts < start or ts >= end:
                        continue
                    action = "start" if rng.random() < 0.5 else "stop"
                    unit = rng.choice(_SYSTEMD_UNITS)
                    intents.append(
                        (
                            ts,
                            "systemd",
                            {"action": action, "unit": unit, "pid": 1},
                        )
                    )

            # --- apt: very rare, fire on Monday 03:00 only ---
            if hour_ts.weekday() == 0 and hour_ts.hour == 3:
                apt_ts = hour_ts + timedelta(minutes=12)
                if start <= apt_ts < end:
                    intents.append((apt_ts, "apt", {"pid": 4000}))

        # PHASE 2: sort intents by timestamp on this host, then assign
        # PIDs/PPIDs in order so PPID always references a previously-
        # emitted PID. Determinism is preserved because intent ordering
        # was deterministic (same RNG sequence) and sort is stable.
        # Use enumerate index as a tiebreaker on identical timestamps so
        # the sort is fully deterministic.
        intents_sorted = sorted(
            enumerate(intents), key=lambda x: (x[1][0], x[0])
        )

        next_pid = 1000
        pid_pool: list[int] = [1]  # systemd is the fallback parent
        msg_seq = 0
        pid_rng = random.Random(host_seed ^ 0xDEADBEEF)

        for _, (ts, kind, payload) in intents_sorted:
            if kind in ("execve", "open", "connect"):
                ppid = pid_rng.choice(pid_pool)
                pid = next_pid
                next_pid += 1
                pid_pool.append(pid)
                if len(pid_pool) > 64:
                    # Drop the second-oldest entry; PID 1 (systemd) stays
                    # at index 0 forever.
                    pid_pool.pop(1)
                auid = 1000 + (pid % 50)
                msg_seq += 1
                if kind == "execve":
                    for rec in _emit_execve(
                        host=host,
                        ts=ts,
                        pid=pid,
                        ppid=ppid,
                        auid=auid,
                        msg_seq=msg_seq,
                        rng=pid_rng,
                    ):
                        # Override comm/exe/argv from intent payload.
                        if rec["type"] == "EXECVE" or rec["type"] == "SYSCALL":
                            rec["comm"] = payload["comm"]
                            rec["exe"] = payload["exe"]
                            rec["argv"] = list(payload["argv"])
                            rec["argc"] = len(payload["argv"])
                        elif rec["type"] == "PATH":
                            rec["name"] = payload["exe"]
                            rec["exe"] = payload["exe"]
                            rec["comm"] = payload["comm"]
                        elif rec["type"] == "CWD":
                            rec["exe"] = payload["exe"]
                            rec["comm"] = payload["comm"]
                        events.append(rec)
                elif kind == "open":
                    events.append(
                        {
                            "_log": "auditd",
                            "type": "SYSCALL",
                            "msg_id": f"{int(ts.timestamp() * 1000)}.{msg_seq}",
                            "timestamp": ts.isoformat(),
                            "pid": pid,
                            "ppid": ppid,
                            "auid": auid,
                            "uid": auid,
                            "gid": auid,
                            "comm": "cat",
                            "exe": "/bin/cat",
                            "argc": 1,
                            "argv": [payload["path"]],
                            "syscall": "open",
                            "success": "yes",
                            "hostname": host.fqdn,
                            "name": payload["path"],
                        }
                    )
                else:  # connect
                    events.append(
                        {
                            "_log": "auditd",
                            "type": "SYSCALL",
                            "msg_id": f"{int(ts.timestamp() * 1000)}.{msg_seq}",
                            "timestamp": ts.isoformat(),
                            "pid": pid,
                            "ppid": ppid,
                            "auid": auid,
                            "uid": auid,
                            "gid": auid,
                            "comm": "curl",
                            "exe": "/usr/bin/curl",
                            "argc": 2,
                            "argv": [
                                "curl",
                                f"http://{payload['ip']}:{payload['port']}/",
                            ],
                            "syscall": "connect",
                            "success": "yes",
                            "hostname": host.fqdn,
                            "remote_ip": payload["ip"],
                            "remote_port": payload["port"],
                        }
                    )
            elif kind == "sshd_accepted":
                msg = (
                    f"Accepted publickey for {payload['user'].username} "
                    f"from {payload['src']} port {payload['port']} "
                    f"ssh2: ED25519 SHA256:{payload['thumb']}"
                )
                events.append(
                    {
                        "_log": "auth_log",
                        "timestamp": ts.isoformat(),
                        "hostname": host.fqdn,
                        "facility": "auth",
                        "process": "sshd",
                        "pid": payload["pid"],
                        "message": msg,
                    }
                )
            elif kind == "sshd_failed":
                msg = (
                    f"Failed password for {payload['user'].username} "
                    f"from {payload['src']} port {payload['port']} ssh2"
                )
                events.append(
                    {
                        "_log": "auth_log",
                        "timestamp": ts.isoformat(),
                        "hostname": host.fqdn,
                        "facility": "auth",
                        "process": "sshd",
                        "pid": payload["pid"],
                        "message": msg,
                    }
                )
            elif kind == "sudo":
                user = payload["user"]
                msg = (
                    f"{user.username} : TTY=pts/0 ; PWD=/home/{user.username} "
                    f"; USER=root ; COMMAND={payload['cmd']}"
                )
                events.append(
                    {
                        "_log": "auth_log",
                        "timestamp": ts.isoformat(),
                        "hostname": host.fqdn,
                        "facility": "auth",
                        "process": "sudo",
                        "pid": payload["pid"],
                        "message": msg,
                    }
                )
            elif kind == "cron":
                cmd = (
                    "[ -x /usr/sbin/anacron ] || ( cd / && run-parts "
                    "--report /etc/cron.hourly )"
                )
                events.append(
                    {
                        "_log": "syslog",
                        "timestamp": ts.isoformat(),
                        "hostname": host.fqdn,
                        "facility": "cron",
                        "process": "cron",
                        "pid": payload["pid"],
                        "message": f"(root) CMD ({cmd})",
                    }
                )
            elif kind == "systemd":
                action = payload["action"]
                unit = payload["unit"]
                text = f"Started {unit}." if action == "start" else f"Stopped {unit}."
                events.append(
                    {
                        "_log": "syslog",
                        "timestamp": ts.isoformat(),
                        "hostname": host.fqdn,
                        "facility": "daemon",
                        "process": "systemd",
                        "pid": payload["pid"],
                        "message": text,
                    }
                )
            elif kind == "apt":
                events.append(
                    {
                        "_log": "syslog",
                        "timestamp": ts.isoformat(),
                        "hostname": host.fqdn,
                        "facility": "daemon",
                        "process": "apt",
                        "pid": payload["pid"],
                        "message": (
                            "Performing automatic upgrade of "
                            "unattended-upgrades"
                        ),
                    }
                )

    # Sort by (timestamp, hostname, _log) for a stable global stream.
    events.sort(key=lambda e: (e["timestamp"], e.get("hostname", ""), e["_log"]))
    log.info(
        "linux_logs: emitted %d events across %d hosts",
        len(events),
        len(linux_hosts),
    )
    yield from events
