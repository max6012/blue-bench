"""Sysmon event generator for Windows hosts in the IT baseline corpus.

Emits Sysmon-shaped event dicts for the following IDs:

    1   process_create
    3   network_connect
    7   image_load
    8   create_remote_thread
    10  process_access
    11  file_create
    12  registry_create_key   (Sysmon "RegistryEvent (Object create and delete)")
    13  registry_value_set
    14  registry_rename       (reserved -- not emitted by v1; see notes)

Benign activity only -- APT process trees are layered on by the
``t-apt-inject`` generator later. Vendor-neutral terminology only; no
scenario vocabulary.

Determinism contract
--------------------

``generate(topology, activity_model, start, end, seed)`` is a pure function
of its inputs. Per-host RNG isolation: each host gets a sub-RNG seeded as
``hash((seed, host.name))`` so adding or removing hosts cannot reshuffle
the events emitted by other hosts.

Rate composition
----------------

For each Windows host, we walk the time window hour-by-hour. Each hour we
ask ``activity_model.rate(host, "process_creation", ts)`` for an expected
events/hour and use a Poisson-shaped deterministic count to draw the
number of EventID 1 records this hour. Each EventID 1 then begets a
small chain of related events (image loads, file creates, network
connects, occasional registry / inter-process events) at fixed
multipliers.

We DELIBERATELY do not pull ``network_connection`` or ``file_access``
from the activity model -- those rates are driven by the network and
file generators respectively. Sysmon's 3/11 events are chained off
EventID 1 here so that every chained event's ``ProcessGuid`` reliably
attaches to a prior EventID 1's process (parent-child consistency).

Boot-tree root
--------------

Every host emits a small boot tree (System -> smss.exe -> winlogon.exe ->
userinit.exe -> explorer.exe) at ``start``. ``System`` is self-parented
(its ``ParentProcessGuid`` equals its ``ProcessGuid``) so the
parent-consistency invariant holds for every emitted EventID 1.
Subsequent role-template trees re-parent under existing processes (most
often ``explorer.exe`` for workstations, ``services.exe`` for servers).

Synthetic hashes
----------------

Hash fields are deterministic synthetic strings of the form
``sha256(f"benign-{host}-{image}-{seed}")``. Every event that carries a
``Hashes`` field also carries a ``_note`` field explicitly flagging the
hash as synthetic so downstream consumers cannot mistake it for a real
IOC.
"""

from __future__ import annotations

import hashlib
import logging
import random
from datetime import datetime, timedelta
from typing import Iterable

from blue_bench_generators.it_baseline.behavior import ActivityModel
from blue_bench_generators.it_baseline.topology import Host, Topology

log = logging.getLogger(__name__)


# --- per-role process templates -------------------------------------------
#
# A template is a list of (parent_image, child_image) edges. ``None`` as
# a parent means "attach the child to the boot-tree root for the host"
# (typically ``explorer.exe`` on workstations, ``services.exe`` on
# servers -- resolved per role at emission time).
#
# Vendor-neutral process names ONLY. Anything that could read as a
# scenario keyword is out.


_ROLE_TEMPLATES: dict[str, tuple[tuple[str, str], ...]] = {
    "workstation": (
        ("explorer.exe", "outlook.exe"),
        ("explorer.exe", "msedge.exe"),
        ("explorer.exe", "teams.exe"),
        ("explorer.exe", "winword.exe"),
        ("explorer.exe", "excel.exe"),
    ),
    "admin-workstation": (
        ("explorer.exe", "outlook.exe"),
        ("explorer.exe", "msedge.exe"),
        ("explorer.exe", "teams.exe"),
        ("explorer.exe", "winword.exe"),
        ("explorer.exe", "excel.exe"),
        ("explorer.exe", "powershell.exe"),
        ("explorer.exe", "mmc.exe"),
        ("explorer.exe", "cmd.exe"),
        ("explorer.exe", "RDPClip.exe"),
    ),
    "file-server": (
        ("services.exe", "svchost.exe"),
        ("services.exe", "lsass.exe"),
        ("services.exe", "defrag.exe"),
    ),
    "database-server": (
        ("services.exe", "svchost.exe"),
        ("services.exe", "lsass.exe"),
        ("services.exe", "sqlservr.exe"),
    ),
    "web-server": (
        ("services.exe", "svchost.exe"),
        ("services.exe", "w3wp.exe"),
    ),
    "mail-server": (
        ("services.exe", "svchost.exe"),
        ("services.exe", "Microsoft.Exchange.Service.exe"),
    ),
    "domain-controller": (
        ("services.exe", "svchost.exe"),
        ("services.exe", "lsass.exe"),
        ("services.exe", "ntds.exe"),
        ("services.exe", "dns.exe"),
    ),
}


# Image -> common command-line stub. Cosmetic; helps EventID 1 records
# look plausible without inventing fake arguments. Vendor-neutral only.
_IMAGE_COMMAND: dict[str, str] = {
    "System": "",
    "smss.exe": "\\SystemRoot\\System32\\smss.exe",
    "winlogon.exe": "winlogon.exe",
    "userinit.exe": "C:\\Windows\\System32\\userinit.exe",
    "explorer.exe": "C:\\Windows\\explorer.exe",
    "services.exe": "C:\\Windows\\system32\\services.exe",
    "svchost.exe": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
    "lsass.exe": "C:\\Windows\\system32\\lsass.exe",
    "outlook.exe": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
    "msedge.exe": "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\"",
    "teams.exe": "\"C:\\Users\\%USER%\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe\"",
    "winword.exe": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\"",
    "excel.exe": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\"",
    "powershell.exe": "powershell.exe -NoProfile -ExecutionPolicy Bypass",
    "mmc.exe": "C:\\Windows\\System32\\mmc.exe",
    "cmd.exe": "C:\\Windows\\System32\\cmd.exe",
    "RDPClip.exe": "C:\\Windows\\System32\\RDPClip.exe",
    "defrag.exe": "C:\\Windows\\System32\\defrag.exe C: -h",
    "sqlservr.exe": "\"C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe\"",
    "w3wp.exe": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
    "Microsoft.Exchange.Service.exe": "\"C:\\Program Files\\Microsoft\\Exchange Server\\Bin\\Microsoft.Exchange.Service.exe\"",
    "ntds.exe": "C:\\Windows\\System32\\ntds.exe",
    "dns.exe": "C:\\Windows\\System32\\dns.exe",
}


# Common image-load DLLs per host class. Keep small and shared -- the
# point is shape, not byte-accuracy. The benign-by-construction Sysmon
# corpus must look ordinary, not deeply realistic.
_COMMON_DLLS: tuple[str, ...] = (
    "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Windows\\System32\\kernel32.dll",
    "C:\\Windows\\System32\\kernelbase.dll",
    "C:\\Windows\\System32\\user32.dll",
    "C:\\Windows\\System32\\advapi32.dll",
    "C:\\Windows\\System32\\msvcrt.dll",
    "C:\\Windows\\System32\\sechost.dll",
    "C:\\Windows\\System32\\rpcrt4.dll",
    "C:\\Windows\\System32\\ole32.dll",
    "C:\\Windows\\System32\\combase.dll",
)


# Chain multipliers per EventID-1. Numbers picked small/round so volume
# stays bounded but realistic-shape: every process spawns several image
# loads, a couple of file creates, and a few outbound network connects.
# 8/10/12/13 are rarer per-process events.
_CHAIN_MULTIPLIERS: dict[int, float] = {
    7: 5.0,    # image_load -- ~5 loaded DLLs per process
    11: 2.0,   # file_create -- ~2 temp / cache files
    3: 3.0,    # network_connect -- ~3 outbound conns per process
    10: 0.3,   # process_access -- rare (handle opens)
    8: 0.05,   # create_remote_thread -- very rare benignly
    12: 0.4,   # registry_event (object create/delete) -- occasional
    13: 0.8,   # registry_value_set -- moderate (settings writes)
}


# Boot-tree timing. Boot events space at 50ms intervals; with 5 events
# the last lands at start + 200ms. Role-template children must clamp
# past this window (+ a small buffer) so a low-rate uniform draw
# cannot place a child inside the boot interval and sort ahead of its
# supposed parent after events.sort(key=UtcTime, event_id).
_BOOT_STEP_MS = 50
_BOOT_WINDOW_MS = 250

_HOST_BOOT_TREE: tuple[tuple[str, str], ...] = (
    # (parent_image, child_image). The first entry must be the boot
    # root (parent_image == ""), whose ProcessGuid is self-parented.
    ("", "System"),
    ("System", "smss.exe"),
    ("smss.exe", "winlogon.exe"),
    ("winlogon.exe", "userinit.exe"),
    ("userinit.exe", "explorer.exe"),
)


def _host_rng(seed: int, host: Host) -> random.Random:
    """Per-host isolated RNG. Adding a host won't reshuffle others.

    Uses a blake2b digest of ``host.name`` rather than ``hash()`` because
    ``hash(str)`` is randomized across processes under
    ``PYTHONHASHSEED=random``. This RNG seeds every Sysmon event for the
    host, so a salted hash would shift the entire stream across runs.
    """
    digest = hashlib.blake2b(host.name.encode("utf-8"), digest_size=8).digest()
    return random.Random(seed ^ int.from_bytes(digest, "little"))


def _stable_hash_hex(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _process_guid(host_name: str, pid: int, image: str, seed: int) -> str:
    """Deterministic Sysmon-style ProcessGuid.

    Real Sysmon emits ``{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}``. We
    follow the same braced-hex shape so consumers / regex pattern matches
    are not surprised, while keeping the hash fully deterministic.
    """
    h = _stable_hash_hex("pguid", host_name, str(pid), image, str(seed))
    return f"{{{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}}}"


def _file_hash(host_name: str, image: str, seed: int) -> str:
    return _stable_hash_hex("benign", host_name, image, str(seed))


def _utc_str(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _user_for(host: Host) -> str:
    """Synthetic per-host user label.

    Workstations log on as ``CORP\\<host>-user``, servers as ``NT
    AUTHORITY\\SYSTEM``. We don't try to resolve the topology's user
    inventory here -- Sysmon's User field is a label, not a join key.
    """
    if host.role in ("workstation", "admin-workstation"):
        return f"CORP\\{host.name}-user"
    return "NT AUTHORITY\\SYSTEM"


def _integrity_for(image: str) -> str:
    if image in ("System", "smss.exe", "winlogon.exe", "services.exe",
                 "lsass.exe", "svchost.exe", "ntds.exe", "dns.exe"):
        return "System"
    if image in ("powershell.exe", "mmc.exe", "cmd.exe"):
        return "High"
    return "Medium"


def _make_process_create(
    *,
    host: Host,
    ts: datetime,
    image: str,
    pid: int,
    parent_image: str,
    parent_pid: int,
    seed: int,
) -> dict:
    """Build a Sysmon EventID 1 dict for a single benign process spawn."""
    proc_guid = _process_guid(host.name, pid, image, seed)
    parent_guid = _process_guid(host.name, parent_pid, parent_image, seed) \
        if parent_image else proc_guid  # boot root self-parents
    user = _user_for(host)
    return {
        "_log": "sysmon",
        "event_id": 1,
        "Computer": host.fqdn,
        "UtcTime": _utc_str(ts),
        "ProcessGuid": proc_guid,
        "ProcessId": pid,
        "Image": _image_path(image),
        "FileVersion": "10.0.19041.1",
        "Description": image,
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "CommandLine": _IMAGE_COMMAND.get(image, image),
        "CurrentDirectory": "C:\\Windows\\system32\\",
        "User": user,
        "LogonGuid": _process_guid(host.name, 0, "logon", seed),
        "LogonId": "0x3e7",
        "TerminalSessionId": 0 if parent_image in ("", "System", "smss.exe", "services.exe") else 1,
        "IntegrityLevel": _integrity_for(image),
        "Hashes": f"SHA256={_file_hash(host.name, image, seed)}",
        "ParentProcessGuid": parent_guid,
        "ParentProcessId": parent_pid,
        "ParentImage": _image_path(parent_image) if parent_image else _image_path(image),
        "ParentCommandLine": _IMAGE_COMMAND.get(parent_image, parent_image) if parent_image else "",
        "_note": "synthetic-deterministic-hash; not a real IOC",
    }


def _image_path(image: str) -> str:
    """Resolve a bare image name to a plausible absolute Windows path."""
    if not image:
        return ""
    if image == "System":
        return "System"
    cmd = _IMAGE_COMMAND.get(image)
    if cmd and cmd.startswith("\""):
        # Strip opening quote and take everything up to the next quote.
        end = cmd.find("\"", 1)
        if end > 0:
            return cmd[1:end]
    if cmd and (cmd.startswith("C:\\") or cmd.startswith("\\")):
        # Take the first whitespace-bounded token.
        return cmd.split()[0]
    return f"C:\\Windows\\System32\\{image}"


def _make_image_load(
    *, host: Host, ts: datetime, proc_image: str, proc_guid: str,
    pid: int, dll: str, seed: int,
) -> dict:
    return {
        "_log": "sysmon",
        "event_id": 7,
        "Computer": host.fqdn,
        "UtcTime": _utc_str(ts),
        "ProcessGuid": proc_guid,
        "ProcessId": pid,
        "Image": _image_path(proc_image),
        "ImageLoaded": dll,
        "FileVersion": "10.0.19041.1",
        "Hashes": f"SHA256={_file_hash(host.name, dll, seed)}",
        "Signed": "true",
        "Signature": "Microsoft Windows",
        "SignatureStatus": "Valid",
        "_note": "synthetic-deterministic-hash; not a real IOC",
    }


def _make_file_create(
    *, host: Host, ts: datetime, proc_image: str, proc_guid: str,
    pid: int, target: str,
) -> dict:
    return {
        "_log": "sysmon",
        "event_id": 11,
        "Computer": host.fqdn,
        "UtcTime": _utc_str(ts),
        "ProcessGuid": proc_guid,
        "ProcessId": pid,
        "Image": _image_path(proc_image),
        "TargetFilename": target,
        "CreationUtcTime": _utc_str(ts),
    }


def _make_network_connect(
    *, host: Host, ts: datetime, proc_image: str, proc_guid: str,
    pid: int, dst_ip: str, dst_port: int, dst_host: str,
) -> dict:
    return {
        "_log": "sysmon",
        "event_id": 3,
        "Computer": host.fqdn,
        "UtcTime": _utc_str(ts),
        "ProcessGuid": proc_guid,
        "ProcessId": pid,
        "Image": _image_path(proc_image),
        "User": _user_for(host),
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIsIpv6": "false",
        "SourceIp": host.ip,
        "SourcePort": 49152 + (pid % 16000),
        "SourceHostname": host.fqdn,
        "DestinationIsIpv6": "false",
        "DestinationIp": dst_ip,
        "DestinationPort": dst_port,
        "DestinationHostname": dst_host,
    }


def _make_process_access(
    *, host: Host, ts: datetime, src_image: str, src_guid: str, src_pid: int,
    tgt_image: str, tgt_guid: str, tgt_pid: int,
) -> dict:
    return {
        "_log": "sysmon",
        "event_id": 10,
        "Computer": host.fqdn,
        "UtcTime": _utc_str(ts),
        "SourceProcessGUID": src_guid,
        "SourceProcessId": src_pid,
        "SourceImage": _image_path(src_image),
        "TargetProcessGUID": tgt_guid,
        "TargetProcessId": tgt_pid,
        "TargetImage": _image_path(tgt_image),
        "GrantedAccess": "0x1000",
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234",
    }


def _make_create_remote_thread(
    *, host: Host, ts: datetime, src_image: str, src_guid: str, src_pid: int,
    tgt_image: str, tgt_guid: str, tgt_pid: int,
) -> dict:
    return {
        "_log": "sysmon",
        "event_id": 8,
        "Computer": host.fqdn,
        "UtcTime": _utc_str(ts),
        "SourceProcessGuid": src_guid,
        "SourceProcessId": src_pid,
        "SourceImage": _image_path(src_image),
        "TargetProcessGuid": tgt_guid,
        "TargetProcessId": tgt_pid,
        "TargetImage": _image_path(tgt_image),
        "NewThreadId": 1000 + (tgt_pid % 5000),
        "StartAddress": "0x7FF6A0001000",
        "StartModule": _image_path(tgt_image),
    }


def _make_registry_event(
    *, host: Host, ts: datetime, event_id: int, proc_image: str, proc_guid: str,
    pid: int, target_object: str, details: str | None,
) -> dict:
    rec = {
        "_log": "sysmon",
        "event_id": event_id,
        "Computer": host.fqdn,
        "UtcTime": _utc_str(ts),
        "EventType": "SetValue" if event_id == 13 else "CreateKey",
        "ProcessGuid": proc_guid,
        "ProcessId": pid,
        "Image": _image_path(proc_image),
        "TargetObject": target_object,
    }
    if details is not None:
        rec["Details"] = details
    return rec


# --- per-host event emission ----------------------------------------------


_PID_BASE = 4000  # Avoid collision with the reserved low PIDs (System=4).


class _PidAllocator:
    """Per-host monotonically-increasing PID allocator."""

    def __init__(self, base: int = _PID_BASE) -> None:
        self._next = base

    def next(self) -> int:
        pid = self._next
        self._next += 1
        return pid


def _emit_boot_tree(host: Host, start: datetime, seed: int) -> list[dict]:
    """Emit the host's boot tree at ``start``.

    System self-parents. Each subsequent process attaches to the prior.
    Returns the list in temporal order; also returns the boot-root state
    (image + guid + pid) via mutation of ``boot_state`` -- but for
    simplicity we let the caller pull the last record's identity.
    """
    events: list[dict] = []
    parent_image = ""
    parent_pid = 0
    ts = start
    # System uses the conventional PID 4. The other boot processes get
    # small fixed PIDs so they sort below the role-template PIDs.
    boot_pids = {
        "System": 4,
        "smss.exe": 300,
        "winlogon.exe": 600,
        "userinit.exe": 900,
        "explorer.exe": 1200,
    }
    for parent, child in _HOST_BOOT_TREE:
        pid = boot_pids[child]
        events.append(
            _make_process_create(
                host=host, ts=ts, image=child, pid=pid,
                parent_image=parent, parent_pid=boot_pids.get(parent, 0),
                seed=seed,
            )
        )
        parent_image = child
        parent_pid = pid
        ts = ts + timedelta(milliseconds=50)
    _ = parent_image, parent_pid  # boot root reachable via boot_pids
    return events


def _boot_root_for(role: str) -> str:
    """Image under which role templates attach.

    Workstations attach role children to ``explorer.exe``; servers to
    ``services.exe``. ``services.exe`` is itself spawned as the first
    role-template child on servers (so it pre-exists for downstream
    chains).
    """
    if role in ("workstation", "admin-workstation"):
        return "explorer.exe"
    return "services.exe"


def _ensure_services_exe_on_servers(
    host: Host, ts: datetime, pid_alloc: _PidAllocator, seed: int,
) -> tuple[list[dict], int]:
    """For servers, spawn services.exe under winlogon.exe at boot.

    Real Windows spawns ``services.exe`` from ``wininit.exe``; we elide
    wininit and attach services.exe to ``winlogon.exe`` (which we
    already emitted in the boot tree) to keep the boot tree small while
    preserving parent-child consistency for the role templates that
    follow.

    Returns ``(events, services_pid)``.
    """
    pid = pid_alloc.next()
    rec = _make_process_create(
        host=host, ts=ts, image="services.exe", pid=pid,
        parent_image="winlogon.exe", parent_pid=600, seed=seed,
    )
    return [rec], pid


def _poisson_count(rng: random.Random, mean: float) -> int:
    """Tiny Poisson sampler -- Knuth's algorithm.

    Returns an int. For ``mean == 0`` returns 0.
    """
    if mean <= 0:
        return 0
    # Cap to avoid pathological loops on absurd means; mean stays in the
    # hundreds for our use, so a 10x safety cap is fine.
    L = pow(2.71828182845904523536, -min(mean, 30.0))
    k = 0
    p = 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= L:
            return k - 1
        # Hard ceiling: if mean is large, fall back to deterministic round.
        if k > 1000:
            return int(mean)


def _generate_for_host(
    host: Host,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int,
) -> list[dict]:
    """All Sysmon events for one Windows host across [start, end)."""
    if host.os != "windows":
        return []
    if end <= start:
        return []

    rng = _host_rng(seed, host)
    pid_alloc = _PidAllocator()
    events: list[dict] = []

    # Boot tree at ``start`` (NOT before, so ``test_no_events_outside_window``
    # passes). Records emitted at start are inside the window since the
    # filter is [start, end).
    events.extend(_emit_boot_tree(host, start, seed))

    # Servers also need services.exe before any role template fires.
    boot_root_image = _boot_root_for(host.role)
    if boot_root_image == "services.exe":
        svc_events, svc_pid = _ensure_services_exe_on_servers(
            host, start + timedelta(milliseconds=400), pid_alloc, seed,
        )
        events.extend(svc_events)
        services_pid = svc_pid
    else:
        services_pid = None  # workstations attach under explorer.exe (pid=1200)

    templates = _ROLE_TEMPLATES.get(host.role, ())
    if not templates:
        # Unknown role with os=windows shouldn't happen given topology
        # contract, but be defensive: emit only boot tree.
        log.debug("no role template for windows host %s role=%s",
                  host.name, host.role)
        return events

    # Hour walk.
    cursor = start
    one_hour = timedelta(hours=1)
    boot_root_pid = 1200 if boot_root_image == "explorer.exe" else services_pid

    while cursor < end:
        rate = activity_model.rate(host, "process_creation", cursor)
        # Scale the rate by hour fraction if we'd overrun ``end``.
        hour_end = min(cursor + one_hour, end)
        hour_fraction = (hour_end - cursor).total_seconds() / 3600.0
        expected = rate * hour_fraction
        count = _poisson_count(rng, expected)

        for i in range(count):
            # Pick a template edge.
            parent_image, child_image = templates[rng.randrange(len(templates))]
            # Resolve parent_image -- if it's the role's boot root we
            # already have a real PID for it. Otherwise we attach to
            # the boot root anyway (single-level templates are enough
            # for v1 benign traffic).
            if parent_image == boot_root_image:
                parent_pid = boot_root_pid
            else:
                # Defensive: attach to the boot root if the template
                # references a parent we don't have a PID for.
                parent_image = boot_root_image
                parent_pid = boot_root_pid

            child_pid = pid_alloc.next()
            # Jitter inside the hour, deterministic per (rng) ordering.
            offset_seconds = rng.uniform(0.0, hour_fraction * 3600.0)
            child_ts = cursor + timedelta(seconds=offset_seconds)
            # First-hour cursor == start; boot tree occupies start..start+200ms.
            # Clamp role-template children so they cannot land inside the
            # boot window after events.sort() runs (else a child could
            # iterate ahead of its supposed parent under low-rate templates).
            min_ts = start + timedelta(milliseconds=_BOOT_WINDOW_MS)
            if child_ts < min_ts:
                child_ts = min_ts
            if child_ts >= end:
                child_ts = end - timedelta(microseconds=1)

            child_record = _make_process_create(
                host=host, ts=child_ts, image=child_image, pid=child_pid,
                parent_image=parent_image, parent_pid=parent_pid, seed=seed,
            )
            events.append(child_record)
            child_guid = child_record["ProcessGuid"]

            # Chain: image loads, file creates, network connects, etc.
            _emit_chain(
                host=host, parent_ts=child_ts, parent_image=child_image,
                parent_guid=child_guid, parent_pid=child_pid,
                rng=rng, end=end, seed=seed, events=events,
            )

        cursor = cursor + one_hour

    # Sort events by UtcTime for deterministic temporal ordering.
    events.sort(key=lambda e: (e["UtcTime"], e["event_id"]))
    return events


def _emit_chain(
    *,
    host: Host,
    parent_ts: datetime,
    parent_image: str,
    parent_guid: str,
    parent_pid: int,
    rng: random.Random,
    end: datetime,
    seed: int,
    events: list[dict],
) -> None:
    """Emit related Sysmon events anchored to a single EventID 1.

    Counts per chained event-id come from ``_CHAIN_MULTIPLIERS`` with
    Poisson sampling. All chained events carry the parent's
    ``ProcessGuid`` so ``test_image_loads_attach_to_existing_processes``
    holds for every chained 7/11/3/10/8/12/13.
    """
    def _jitter_ts() -> datetime:
        offset_ms = rng.randint(1, 60_000)  # within ~1 minute
        ts = parent_ts + timedelta(milliseconds=offset_ms)
        if ts >= end:
            return end - timedelta(microseconds=1)
        return ts

    # Image loads (7).
    n_loads = _poisson_count(rng, _CHAIN_MULTIPLIERS[7])
    for _ in range(n_loads):
        dll = _COMMON_DLLS[rng.randrange(len(_COMMON_DLLS))]
        events.append(_make_image_load(
            host=host, ts=_jitter_ts(), proc_image=parent_image,
            proc_guid=parent_guid, pid=parent_pid, dll=dll, seed=seed,
        ))

    # File creates (11).
    n_files = _poisson_count(rng, _CHAIN_MULTIPLIERS[11])
    for i in range(n_files):
        target = f"C:\\Users\\{host.name}-user\\AppData\\Local\\Temp\\benign-{parent_pid}-{i}.tmp"
        events.append(_make_file_create(
            host=host, ts=_jitter_ts(), proc_image=parent_image,
            proc_guid=parent_guid, pid=parent_pid, target=target,
        ))

    # Network connects (3).
    n_net = _poisson_count(rng, _CHAIN_MULTIPLIERS[3])
    for i in range(n_net):
        # Deterministic-fake destination. Stays inside RFC5737 doc range.
        dst_ip = f"198.51.100.{(parent_pid + i) % 254 + 1}"
        dst_port = 443 if rng.random() < 0.7 else 80
        events.append(_make_network_connect(
            host=host, ts=_jitter_ts(), proc_image=parent_image,
            proc_guid=parent_guid, pid=parent_pid,
            dst_ip=dst_ip, dst_port=dst_port,
            dst_host=f"svc-{parent_pid}-{i}.example.invalid",
        ))

    # Process access (10) -- target is the parent boot root (e.g. lsass
    # access from svchost is normal Windows housekeeping). Use the
    # parent's own guid as a stand-in target -- v1 doesn't try to model
    # cross-process targets accurately.
    n_pa = _poisson_count(rng, _CHAIN_MULTIPLIERS[10])
    for _ in range(n_pa):
        events.append(_make_process_access(
            host=host, ts=_jitter_ts(),
            src_image=parent_image, src_guid=parent_guid, src_pid=parent_pid,
            tgt_image=parent_image, tgt_guid=parent_guid, tgt_pid=parent_pid,
        ))

    # Create remote thread (8). Very rare benignly.
    n_crt = _poisson_count(rng, _CHAIN_MULTIPLIERS[8])
    for _ in range(n_crt):
        events.append(_make_create_remote_thread(
            host=host, ts=_jitter_ts(),
            src_image=parent_image, src_guid=parent_guid, src_pid=parent_pid,
            tgt_image=parent_image, tgt_guid=parent_guid, tgt_pid=parent_pid,
        ))

    # Registry create/delete (12).
    n_reg_key = _poisson_count(rng, _CHAIN_MULTIPLIERS[12])
    for i in range(n_reg_key):
        events.append(_make_registry_event(
            host=host, ts=_jitter_ts(), event_id=12,
            proc_image=parent_image, proc_guid=parent_guid, pid=parent_pid,
            target_object=f"HKLM\\Software\\Benign\\App-{parent_pid}\\Key-{i}",
            details=None,
        ))

    # Registry value set (13).
    n_reg_val = _poisson_count(rng, _CHAIN_MULTIPLIERS[13])
    for i in range(n_reg_val):
        events.append(_make_registry_event(
            host=host, ts=_jitter_ts(), event_id=13,
            proc_image=parent_image, proc_guid=parent_guid, pid=parent_pid,
            target_object=f"HKCU\\Software\\Benign\\App-{parent_pid}\\Value-{i}",
            details=f"DWORD (0x0000000{i % 10})",
        ))


# --- public API ------------------------------------------------------------


def generate(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Yield Sysmon-shaped event dicts. Windows hosts only.

    Deterministic given ``(topology, start, end, seed)``. Linux hosts
    are silently skipped (Sysmon doesn't exist there).

    Args:
        topology: enterprise topology produced by ``build_topology``.
        activity_model: pre-built activity model; we sample
            ``rate(host, "process_creation", ts)`` per hour.
        start: window start (inclusive).
        end: window end (exclusive).
        seed: deterministic seed for the per-host RNGs.

    Yields:
        Sysmon-shaped event dicts. Each dict carries ``_log: "sysmon"``
        and an ``event_id`` field. Process creates and image loads also
        carry ``_note`` flagging the synthetic hash.
    """
    windows_hosts = [h for h in topology.hosts if h.os == "windows"]
    log.info(
        "generating sysmon events: %d windows hosts (skipping %d linux) "
        "window=%s..%s seed=%d",
        len(windows_hosts),
        len(topology.hosts) - len(windows_hosts),
        start.isoformat(),
        end.isoformat(),
        seed,
    )

    for host in windows_hosts:
        host_events = _generate_for_host(host, activity_model, start, end, seed)
        for ev in host_events:
            yield ev
