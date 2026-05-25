"""AD identity event generator for the IT baseline corpus.

Emits Windows-style identity events from the perspective of domain
controllers: Kerberos TGT requests (4768), TGS service-ticket requests
(4769), pre-authentication failures (4771), credential validation
(4776 / NTLM), and Directory Service LDAP query events.

Design contract
---------------

* Events are emitted ONLY by ``domain-controller`` hosts -- the DC is
  the central authentication authority, so every Kerberos ticket and
  every NTLM credential validation lands on a DC.
* Skips silently when the topology has no DC.
* Volume is driven by the **per-user** logon-attempt rate (sampled at
  the user's primary host -- a workstation, admin-WS, or server) so
  the DC's 4768 volume equals the aggregated workstation-side logon
  volume. The DC's own ``logon_attempt`` baseline rate is NOT used as
  a count source; it's already an aggregate of incoming requests.
* TGT-before-TGS ordering per user: for each user-hour we emit all
  4768 events strictly before all 4769 events (and 4771 between them
  ordered by minute offset). This guarantees the
  ``first 4768 ts <= first 4769 ts`` invariant per user across the
  whole window.
* TGS ServiceNames are SPNs built from real ``topology.services``
  endpoints (e.g. ``cifs/srv-files-01.corp.example.invalid``). The map
  from service.name to SPN class is centralised in ``_SPN_CLASS``.
* LDAP queries are gated to business hours for regular (workstation)
  users; admin and service users may run LDAP queries off-hours
  (scheduled scripts, service-account lookups).

Determinism
-----------

Pure deterministic emission from ``(topology, activity_model, start,
end, seed)``. A single ``random.Random(seed)`` is used for all
probabilistic draws (Bernoulli fractional remainders, status-code
selection, LDAP query shape). The hour-by-hour outer loop and the
sorted user inner loop keep ordering stable across runs.
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from blue_bench_generators.it_baseline.behavior import ActivityModel
from blue_bench_generators.it_baseline.topology import (
    Host,
    Service,
    Topology,
    User,
)

log = logging.getLogger(__name__)


# --- event-id constants ---------------------------------------------------

_EVENT_TGT_REQUEST = 4768  # Kerberos TGT request
_EVENT_TGS_REQUEST = 4769  # Kerberos service ticket (TGS)
_EVENT_PREAUTH_FAIL = 4771  # Kerberos pre-auth failure
_EVENT_CREDENTIAL_VALIDATION = 4776  # NTLM credential validation
_EVENT_LDAP_QUERY = 1644  # Directory Service expensive-search style id

# Kerberos status codes (Windows Security log convention).
# 0x0  = KDC_ERR_NONE / success
# 0x6  = KDC_ERR_C_PRINCIPAL_UNKNOWN (bad username)
# 0x12 = KDC_ERR_CLIENT_REVOKED (account disabled / locked)
# 0x18 = KDC_ERR_PREAUTH_FAILED (bad password)
# 0x25 = KRB_AP_ERR_SKEW (clock skew, rare benign)
_SUCCESS_STATUS = "0x0"
_FAILURE_STATUSES: tuple[tuple[str, float], ...] = (
    ("0x18", 0.70),  # bad password -- the bulk of benign failures
    ("0x6", 0.20),   # typo'd username
    ("0x12", 0.07),  # disabled / locked
    ("0x25", 0.03),  # clock skew (rare)
)
_KNOWN_STATUSES: frozenset[str] = frozenset(
    {_SUCCESS_STATUS} | {s for s, _ in _FAILURE_STATUSES}
)

# NTLM-side status codes (subset).
_NTLM_SUCCESS = "0x0"
_NTLM_FAILURE_STATUSES: tuple[tuple[str, float], ...] = (
    ("0xC000006A", 0.70),  # STATUS_WRONG_PASSWORD
    ("0xC0000064", 0.20),  # STATUS_NO_SUCH_USER
    ("0xC0000234", 0.07),  # STATUS_ACCOUNT_LOCKED_OUT
    ("0xC0000071", 0.03),  # STATUS_PASSWORD_EXPIRED
)
_KNOWN_NTLM_STATUSES: frozenset[str] = frozenset(
    {_NTLM_SUCCESS} | {s for s, _ in _NTLM_FAILURE_STATUSES}
)

# Service.name -> SPN class. Only services whose name appears here are
# eligible TGS targets. ``ad-dc`` maps to ``ldap`` (the LDAP SPN on a
# DC); ``smb`` maps to ``cifs`` (the canonical SMB SPN class).
_SPN_CLASS: dict[str, str] = {
    "smb": "cifs",
    "ad-dc": "ldap",
    "dns": "DNS",
    "proxy": "HTTP",
    "siem": "HOST",
    "dhcp": "HOST",
}

# Approximate ticket-encryption-type values (Windows log convention).
# 0x12 = AES256_CTS_HMAC_SHA1_96
# 0x11 = AES128_CTS_HMAC_SHA1_96
# 0x17 = RC4_HMAC (legacy, infrequent)
_TICKET_ENC_TYPES: tuple[tuple[str, float], ...] = (
    ("0x12", 0.80),
    ("0x11", 0.18),
    ("0x17", 0.02),
)

# PreAuthType values seen on real DCs.
# 2  = encrypted-timestamp (modern)
# 0  = no pre-auth (rare)
# 11 = PA-ETYPE-INFO
_PREAUTH_TYPES: tuple[tuple[int, float], ...] = (
    (2, 0.93),
    (11, 0.05),
    (0, 0.02),
)

# Default Kerberos client port range (ephemeral).
_EPHEMERAL_PORT_LOW = 49152
_EPHEMERAL_PORT_HIGH = 65535

# LDAP filter shapes -- a small canned set of benign queries.
_LDAP_SEARCH_FILTERS: tuple[str, ...] = (
    "(objectClass=user)",
    "(&(objectCategory=person)(objectClass=user))",
    "(memberOf=CN=Engineering,OU=Workstations,DC=corp,DC=example,DC=invalid)",
    "(sAMAccountName=*)",
    "(objectClass=computer)",
)


# --- helpers --------------------------------------------------------------


def _domain_netbios(topology: Topology) -> str:
    """Return the NetBIOS-style domain label (first label of the FQDN, upper)."""
    return topology.forest.root_domain.split(".", 1)[0].upper()


def _domain_dn(topology: Topology) -> str:
    """Return the LDAP DN form of the root domain (DC=corp,DC=example,...)."""
    return ",".join(
        f"DC={label}" for label in topology.forest.root_domain.split(".")
    )


def _weighted_choice(
    rng: random.Random, choices: tuple[tuple[object, float], ...]
) -> object:
    """Pick one value from a (value, weight) tuple list using ``rng``."""
    r = rng.random()
    cumulative = 0.0
    for value, weight in choices:
        cumulative += weight
        if r < cumulative:
            return value
    return choices[-1][0]


def _count_from_rate(rate_per_hour: float, rng: random.Random) -> int:
    """Convert an events/hour rate into an integer count for one hour.

    ``floor(rate) + Bernoulli(frac)`` -- deterministic with the rng,
    avoids the per-call cost of a true Poisson draw, and preserves the
    expected mean exactly.
    """
    if rate_per_hour <= 0.0:
        return 0
    whole = int(rate_per_hour)
    frac = rate_per_hour - whole
    if frac > 0.0 and rng.random() < frac:
        whole += 1
    return whole


def _spaced_timestamps(
    hour_start: datetime,
    count: int,
    slot_start: int,
    slot_end: int,
    rng: random.Random,
) -> list[datetime]:
    """Return ``count`` timestamps inside ``[slot_start, slot_end)`` of the hour.

    ``slot_start`` and ``slot_end`` are integer second-offsets into the
    hour, with ``0 <= slot_start < slot_end <= 3600``. Different event
    classes use disjoint, ordered slots so that all events of class A
    are guaranteed to precede all events of class B in the same hour
    when A's slot ends at or before B's slot starts. This is what
    enforces TGT-before-TGS at the per-user level.

    Within the slot, ``rng.sample`` selects distinct second-offsets and
    sorts them. Falls back to consecutive seconds when the slot is too
    tight to sample.
    """
    if count <= 0:
        return []
    if slot_end <= slot_start:
        raise ValueError(
            f"empty slot [{slot_start}, {slot_end}) in _spaced_timestamps"
        )
    width = slot_end - slot_start
    if width <= count:
        # Tightly packed -- consecutive seconds, clipped to the slot.
        return [
            hour_start + timedelta(seconds=slot_start + i)
            for i in range(min(count, width))
        ]
    seconds = sorted(rng.sample(range(width), count))
    return [
        hour_start + timedelta(seconds=slot_start + s) for s in seconds
    ]


# Time slots inside one hour for each event class, in seconds. Disjoint
# + ordered so that 4768 < 4771 < 4769 < 1644 < 4776 holds strictly
# within each user-hour. Slot widths roughly track expected volume.
_SLOT_TGT = (0, 900)         # 0-15 min: TGT requests
_SLOT_PREAUTH = (900, 1200)  # 15-20 min: pre-auth failures
_SLOT_TGS = (1200, 3000)     # 20-50 min: TGS service-ticket requests
_SLOT_LDAP = (3000, 3300)    # 50-55 min: LDAP queries
_SLOT_NTLM = (3300, 3600)    # 55-60 min: NTLM credential validations


# --- public API -----------------------------------------------------------


def generate(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Yield AD identity-event dicts emitted by domain controllers.

    Args:
        topology: enterprise topology (see ``it_baseline.topology``).
        activity_model: activity model bound to the same topology.
            ``rate(user.primary_host, "logon_attempt", ts)`` drives
            4768 volume; ``logon_failure`` drives 4771; LDAP volume is
            a fraction of TGS volume.
        start: inclusive window start (UTC-naive ok).
        end: exclusive window end. ``end <= start`` yields no events.
        seed: deterministic RNG seed.

    Yields:
        ``dict`` per identity event. Every dict has ``_log == "winevtx"``,
        an integer ``event_id``, a ``channel`` field, and ``host`` set
        to a DC FQDN. Skips silently if topology has no DC.
    """
    if end <= start:
        return
    dcs = tuple(h for h in topology.hosts if h.role == "domain-controller")
    if not dcs:
        log.info("identity.generate: no domain controllers in topology -- skipping")
        return
    yield from _emit(topology, activity_model, start, end, seed, dcs)


def _emit(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int,
    dcs: tuple[Host, ...],
) -> Iterator[dict]:
    rng = random.Random(seed)
    host_ip: dict[str, str] = {h.name: h.ip for h in topology.hosts}
    host_fqdn: dict[str, str] = {h.name: h.fqdn for h in topology.hosts}
    domain_netbios = _domain_netbios(topology)
    domain_dn = _domain_dn(topology)

    # Sort users for stable iteration order.
    users = tuple(sorted(topology.users, key=lambda u: u.username))
    # Service lookup -- include only services whose name has an SPN class.
    spn_eligible = tuple(
        s for s in topology.services if s.name in _SPN_CLASS
    )

    # Stable DC pick per user -- round-robin so multi-DC topologies
    # distribute load deterministically.
    user_dc: dict[str, Host] = {}
    for idx, u in enumerate(users):
        user_dc[u.username] = dcs[idx % len(dcs)]

    cursor = start
    step = timedelta(hours=1)
    while cursor < end:
        # Per-hour, per-user emission. Inside each user-hour we order
        # event classes by class-offset so TGT < pre-auth-fail < TGS
        # < LDAP < NTLM holds strictly.
        for user in users:
            primary = _host_by_name(topology, user.primary_host)
            if primary is None:
                continue
            dc = user_dc[user.username]
            client_ip = host_ip.get(primary.name)
            if client_ip is None:
                continue

            # Volume from the user's primary host (the workstation).
            attempt_rate = activity_model.rate(
                primary, "logon_attempt", cursor
            )
            failure_rate = activity_model.rate(
                primary, "logon_failure", cursor
            )
            tgt_count = _count_from_rate(attempt_rate, rng)
            preauth_fail_count = _count_from_rate(failure_rate, rng)
            # One TGS per ~2 TGTs (services accessed per logon session),
            # rounded probabilistically. Capped by SPN-eligible services.
            tgs_rate = attempt_rate * 1.5
            tgs_count = _count_from_rate(tgs_rate, rng)
            # LDAP volume: workstation users only during business hours
            # (08-18 weekday); admins/services anytime. Modest fraction
            # of TGS volume.
            ldap_count = _ldap_count_for_user(
                user, cursor, tgs_rate, rng
            )
            # NTLM credential validation: a small fraction of logons
            # (legacy clients, IIS, etc.). 10% of attempt rate.
            ntlm_count = _count_from_rate(attempt_rate * 0.1, rng)

            # Disjoint, ordered slots inside the hour guarantee:
            #   4768 (TGT) < 4771 (pre-auth fail) < 4769 (TGS)
            #     < 1644 (LDAP) < 4776 (NTLM)
            # for every (user, hour) tuple, regardless of count.
            for ts in _spaced_timestamps(
                cursor, tgt_count, *_SLOT_TGT, rng=rng
            ):
                yield _make_4768(
                    user=user,
                    dc=dc,
                    client_ip=client_ip,
                    ts=ts,
                    domain_netbios=domain_netbios,
                    rng=rng,
                    success=True,
                )
            for ts in _spaced_timestamps(
                cursor, preauth_fail_count, *_SLOT_PREAUTH, rng=rng
            ):
                yield _make_4771(
                    user=user,
                    dc=dc,
                    client_ip=client_ip,
                    ts=ts,
                    domain_netbios=domain_netbios,
                    rng=rng,
                )
            for ts in _spaced_timestamps(
                cursor, tgs_count, *_SLOT_TGS, rng=rng
            ):
                yield _make_4769(
                    user=user,
                    dc=dc,
                    client_ip=client_ip,
                    ts=ts,
                    domain_netbios=domain_netbios,
                    services=spn_eligible,
                    host_fqdn=host_fqdn,
                    rng=rng,
                )
            for ts in _spaced_timestamps(
                cursor, ldap_count, *_SLOT_LDAP, rng=rng
            ):
                yield _make_ldap(
                    user=user,
                    dc=dc,
                    client_ip=client_ip,
                    ts=ts,
                    domain_dn=domain_dn,
                    rng=rng,
                )
            for ts in _spaced_timestamps(
                cursor, ntlm_count, *_SLOT_NTLM, rng=rng
            ):
                yield _make_4776(
                    user=user,
                    dc=dc,
                    client_ip=client_ip,
                    primary_host=primary,
                    ts=ts,
                    rng=rng,
                )
        cursor = cursor + step


def _host_by_name(topology: Topology, name: str) -> Host | None:
    for h in topology.hosts:
        if h.name == name:
            return h
    return None


def _ldap_count_for_user(
    user: User,
    ts: datetime,
    tgs_rate: float,
    rng: random.Random,
) -> int:
    """LDAP query volume for one user in one hour.

    Workstation (regular) users only query LDAP during business hours
    (Mon-Fri 08:00-18:00). Admin and service users may query LDAP
    anytime (scheduled scripts, service-account directory walks).
    """
    is_business_hours = ts.weekday() < 5 and 8 <= ts.hour < 18
    if user.role == "user" and not is_business_hours:
        return 0
    # Roughly 30% of TGS rate -- LDAP is heavier than tickets but
    # we don't want to dwarf the rest.
    return _count_from_rate(tgs_rate * 0.3, rng)


# --- event builders -------------------------------------------------------


def _select_failure_status(
    rng: random.Random,
    table: tuple[tuple[str, float], ...],
) -> str:
    return str(_weighted_choice(rng, table))  # type: ignore[arg-type]


def _make_4768(
    *,
    user: User,
    dc: Host,
    client_ip: str,
    ts: datetime,
    domain_netbios: str,
    rng: random.Random,
    success: bool,
) -> dict:
    status = (
        _SUCCESS_STATUS
        if success
        else _select_failure_status(rng, _FAILURE_STATUSES)
    )
    enc = str(_weighted_choice(rng, _TICKET_ENC_TYPES))
    preauth = int(_weighted_choice(rng, _PREAUTH_TYPES))  # type: ignore[arg-type]
    port = rng.randint(_EPHEMERAL_PORT_LOW, _EPHEMERAL_PORT_HIGH)
    return {
        "_log": "winevtx",
        "event_id": _EVENT_TGT_REQUEST,
        "channel": "Security",
        "host": dc.fqdn,
        "timestamp": ts.isoformat(),
        "TargetUserName": user.username,
        "TargetDomainName": domain_netbios,
        "ServiceName": f"krbtgt/{domain_netbios}",
        "TicketOptions": "0x40810010",
        "Status": status,
        "TicketEncryptionType": enc,
        "PreAuthType": preauth,
        "IpAddress": client_ip,
        "IpPort": port,
        # Certificate fields blank for password-based pre-auth (the
        # overwhelming benign case). Reserved for future smartcard
        # logon modeling.
        "CertIssuerName": "",
        "CertSerialNumber": "",
        "CertThumbprint": "",
    }


def _make_4769(
    *,
    user: User,
    dc: Host,
    client_ip: str,
    ts: datetime,
    domain_netbios: str,
    services: tuple[Service, ...],
    host_fqdn: dict[str, str],
    rng: random.Random,
) -> dict:
    # Pick a service the user touches. Service users with role "service"
    # are biased toward their own service endpoint via primary_host;
    # regular and admin users pick from any SPN-eligible service.
    service = services[rng.randrange(len(services))]
    endpoint = service.endpoint_hosts[
        rng.randrange(len(service.endpoint_hosts))
    ]
    endpoint_fqdn = host_fqdn.get(endpoint, endpoint)
    spn_class = _SPN_CLASS[service.name]
    enc = str(_weighted_choice(rng, _TICKET_ENC_TYPES))
    port = rng.randint(_EPHEMERAL_PORT_LOW, _EPHEMERAL_PORT_HIGH)
    return {
        "_log": "winevtx",
        "event_id": _EVENT_TGS_REQUEST,
        "channel": "Security",
        "host": dc.fqdn,
        "timestamp": ts.isoformat(),
        "TargetUserName": user.username,
        "TargetDomainName": domain_netbios,
        "ServiceName": f"{spn_class}/{endpoint_fqdn}",
        "ServiceSid": f"S-1-5-21-{abs(hash(endpoint)) % (10**9):09d}-1104",
        "TicketOptions": "0x40810000",
        "TicketEncryptionType": enc,
        "IpAddress": client_ip,
        "IpPort": port,
        "Status": _SUCCESS_STATUS,
    }


def _make_4771(
    *,
    user: User,
    dc: Host,
    client_ip: str,
    ts: datetime,
    domain_netbios: str,
    rng: random.Random,
) -> dict:
    status = _select_failure_status(rng, _FAILURE_STATUSES)
    preauth = int(_weighted_choice(rng, _PREAUTH_TYPES))  # type: ignore[arg-type]
    port = rng.randint(_EPHEMERAL_PORT_LOW, _EPHEMERAL_PORT_HIGH)
    return {
        "_log": "winevtx",
        "event_id": _EVENT_PREAUTH_FAIL,
        "channel": "Security",
        "host": dc.fqdn,
        "timestamp": ts.isoformat(),
        "TargetUserName": user.username,
        "TargetSid": f"S-1-5-21-{abs(hash(user.username)) % (10**9):09d}-1108",
        "ServiceName": f"krbtgt/{domain_netbios}",
        "TicketOptions": "0x40810010",
        "Status": status,
        "PreAuthType": preauth,
        "IpAddress": client_ip,
        "IpPort": port,
    }


def _make_4776(
    *,
    user: User,
    dc: Host,
    client_ip: str,
    primary_host: Host,
    ts: datetime,
    rng: random.Random,
) -> dict:
    # NTLM credential validation. Use a small failure rate consistent
    # with overall logon-failure ratios.
    is_failure = rng.random() < 0.05
    status = (
        _select_failure_status(rng, _NTLM_FAILURE_STATUSES)
        if is_failure
        else _NTLM_SUCCESS
    )
    return {
        "_log": "winevtx",
        "event_id": _EVENT_CREDENTIAL_VALIDATION,
        "channel": "Security",
        "host": dc.fqdn,
        "timestamp": ts.isoformat(),
        "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "TargetUserName": user.username,
        "WorkstationName": primary_host.name.upper(),
        "Status": status,
        # Carry the originating IP for parity with Kerberos events so
        # downstream correlation has a uniform field surface.
        "IpAddress": client_ip,
    }


def _make_ldap(
    *,
    user: User,
    dc: Host,
    client_ip: str,
    ts: datetime,
    domain_dn: str,
    rng: random.Random,
) -> dict:
    search_filter = _LDAP_SEARCH_FILTERS[
        rng.randrange(len(_LDAP_SEARCH_FILTERS))
    ]
    items_returned = rng.randint(0, 50)
    return {
        "_log": "winevtx",
        "event_id": _EVENT_LDAP_QUERY,
        "channel": "Directory Service",
        "host": dc.fqdn,
        "timestamp": ts.isoformat(),
        "BindUserName": user.username,
        "ClientIp": client_ip,
        "SearchBase": domain_dn,
        "SearchFilter": search_filter,
        "ResultCode": 0,
        "ItemsReturned": items_returned,
    }
