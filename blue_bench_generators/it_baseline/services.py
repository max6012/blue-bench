"""Shared-service server-side log generator for the IT baseline corpus.

Emits server-vantage log records for four shared services:

* DNS server (bind / dnsmasq style) -- ``_log = "dns_server"``
* DHCP server (lease lifecycle)     -- ``_log = "dhcp_server"``
* SMB server (session lifecycle)    -- ``_log = "smb_server"``
* Proxy access (squid-like)         -- ``_log = "proxy_access"``

These are the SERVER-SIDE complement to the client-side Zeek/network
events that ``network_zeek`` produces. Every workstation that emits a
client-side ``dns.log`` query should be observable as a corresponding
DNS server query log on the dhcp-dns-server vantage; this module is the
generator for that server view.

Volumes are derived from the ``ActivityModel`` rate table:

* DNS:    per hour, expected events = sum of ``dns_query`` rates across
  all topology hosts (every host queries the DNS server).
* DHCP:   one RENEW per workstation per ~24h (lease half-life); plus a
  weekday-morning DISCOVER->OFFER->REQUEST->ACK boot quadruplet per
  workstation, concentrated in the 07:00-09:00 ramp.
* SMB:    per workstation+file-server pair, sessions opened at a rate
  proportional to the workstation's ``file_access`` rate. Each session
  emits ``session_setup`` -> 1+ ``tree_connect`` -> matching
  ``tree_disconnect`` -> ``session_logoff`` -- the events share a
  ``session_id`` and timestamp-order setup < tree_connect <
  tree_disconnect < logoff.
* Proxy:  per hour, expected events = sum of workstation ``http_request``
  rates (proxy forwards workstation outbound HTTP).

Hard rules
----------

* Vendor-neutral, benign-internet URL pool: every proxy URL host ends in
  ``.example.invalid``. No real domains.
* Deterministic: seeded RNG (``seed`` arg), same ``(topology, model,
  start, end, seed)`` always yields the same event sequence.
* MAC stability: same client hostname always maps to the same fake MAC
  across the window (the test enforces this) -- derived by hash, not by
  per-event RNG draw.
* Session-state ordering: per session_id, ``session_setup`` timestamp
  precedes ``tree_connect`` precedes ``tree_disconnect`` precedes
  ``session_logoff``.
* Skip silently when a service-endpoint role is absent (e.g. S tier has
  no proxy-server -> zero ``proxy_access`` events).
* Distinct ``_log`` strings per service type so downstream composer/
  parsers can route by single field lookup.
* Logging via the ``logging`` module; never ``print``.
"""

from __future__ import annotations

import hashlib
import logging
import random
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from blue_bench_generators.it_baseline.behavior import ActivityModel
from blue_bench_generators.it_baseline.topology import Host, Topology

log = logging.getLogger(__name__)


# --- constants -------------------------------------------------------------


# Benign vendor-neutral host pool for proxy access URLs. Every entry ends
# in ``.example.invalid`` so the proxy URL test ("no real-domain URLs")
# stays trivially true. Keep small and stable.
_PROXY_URL_HOSTS: tuple[str, ...] = (
    "updates.vendor-a.example.invalid",
    "cdn.vendor-b.example.invalid",
    "api.vendor-c.example.invalid",
    "docs.vendor-d.example.invalid",
    "portal.vendor-e.example.invalid",
    "mirror.vendor-f.example.invalid",
    "static.vendor-g.example.invalid",
    "files.vendor-h.example.invalid",
    "registry.vendor-i.example.invalid",
    "search.vendor-j.example.invalid",
)

_PROXY_PATHS: tuple[str, ...] = (
    "/",
    "/index.html",
    "/api/v1/status",
    "/assets/main.js",
    "/assets/main.css",
    "/static/logo.png",
    "/download/package.tgz",
    "/docs/getting-started",
    "/feed.rss",
    "/health",
)

_PROXY_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) corp-browser/1.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) corp-browser/1.1",
    "corp-updater/2.3 (Windows)",
    "curl/8.4.0",
)

# DNS query-type weights. Most queries are A; PTR for reverse lookups;
# SRV for AD; AAAA modest; TXT small.
_DNS_QUERY_TYPE_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("A", 70),
    ("AAAA", 12),
    ("PTR", 10),
    ("SRV", 6),
    ("TXT", 2),
)

# Most DNS responses succeed. Small NXDOMAIN tail, tiny SERVFAIL.
_DNS_RESPONSE_CODE_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("NOERROR", 92),
    ("NXDOMAIN", 7),
    ("SERVFAIL", 1),
)

# DNS names corp hosts resolve. Mix of internal (corp.example.invalid)
# and external benign (.example.invalid) names. Internal-heavy because
# enterprise DNS is dominated by AD lookups.
_DNS_QUERY_NAMES: tuple[str, ...] = (
    "dc-01.corp.example.invalid",
    "dc-02.corp.example.invalid",
    "ns-01.corp.example.invalid",
    "srv-files-01.corp.example.invalid",
    "srv-db-01.corp.example.invalid",
    "srv-web-01.corp.example.invalid",
    "srv-mail-01.corp.example.invalid",
    "proxy-01.corp.example.invalid",
    "updates.vendor-a.example.invalid",
    "api.vendor-c.example.invalid",
    "cdn.vendor-b.example.invalid",
)


_SMB_SHARES: tuple[str, ...] = (
    "shared",
    "depts",
    "homes",
    "software",
    "scratch",
)

# Lease duration: 24h. RENEW typically at ~50% lease (T1).
_DHCP_LEASE_SECONDS: int = 86400

# Fraction of file_access events that materialise as a SMB
# server-vantage session_setup. The rest are within-session activity
# (covered by the per-session tree_connect events).
_FILE_ACCESS_TO_SMB_SESSION_FRACTION: float = 0.02

# Tree-connects per session.
_SMB_TREE_CONNECTS_PER_SESSION_MIN: int = 1
_SMB_TREE_CONNECTS_PER_SESSION_MAX: int = 3

# Session duration in seconds (uniform random).
_SMB_SESSION_DURATION_MIN: int = 30
_SMB_SESSION_DURATION_MAX: int = 1800


# --- determinism helpers ---------------------------------------------------


def _stable_mac_for_hostname(hostname: str) -> str:
    """Return a deterministic, hostname-stable, locally-administered MAC.

    Same hostname always yields the same MAC across runs and across the
    time window. Uses SHA-256 over the hostname so we don't consume the
    per-event RNG (which would produce different MACs on different
    DHCP events for the same client).

    The first byte's low two bits are forced to ``10`` so the address
    is *locally administered* and *unicast* -- the standard convention
    for synthetic/test MACs.
    """
    digest = hashlib.sha256(hostname.encode("utf-8")).digest()
    raw = bytearray(digest[:6])
    raw[0] = (raw[0] & 0xFC) | 0x02  # locally-administered, unicast
    return ":".join(f"{b:02x}" for b in raw)


def _weighted_choice(rng: random.Random, weights: tuple[tuple[str, int], ...]) -> str:
    total = sum(w for _, w in weights)
    pick = rng.randint(1, total)
    cumulative = 0
    for value, weight in weights:
        cumulative += weight
        if pick <= cumulative:
            return value
    return weights[-1][0]


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _iter_hours(start: datetime, end: datetime) -> Iterator[datetime]:
    cursor = _hour_floor(start)
    if cursor < start:
        cursor = cursor + timedelta(hours=1)
    while cursor < end:
        yield cursor
        cursor = cursor + timedelta(hours=1)


def _expected_to_count(rng: random.Random, expected: float) -> int:
    """Convert a fractional expected-events-per-hour to an integer count.

    Floor + Bernoulli on the fractional part -- preserves the expected
    value in aggregate while giving small-rate hours an honest chance
    of zero events.
    """
    if expected <= 0.0:
        return 0
    whole = int(expected)
    frac = expected - whole
    if frac > 0.0 and rng.random() < frac:
        whole += 1
    return whole


def _hosts_by_role(topology: Topology, role: str) -> list[Host]:
    return [h for h in topology.hosts if h.role == role]


# --- DNS server log --------------------------------------------------------


def _emit_dns_server(
    topology: Topology,
    model: ActivityModel,
    start: datetime,
    end: datetime,
    rng: random.Random,
) -> Iterator[dict]:
    """Yield ``dns_server`` events.

    Volume per hour = sum of ``dns_query`` rate across all topology
    hosts. Each event picks a client host uniformly at random across
    the hosts that contribute to the hour's volume (rate-weighted).
    """
    dns_servers = _hosts_by_role(topology, "dhcp-dns-server")
    if not dns_servers:
        return
    hosts = list(topology.hosts)
    if not hosts:
        return

    for hour_start in _iter_hours(start, end):
        # Per-host dns_query rates this hour.
        per_host_rates = [
            (h, model.rate(h, "dns_query", hour_start)) for h in hosts
        ]
        total_rate = sum(r for _, r in per_host_rates)
        count = _expected_to_count(rng, total_rate)
        if count <= 0:
            continue
        # Build weighted client picker. If total_rate==0 (shouldn't
        # happen here because count>0 implies it was >0), fall back to
        # uniform.
        clients = [h for h, _ in per_host_rates]
        weights = [r for _, r in per_host_rates]
        for _ in range(count):
            offset = rng.random() * 3600.0
            ts = hour_start + timedelta(seconds=offset)
            if ts >= end:
                continue
            server = dns_servers[rng.randrange(len(dns_servers))]
            client = rng.choices(clients, weights=weights, k=1)[0]
            qtype = _weighted_choice(rng, _DNS_QUERY_TYPE_WEIGHTS)
            qname = _DNS_QUERY_NAMES[rng.randrange(len(_DNS_QUERY_NAMES))]
            rcode = _weighted_choice(rng, _DNS_RESPONSE_CODE_WEIGHTS)
            if rcode == "NOERROR" and qtype in ("A", "AAAA"):
                if qtype == "A":
                    answers = [
                        f"10.{rng.randint(10, 30)}.0.{rng.randint(10, 200)}"
                    ]
                else:
                    answers = [
                        "fd00::"
                        + ":".join(f"{rng.randint(0, 0xFFFF):x}" for _ in range(3))
                    ]
            else:
                answers = []
            yield {
                "_log": "dns_server",
                "timestamp": ts.isoformat(),
                "server_host": server.fqdn,
                "client_ip": client.ip,
                "client_port": rng.randint(1024, 65535),
                "query_name": qname,
                "query_type": qtype,
                "response_code": rcode,
                "answers": answers,
                "response_time_ms": rng.randint(1, 25),
            }


# --- DHCP server log -------------------------------------------------------


def _emit_dhcp_server(
    topology: Topology,
    model: ActivityModel,
    start: datetime,
    end: datetime,
    rng: random.Random,
) -> Iterator[dict]:
    """Yield ``dhcp_server`` events.

    Two streams composed:

    * One RENEW per workstation per ~24h window -- emitted at a stable
      per-workstation hour-of-day so the test
      ``test_dhcp_renew_volume_matches_workstation_count_per_day`` gets
      a reliable count. Volume is NOT rate-driven; it's per-host
      scheduled so the test (which compares ``count ≈ N_ws * days``)
      passes reliably.
    * One DISCOVER->OFFER->REQUEST->ACK quadruplet per workstation per
      weekday morning, concentrated 07:00-09:00 (workday boot).
    """
    dhcp_servers = _hosts_by_role(topology, "dhcp-dns-server")
    if not dhcp_servers:
        return
    workstations = [
        h for h in topology.hosts if h.role in ("workstation", "admin-workstation")
    ]
    if not workstations:
        return
    # Single DHCP server endpoint -- pick the first deterministically.
    server = dhcp_servers[0]

    # --- RENEW: per-workstation hour-of-day + minute-of-hour, every 24h ---
    for ws in workstations:
        mac = _stable_mac_for_hostname(ws.name)
        # Deterministic hour-of-day and minute-of-hour from hostname.
        digest = hashlib.sha256(ws.name.encode("utf-8")).digest()
        hour_of_day = digest[6] % 24
        minute_of_hour = digest[7] % 60
        second_of_minute = digest[8] % 60
        # Walk day-by-day across the window emitting one RENEW per day
        # at the deterministic time-of-day for this workstation.
        day_cursor = datetime(start.year, start.month, start.day)
        while day_cursor < end:
            renew_ts = day_cursor.replace(
                hour=hour_of_day,
                minute=minute_of_hour,
                second=second_of_minute,
                microsecond=0,
            )
            if start <= renew_ts < end:
                yield {
                    "_log": "dhcp_server",
                    "timestamp": renew_ts.isoformat(),
                    "server_host": server.fqdn,
                    "event_type": "RENEW",
                    "client_mac": mac,
                    "client_ip": ws.ip,
                    "client_hostname": ws.fqdn,
                    "lease_duration_seconds": _DHCP_LEASE_SECONDS,
                }
            day_cursor = day_cursor + timedelta(days=1)

    # --- Boot quadruplet: weekday mornings 07:00-09:00 ---------------------
    boot_event_order: tuple[str, ...] = ("DISCOVER", "OFFER", "REQUEST", "ACK")
    day_cursor = datetime(start.year, start.month, start.day)
    while day_cursor < end:
        if day_cursor.weekday() < 5:  # weekday only
            for ws in workstations:
                mac = _stable_mac_for_hostname(ws.name)
                # Stable per-(host, day) random offset within 07:00-09:00.
                seed_bytes = hashlib.sha256(
                    f"{ws.name}|{day_cursor.date().isoformat()}".encode("utf-8")
                ).digest()
                offset_minutes = int.from_bytes(seed_bytes[:2], "big") % 120  # 0..119
                base_ts = day_cursor.replace(hour=7, minute=0, second=0) + timedelta(
                    minutes=offset_minutes
                )
                for step_idx, event_type in enumerate(boot_event_order):
                    ts = base_ts + timedelta(seconds=step_idx)  # tight sequence
                    if start <= ts < end:
                        yield {
                            "_log": "dhcp_server",
                            "timestamp": ts.isoformat(),
                            "server_host": server.fqdn,
                            "event_type": event_type,
                            "client_mac": mac,
                            "client_ip": ws.ip,
                            "client_hostname": ws.fqdn,
                            "lease_duration_seconds": _DHCP_LEASE_SECONDS,
                        }
        day_cursor = day_cursor + timedelta(days=1)


# --- SMB server log --------------------------------------------------------


def _emit_smb_server(
    topology: Topology,
    model: ActivityModel,
    start: datetime,
    end: datetime,
    rng: random.Random,
) -> Iterator[dict]:
    """Yield ``smb_server`` events.

    For each workstation, sessions to each file-server are opened at a
    rate proportional to the workstation's ``file_access`` rate
    (a small fraction translates to a server-side session_setup).

    Each session is emitted as a four-state bundle sharing one
    ``session_id``:

        session_setup  @  t0
        tree_connect   @  t0 + small_delta             [1..N times]
        tree_disconnect@  t0 + small_delta + dwell
        session_logoff @  t_end (>= last tree_disconnect)

    All bundle events share the session_id and timestamps are strictly
    monotonic per-session.
    """
    file_servers = _hosts_by_role(topology, "file-server")
    if not file_servers:
        return
    workstations = [
        h for h in topology.hosts if h.role in ("workstation", "admin-workstation")
    ]
    if not workstations:
        return
    # Map workstation -> primary file-server (deterministic round-robin).
    # Each workstation talks to ONE file-server in this v1 model;
    # extending to fan-out is a future enhancement.
    ws_to_fs: dict[str, Host] = {
        ws.name: file_servers[idx % len(file_servers)]
        for idx, ws in enumerate(workstations)
    }
    # Map workstation -> stable username for SMB client (first user
    # whose primary_host == ws.name, else fallback).
    ws_to_user: dict[str, str] = {}
    for ws in workstations:
        match = next(
            (u for u in topology.users if u.primary_host == ws.name and u.role == "user"),
            None,
        )
        if match is None:
            match = next(
                (u for u in topology.users if u.primary_host == ws.name),
                None,
            )
        ws_to_user[ws.name] = match.username if match is not None else "anonymous"

    session_counter = 1

    for hour_start in _iter_hours(start, end):
        for ws in workstations:
            file_access_rate = model.rate(ws, "file_access", hour_start)
            expected_sessions = file_access_rate * _FILE_ACCESS_TO_SMB_SESSION_FRACTION
            count = _expected_to_count(rng, expected_sessions)
            for _ in range(count):
                fs = ws_to_fs[ws.name]
                user = ws_to_user[ws.name]
                # Session start uniformly distributed within hour.
                t0 = hour_start + timedelta(seconds=rng.random() * 3600.0)
                if t0 >= end:
                    continue
                duration = rng.randint(
                    _SMB_SESSION_DURATION_MIN, _SMB_SESSION_DURATION_MAX
                )
                n_trees = rng.randint(
                    _SMB_TREE_CONNECTS_PER_SESSION_MIN,
                    _SMB_TREE_CONNECTS_PER_SESSION_MAX,
                )
                session_id = session_counter
                session_counter += 1
                # session_setup
                setup_ts = t0
                yield {
                    "_log": "smb_server",
                    "timestamp": setup_ts.isoformat(),
                    "server_host": fs.fqdn,
                    "event_type": "session_setup",
                    "client_ip": ws.ip,
                    "client_user": f"CORP\\{user}",
                    "share_name": None,
                    "session_id": session_id,
                }
                # tree_connects and matching tree_disconnects. Hold the
                # tree-connect timestamps so the matching disconnects
                # land strictly after them but before logoff.
                last_disconnect_ts = setup_ts
                for tree_idx in range(n_trees):
                    share = _SMB_SHARES[rng.randrange(len(_SMB_SHARES))]
                    tc_ts = setup_ts + timedelta(seconds=1 + tree_idx)
                    if tc_ts >= end:
                        break
                    yield {
                        "_log": "smb_server",
                        "timestamp": tc_ts.isoformat(),
                        "server_host": fs.fqdn,
                        "event_type": "tree_connect",
                        "client_ip": ws.ip,
                        "client_user": f"CORP\\{user}",
                        "share_name": share,
                        "session_id": session_id,
                    }
                    td_ts = tc_ts + timedelta(
                        seconds=max(1, duration // max(1, n_trees))
                    )
                    if td_ts >= end:
                        break
                    yield {
                        "_log": "smb_server",
                        "timestamp": td_ts.isoformat(),
                        "server_host": fs.fqdn,
                        "event_type": "tree_disconnect",
                        "client_ip": ws.ip,
                        "client_user": f"CORP\\{user}",
                        "share_name": share,
                        "session_id": session_id,
                    }
                    if td_ts > last_disconnect_ts:
                        last_disconnect_ts = td_ts
                # session_logoff strictly after last disconnect.
                logoff_ts = last_disconnect_ts + timedelta(seconds=1)
                if logoff_ts < end:
                    yield {
                        "_log": "smb_server",
                        "timestamp": logoff_ts.isoformat(),
                        "server_host": fs.fqdn,
                        "event_type": "session_logoff",
                        "client_ip": ws.ip,
                        "client_user": f"CORP\\{user}",
                        "share_name": None,
                        "session_id": session_id,
                    }


# --- Proxy access log ------------------------------------------------------


def _emit_proxy_access(
    topology: Topology,
    model: ActivityModel,
    start: datetime,
    end: datetime,
    rng: random.Random,
) -> Iterator[dict]:
    """Yield ``proxy_access`` events.

    Volume per hour = sum of ``http_request`` rate across workstations
    (proxy forwards workstation outbound HTTP). URLs come from the
    benign vendor-neutral pool. ``CONNECT`` is used for HTTPS tunnels
    (the host:port form), ``GET``/``POST`` for plain HTTP-style entries.
    """
    proxy_servers = _hosts_by_role(topology, "proxy-server")
    if not proxy_servers:
        return
    workstations = [
        h for h in topology.hosts if h.role in ("workstation", "admin-workstation")
    ]
    if not workstations:
        return
    server = proxy_servers[0]
    # Map workstation -> stable username (mirrors SMB).
    ws_to_user: dict[str, str] = {}
    for ws in workstations:
        match = next(
            (u for u in topology.users if u.primary_host == ws.name and u.role == "user"),
            None,
        )
        ws_to_user[ws.name] = match.username if match is not None else "anonymous"

    method_weights: tuple[tuple[str, int], ...] = (
        ("GET", 60),
        ("CONNECT", 30),
        ("POST", 10),
    )
    response_code_weights: tuple[tuple[int, int], ...] = (
        (200, 70),
        (304, 12),
        (302, 8),
        (404, 5),
        (403, 3),
        (500, 2),
    )

    for hour_start in _iter_hours(start, end):
        per_ws_rates = [
            (ws, model.rate(ws, "http_request", hour_start)) for ws in workstations
        ]
        total_rate = sum(r for _, r in per_ws_rates)
        count = _expected_to_count(rng, total_rate)
        if count <= 0:
            continue
        clients = [ws for ws, _ in per_ws_rates]
        weights = [r for _, r in per_ws_rates]
        for _ in range(count):
            offset = rng.random() * 3600.0
            ts = hour_start + timedelta(seconds=offset)
            if ts >= end:
                continue
            ws = rng.choices(clients, weights=weights, k=1)[0]
            user = ws_to_user[ws.name]
            method = _weighted_choice(rng, method_weights)
            host = _PROXY_URL_HOSTS[rng.randrange(len(_PROXY_URL_HOSTS))]
            if method == "CONNECT":
                url = f"{host}:443"
            else:
                path = _PROXY_PATHS[rng.randrange(len(_PROXY_PATHS))]
                url = f"http://{host}{path}"
            # _weighted_choice operates on str values; do the int picker inline.
            total = sum(w for _, w in response_code_weights)
            pick = rng.randint(1, total)
            cumulative = 0
            response_code = response_code_weights[-1][0]
            for code, weight in response_code_weights:
                cumulative += weight
                if pick <= cumulative:
                    response_code = code
                    break
            response_bytes = (
                rng.randint(200, 50_000)
                if response_code in (200, 302, 304)
                else rng.randint(0, 2_000)
            )
            user_agent = _PROXY_USER_AGENTS[rng.randrange(len(_PROXY_USER_AGENTS))]
            yield {
                "_log": "proxy_access",
                "timestamp": ts.isoformat(),
                "server_host": server.fqdn,
                "client_ip": ws.ip,
                "client_user": user,
                "method": method,
                "url": url,
                "response_code": response_code,
                "response_bytes": response_bytes,
                "user_agent": user_agent,
            }


# --- public API ------------------------------------------------------------


def generate(
    topology: Topology,
    activity_model: ActivityModel,
    start: datetime,
    end: datetime,
    seed: int = 0,
) -> Iterable[dict]:
    """Yield server-side shared-service log dicts.

    Composes four streams (DNS / DHCP / SMB / proxy). Each stream
    silently skips when its endpoint role is absent from the topology
    (e.g. S tier has no proxy-server -> no ``proxy_access`` events).

    Args:
        topology: built topology (provides hosts, users, services).
        activity_model: rate model the volumes are derived from.
        start: window start (inclusive).
        end: window end (exclusive).
        seed: RNG seed. Same ``(topology, model, start, end, seed)``
            always yields the same event sequence in the same order.

    Yields:
        ``dict`` records. Each record carries a ``_log`` field set to
        one of ``"dns_server"``, ``"dhcp_server"``, ``"smb_server"``,
        ``"proxy_access"``. No ordering guarantee across streams beyond
        per-session-id monotonicity inside the SMB stream.
    """
    if end <= start:
        log.info(
            "services.generate: empty window start=%s end=%s -- no events",
            start.isoformat(),
            end.isoformat(),
        )
        return
    # Per-stream RNGs derived from the user seed -- keeps each stream's
    # randomness independent so adding events to one stream doesn't
    # shift the others. Constants are arbitrary stable odd offsets.
    rng_dns = random.Random(seed * 2654435761 + 1)
    rng_dhcp = random.Random(seed * 2654435761 + 2)
    rng_smb = random.Random(seed * 2654435761 + 3)
    rng_proxy = random.Random(seed * 2654435761 + 4)

    log.info(
        "services.generate: tier=%s start=%s end=%s seed=%d",
        topology.tier,
        start.isoformat(),
        end.isoformat(),
        seed,
    )

    yield from _emit_dns_server(topology, activity_model, start, end, rng_dns)
    yield from _emit_dhcp_server(topology, activity_model, start, end, rng_dhcp)
    yield from _emit_smb_server(topology, activity_model, start, end, rng_smb)
    yield from _emit_proxy_access(topology, activity_model, start, end, rng_proxy)
