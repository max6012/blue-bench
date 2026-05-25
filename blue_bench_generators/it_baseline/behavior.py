"""Behavioral / time-of-day activity model for the IT baseline corpus.

This is the second contract under ``t-it-base``. It sits between
``topology`` (host/user/service shapes) and the seven per-source
telemetry generators (Zeek noise, Suricata noise, Sysmon, EVTX, Linux
audit, AD identity, shared services).

This module does NOT emit events. It returns **expected event-rates per
host per event-class per hour** that the per-source generators will use
to drive their own emission timing. Splitting rate-modeling from
event-emission keeps the per-source generators simple and lets all
seven cross-coordinate against the same activity heartbeat.

Composition of ``rate(host, event_class, timestamp)``::

    baseline_rate(host.role, event_class)         # per-(role, class) table
        * time_of_day_multiplier(timestamp)       # rule-based piecewise
        * after_hours_admin_overlay(host, ts)     # admin-WS lift 22:00-02:00
        * anomaly_overlay(ts, anomaly_windows)    # holiday / outage / campaign

All factors are deterministic. The ``seed`` field is reserved for
future stochastic overlays (jitter, weighted random per-user activity);
v1 rates are a pure function of (topology, time, anomaly windows).

Baseline-rate table (events/hour at multiplier 1.0)
---------------------------------------------------

The numbers below are the v1 choice. They are illustrative but the
relative orderings ARE load-bearing for the tests and for downstream
generator realism:

* DC logon_attempt >> workstation logon_attempt (every workstation
  hits the DC for ticket grants).
* Admin-workstation > workstation across process_creation,
  logon_attempt (admin scripts + tooling).
* file-server file_access >> workstation file_access (SMB-heavy host).
* Servers run constantly (overnight multiplier still floors at ~0.1
  via time-of-day rules); workstations go ~quiet overnight.
* SIEM produces a small heartbeat across all classes; consumes nothing.

::

    event_class       | wkst | adm  | file | DC   | web/mail | service
    ------------------|------|------|------|------|----------|--------
    logon_attempt     |    5 |   15 |   30 |  200 |       50 |     10
    logon_failure     |  0.1 |  0.3 |  0.5 |    3 |        1 |   0.05
    process_creation  |   40 |  120 |   30 |   30 |       80 |     50
    network_connection|  150 |  300 |  200 |  500 |      400 |    100
    dns_query         |   80 |  150 |   50 |  100 |      200 |     30
    http_request      |   60 |  100 |    5 |    5 |      400 |      5
    file_access       |   30 |   50 | 2000 |   50 |      100 |    100
    service_event     |  0.5 |    2 |    2 |    5 |        3 |     10

Vendor-neutral terminology only. No scenario vocabulary. Logging via
the ``logging`` module; no print-for-control-flow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from blue_bench_generators.it_baseline.topology import Host, Topology

log = logging.getLogger(__name__)


# --- event-class taxonomy --------------------------------------------------


EventClass = Literal[
    "logon_attempt",
    "logon_failure",
    "process_creation",
    "network_connection",
    "dns_query",
    "http_request",
    "file_access",
    "service_event",
]


EVENT_CLASSES: tuple[str, ...] = (
    "logon_attempt",
    "logon_failure",
    "process_creation",
    "network_connection",
    "dns_query",
    "http_request",
    "file_access",
    "service_event",
)


# --- role buckets for baseline-rate lookup --------------------------------
#
# 11 host roles collapse onto 6 baseline-rate buckets. The collapse keeps
# the table small and the relative orderings explicit; per-class quirks
# (e.g. proxy-server is HTTP-heavy) layer on via _ROLE_CLASS_OVERRIDES.

_ROLE_BUCKET: dict[str, str] = {
    "workstation": "workstation",
    "admin-workstation": "admin-workstation",
    "file-server": "file-server",
    "database-server": "file-server",  # DB lives in the file-server bucket
    "domain-controller": "domain-controller",
    "web-server": "web-mail",
    "mail-server": "web-mail",
    "proxy-server": "web-mail",  # also HTTP-heavy, gets web-mail bucket
    "dhcp-dns-server": "service-host",
    "siem-server": "service-host",
    "jump-host": "service-host",
}


# Baseline rates: bucket -> event_class -> events/hour at multiplier 1.0.
_BASELINE_RATES: dict[str, dict[str, float]] = {
    "workstation": {
        "logon_attempt": 5.0,
        "logon_failure": 0.1,
        "process_creation": 40.0,
        "network_connection": 150.0,
        "dns_query": 80.0,
        "http_request": 60.0,
        "file_access": 30.0,
        "service_event": 0.5,
    },
    "admin-workstation": {
        "logon_attempt": 15.0,
        "logon_failure": 0.3,
        "process_creation": 120.0,
        "network_connection": 300.0,
        "dns_query": 150.0,
        "http_request": 100.0,
        "file_access": 50.0,
        "service_event": 2.0,
    },
    "file-server": {
        "logon_attempt": 30.0,
        "logon_failure": 0.5,
        "process_creation": 30.0,
        "network_connection": 200.0,
        "dns_query": 50.0,
        "http_request": 5.0,
        "file_access": 2000.0,
        "service_event": 2.0,
    },
    "domain-controller": {
        "logon_attempt": 200.0,
        "logon_failure": 3.0,
        "process_creation": 30.0,
        "network_connection": 500.0,
        "dns_query": 100.0,
        "http_request": 5.0,
        "file_access": 50.0,
        "service_event": 5.0,
    },
    "web-mail": {
        "logon_attempt": 50.0,
        "logon_failure": 1.0,
        "process_creation": 80.0,
        "network_connection": 400.0,
        "dns_query": 200.0,
        "http_request": 400.0,
        "file_access": 100.0,
        "service_event": 3.0,
    },
    "service-host": {
        "logon_attempt": 10.0,
        "logon_failure": 0.05,
        "process_creation": 50.0,
        "network_connection": 100.0,
        "dns_query": 30.0,
        "http_request": 5.0,
        "file_access": 100.0,
        "service_event": 10.0,
    },
}


# Per-(specific-role, event_class) overrides. Use sparingly -- these
# carve out the spots where a role inside a bucket diverges enough to
# matter. Currently:
#   * siem-server: small constant heartbeat, NOT a service-host floor.
_ROLE_CLASS_OVERRIDES: dict[tuple[str, str], float] = {
    # SIEM consumes lots of inputs but emits a small constant heartbeat
    # of its own logs. Down-rate everything compared to the service-host
    # bucket so the SIEM doesn't dominate its own telemetry.
    ("siem-server", "logon_attempt"): 3.0,
    ("siem-server", "logon_failure"): 0.02,
    ("siem-server", "process_creation"): 10.0,
    ("siem-server", "network_connection"): 80.0,
    ("siem-server", "dns_query"): 20.0,
    ("siem-server", "http_request"): 2.0,
    ("siem-server", "file_access"): 30.0,
    ("siem-server", "service_event"): 5.0,
    # Proxy-server diverges sharply from web/mail on http_request: it
    # forwards ALL workstation outbound HTTP and is the heaviest http
    # host in the corpus by a wide margin.
    ("proxy-server", "http_request"): 2000.0,
    ("proxy-server", "dns_query"): 500.0,
}


# Service-account-host roles whose load is constant overnight. The
# time-of-day taper applies only weakly to these; see
# ``_is_constant_overnight_role``.
_CONSTANT_OVERNIGHT_ROLES: frozenset[str] = frozenset(
    {
        "domain-controller",
        "dhcp-dns-server",
        "siem-server",
        "file-server",
        "database-server",
        "web-server",
        "mail-server",
        "proxy-server",
        "jump-host",
    }
)


def _is_constant_overnight_role(role: str) -> bool:
    """Servers run constantly; workstations go quiet."""
    return role in _CONSTANT_OVERNIGHT_ROLES


# --- time-of-day rules -----------------------------------------------------
#
# A rule is (day_predicate, hour_range, multiplier). The first rule whose
# predicate + hour-range matches wins. Order matters; rules are scanned
# top-to-bottom. Day predicate is a callable on weekday (Mon=0..Sun=6).
# Hour range is a half-open [start, end) on hour_of_day with the special
# convention that end < start means "wraps through midnight" (e.g.
# 22..02 covers 22:00-23:59 + 00:00-01:59).


@dataclass(frozen=True)
class TimeRule:
    """One piecewise time-of-day rule.

    Attributes:
        name: human label, for logging / debugging only.
        weekday_predicate_name: ``"weekday"`` | ``"weekend"`` | ``"any"``.
            Stored as a string so the dataclass stays frozen-hashable
            (callables aren't hashable).
        start_hour: inclusive start, 0..23.
        end_hour: exclusive end, 0..24 (24 == midnight wrap-stop).
            If ``end_hour <= start_hour`` the range wraps midnight.
        multiplier: scalar in [0.0, 2.0].
    """

    name: str
    weekday_predicate_name: Literal["weekday", "weekend", "any"]
    start_hour: int
    end_hour: int
    multiplier: float


def _weekday_matches(predicate_name: str, weekday: int) -> bool:
    if predicate_name == "any":
        return True
    if predicate_name == "weekday":
        return weekday < 5  # Mon-Fri
    if predicate_name == "weekend":
        return weekday >= 5
    raise ValueError(f"unknown weekday predicate {predicate_name!r}")


def _hour_in_range(start: int, end: int, hour: int) -> bool:
    """[start, end) with midnight-wrap when end <= start."""
    if end > start:
        return start <= hour < end
    # Wraps: e.g. start=22, end=2 -> 22,23,0,1
    return hour >= start or hour < end


# Rule list scanned in order. First match wins. The list is data, not
# hard-coded if/elif, so adding new windows (holidays, late-night-cron)
# is a one-line change.
_TIME_RULES: tuple[TimeRule, ...] = (
    # Weekday workday shape.
    TimeRule("weekday-early-morning", "weekday", 0, 6, 0.1),
    TimeRule("weekday-ramp-06-09", "weekday", 6, 9, 0.5),
    TimeRule("weekday-morning-peak", "weekday", 9, 12, 1.0),
    TimeRule("weekday-lunch-dip", "weekday", 12, 14, 0.5),
    TimeRule("weekday-afternoon-peak", "weekday", 14, 17, 1.0),
    TimeRule("weekday-evening-taper", "weekday", 17, 19, 0.6),
    TimeRule("weekday-late-evening", "weekday", 19, 22, 0.2),
    TimeRule("weekday-overnight", "weekday", 22, 24, 0.15),
    # Weekend shape: flat low. Small admin spike 02-04 layered later
    # via the after-hours admin overlay (works for admin-WS), and the
    # constant-overnight-role floor lifts servers regardless.
    TimeRule("weekend-baseline", "weekend", 0, 24, 0.1),
)


def _time_of_day_multiplier(ts: datetime) -> float:
    """Return the piecewise multiplier for the timestamp."""
    weekday = ts.weekday()  # Mon=0..Sun=6
    hour = ts.hour
    for rule in _TIME_RULES:
        if not _weekday_matches(rule.weekday_predicate_name, weekday):
            continue
        if _hour_in_range(rule.start_hour, rule.end_hour, hour):
            return rule.multiplier
    # No rule matched: fall back to a low constant. Defensive -- the
    # rule set above is exhaustive over (weekday|weekend) x [0,24).
    log.warning(
        "no time rule matched ts=%s weekday=%d hour=%d; falling back to 0.1",
        ts.isoformat(),
        weekday,
        hour,
    )
    return 0.1


# --- after-hours admin overlay --------------------------------------------
#
# Admin workstations run maintenance scripts overnight. Apply a +0.4
# additive lift to the time-of-day multiplier on weekdays 22:00-02:00
# for admin-workstation hosts. ALSO apply during 02:00-04:00 on weekends
# (the small admin-cron spike from the spec).


def _after_hours_admin_lift(host: Host, ts: datetime) -> float:
    if host.role != "admin-workstation":
        return 0.0
    weekday = ts.weekday()
    hour = ts.hour
    # Weekday after-hours: 22-02 wrap.
    if weekday < 5 and _hour_in_range(22, 2, hour):
        return 0.4
    # Weekend admin-cron spike: 02-04.
    if weekday >= 5 and 2 <= hour < 4:
        return 0.4
    return 0.0


# --- constant-overnight floor ---------------------------------------------
#
# Servers run constantly. The time-of-day rules can dip below 0.5 even
# for servers (lunch dip, evening taper, overnight). Floor servers at
# 0.85 of their day-rate so a service-account-host at 03:00 is within
# ~20% of its 14:00 rate.


_SERVER_FLOOR_MULTIPLIER = 0.85


def _constant_overnight_floor(host: Host, base_multiplier: float) -> float:
    if not _is_constant_overnight_role(host.role):
        return base_multiplier
    return max(base_multiplier, _SERVER_FLOOR_MULTIPLIER)


# --- anomaly windows -------------------------------------------------------


AnomalyKind = Literal["holiday", "outage", "campaign"]


@dataclass(frozen=True)
class AnomalyWindow:
    """A datetime range that overrides the normal time-of-day multiplier.

    Attributes:
        start: inclusive (UTC-naive or aware -- compared as-is to query ts).
        end: exclusive.
        kind: ``"holiday"`` | ``"outage"`` | ``"campaign"`` -- label only;
            the multiplier carries the actual effect.
        multiplier: scalar applied multiplicatively to the composed rate.
            Holidays use ~0.05; outages ~0.0; campaigns ~1.5.
    """

    start: datetime
    end: datetime
    kind: AnomalyKind
    multiplier: float


def _anomaly_overlay(
    ts: datetime, windows: tuple[AnomalyWindow, ...]
) -> float:
    """Return the strongest-effect multiplier across active windows.

    "Strongest effect" = the multiplier whose distance from 1.0 is
    largest. This way an outage (~0) inside a campaign window (~1.5)
    correctly wins. With no windows or no matches, returns 1.0.
    """
    best: float = 1.0
    best_distance: float = 0.0
    for w in windows:
        if w.start <= ts < w.end:
            distance = abs(w.multiplier - 1.0)
            if distance > best_distance:
                best = w.multiplier
                best_distance = distance
    return best


# --- public API ------------------------------------------------------------


@dataclass(frozen=True)
class ActivityModel:
    """Wraps a Topology and answers expected-event-rate queries.

    Rates are events/hour. v1 is fully deterministic from
    (topology, timestamp, anomaly_windows); the ``seed`` field is
    reserved for future stochastic overlays.
    """

    topology: Topology
    seed: int = 0
    anomaly_windows: tuple[AnomalyWindow, ...] = field(default_factory=tuple)

    def rate(self, host: Host, event_class: str, timestamp: datetime) -> float:
        """Return expected events/hour for (host, event_class) at timestamp.

        Composition:
            baseline_rate(host.role, event_class)
            * (time_of_day_multiplier(timestamp)
               + after_hours_admin_overlay(host, timestamp))
            * constant_overnight_floor_correction  (servers floor at 0.85)
            * anomaly_overlay(timestamp)

        Raises:
            ValueError: if ``event_class`` is not a known event class.
        """
        if event_class not in EVENT_CLASSES:
            raise ValueError(
                f"unknown event class {event_class!r}; expected one of "
                f"{EVENT_CLASSES}"
            )
        baseline = _baseline_for(host.role, event_class)
        tod = _time_of_day_multiplier(timestamp)
        admin_lift = _after_hours_admin_lift(host, timestamp)
        composed = tod + admin_lift
        composed = _constant_overnight_floor(host, composed)
        anomaly = _anomaly_overlay(timestamp, self.anomaly_windows)
        return baseline * composed * anomaly

    def hour_schedule(
        self,
        host: Host,
        event_class: str,
        start: datetime,
        end: datetime,
    ) -> list[tuple[datetime, float]]:
        """Hour-by-hour rates across the window.

        Steps in 1-hour increments from ``start`` (inclusive) to
        ``end`` (exclusive). Useful for generators that need to
        materialise per-hour event counts. Returns ``[]`` if
        ``end <= start``.
        """
        from datetime import timedelta

        if end <= start:
            return []
        if event_class not in EVENT_CLASSES:
            raise ValueError(
                f"unknown event class {event_class!r}; expected one of "
                f"{EVENT_CLASSES}"
            )
        out: list[tuple[datetime, float]] = []
        cursor = start
        step = timedelta(hours=1)
        while cursor < end:
            out.append((cursor, self.rate(host, event_class, cursor)))
            cursor = cursor + step
        return out


def _baseline_for(role: str, event_class: str) -> float:
    """Resolve (role, event_class) -> baseline rate.

    Override-by-role wins over the bucket lookup. Raises if role is
    unknown -- the topology contract guarantees only the 11 declared
    roles, so an unknown role here means a contract violation.
    """
    override = _ROLE_CLASS_OVERRIDES.get((role, event_class))
    if override is not None:
        return override
    bucket = _ROLE_BUCKET.get(role)
    if bucket is None:
        raise ValueError(
            f"unknown host role {role!r}; topology contract violation"
        )
    return _BASELINE_RATES[bucket][event_class]


def build_activity_model(
    topology: Topology,
    *,
    seed: int = 0,
    anomaly_windows: tuple[AnomalyWindow, ...] = (),
) -> ActivityModel:
    """Builder for symmetry with ``build_topology``.

    Args:
        topology: the topology this model is bound to.
        seed: reserved for future stochastic overlays; v1 ignores it
            for rate composition. Stored on the model for traceability.
        anomaly_windows: optional holiday / outage / campaign windows.

    Returns:
        ``ActivityModel`` (frozen, hashable-tuple-based).
    """
    model = ActivityModel(
        topology=topology, seed=seed, anomaly_windows=tuple(anomaly_windows)
    )
    log.info(
        "built activity model: tier=%s hosts=%d anomaly_windows=%d",
        topology.tier,
        len(topology.hosts),
        len(model.anomaly_windows),
    )
    return model
