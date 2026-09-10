"""TZ-invariance of the OT protocol + IT/OT bridge generators (issue #30).

The generators take "naive UTC" datetimes and derive Zeek epoch
timestamps from them with ``datetime.timestamp()``. On a *naive*
datetime that method interprets the value in the **local** timezone, so
before the fix every emitted epoch (and every uid/RNG stream seeded from
one) moved with the build machine's ``TZ``: the same call produced
``1767571200`` under ``TZ=UTC`` and ``1767589200`` under
``TZ=America/New_York`` -- an 18000 s (5 h) shift that silently
desynchronised OT telemetry from the IT baseline.

These tests run the same deterministic generation under two timezones
and assert the **full emitted event stream** is byte-identical. Asserting
``tzinfo is not None`` would not catch the defect; only comparing output
across timezones does.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from blue_bench_generators.it_baseline.topology import build_topology
from blue_bench_generators.it_ot_bridge.bridge import (
    generate_for_topologies,
)
from blue_bench_generators.it_ot_bridge.bridge import (
    AnomalyWindow as BridgeAnomalyWindow,
)
from blue_bench_generators.ot_protocols import dnp3, iec104, modbus, s7comm
from blue_bench_generators.ot_protocols.topology import build_ot_network


# A weekday (Monday 2026-01-05, matching composer.DEFAULT_START) so the
# business-hours / shift-window branches are exercised, plus a window
# short enough to keep the test cheap.
START = datetime(2026, 1, 5, 9, 0, 0)
END = START + timedelta(hours=1)

# 09:00 UTC is 04:00 in New York: the two timezones disagree on the hour
# AND on business-hours-ness, so a TZ-dependent generator diverges in
# content, not just in epoch offset.
TZ_A = "UTC"
TZ_B = "America/New_York"

_PROTOCOL_MODULES = (
    ("modbus", modbus),
    ("dnp3", dnp3),
    ("iec104", iec104),
    ("s7comm", s7comm),
)


@contextmanager
def _local_timezone(tz: str):
    """Run the block with the process' local timezone set to ``tz``.

    ``os.environ["TZ"]`` alone does nothing -- libc caches the zone until
    ``time.tzset()`` is called. The restore path resets both, so no later
    test in this process inherits the override.
    """
    previous = os.environ.get("TZ")
    os.environ["TZ"] = tz
    time.tzset()
    try:
        yield
    finally:
        if previous is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = previous
        time.tzset()


def _events_under(tz: str, produce) -> str:
    """JSON dump of ``produce()``'s events, generated under ``tz``."""
    with _local_timezone(tz):
        events = list(produce())
    assert events, "generation produced no events; the test would be vacuous"
    return json.dumps(events, sort_keys=True, default=str)


def test_local_timezone_helper_actually_switches_zone():
    """Guard against the whole suite passing vacuously.

    If ``time.tzset()`` were omitted (or the platform ignored ``TZ``),
    both halves of every test below would run under the same zone and
    the equality assertions would prove nothing.
    """
    naive = datetime(2026, 1, 5, 9, 0, 0)
    with _local_timezone(TZ_A):
        epoch_a = naive.timestamp()
    with _local_timezone(TZ_B):
        epoch_b = naive.timestamp()
    assert epoch_b - epoch_a == 18000.0, (
        "TZ override is not taking effect, so the TZ-invariance assertions "
        f"below cannot fail: {epoch_a} vs {epoch_b}"
    )


@pytest.mark.parametrize("name,module", _PROTOCOL_MODULES, ids=lambda v: getattr(v, "__name__", v))
def test_protocol_output_is_timezone_invariant(name, module):
    net = build_ot_network(tier="S", seed=0)

    def produce():
        return module.generate(net, START, END, seed=0)

    assert _events_under(TZ_A, produce) == _events_under(TZ_B, produce), (
        f"{name}.generate output depends on the machine's TZ"
    )


def test_bridge_output_is_timezone_invariant():
    it_topo = build_topology(tier="M", seed=0)
    ot_net = build_ot_network(tier="M", seed=0)
    # A full weekday: bridge sessions are scheduled per weekday inside a
    # shift window, so a one-hour slice can legitimately emit nothing.
    day_start = datetime(2026, 1, 5, 0, 0, 0)
    day_end = day_start + timedelta(days=1)

    def produce():
        return generate_for_topologies(it_topo, ot_net, day_start, day_end, seed=0)

    assert _events_under(TZ_A, produce) == _events_under(TZ_B, produce), (
        "it_ot_bridge.generate_for_topologies output depends on the machine's TZ"
    )


def test_anomaly_overlay_output_is_timezone_invariant():
    """Anomaly windows carry their own datetimes -- cover that path too."""
    net = build_ot_network(tier="S", seed=0)
    window = modbus.AnomalyWindow(
        kind="out_of_cycle_write",
        start=START + timedelta(minutes=10),
        end=START + timedelta(minutes=20),
    )

    def produce():
        return modbus.generate(net, START, END, seed=0, anomaly_windows=(window,))

    assert _events_under(TZ_A, produce) == _events_under(TZ_B, produce), (
        "modbus anomaly-overlay output depends on the machine's TZ"
    )


def test_epoch_matches_utc_interpretation_of_naive_input():
    """The epochs are not merely stable -- they are the UTC ones.

    A generator that pinned every datetime to some *other* fixed zone
    would be TZ-invariant yet still misplace OT events relative to the
    IT baseline's intended UTC wall-clock.
    """
    net = build_ot_network(tier="S", seed=0)
    expected = START.replace(tzinfo=timezone.utc).timestamp()
    with _local_timezone(TZ_B):
        events = list(modbus.generate(net, START, END, seed=0))
    first = min(float(e["ts"]) for e in events)
    assert first == pytest.approx(expected, abs=1e-6), (
        f"first modbus epoch {first} != UTC interpretation of {START} "
        f"({expected})"
    )


def test_anomaly_windows_normalise_naive_input_to_utc():
    """Naive window datetimes must not compare naive-vs-aware later."""
    naive = datetime(2026, 1, 5, 9, 0, 0)
    windows = (
        modbus.AnomalyWindow(kind="out_of_cycle_write", start=naive, end=naive + timedelta(minutes=5)),
        dnp3.AnomalyWindow(kind="cold_restart", start=naive, end=naive + timedelta(minutes=5)),
        iec104.AnomalyWindow(kind="stopdt_off_hours", start=naive, end=naive + timedelta(minutes=5)),
        s7comm.AnomalyWindow(kind="plc_stop", start=naive, end=naive + timedelta(minutes=5)),
        BridgeAnomalyWindow(kind="jump_host_bypass", start=naive, end=naive + timedelta(minutes=5)),
    )
    for w in windows:
        assert w.start.tzinfo is not None and w.end.tzinfo is not None, w
        assert w.start.utcoffset() == timedelta(0), w
        assert w.start.timestamp() == naive.replace(tzinfo=timezone.utc).timestamp()
