"""Provider failures are retried, and when they outlast the retries they are
not scored as the model's miss. Plus: pointer handles accept what the corpus
actually contains (hex record ids from the injected capture)."""
import asyncio

import ollama
import pytest

from blue_bench_client import runner
from blue_bench_client.fanout.schema import Pointer, parse_worker_report
from blue_bench_client.trace import Trace
from blue_bench_eval import worker_score as ws


def _trace():
    return Trace(prompt_id="p", profile_name="x", model_id="m", tool_protocol="native",
                 question="q", composed_system_prompt="s", tools_available=[])


class _Flaky:
    def __init__(self, fails, status=500):
        self.fails, self.status, self.calls = fails, status, 0

    async def chat(self, **kw):
        self.calls += 1
        if self.calls <= self.fails:
            raise ollama.ResponseError("Internal Server Error", self.status)
        return "ok"


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(runner, "PROVIDER_RETRY_DELAYS", (0, 0, 0))


def test_transient_500s_are_retried_and_counted():
    t = _trace()
    inner = _Flaky(fails=2)
    assert asyncio.run(runner._RetryingOllama(inner, t).chat(model="m")) == "ok"
    assert inner.calls == 3 and t.provider_retries == 2


def test_a_client_error_is_not_retried():
    t = _trace()
    inner = _Flaky(fails=1, status=400)
    with pytest.raises(ollama.ResponseError):
        asyncio.run(runner._RetryingOllama(inner, t).chat(model="m"))
    assert inner.calls == 1 and t.provider_retries == 0


def test_retries_give_up_after_the_last_delay():
    inner = _Flaky(fails=99)
    with pytest.raises(ollama.ResponseError):
        asyncio.run(runner._RetryingOllama(inner, _trace()).chat(model="m"))
    assert inner.calls == 1 + len(runner.PROVIDER_RETRY_DELAYS)


def test_a_provider_failure_is_excluded_not_scored_wrong():
    from datetime import datetime, timezone

    from blue_bench_client.fanout.schema import Slice, SliceFilters
    sl = Slice(id="s", question="q", rationale="r", turn_budget=5,
               filters=SliceFilters(time_start=datetime(2026, 1, 1, tzinfo=timezone.utc)))
    case = ws.SliceCase(slice=sl, expect_incidents=["a"])
    gt = {"a": {"x"}}
    bad = ws.score_case(case, None, [], gt,
                        error="ResponseError: Internal Server Error (ref: z) (status code: 500)")
    assert bad.infra_error and not bad.correct
    model = ws.ModelScore(model="m", cases=[bad])
    assert model.scored == [] and model.summary()["infra_errors"] == 1
    assert model.summary()["unparsed_reports"] == 0


def test_hex_record_ids_and_odd_timestamps_do_not_cost_the_report():
    p = Pointer(index="windows-sysmon", event_record_id="0x1a2f", timestamp="around noon", doc_id=77)
    assert p.event_record_id == "0x1a2f" and p.timestamp is None and p.doc_id == "77"
    r = parse_worker_report('{"slice_id": "s", "nothing_found": false, "findings": [{"statement": "x", '
                            '"confidence": 0.9, "pointers": [{"index": "i", "doc_id": "d", '
                            '"event_record_id": "0xFF"}]}]}')
    assert len(r.findings) == 1
