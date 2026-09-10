"""Cloud-model catalogue filtering + generic profile."""
from datetime import datetime, timedelta, timezone

import blue_bench_client.cloud_models as cm


def _fake(monkeypatch, models):
    monkeypatch.setattr(cm, "_all_cloud_models", lambda: models)


def _m(name, days_ago, gb):
    return cm.CloudModel(name, datetime.now(timezone.utc) - timedelta(days=days_ago), gb)


def test_recency_filter(monkeypatch):
    _fake(monkeypatch, [_m("new", 30, 60), _m("old", 400, 60)])
    names = [m.model for m in cm.list_cloud_models(since_months=6)]
    assert names == ["new"]  # old (>6mo) dropped; newest first


def test_size_band_mid(monkeypatch):
    _fake(monkeypatch, [_m("s", 10, 60), _m("m", 10, 300), _m("l", 10, 800)])
    names = {m.model for m in cm.list_cloud_models(since_months=None, size="mid")}
    assert names == {"m"}  # 100-500 GB


def test_hosted_zero_size_dropped_only_when_size_filtered(monkeypatch):
    _fake(monkeypatch, [_m("hosted", 10, 0), _m("big", 10, 800)])
    assert {m.model for m in cm.list_cloud_models(since_months=None)} == {"hosted", "big"}
    assert {m.model for m in cm.list_cloud_models(since_months=None, size="large")} == {"big"}


def test_generic_cloud_profile_is_native_with_model_id():
    p = cm.generic_cloud_profile("glm-5.2")
    assert p.model_id == "glm-5.2" and p.tool_protocol == "native"
    assert p.name == "cloud-glm-5.2" and p.context_size >= 16384
