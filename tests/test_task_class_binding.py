"""Phase A enforcement tests — task class scope binding.

Covers the contract between profile/session/CLI that prevents the AI from
running outside its operator-declared task scope.
"""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from blue_bench_cli.main import app
from blue_bench_client.interactive import EngagementScopeError, InteractiveSession
from blue_bench_mcp.profiles import ModelProfile
from blue_bench_mcp.task_classes import TaskClass


BASE_PROFILE = {
    "name": "test-profile",
    "model_id": "test-model",
    "tool_protocol": "native",
    "prompt_style": "terse",
    "context_size": 4096,
}


def _profile(allowed: list[str] | None = None) -> ModelProfile:
    data = dict(BASE_PROFILE)
    if allowed is not None:
        data["allowed_task_classes"] = allowed
    return ModelProfile.model_validate(data)


# ── session-layer ────────────────────────────────────────────────────────────


def test_session_rejects_disallowed_task_class():
    profile = _profile(allowed=["IOC_EXTRACTION"])
    session = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    with pytest.raises(EngagementScopeError) as exc:
        session._enforce_scope()
    msg = str(exc.value)
    assert "ALERT_TRIAGE" in msg
    assert "test-profile" in msg
    assert "IOC_EXTRACTION" in msg


def test_session_rejects_missing_task_class():
    profile = _profile()
    session = InteractiveSession(profile)
    with pytest.raises(EngagementScopeError) as exc:
        session._enforce_scope()
    assert "no silent defaulting" in str(exc.value)


def test_session_skips_enforcement_when_require_task_class_false():
    """require_task_class=False in the profile disables the enforcement gate.
    Operators can set this to unblock engagement start while the full control
    surface is being built; production profiles leave it true."""
    data = dict(BASE_PROFILE)
    data["require_task_class"] = False
    profile = ModelProfile.model_validate(data)
    # task_class=None does NOT raise when enforcement is disabled.
    session = InteractiveSession(profile)
    session._enforce_scope()  # must not raise
    # Banner says disabled, not unbound.
    assert "disabled by profile" in session.banner()


def test_session_skips_allowed_list_check_when_require_task_class_false():
    """Even a class that isn't in allowed_task_classes passes when enforcement
    is off — the profile restriction has no meaning without the gate."""
    data = dict(BASE_PROFILE)
    data["require_task_class"] = False
    data["allowed_task_classes"] = ["IOC_EXTRACTION"]
    profile = ModelProfile.model_validate(data)
    session = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    session._enforce_scope()  # must not raise despite ALERT_TRIAGE not in allowed list


def test_session_rejects_unknown_task_class_string():
    profile = _profile()
    with pytest.raises(EngagementScopeError) as exc:
        InteractiveSession(profile, task_class="NONSENSE")
    assert "NONSENSE" in str(exc.value)


def test_session_accepts_valid_class_string_or_enum():
    profile = _profile()
    s1 = InteractiveSession(profile, task_class="ALERT_TRIAGE")
    s2 = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    assert s1.task_class == TaskClass.ALERT_TRIAGE
    assert s2.task_class == TaskClass.ALERT_TRIAGE


def test_session_banner_includes_bound_state():
    profile = _profile()
    session = InteractiveSession(profile, task_class=TaskClass.SIGMA_DRAFT)
    banner = session.banner()
    assert "SIGMA_DRAFT" in banner
    assert "test-profile" in banner
    # Citation enforcement state surfaces too — needed by operators reading the banner.
    assert "Citation enforcement: on" in banner


def test_set_profile_revalidates_against_new_profile():
    permissive = _profile()
    restricted = _profile(allowed=["IOC_EXTRACTION"])
    session = InteractiveSession(permissive, task_class=TaskClass.ALERT_TRIAGE)
    # On permissive profile, scope passes.
    session._enforce_scope()
    # Swapping to a profile that doesn't permit the bound class must raise —
    # silently widening scope at swap-time would defeat the binding.
    with pytest.raises(EngagementScopeError):
        session.set_profile(restricted)


def test_downstream_consumers_see_task_class():
    """The session exposes task_class for the renderer / audit log / grounding pass
    to consume. This is a structural test — anyone reading session state must find
    the bound class."""
    profile = _profile()
    session = InteractiveSession(profile, task_class=TaskClass.LOG_QUERY)
    # Public attribute, typed as TaskClass enum.
    assert isinstance(session.task_class, TaskClass)
    assert session.task_class == TaskClass.LOG_QUERY
    # Banner serialization for renderer hand-off.
    assert "LOG_QUERY" in session.banner()


# ── CLI layer (early-exit paths only — these don't require MCP startup) ──────

runner = CliRunner()


def test_cli_rejects_unknown_task_class():
    """--task-class with a bogus value errors before any MCP setup."""
    result = runner.invoke(
        app,
        ["analyst", "--profile", "claude-sonnet-4-6", "--task-class", "BOGUS"],
    )
    assert result.exit_code == 2
    assert "unknown task class" in result.stdout.lower() or "unknown task class" in result.output.lower()


def test_cli_refuses_without_task_class_when_no_tty(tmp_path):
    """No --task-class + no TTY (input closed) → engagement refused (no silent default).

    Uses a synthetic strict profile because production profiles no longer
    require task class — the contract still applies to any profile whose
    YAML opts in with require_task_class: true.
    """
    import yaml

    strict_yaml = tmp_path / "strict.yaml"
    strict_yaml.write_text(
        yaml.safe_dump(
            {
                "name": "strict",
                "model_id": "claude-sonnet-4-6",
                "tool_protocol": "anthropic-native",
                "prompt_style": "terse",
                "context_size": 4096,
                "require_task_class": True,
            }
        )
    )
    from blue_bench_cli.analyst import PROFILES_DIR

    target = PROFILES_DIR / "strict-test-tmp.yaml"
    try:
        target.symlink_to(strict_yaml)
        result = runner.invoke(
            app,
            ["analyst", "--profile", "strict-test-tmp"],
            input="",
        )
        assert result.exit_code == 2
        out = (result.stdout + result.output).lower()
        assert "task class required" in out
    finally:
        if target.exists() or target.is_symlink():
            target.unlink()


def test_cli_rejects_task_class_not_permitted_by_profile(tmp_path):
    """A profile that restricts allowed_task_classes refuses an out-of-set --task-class."""
    import yaml
    # Write a temp profile YAML restricted to IOC_EXTRACTION only.
    restricted_yaml = tmp_path / "restricted.yaml"
    restricted_yaml.write_text(
        yaml.safe_dump(
            {
                "name": "restricted",
                "model_id": "claude-sonnet-4-6",
                "tool_protocol": "anthropic-native",
                "prompt_style": "terse",
                "context_size": 4096,
                "allowed_task_classes": ["IOC_EXTRACTION"],
            }
        )
    )
    # The CLI loads from PROFILES_DIR by name, so symlink into it for the test.
    from blue_bench_cli.analyst import PROFILES_DIR

    target = PROFILES_DIR / "restricted-test-tmp.yaml"
    try:
        target.symlink_to(restricted_yaml)
        result = runner.invoke(
            app,
            [
                "analyst",
                "--profile",
                "restricted-test-tmp",
                "--task-class",
                "ALERT_TRIAGE",
            ],
        )
        assert result.exit_code == 2
        out = (result.stdout + result.output).lower()
        assert "not permitted" in out
        assert "ioc_extraction" in out
    finally:
        if target.exists() or target.is_symlink():
            target.unlink()
