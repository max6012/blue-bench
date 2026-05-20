"""Phase A enforcement tests — extended coverage for task class scope binding.

Covers gaps left by test_task_class_binding.py:
  - registry/schema layer validation
  - profile YAML round-trips (load_profile, explicit empty list, invalid strings)
  - session-layer edge cases (case sensitivity, whitespace, concurrent sessions,
    banner citation state, set_profile idempotence, error-type boundary,
    profile mutation without revalidation)
  - CLI paths (-T short form, prompt normalization via monkeypatch)
  - downstream consumer contract (audit-log-safe string value)
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from blue_bench_cli.main import app
from blue_bench_client.interactive import EngagementScopeError, InteractiveSession
from blue_bench_mcp.profiles import ModelProfile, load_profile
from blue_bench_mcp.task_classes import (
    TASK_CLASSES,
    TaskClass,
    TaskClassSpec,
    UnknownTaskClassError,
    all_task_classes,
    get_task_class,
)


# ── shared helpers ────────────────────────────────────────────────────────────

BASE_PROFILE = {
    "name": "test-profile",
    "model_id": "test-model",
    "tool_protocol": "native",
    "prompt_style": "terse",
    "context_size": 4096,
}


def _profile(allowed: list[str] | None = None, *, citation: bool = True) -> ModelProfile:
    data = dict(BASE_PROFILE)
    if allowed is not None:
        data["allowed_task_classes"] = allowed
    data["require_evidence_citation"] = citation
    return ModelProfile.model_validate(data)


# ── registry layer ────────────────────────────────────────────────────────────


def test_task_classes_dict_keys_are_enum_members():
    """TASK_CLASSES is keyed by TaskClass enum members.

    Because TaskClass inherits from (str, Enum), a bare string key like
    ``"ALERT_TRIAGE"`` ALSO resolves correctly (str-Enum equality with the
    underlying value) — this is a feature, not a bug. The contract for
    downstream code is: pass either the enum or the string; both work.
    """
    for key in TASK_CLASSES:
        assert isinstance(key, TaskClass), (
            f"TASK_CLASSES key {key!r} is not a TaskClass enum — "
            "string keys would break dict[TaskClass, ...] consumers"
        )
    # str-Enum equality means string lookup ALSO works — document it.
    assert TASK_CLASSES["ALERT_TRIAGE"] is TASK_CLASSES[TaskClass.ALERT_TRIAGE]


def test_all_task_classes_stable_order():
    """all_task_classes() must return every declared member in stable order.

    Stable order is needed so the interactive prompt numbers are reproducible
    across invocations — an operator who types '3' must always select the same
    class.
    """
    result = all_task_classes()
    assert result == list(TaskClass), (
        "all_task_classes() order diverges from enum member declaration order"
    )
    # Calling twice must produce the same sequence (not a lazy iterator).
    assert all_task_classes() == result


def test_get_task_class_string_and_enum_return_same_spec():
    """get_task_class accepts both str and TaskClass; both must return the same spec."""
    for member in TaskClass:
        by_str = get_task_class(member.value)
        by_enum = get_task_class(member)
        assert by_str is by_enum, (
            f"get_task_class({member.value!r}) and get_task_class(TaskClass.{member.name}) "
            "returned different objects — lookup is not stable"
        )
        assert isinstance(by_str, TaskClassSpec)


def test_get_task_class_raises_unknown_task_class_error_not_value_error():
    """get_task_class must raise UnknownTaskClassError (a ValueError subclass).

    The session layer catches UnknownTaskClassError to wrap it; if the registry
    raised a plain ValueError the session would swallow it without the right
    message shape.
    """
    with pytest.raises(UnknownTaskClassError) as exc_info:
        get_task_class("NOT_A_CLASS")
    # Must be a ValueError subclass so except ValueError: consumers still work.
    assert isinstance(exc_info.value, ValueError)
    assert "NOT_A_CLASS" in str(exc_info.value)
    # The error message should mention valid classes so the operator can self-serve.
    for member in TaskClass:
        assert member.value in str(exc_info.value), (
            f"valid class {member.value!r} missing from error message"
        )


@pytest.mark.parametrize(
    "member,expected_verifiable",
    [
        (TaskClass.IOC_EXTRACTION, True),
        (TaskClass.SIGMA_DRAFT, True),
        (TaskClass.LOG_QUERY, True),
        (TaskClass.ALERT_TRIAGE, True),
        (TaskClass.THREAT_NARRATIVE, False),
        (TaskClass.INTENT_ASSESSMENT, False),
    ],
)
def test_per_class_verifiable_flag(member: TaskClass, expected_verifiable: bool):
    """verifiable=True for mechanically-scorable classes, False for operator-led ones.

    The rendering layer and test harness use this flag to decide whether to
    run grounding passes. A wrong flag silently disables automated checks.
    """
    spec = get_task_class(member)
    assert spec.verifiable is expected_verifiable, (
        f"{member.value}: expected verifiable={expected_verifiable}, "
        f"got {spec.verifiable}"
    )


# ── YAML / profile schema layer ───────────────────────────────────────────────


def test_yaml_explicit_allowed_task_classes_round_trips(tmp_path):
    """An explicit allowed_task_classes list in YAML is preserved after load.

    Pydantic's default_factory only runs when the field is absent. An explicit
    list (including a restrictive subset) must survive the load/validate cycle
    unchanged.
    """
    yaml_file = tmp_path / "restricted.yaml"
    yaml_file.write_text(
        yaml.safe_dump(
            {
                **BASE_PROFILE,
                "name": "restricted-rt",
                "allowed_task_classes": ["IOC_EXTRACTION", "SIGMA_DRAFT"],
            }
        )
    )
    profile = load_profile(yaml_file)
    assert profile.allowed_task_classes == [
        TaskClass.IOC_EXTRACTION,
        TaskClass.SIGMA_DRAFT,
    ], (
        "allowed_task_classes round-trip failed — explicit list was overwritten "
        "by the default_factory"
    )


def test_yaml_missing_fields_defaults_to_all_classes_and_citation_on(tmp_path):
    """A profile YAML without optional fields gets permissive defaults.

    allowed_task_classes defaults to all declared classes; require_evidence_citation
    defaults to True. These defaults are the safe/permissive baseline — no silent
    restriction when fields are absent.
    """
    yaml_file = tmp_path / "minimal.yaml"
    yaml_file.write_text(yaml.safe_dump(dict(BASE_PROFILE, name="minimal-rt")))
    profile = load_profile(yaml_file)
    assert set(profile.allowed_task_classes) == set(TaskClass), (
        "missing allowed_task_classes did not default to all declared classes"
    )
    assert profile.require_evidence_citation is True, (
        "missing require_evidence_citation did not default to True"
    )


def test_yaml_invalid_task_class_string_rejected_at_load_time(tmp_path):
    """A YAML file listing an unknown task class name must fail at load time.

    Pydantic validates list[TaskClass] against the enum; an invalid member
    should raise rather than silently skip. This prevents misconfigured profiles
    from reaching the runtime where the error would be harder to diagnose.
    """
    yaml_file = tmp_path / "invalid.yaml"
    yaml_file.write_text(
        yaml.safe_dump(
            {
                **BASE_PROFILE,
                "name": "invalid-class",
                "allowed_task_classes": ["IOC_EXTRACTION", "NONEXISTENT_CLASS"],
            }
        )
    )
    with pytest.raises(Exception) as exc_info:
        load_profile(yaml_file)
    # Pydantic raises ValidationError; check the message names the bad value.
    assert "NONEXISTENT_CLASS" in str(exc_info.value)


def test_yaml_require_evidence_citation_false_round_trips(tmp_path):
    """require_evidence_citation=false in YAML is preserved and surfaces in banner."""
    yaml_file = tmp_path / "no-citation.yaml"
    yaml_file.write_text(
        yaml.safe_dump(
            {
                **BASE_PROFILE,
                "name": "no-citation-rt",
                "require_evidence_citation": False,
            }
        )
    )
    profile = load_profile(yaml_file)
    assert profile.require_evidence_citation is False
    # The session banner must reflect the loaded value.
    session = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    banner = session.banner()
    assert "Citation enforcement: off" in banner, (
        "banner did not reflect require_evidence_citation=False from loaded profile"
    )


# ── session-layer edge cases ──────────────────────────────────────────────────


def test_session_banner_citation_off_shows_off():
    """Banner shows 'Citation enforcement: off' when the profile disables it."""
    profile = _profile(citation=False)
    session = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    banner = session.banner()
    assert "Citation enforcement: off" in banner
    assert "Citation enforcement: on" not in banner


def test_session_banner_is_deterministic():
    """Two banner() calls on the same session return identical strings.

    The banner must not contain timestamps or random identifiers — it is
    rendered once but may be re-read by the audit log or test assertions.
    """
    profile = _profile()
    session = InteractiveSession(profile, task_class=TaskClass.SIGMA_DRAFT)
    assert session.banner() == session.banner()


def test_concurrent_sessions_do_not_bleed_task_class():
    """Two InteractiveSession instances do not share task_class state.

    Sessions are independent objects; a mutation on one must not affect the
    other. Guards against accidental class-level mutable state.
    """
    profile = _profile()
    s1 = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    s2 = InteractiveSession(profile, task_class=TaskClass.IOC_EXTRACTION)
    assert s1.task_class == TaskClass.ALERT_TRIAGE
    assert s2.task_class == TaskClass.IOC_EXTRACTION
    # Changing s2's task_class should not affect s1.
    s2.task_class = TaskClass.SIGMA_DRAFT
    assert s1.task_class == TaskClass.ALERT_TRIAGE


def test_set_profile_same_profile_does_not_raise():
    """set_profile with the same profile object is idempotent — no spurious error."""
    profile = _profile()
    session = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    # Should not raise.
    session.set_profile(profile)
    assert session.task_class == TaskClass.ALERT_TRIAGE


def test_profile_mutation_after_construction_does_not_re_evaluate_scope():
    """Direct attribute mutation on ModelProfile bypasses Pydantic (no validate_assignment).

    This test documents the current behaviour: after construction, directly
    mutating session.profile.allowed_task_classes to remove the bound class does
    NOT trigger EngagementScopeError — the scope is only re-evaluated on
    __aenter__ or set_profile, not on arbitrary attribute writes.

    This is a known gap documented here so operators know to call set_profile
    rather than mutating the profile object directly.
    """
    profile = _profile()
    session = InteractiveSession(profile, task_class=TaskClass.ALERT_TRIAGE)
    # Directly narrow the allowed list to something that excludes ALERT_TRIAGE.
    session.profile.allowed_task_classes = [TaskClass.IOC_EXTRACTION]
    # No exception is raised — the scope guard was not re-evaluated.
    # This is intentional: the test documents the boundary, not a bug.
    # Operators must call set_profile() to trigger re-evaluation.
    assert session.task_class == TaskClass.ALERT_TRIAGE  # still bound


def test_engagement_scope_error_is_only_exception_at_session_boundary():
    """The session constructor raises EngagementScopeError for ALL bad inputs.

    UnknownTaskClassError (from the registry) must be wrapped — callers at the
    session boundary must handle exactly one exception type.
    """
    profile = _profile()
    # Unknown string → EngagementScopeError, NOT UnknownTaskClassError.
    with pytest.raises(EngagementScopeError):
        InteractiveSession(profile, task_class="NOT_VALID")
    # Verify it is NOT leaking the inner exception type directly.
    try:
        InteractiveSession(profile, task_class="NOT_VALID")
    except EngagementScopeError:
        pass  # expected
    except UnknownTaskClassError:
        pytest.fail(
            "UnknownTaskClassError escaped session boundary — "
            "callers must not handle two exception types"
        )


def test_task_class_lowercase_rejected_by_session_constructor():
    """Lowercase task class string is rejected at the session constructor.

    TaskClass(name) is an exact-match enum lookup — 'alert_triage' is not
    a valid member even though 'ALERT_TRIAGE' is. Case normalization happens
    only in the interactive prompt path (_prompt_task_class), not here.
    """
    profile = _profile()
    with pytest.raises(EngagementScopeError) as exc_info:
        InteractiveSession(profile, task_class="alert_triage")
    assert "alert_triage" in str(exc_info.value)


def test_task_class_whitespace_rejected_by_session_constructor():
    """A task class string with surrounding whitespace is rejected."""
    profile = _profile()
    with pytest.raises(EngagementScopeError):
        InteractiveSession(profile, task_class=" ALERT_TRIAGE ")


def test_task_class_value_is_stable_string_for_audit_log():
    """TaskClass.value is the audit-log-safe form.

    The audit log records ``task_class.value`` (e.g. ``"IOC_EXTRACTION"``).
    Note that ``str(member)`` on Python 3.11+ returns the qualified form
    (``"TaskClass.IOC_EXTRACTION"``) — audit code MUST use ``.value``, not
    ``str(...)``. This test pins the value/name parity so a future rename
    would force the audit code to be reviewed.
    """
    for member in TaskClass:
        assert member.value == member.name, (
            f"TaskClass.{member.name}.value ({member.value!r}) diverges from .name — "
            "audit log serialisation would be inconsistent"
        )
        # The .value attribute is the canonical audit-log form (NOT str(member)).
        assert isinstance(member.value, str)
        assert " " not in member.value
        assert member.value == member.value.upper()


# ── CLI layer — -T short form ─────────────────────────────────────────────────

runner = CliRunner()


def test_cli_short_T_flag_equivalent_to_task_class_flag():
    """The -T short form rejects unknown classes identically to --task-class."""
    result_long = runner.invoke(
        app,
        ["analyst", "--profile", "claude-sonnet-4-6", "--task-class", "BOGUS"],
    )
    result_short = runner.invoke(
        app,
        ["analyst", "--profile", "claude-sonnet-4-6", "-T", "BOGUS"],
    )
    assert result_short.exit_code == 2, (
        "-T short form did not exit 2 on unknown task class"
    )
    assert result_long.exit_code == 2
    # Both paths must surface the class name in output.
    assert "bogus" in result_short.output.lower() or "unknown task class" in result_short.output.lower()


def test_cli_disallowed_class_rejected_via_T_short_form(tmp_path):
    """A restricted profile refuses a disallowed class via -T as well as --task-class."""
    restricted_yaml = tmp_path / "restricted-t.yaml"
    restricted_yaml.write_text(
        yaml.safe_dump(
            {
                "name": "restricted-t",
                "model_id": "claude-sonnet-4-6",
                "tool_protocol": "anthropic-native",
                "prompt_style": "terse",
                "context_size": 4096,
                "allowed_task_classes": ["IOC_EXTRACTION"],
            }
        )
    )
    from blue_bench_cli.analyst import PROFILES_DIR

    target = PROFILES_DIR / "restricted-t-tmp.yaml"
    try:
        target.symlink_to(restricted_yaml)
        result = runner.invoke(
            app,
            ["analyst", "--profile", "restricted-t-tmp", "-T", "ALERT_TRIAGE"],
        )
        assert result.exit_code == 2
        out = result.output.lower()
        assert "not permitted" in out
    finally:
        if target.exists() or target.is_symlink():
            target.unlink()


# ── _prompt_task_class monkeypatch tests ──────────────────────────────────────


def _make_inputs(*answers: str):
    """Return a callable that feeds ``answers`` one at a time to console.input."""
    it = iter(answers)

    def _input(_prompt: str) -> str:
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    return _input


def test_prompt_accepts_number_selection():
    """Entering '1' selects the first class in the profile's allowed list."""
    from blue_bench_cli.analyst import _prompt_task_class

    profile = _profile()
    classes = list(profile.allowed_task_classes)
    with patch("blue_bench_cli.analyst.console.input", _make_inputs("1")):
        result = _prompt_task_class(profile)
    assert result == classes[0]


def test_prompt_accepts_name_exact_case():
    """Entering the class name in its canonical uppercase form resolves correctly."""
    from blue_bench_cli.analyst import _prompt_task_class

    profile = _profile()
    with patch("blue_bench_cli.analyst.console.input", _make_inputs("SIGMA_DRAFT")):
        result = _prompt_task_class(profile)
    assert result == TaskClass.SIGMA_DRAFT


def test_prompt_accepts_lowercase_name():
    """The prompt path normalises via .upper() — lowercase input must resolve."""
    from blue_bench_cli.analyst import _prompt_task_class

    profile = _profile()
    with patch("blue_bench_cli.analyst.console.input", _make_inputs("sigma_draft")):
        result = _prompt_task_class(profile)
    assert result == TaskClass.SIGMA_DRAFT, (
        "prompt path did not normalise lowercase input — contrast with flag path "
        "which is case-sensitive and would reject 'sigma_draft'"
    )


def test_prompt_reprompts_on_out_of_range_number():
    """An out-of-range number triggers a re-prompt; the subsequent valid input resolves."""
    from blue_bench_cli.analyst import _prompt_task_class

    profile = _profile()
    classes = list(profile.allowed_task_classes)
    # First answer is out of range, second is valid.
    with patch("blue_bench_cli.analyst.console.input", _make_inputs("999", "1")):
        result = _prompt_task_class(profile)
    assert result == classes[0]


def test_prompt_returns_none_on_eof():
    """EOFError (closed stdin, Ctrl+D) causes _prompt_task_class to return None."""
    from blue_bench_cli.analyst import _prompt_task_class

    profile = _profile()
    with patch("blue_bench_cli.analyst.console.input", side_effect=EOFError):
        result = _prompt_task_class(profile)
    assert result is None


def test_prompt_returns_none_when_profile_has_no_allowed_classes():
    """A profile with an explicit empty allowed_task_classes returns None immediately.

    The prompt function short-circuits on an empty class list rather than
    presenting an empty menu. The caller (in _amain) then refuses to start
    the engagement.
    """
    from blue_bench_cli.analyst import _prompt_task_class

    profile = _profile(allowed=[])
    # No console.input call should occur — the function returns before the loop.
    with patch("blue_bench_cli.analyst.console.input", side_effect=AssertionError("should not be called")):
        result = _prompt_task_class(profile)
    assert result is None
