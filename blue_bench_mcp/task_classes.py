"""TaskClass registry — declares the kinds of analyst work the AI is allowed to do.

Each task class carries: whether the work is mechanically verifiable (grounding
pass + coverage-gap pass can apply), human-readable acceptance criteria for what
counts as a grounded finding, and the expected tool-category coverage shape.

Profiles declare `allowed_task_classes`; the engagement-start binding refuses to
launch a session for a class the profile doesn't permit. The runtime never lets
the model classify its own scope — task class is operator-declared, surfaced in
the engagement banner, and recorded in the audit log.

Coverage-category declarations are placeholders here; they are filled in by the
coverage-declarations task (Phase B) once the runtime substrate for grounding
and coverage gaps exists.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class TaskClass(str, Enum):
    IOC_EXTRACTION = "IOC_EXTRACTION"
    SIGMA_DRAFT = "SIGMA_DRAFT"
    LOG_QUERY = "LOG_QUERY"
    ALERT_TRIAGE = "ALERT_TRIAGE"
    THREAT_NARRATIVE = "THREAT_NARRATIVE"
    INTENT_ASSESSMENT = "INTENT_ASSESSMENT"


class CategorySpec(BaseModel):
    """One required-or-recommended tool category for a task class.

    `any_of` lists tool names that satisfy the category — entries may be exact
    tool names (`sigma.validate_sigma_rule`) or wildcard prefixes (`evidence.*`).
    `min_distinct_tool_classes` requires that at least N distinct tool-class
    prefixes appear among the satisfying calls (used for corroboration-style
    categories where the *spread* of tools matters more than which specific one).
    """
    any_of: list[str] = Field(default_factory=list)
    min_distinct_tool_classes: int | None = None


class TaskClassSpec(BaseModel):
    name: TaskClass
    verifiable: bool
    """True if grounding/coverage passes can mechanically score this class.

    False marks classes where the right answer is synthesis or judgment that
    has no entity-level signal — the architecture does not enforce structural
    defenses for these; the operator owns the call end-to-end.
    """
    acceptance_criteria: list[str] = Field(default_factory=list)
    required_tool_categories: dict[str, CategorySpec] = Field(default_factory=dict)
    """Categories that MUST have at least one substantive call. Missing required
    categories block sign-off in the renderer."""
    recommended_tool_categories: dict[str, CategorySpec] = Field(default_factory=dict)
    """Categories that SHOULD have a substantive call. Missing recommended
    categories render as informational, not blocking."""


TASK_CLASSES: dict[TaskClass, TaskClassSpec] = {
    TaskClass.IOC_EXTRACTION: TaskClassSpec(
        name=TaskClass.IOC_EXTRACTION,
        verifiable=True,
        acceptance_criteria=[
            "Each IOC named in the answer appears literally in a tool result.",
            "IOC type (hash, IP, domain, hostname) matches the tool's extraction.",
        ],
    ),
    TaskClass.SIGMA_DRAFT: TaskClassSpec(
        name=TaskClass.SIGMA_DRAFT,
        verifiable=True,
        acceptance_criteria=[
            "Rule is syntactically valid per validate_sigma_rule.",
            "Logsource fields match the source category named in the prompt.",
            "Detection fields cite specific artifact attributes returned by tools.",
        ],
    ),
    TaskClass.LOG_QUERY: TaskClassSpec(
        name=TaskClass.LOG_QUERY,
        verifiable=True,
        acceptance_criteria=[
            "Each result reported appears in at least one tool result.",
            "Result counts and time windows are consistent with the tool's output.",
        ],
    ),
    TaskClass.ALERT_TRIAGE: TaskClassSpec(
        name=TaskClass.ALERT_TRIAGE,
        verifiable=True,
        acceptance_criteria=[
            "Each alert referenced appears in a tool result with matching ID/timestamp.",
            "Severity assignments cite the source field they derive from.",
            "Recommended next steps cite the specific evidence motivating them.",
        ],
    ),
    TaskClass.THREAT_NARRATIVE: TaskClassSpec(
        name=TaskClass.THREAT_NARRATIVE,
        verifiable=False,
        acceptance_criteria=[
            "Narrative judgments not mechanically verifiable. Operator-led only; "
            "the AI may assist with drafting, but the operator owns the call.",
        ],
    ),
    TaskClass.INTENT_ASSESSMENT: TaskClassSpec(
        name=TaskClass.INTENT_ASSESSMENT,
        verifiable=False,
        acceptance_criteria=[
            "Attribution and intent claims not mechanically verifiable. "
            "Operator-led only; the AI may not declare attribution unilaterally.",
        ],
    ),
}


class UnknownTaskClassError(ValueError):
    pass


def get_task_class(name: str | TaskClass) -> TaskClassSpec:
    """Return the spec for a task class. Accepts the enum or its string name.

    Raises :class:`UnknownTaskClassError` with the valid set in the message
    when the name doesn't resolve — used by engagement-start binding and the
    CLI prompt to give the operator a clear error.
    """
    if isinstance(name, TaskClass):
        return TASK_CLASSES[name]
    try:
        member = TaskClass(name)
    except ValueError as e:
        valid = ", ".join(c.value for c in TaskClass)
        raise UnknownTaskClassError(
            f"unknown task class: {name!r}. valid: {valid}"
        ) from e
    return TASK_CLASSES[member]


def all_task_classes() -> list[TaskClass]:
    """Stable-ordered list of declared task classes. Used by profile defaults
    (a profile with no explicit ``allowed_task_classes`` gets the full list)
    and by the CLI prompt to show the operator's choices."""
    return list(TaskClass)


__all__ = [
    "TaskClass",
    "CategorySpec",
    "TaskClassSpec",
    "TASK_CLASSES",
    "UnknownTaskClassError",
    "get_task_class",
    "all_task_classes",
]
