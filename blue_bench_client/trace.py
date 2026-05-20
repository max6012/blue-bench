"""Runner trace schema — consumed by blue_bench_eval.qualify for scoring.

This format is load-bearing: Phase 2 judging reads `turns` to score tool usage
and `final_answer` to score findings. Keep existing field names stable.

The optional ``grounding`` field is populated by the mechanical grounding pass
(blue_bench_client/grounding.py) when enabled by the engagement's defenses
config. ``None`` means the pass did not run for this trace.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


EntityType = Literal[
    "ip",
    "cidr",
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "hostname",
    "event_id",
    "pid",
    "username",
    "path",
    "cve",
    "domain",
    "port",
]


class ToolCall(BaseModel):
    name: str
    args: dict[str, Any]


class Turn(BaseModel):
    role: Literal["assistant", "tool", "user"]
    content: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_name: str | None = None  # for role="tool"
    duration_ms: int | None = None


class EntityClaim(BaseModel):
    """A specific entity extracted from the model's final answer.

    ``span_start`` and ``span_end`` are character offsets into ``Trace.final_answer``
    — the renderer uses them to insert citation markers in place. ``value`` is
    the literal substring at that span, stored separately for convenience and
    serialization stability (audit log replay should not require re-extracting).
    """
    entity_type: EntityType
    value: str
    span_start: int
    span_end: int


class ToolCallRef(BaseModel):
    """Stable reference to a tool call in a Trace.

    Synthesized at grounding time from (turn_index, call_index_within_turn) —
    the ``Turn`` model does not carry a persistent id, so this ref is the
    canonical way for ``GroundedClaim`` and audit-log entries to point at a
    specific tool call.
    """
    turn_index: int
    call_index: int
    tool_name: str


class GroundedClaim(BaseModel):
    """An ``EntityClaim`` linked to the tool call whose output literally contains
    the entity value. The ``excerpt`` is the matching substring from the tool
    result — preserved verbatim so the renderer can quote it in the evidence
    appendix without re-walking the trace."""
    claim: EntityClaim
    grounded_in: ToolCallRef
    excerpt: str


class GroundingResult(BaseModel):
    """Output of the mechanical grounding pass over a completed trace.

    Three buckets:
      - ``grounded``: entity claims whose value appears literally in a tool result
      - ``ungrounded``: entity claims that do NOT appear in any tool result —
        the high-signal failure mode (fabricated entities)
      - ``unverifiable_spans``: character ranges in ``final_answer`` containing
        prose with no extractable entity — pure conjecture, scored separately

    The renderer surfaces all three. ``ungrounded`` claims and unverifiable
    spans are visually distinct from grounded findings so the operator can tell
    plausible-but-unsupported text from evidence-anchored findings.
    """
    grounded: list[GroundedClaim] = Field(default_factory=list)
    ungrounded: list[EntityClaim] = Field(default_factory=list)
    unverifiable_spans: list[tuple[int, int]] = Field(default_factory=list)


class Trace(BaseModel):
    prompt_id: str
    profile_name: str
    model_id: str
    tool_protocol: Literal["native", "text-embedded", "anthropic-native"]
    question: str
    composed_system_prompt: str
    tools_available: list[str]
    turns: list[Turn] = Field(default_factory=list)
    final_answer: str = ""
    turns_used: int = 0
    max_turns: int = 10
    total_duration_ms: int = 0
    error: str | None = None
    grounding: GroundingResult | None = None
    """Populated when the mechanical grounding pass runs over this trace.
    ``None`` means the pass did not run (e.g., defenses.grounding.mode=off,
    or the engagement's task class has verifiable=False)."""
