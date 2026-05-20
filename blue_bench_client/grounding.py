"""Mechanical grounding pass — validates entity claims against the tool-call ledger.

Strict-by-design: an entity is grounded if and only if its literal value
appears as a substring in at least one tool result turn. No fuzzy matching,
no normalisation beyond case-fold for hex hashes.
"""
from __future__ import annotations

from blue_bench_client.entities import SLICE_ENTITY_TYPES, extract_entities
from blue_bench_client.trace import (
    EntityClaim,
    EntityType,
    GroundedClaim,
    GroundingResult,
    ToolCallRef,
    Trace,
)


def _collect_tool_results(trace: Trace) -> list[tuple[int, str, str]]:
    """Return (turn_index, tool_name, content) for every tool-result turn."""
    results = []
    for i, turn in enumerate(trace.turns):
        if turn.role == "tool" and turn.content:
            results.append((i, turn.tool_name or "", turn.content))
    return results


def _find_excerpt(value: str, content: str, entity_type: EntityType) -> str | None:
    """Return the matching excerpt from content, or None if not found.

    Hash values are matched case-insensitively — hex strings are case-ambiguous
    across tools (Wazuh may uppercase; the model may normalise). All other
    entity types require a literal case-sensitive match so we don't accept
    prose that happens to share an IP-shaped octet run.
    """
    if entity_type.startswith("hash_"):
        idx = content.lower().find(value.lower())
        if idx == -1:
            return None
        return content[idx : idx + len(value)]
    idx = content.find(value)
    if idx == -1:
        return None
    return content[idx : idx + len(value)]


def run_grounding_pass(
    trace: Trace,
    entity_types: tuple[EntityType, ...] | None = None,
) -> GroundingResult:
    """Run the mechanical grounding pass over a completed trace.

    Extracts entities from ``trace.final_answer`` and checks each against every
    tool-result turn. Produces a ``GroundingResult`` classifying claims into:

    - ``grounded``: entity value appears literally in a tool result
    - ``ungrounded``: entity value absent from every tool result (fabricated or
      paraphrased away — the high-signal failure mode)
    - ``unverifiable_spans``: prose regions in ``final_answer`` that contain no
      extractable entity claim

    ``entity_types`` defaults to ``SLICE_ENTITY_TYPES``. Pass a subset to
    match the profile's ``defenses.grounding.entity_types`` restriction.
    """
    effective_types = entity_types if entity_types is not None else SLICE_ENTITY_TYPES
    claims = extract_entities(trace.final_answer, types=effective_types)
    tool_results = _collect_tool_results(trace)

    grounded: list[GroundedClaim] = []
    ungrounded: list[EntityClaim] = []

    for claim in claims:
        matched = False
        for turn_idx, tool_name, content in tool_results:
            excerpt = _find_excerpt(claim.value, content, claim.entity_type)
            if excerpt is not None:
                grounded.append(
                    GroundedClaim(
                        claim=claim,
                        grounded_in=ToolCallRef(
                            turn_index=turn_idx,
                            call_index=0,
                            tool_name=tool_name,
                        ),
                        excerpt=excerpt,
                    )
                )
                matched = True
                break
        if not matched:
            ungrounded.append(claim)

    unverifiable_spans = _compute_unverifiable_spans(trace.final_answer, claims)

    return GroundingResult(
        grounded=grounded,
        ungrounded=ungrounded,
        unverifiable_spans=unverifiable_spans,
    )


def _compute_unverifiable_spans(
    text: str,
    claims: list[EntityClaim],
    min_length: int = 20,
) -> list[tuple[int, int]]:
    """Return spans in ``text`` not covered by any entity claim.

    Spans shorter than ``min_length`` characters are omitted — single spaces,
    punctuation, and conjunctions between entities are not useful to surface.
    """
    if not text:
        return []
    covered = sorted((c.span_start, c.span_end) for c in claims)
    spans: list[tuple[int, int]] = []
    cursor = 0
    for start, end in covered:
        if start > cursor and start - cursor >= min_length:
            spans.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < len(text) and len(text) - cursor >= min_length:
        spans.append((cursor, len(text)))
    return spans
