"""Runner trace schema — consumed by blue_bench_eval.qualify for scoring.

This format is load-bearing: Phase 2 judging reads `turns` to score tool usage
and `final_answer` to score findings. Keep field names stable.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    name: str
    args: dict[str, Any]


class Turn(BaseModel):
    role: Literal["assistant", "tool", "user"]
    content: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_name: str | None = None  # for role="tool"
    duration_ms: int | None = None


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
