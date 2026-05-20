"""ModelProfile — YAML-defined adapter per model.

Every supported model declares: tool-call protocol, prompt style, context size,
generation params, coaching hints, recommended workflows, and which prompt parts
to compose. Swapping models is a profile-file swap, not a code change.

The structural-defenses fields (``allowed_task_classes``,
``require_evidence_citation``) gate which kinds of analyst work a profile may
engage with and whether the rendering layer enforces evidence citations on its
output. Both default to permissive — explicit restriction is the opt-in.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from blue_bench_mcp.task_classes import TaskClass, all_task_classes


ToolProtocol = Literal["native", "text-embedded", "anthropic-native"]
PromptStyle = Literal["verbose-ok", "terse", "thinking-enabled"]


class GenerationParams(BaseModel):
    temperature: float | None = None
    top_p: float | None = None
    top_k: int | None = None


class ModelProfile(BaseModel):
    name: str
    model_id: str
    tool_protocol: ToolProtocol
    prompt_style: PromptStyle
    context_size: int = Field(..., gt=0)
    generation: GenerationParams = Field(default_factory=GenerationParams)
    coaching_hints: list[str] = Field(default_factory=list)
    recommended_workflows: list[str] = Field(default_factory=list)
    prompt_parts: dict[str, str] = Field(default_factory=dict)
    allowed_task_classes: list[TaskClass] = Field(default_factory=all_task_classes)
    """Task classes this profile may engage with. Defaults to all declared
    classes; restrict explicitly when a model should not be trusted with the
    full surface (e.g. an uncoached or capability-limited profile)."""
    require_task_class: bool = True
    """When false, the task-class prompt and enforcement are skipped entirely.
    Set to false in development profiles or when task-class scoping is not yet
    required for an engagement. Production profiles should leave this true."""
    require_evidence_citation: bool = True
    """When true, the renderer enforces citation markers on findings and
    surfaces ungrounded entities as conjecture. Disable only for free-form
    profiles where citation enforcement is out of scope."""


def load_profile(path: Path) -> ModelProfile:
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return ModelProfile.model_validate(data)
