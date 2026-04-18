"""ModelProfile — YAML-defined adapter per model.

Every supported model declares: tool-call protocol, prompt style, context size,
generation params, coaching hints, recommended workflows, and which prompt parts
to compose. Swapping models is a profile-file swap, not a code change.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


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


def load_profile(path: Path) -> ModelProfile:
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return ModelProfile.model_validate(data)
