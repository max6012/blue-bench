"""PromptSpec — YAML schema + loader for Phase 2 prompts.

Each prompt in blue_bench_eval/prompts/{id}.yaml validates against this model.
The question field is what's sent to the model; expected_tools and
expected_findings drive scoring.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class FindingSynonymSet(BaseModel):
    synonyms: list[str] = Field(..., min_length=1)


class PromptSpec(BaseModel):
    id: str
    category: str
    archive_id: int | None = None
    title: str
    question: str
    expected_tools: list[str] = Field(default_factory=list)
    expected_findings: list[FindingSynonymSet] = Field(default_factory=list)
    pass_criteria: str = ""
    tags: list[str] = Field(default_factory=list)
    max_turns: int = 10


def load_prompt(path: Path) -> PromptSpec:
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return PromptSpec.model_validate(data)


def load_all(prompts_dir: Path) -> list[PromptSpec]:
    out: list[PromptSpec] = []
    for yaml_path in sorted(prompts_dir.glob("p2-*.yaml")):
        out.append(load_prompt(yaml_path))
    return out
