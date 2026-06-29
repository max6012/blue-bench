"""Ollama Cloud catalogue — filtered to a manageable shortlist.

The raw cloud catalogue is ~35 models, too many to surface as run options. This
narrows it the way an operator picks a bake-off model: by recency (default: the
last 6 months) and by scale. The API does not expose ``parameter_size``, so we
use the model's download ``size`` (GB) as an honest scale proxy and label it as
such.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Friendly size buckets (download GB as a scale proxy — the API does not expose
# parameter counts). Rough param mapping in the labels is approximate.
SIZE_BANDS: dict[str, tuple[float | None, float | None]] = {
    "small": (None, 100.0),    # <=100 GB  (~ up to ~150B params: gpt-oss, gemma4:31b)
    "mid": (100.0, 500.0),     # 100-500 GB (~150-500B: qwen3.5:397b, minimax)
    "large": (500.0, None),    # >500 GB   (~500B+: glm-5, kimi, deepseek-v4-pro)
}


@dataclass(frozen=True)
class CloudModel:
    model: str            # the tag to put in a profile's model_id
    modified: datetime    # catalogue modified_at
    size_gb: float        # download size in GB (scale proxy; params not exposed)

    @property
    def age_months(self) -> float:
        return (datetime.now(timezone.utc) - self.modified).days / 30.44


def _all_cloud_models() -> list[CloudModel]:
    from blue_bench_client._ollama import make_client
    out: list[CloudModel] = []
    for m in make_client().list().models:
        mod = getattr(m, "modified_at", None)
        if mod is not None and mod.tzinfo is None:
            mod = mod.replace(tzinfo=timezone.utc)
        out.append(CloudModel(
            model=m.model,
            modified=mod or datetime.now(timezone.utc),
            size_gb=round((getattr(m, "size", 0) or 0) / 1e9, 1),
        ))
    return out


def list_cloud_models(
    *,
    since_months: float | None = 6.0,
    size: str | None = None,
    min_gb: float | None = None,
    max_gb: float | None = None,
) -> list[CloudModel]:
    """Filtered, sorted (newest first) cloud catalogue.

    Args:
        since_months: keep models modified within this many months (None = all).
        size: a SIZE_BANDS key (small|mid|large) — convenience for min/max_gb.
        min_gb / max_gb: keep models whose download size is in this range
            (None = unbounded). Size is a scale proxy — the API doesn't report
            parameter counts. Models hosted with no download size (0 GB) pass
            only when no size filter is applied.
    """
    if size is not None:
        if size not in SIZE_BANDS:
            raise ValueError(f"unknown size {size!r}; expected one of {list(SIZE_BANDS)}")
        min_gb, max_gb = SIZE_BANDS[size]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=since_months * 30.44)
              if since_months else None)
    size_filter = min_gb is not None or max_gb is not None
    models = [
        m for m in _all_cloud_models()
        if (cutoff is None or m.modified >= cutoff)
        # 0 GB = API-hosted (no download size); only drop it when a size band
        # was explicitly requested, since we can't place it on the scale.
        and not (size_filter and m.size_gb == 0)
        and (min_gb is None or m.size_gb >= min_gb)
        and (max_gb is None or m.size_gb <= max_gb)
    ]
    return sorted(models, key=lambda m: m.modified, reverse=True)


def generic_cloud_profile(model_id: str, *, guidelines: str = "threat_hunting_protocol.md"):
    """An in-memory ModelProfile for any cloud model_id — native tool-calling,
    large context, standard blue-team coaching. Lets the bench run any filtered
    catalogue model without a per-model profile file.

    ``guidelines`` selects the prompt-parts guidelines file; defaults to the
    phase-3 threat-hunting protocol (cloud bake-offs run the heavy-telemetry
    hunt). Pass ``investigation_protocol.md`` for phase-2 triage."""
    from blue_bench_mcp.profiles import ModelProfile
    return ModelProfile.model_validate({
        "name": f"cloud-{model_id.replace(':', '-').replace('/', '-')}",
        "model_id": model_id,
        "tool_protocol": "native",
        "prompt_style": "terse",
        "context_size": 32768,
        "generation": {"temperature": 0.3, "top_p": 0.9},
        "coaching_hints": [
            "Native tool-call protocol — emit structured tool_calls, no fenced JSON in the assistant text.",
            "Prefer aggregation (count_by_field, top-N) over raw reads during triage.",
            "Chain tools across host and network sources for correlation.",
            "For low-and-slow hunts, widen the tool time windows (large timerange_minutes).",
            "Flag data inconsistencies honestly rather than fabricating around them.",
        ],
        "recommended_workflows": ["triage", "forensics-lite", "detection-rules", "correlation"],
        "prompt_parts": {"role": "blue_team_analyst.md", "site": "default.md",
                         "guidelines": guidelines},
        "require_task_class": False,
    })
