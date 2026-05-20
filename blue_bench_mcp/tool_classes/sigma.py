"""SigmaTool — Sigma rule validation (pure-Python, no sigma-cli dependency).

Phase 2 p2-06 is the DR prompt that targets G4's known Phase 1 regression.
The model writes a Sigma rule; this tool validates YAML structure + required
fields. More strict than 'does it parse' — we also check selection shape.
"""
from __future__ import annotations

from typing import Any

import yaml

from blue_bench_mcp.config import ServerConfig
from blue_bench_mcp.guardrails import truncate_results


class SigmaTool:
    REQUIRED_TOP = ("title", "logsource", "detection")
    LOGSOURCE_HINTS = ("category", "product", "service")

    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.max_chars = cfg.limits.max_result_chars

    async def validate_rule(self, rule_yaml: str) -> str:
        """Validate a Sigma rule's YAML syntax + required schema fields.

        Checks: parseability; required top-level keys (title, logsource,
        detection); logsource contains at least one of category/product/service;
        detection contains a 'condition' field; detection selections are
        mappings (field keys), not literal AND/OR keywords.

        Args:
            rule_yaml: The Sigma rule as a YAML string.
        """
        try:
            data = yaml.safe_load(rule_yaml)
        except yaml.YAMLError as e:
            return f"INVALID — YAML parse error: {e}"
        if not isinstance(data, dict):
            return "INVALID — top-level must be a YAML mapping (dict)."

        errors: list[str] = []
        for key in self.REQUIRED_TOP:
            if key not in data:
                errors.append(f"missing required top-level key: '{key}'")

        if "logsource" in data:
            ls = data["logsource"]
            if not isinstance(ls, dict):
                errors.append("'logsource' must be a mapping")
            elif not any(k in ls for k in self.LOGSOURCE_HINTS):
                errors.append(
                    f"'logsource' should contain at least one of {list(self.LOGSOURCE_HINTS)}"
                )

        if "detection" in data:
            det = data["detection"]
            if not isinstance(det, dict):
                errors.append("'detection' must be a mapping")
            else:
                if "condition" not in det:
                    errors.append("'detection' must contain a 'condition' field")
                # Check selections aren't literal AND/OR keywords (common G4 mistake).
                for sel_name, sel_body in det.items():
                    if sel_name == "condition":
                        continue
                    if isinstance(sel_body, dict):
                        for field in sel_body:
                            if isinstance(field, str) and field.strip().upper() in ("AND", "OR", "NOT"):
                                errors.append(
                                    f"selection '{sel_name}' uses literal '{field}' as a field key — "
                                    f"AND/OR/NOT belong in 'condition', not selection bodies"
                                )

        if errors:
            body = "\n".join(f"  - {e}" for e in errors)
            return f"INVALID — {len(errors)} problem(s):\n{body}"

        # Warnings for common omissions (don't fail the rule; surface for coaching).
        warnings: list[str] = []
        if "level" not in data:
            warnings.append("no 'level' field (recommend informational|low|medium|high|critical)")
        if "status" not in data:
            warnings.append("no 'status' field (recommend experimental|test|stable)")
        if "tags" not in data:
            warnings.append("no 'tags' field (MITRE ATT&CK references recommended)")

        result = "VALID — rule structure OK."
        if warnings:
            body = "\n".join(f"  - {w}" for w in warnings)
            result += f"\n\nWarnings (non-blocking):\n{body}"
        return truncate_results(result, self.max_chars)
