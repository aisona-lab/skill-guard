"""Optional `.skill-guard.yml` configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class RuleConfig(BaseModel):
    enabled: bool = True
    severity: str | None = None  # optional override: low|medium|high|critical


class SkillGuardConfig(BaseModel):
    """User/project configuration for scan behavior."""

    fail_on: str = "block"  # never|warn|block
    rules: dict[str, RuleConfig] = Field(default_factory=dict)
    suppress: list[str] = Field(
        default_factory=list,
        description="Rule ids or rule:path globs to suppress, e.g. SG008 or SG001:SKILL.md",
    )


def load_config(path: str | Path | None = None) -> SkillGuardConfig:
    """Load config from path, or walk parents for `.skill-guard.yml`."""
    if path is not None:
        p = Path(path)
        if not p.is_file():
            return SkillGuardConfig()
        return _parse(p.read_text(encoding="utf-8"))

    cwd = Path.cwd()
    for folder in [cwd, *cwd.parents]:
        candidate = folder / ".skill-guard.yml"
        if candidate.is_file():
            return _parse(candidate.read_text(encoding="utf-8"))
        if (folder / ".git").exists():
            break
    return SkillGuardConfig()


def _parse(raw: str) -> SkillGuardConfig:
    data: Any = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        return SkillGuardConfig()
    rules_in = data.get("rules") or {}
    rules: dict[str, RuleConfig] = {}
    if isinstance(rules_in, dict):
        for k, v in rules_in.items():
            if isinstance(v, bool):
                rules[str(k).upper()] = RuleConfig(enabled=v)
            elif isinstance(v, dict):
                rules[str(k).upper()] = RuleConfig.model_validate(v)
    return SkillGuardConfig(
        fail_on=str(data.get("fail_on", "block")),
        rules=rules,
        suppress=[str(x) for x in (data.get("suppress") or [])],
    )


def apply_config_to_findings(findings: list, cfg: SkillGuardConfig) -> list:
    """Filter suppressed / disabled rules."""
    disabled = {rid for rid, rc in cfg.rules.items() if not rc.enabled}
    out = []
    for f in findings:
        rid = f.rule_id.value if hasattr(f.rule_id, "value") else str(f.rule_id)
        if rid in disabled:
            continue
        if _suppressed(rid, f.path, cfg.suppress):
            continue
        # severity override
        rc = cfg.rules.get(rid)
        if rc and rc.severity:
            from skill_guard.models import Severity

            try:
                f = f.model_copy(update={"severity": Severity(rc.severity.lower())})
            except Exception:
                pass
        out.append(f)
    return out


def _suppressed(rule_id: str, path: str | None, suppress: list[str]) -> bool:
    path = path or ""
    for item in suppress:
        if item.upper() == rule_id.upper():
            return True
        if ":" in item:
            rid, p = item.split(":", 1)
            if rid.upper() == rule_id.upper() and (p == path or path.endswith(p)):
                return True
    return False
