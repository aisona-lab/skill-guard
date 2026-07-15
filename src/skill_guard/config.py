"""Optional `.skill-guard.yml` configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from skill_guard.models import Finding, Severity

FailOn = Literal["never", "warn", "block"]


class RuleConfig(BaseModel):
    enabled: bool = True
    severity: Severity | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _parse_severity(cls, v: object) -> Severity | None:
        if v is None or v == "":
            return None
        if isinstance(v, Severity):
            return v
        try:
            return Severity(str(v).lower())
        except ValueError as exc:
            raise ValueError(
                f"invalid severity {v!r}; expected one of "
                f"{', '.join(s.value for s in Severity)}"
            ) from exc


class SkillGuardConfig(BaseModel):
    """User/project configuration for scan behavior."""

    fail_on: FailOn = "block"
    rules: dict[str, RuleConfig] = Field(default_factory=dict)
    suppress: list[str] = Field(
        default_factory=list,
        description="Rule ids or rule:path, e.g. SG008 or SG001:SKILL.md",
    )

    @field_validator("fail_on", mode="before")
    @classmethod
    def _parse_fail_on(cls, v: object) -> str:
        s = str(v or "block").lower()
        if s not in {"never", "warn", "block"}:
            raise ValueError("fail_on must be never|warn|block")
        return s


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
            key = str(k).upper()
            if isinstance(v, bool):
                rules[key] = RuleConfig(enabled=v)
            elif isinstance(v, dict):
                rules[key] = RuleConfig.model_validate(v)
    return SkillGuardConfig(
        fail_on=data.get("fail_on", "block"),
        rules=rules,
        suppress=[str(x) for x in (data.get("suppress") or [])],
    )


def apply_config_to_findings(
    findings: list[Finding], cfg: SkillGuardConfig
) -> list[Finding]:
    """Filter suppressed / disabled rules; apply severity overrides."""
    disabled = {rid for rid, rc in cfg.rules.items() if not rc.enabled}
    out: list[Finding] = []
    for f in findings:
        rid = f.rule_id.value
        if rid in disabled:
            continue
        if _suppressed(rid, f.path, cfg.suppress):
            continue
        rc = cfg.rules.get(rid)
        if rc and rc.severity is not None:
            f = f.model_copy(update={"severity": rc.severity})
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
