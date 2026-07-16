"""Optional `.skill-guard.yml` configuration + built-in policy packs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from skill_guard.models import Finding, Severity

FailOn = Literal["never", "warn", "block"]
PackName = Literal["default", "strict"]

# Built-in packs (ponytail: no separate files until we need more knobs).
POLICY_PACKS: dict[str, dict[str, Any]] = {
    "default": {
        "fail_on": "block",  # WARN does not fail CI
    },
    "strict": {
        "fail_on": "warn",  # MEDIUM+ fails CI
    },
}


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

    pack: str | None = None
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


def load_config(
    path: str | Path | None = None,
    *,
    pack: str | None = None,
) -> SkillGuardConfig:
    """Load config from path / parents, then apply optional pack + pack field."""
    base = SkillGuardConfig()
    if path is not None:
        p = Path(path)
        if p.is_file():
            base = _parse(p.read_text(encoding="utf-8"))
    else:
        cwd = Path.cwd()
        for folder in [cwd, *cwd.parents]:
            candidate = folder / ".skill-guard.yml"
            if candidate.is_file():
                base = _parse(candidate.read_text(encoding="utf-8"))
                break
            if (folder / ".git").exists():
                break

    chosen = pack or base.pack
    if chosen:
        base = apply_pack(base, chosen)
    return base


def apply_pack(cfg: SkillGuardConfig, pack: str) -> SkillGuardConfig:
    """Overlay a built-in policy pack. Explicit fail_on in file wins only if pack not forced.

    Pack applies fail_on defaults; YAML keys already on cfg that match pack are
    overwritten by pack for fail_on (pack is the profile selector).
    """
    name = pack.strip().lower()
    if name not in POLICY_PACKS:
        raise ValueError(
            f"unknown pack {pack!r}; expected one of {', '.join(sorted(POLICY_PACKS))}"
        )
    overlay = POLICY_PACKS[name]
    return cfg.model_copy(
        update={
            "pack": name,
            "fail_on": overlay.get("fail_on", cfg.fail_on),
        }
    )


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
    pack = data.get("pack")
    cfg = SkillGuardConfig(
        pack=str(pack) if pack else None,
        fail_on=data.get("fail_on", "block"),
        rules=rules,
        suppress=[str(x) for x in (data.get("suppress") or [])],
    )
    # If YAML sets pack but also fail_on, keep explicit fail_on after pack default:
    if pack:
        packed = apply_pack(SkillGuardConfig(pack=str(pack)), str(pack))
        # file fail_on wins when user set both pack and fail_on
        if "fail_on" in data:
            return packed.model_copy(
                update={
                    "fail_on": cfg.fail_on,
                    "rules": rules,
                    "suppress": cfg.suppress,
                }
            )
        return packed.model_copy(update={"rules": rules, "suppress": cfg.suppress})
    return cfg


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
