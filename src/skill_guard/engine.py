"""Scan orchestration: load → rules → config filter → aggregate.

Never executes skill code. Normalization happens once in load_package.
"""

from __future__ import annotations

from pathlib import Path

from skill_guard.config import SkillGuardConfig, apply_config_to_findings, load_config
from skill_guard.models import ScanResult, aggregate_verdict, dedupe_findings
from skill_guard.parser import load_package
from skill_guard.rules import all_rules


def scan_path(
    path: str | Path,
    *,
    rules: list[str] | None = None,
    config: SkillGuardConfig | None = None,
    config_path: str | Path | None = None,
) -> ScanResult:
    """Scan a skill directory or SKILL.md path."""
    cfg = config if config is not None else load_config(config_path)
    ctx = load_package(path)
    selected = all_rules()
    if rules:
        allow = {r.upper() for r in rules}
        selected = [(rid, fn) for rid, fn in selected if rid.value in allow]
    else:
        selected = [
            (rid, fn)
            for rid, fn in selected
            if cfg.rules.get(rid.value) is None or cfg.rules[rid.value].enabled
        ]

    findings = []
    ran: list[str] = []
    for rid, fn in selected:
        ran.append(rid.value)
        findings.extend(fn(ctx))

    findings = dedupe_findings(findings)
    findings = apply_config_to_findings(findings, cfg)
    verdict = aggregate_verdict(findings)

    return ScanResult(
        target=str(Path(path).expanduser().resolve()),
        verdict=verdict,
        findings=findings,
        skill_name=ctx.name,
        files_scanned=len(ctx.files),
        rules_run=ran,
        meta={
            "parse_errors": list(ctx.parse_errors),
            "root": ctx.root,
            "fail_on": cfg.fail_on,
        },
    )


def scan_many(
    paths: list[str | Path],
    *,
    rules: list[str] | None = None,
    config: SkillGuardConfig | None = None,
    config_path: str | Path | None = None,
) -> list[ScanResult]:
    """Batch scan multiple skill roots."""
    return [
        scan_path(p, rules=rules, config=config, config_path=config_path) for p in paths
    ]
