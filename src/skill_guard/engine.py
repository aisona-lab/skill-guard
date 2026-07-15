"""Scan orchestration: load → rules → config filter → aggregate. Never executes skill code."""

from __future__ import annotations

from pathlib import Path

from skill_guard.config import SkillGuardConfig, apply_config_to_findings, load_config
from skill_guard.models import ScanResult, aggregate_verdict
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
    pkg = load_package(path)
    selected = all_rules()
    if rules:
        allow = {r.upper() for r in rules}
        selected = [(rid, fn) for rid, fn in selected if rid in allow]
    else:
        # respect disabled rules from config
        selected = [
            (rid, fn)
            for rid, fn in selected
            if cfg.rules.get(rid) is None or cfg.rules[rid].enabled
        ]

    findings = []
    ran: list[str] = []
    for rid, fn in selected:
        ran.append(rid)
        findings.extend(fn(pkg))

    findings = _dedupe(findings)
    findings = apply_config_to_findings(findings, cfg)
    verdict = aggregate_verdict(findings)

    return ScanResult(
        target=str(Path(path).expanduser().resolve()),
        verdict=verdict,
        findings=findings,
        skill_name=pkg.name,
        files_scanned=len(pkg.files),
        rules_run=ran,
        meta={
            "parse_errors": list(pkg.parse_errors),
            "root": pkg.root,
            "fail_on": cfg.fail_on,
        },
    )


def scan_many(paths: list[str | Path], **kwargs) -> list[ScanResult]:
    """Batch scan multiple skill roots."""
    return [scan_path(p, **kwargs) for p in paths]


def _dedupe(findings: list) -> list:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.path, f.title, f.line, f.message)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
