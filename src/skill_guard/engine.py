"""Scan orchestration: load → rules → aggregate. Never executes skill code."""

from __future__ import annotations

from pathlib import Path

from skill_guard.models import ScanResult, aggregate_verdict
from skill_guard.parser import load_package
from skill_guard.rules import all_rules


def scan_path(path: str | Path, *, rules: list[str] | None = None) -> ScanResult:
    """Scan a skill directory or SKILL.md path.

    Parameters
    ----------
    path:
        Filesystem path to audit.
    rules:
        Optional allowlist of rule ids (e.g. ["SG002", "SG004"]). Default: all.
    """
    pkg = load_package(path)
    selected = all_rules()
    if rules:
        allow = {r.upper() for r in rules}
        selected = [(rid, fn) for rid, fn in selected if rid in allow]

    findings = []
    ran: list[str] = []
    for rid, fn in selected:
        ran.append(rid)
        findings.extend(fn(pkg))

    # Deduplicate identical findings (same rule, path, title, line)
    findings = _dedupe(findings)
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
        },
    )


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
