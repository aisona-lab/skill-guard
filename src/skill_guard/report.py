"""Human and JSON report rendering."""

from __future__ import annotations

import json
from typing import Any

from skill_guard.models import ScanResult, Severity

_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def result_dict(result: ScanResult) -> dict[str, Any]:
    """Canonical JSON-serializable scan result (includes exit_code)."""
    payload = result.model_dump(mode="json")
    payload["exit_code"] = result.exit_code
    return payload


def render_text(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"skill-guard  verdict={result.verdict.value}  exit={result.exit_code}")
    lines.append(f"target: {result.target}")
    if result.skill_name:
        lines.append(f"skill:  {result.skill_name}")
    lines.append(f"files:  {result.files_scanned}  rules: {', '.join(result.rules_run)}")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    ordered = sorted(
        result.findings, key=lambda f: (_SEV_ORDER[f.severity], f.rule_id.value)
    )
    for f in ordered:
        loc = f.path or ""
        if f.line:
            loc = f"{loc}:{f.line}" if loc else f"line {f.line}"
        head = f"[{f.severity.value.upper():8}] {f.rule_id.value}  {f.title}"
        lines.append(head)
        if loc:
            lines.append(f"  at: {loc}")
        lines.append(f"  {f.message}")
        if f.evidence:
            lines.append(f"  evidence: {f.evidence}")
        if f.remediation:
            lines.append(f"  fix: {f.remediation}")
        lines.append("")

    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    lines.append(f"{len(result.findings)} finding(s): {summary}")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    """JSON for a single scan target."""
    return json.dumps(result_dict(result), indent=2, ensure_ascii=False)


def render_json_multi(results: list[ScanResult]) -> str:
    """JSON for one or more targets (always a list when multi; single object when one)."""
    if len(results) == 1:
        return render_json(results[0])
    return json.dumps(
        [result_dict(r) for r in results], indent=2, ensure_ascii=False
    )
