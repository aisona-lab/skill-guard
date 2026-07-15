"""SG009 — identity spoofing / typosquat signals."""

from __future__ import annotations

import re

from skill_guard.models import Finding, PackageContext, RuleId, Severity, make_finding

_CLAIM = re.compile(
    r"(?i)\b(official\s+(anthropic|openai|google|microsoft|amazon|meta)\s+skill|"
    r"this\s+is\s+the\s+official\s+(claude|chatgpt|gemini)\s+skill|"
    r"published\s+by\s+(anthropic|openai)\s+staff|"
    r"verified\s+by\s+(anthropic|openai)\b)"
)

_LOOKALIKE_NAMES = {
    "superpower",
    "superpowerss",
    "frontend-deslgn",
    "claude-offical",
    "anthropic-skill",
    "openai-official",
}


def check(pkg: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    name = (pkg.name or "").lower()
    if name in _LOOKALIKE_NAMES:
        findings.append(
            make_finding(
                RuleId.SG009,
                Severity.HIGH,
                title="Skill name matches known lookalike/typosquat pattern",
                path="SKILL.md",
                message=f"name `{name}` is on the lookalike denylist.",
                remediation="Choose a distinct name; do not mimic popular skills.",
            )
        )

    for m in _CLAIM.finditer(pkg.text_blob()):
        findings.append(
            make_finding(
                RuleId.SG009,
                Severity.HIGH,
                title="Impersonation claim of a major vendor",
                message=(
                    "Skill claims official vendor affiliation without verifiable metadata."
                ),
                evidence=m.group(0),
                remediation=(
                    "Remove official-vendor claims unless you control that publisher identity."
                ),
            )
        )
    return findings
