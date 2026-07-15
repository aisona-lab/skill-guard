"""SG009 — identity spoofing / typosquat signals.

Conservative: flags only explicit impersonation claims, not every famous name
mention in a tutorial.
"""

from __future__ import annotations

import re

from skill_guard.models import Finding, PackageContext, RuleId, Severity

_CLAIM = re.compile(
    r"(?i)\b(official\s+(anthropic|openai|google|microsoft|amazon|meta)\s+skill|"
    r"this\s+is\s+the\s+official\s+(claude|chatgpt|gemini)\s+skill|"
    r"published\s+by\s+(anthropic|openai)\s+staff|"
    r"verified\s+by\s+(anthropic|openai)\b)"
)

# Homoglyph / lookalike names vs common trusted skills (small denylist).
_LOOKALIKE_NAMES = {
    "superpower",  # vs superpowers
    "superpowerss",
    "frontend-deslgn",  # i/l swap demo
    "claude-offical",
    "anthropic-skill",
    "openai-official",
}


def check(pkg: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    name = (pkg.name or "").lower()
    if name in _LOOKALIKE_NAMES:
        findings.append(
            Finding(
                rule_id=RuleId.SG009,
                severity=Severity.HIGH,
                title="Skill name matches known lookalike/typosquat pattern",
                message=f"name `{name}` is on the lookalike denylist.",
                path="SKILL.md",
                remediation="Choose a distinct name; do not mimic popular skills.",
            )
        )

    blob = pkg.text_blob()
    for m in _CLAIM.finditer(blob):
        findings.append(
            Finding(
                rule_id=RuleId.SG009,
                severity=Severity.HIGH,
                title="Impersonation claim of a major vendor",
                message="Skill claims official vendor affiliation without verifiable metadata.",
                evidence=m.group(0)[:120],
                remediation="Remove official-vendor claims unless you control that publisher identity.",
            )
        )
    return findings
