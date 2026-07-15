"""SG008 — token / context bloat.

Agent Skills progressive disclosure recommends SKILL.md under ~500 lines.
We approximate size with line/word counts (not a tokenizer claim).
"""

from __future__ import annotations

from skill_guard.models import Finding, PackageContext, RuleId, Severity, make_finding

_MAX_BODY_LINES = 500
_MAX_BODY_WORDS = 3500
_MAX_TOTAL_WORDS = 20000
_MAX_FILES = 80


def check(pkg: PackageContext) -> list[Finding]:
    findings: list[Finding] = []

    if pkg.skill_md:
        body = pkg.body or ""
        lines = body.count("\n") + (1 if body else 0)
        words = len(body.split())
        if lines > _MAX_BODY_LINES:
            findings.append(
                make_finding(
                    RuleId.SG008,
                    Severity.MEDIUM,
                    title="SKILL.md body exceeds recommended line budget",
                    path="SKILL.md",
                    message=(
                        f"Body has {lines} lines; progressive disclosure recommends "
                        f"≤{_MAX_BODY_LINES}. Move detail into references/."
                    ),
                    remediation="Split long instructions into references/ loaded on demand.",
                )
            )
        if words > _MAX_BODY_WORDS:
            findings.append(
                make_finding(
                    RuleId.SG008,
                    Severity.MEDIUM,
                    title="SKILL.md body is very large (token bloat risk)",
                    path="SKILL.md",
                    message=f"Body has ~{words} words (rough offline estimate).",
                    remediation=(
                        "Keep activation instructions short; put deep docs in references/."
                    ),
                )
            )

    total_words = sum(len(f.content.split()) for f in pkg.files)
    if total_words > _MAX_TOTAL_WORDS:
        findings.append(
            make_finding(
                RuleId.SG008,
                Severity.MEDIUM,
                title="Skill package total text is very large",
                message=(
                    f"Package contains ~{total_words} words across {len(pkg.files)} files."
                ),
                remediation="Trim vendor docs; keep only what the agent must load.",
            )
        )

    if len(pkg.files) > _MAX_FILES:
        findings.append(
            make_finding(
                RuleId.SG008,
                Severity.LOW,
                title="Many files in skill package",
                message=f"{len(pkg.files)} text files scanned (budget {_MAX_FILES}).",
            )
        )

    return findings
