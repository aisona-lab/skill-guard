"""SG006 — supply-chain risks: remote code install, unpinned packages, postinstall."""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity, SkillPackage

_PATTERNS: list[tuple[Severity, re.Pattern[str], str, str]] = [
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)\b(npm|pnpm|yarn)\s+install\b[^\n]{0,80}"
            r"(https?://|git\+|github:|gist\.github)"
        ),
        "Install package from remote URL",
        "Pin to a registry package with version and integrity hash.",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)\bpip\s+install\b[^\n]{0,120}(https?://|git\+https|git\+ssh|--index-url|--extra-index-url)"
        ),
        "pip install from remote URL or custom index",
        "Install from PyPI with a pinned version, or vendor the package.",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)\b(npm|pnpm|yarn)\s+install\b[^\n]{0,100}(git\+ssh://|git\+https://|ssh://)"
        ),
        "Install package from git+ssh/https URL",
        "Pin to a registry package with version and integrity hash.",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)\b(npx|bunx)\s+(-y\s+)?https?://"
        ),
        "npx/bunx execution of remote URL",
        "Do not execute remote scripts via npx URL.",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)\b(eval|exec)\s*\(\s*(curl|wget|fetch|requests\.get|httpx\.get|urlopen)"
        ),
        "eval/exec of network-fetched content",
        "Never eval remote content.",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)[\"']postinstall[\"']\s*:\s*[\"'][^\"']*(curl|wget|node\s+-e|python\s+-c)"
        ),
        "Suspicious package.json postinstall script",
        "Remove network or dynamic execution from postinstall.",
    ),
    (
        Severity.MEDIUM,
        re.compile(
            r"(?i)\b(npm\s+install\s+-g|pip\s+install\s+--user|cargo\s+install)\b"
        ),
        "Global package install from skill",
        "Prefer project-local installs; document exact versions.",
    ),
]


def check(pkg: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        for severity, pattern, title, remediation in _PATTERNS:
            for m in pattern.finditer(f.content):
                findings.append(
                    Finding(
                        rule_id=RuleId.SG006,
                        severity=severity,
                        title=title,
                        message=f"Supply-chain risk in `{f.relpath}`.",
                        path=f.relpath,
                        line=f.content.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0)[:120],
                        remediation=remediation,
                    )
                )
    return findings
