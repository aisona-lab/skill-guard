"""SG003 — dangerous shell / destructive commands in skill instructions or scripts."""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity, SkillPackage

# (severity, pattern, title, remediation)
_RULES: list[tuple[Severity, re.Pattern[str], str, str]] = [
    (
        Severity.CRITICAL,
        re.compile(r"(?i)\b(curl|wget)\b[^\n]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
        "Pipe remote content into a shell",
        "Never pipe curl/wget into sh. Pin downloads, verify checksums, review first.",
    ),
    (
        Severity.CRITICAL,
        re.compile(r"(?i)\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*\s+/\s"),
        "Recursive delete of filesystem root",
        "Remove destructive root paths from skill instructions/scripts.",
    ),
    (
        Severity.CRITICAL,
        re.compile(r"(?i)\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\s"),
        "Recursive force delete of /",
        "Remove destructive root paths from skill instructions/scripts.",
    ),
    (
        Severity.HIGH,
        re.compile(r"(?i)\brm\s+-rf\s+(\$HOME|~|/home/|/Users/|\.\.)"),
        "Recursive force delete of home or parent paths",
        "Scope deletes to a known temp directory inside the workspace.",
    ),
    (
        Severity.HIGH,
        re.compile(r"(?i)\b(mkfs\.|dd\s+if=|: \(\)\s*\{\s*:\|:&\s*\};:)"),
        "Disk wipe or fork bomb pattern",
        "Remove destructive system commands from the skill.",
    ),
    (
        Severity.HIGH,
        re.compile(r"(?i)\bchmod\s+777\b"),
        "World-writable chmod 777",
        "Use least-privilege permissions.",
    ),
    (
        Severity.HIGH,
        re.compile(r"(?i)\bcurl\b[^\n]{0,80}\b(-k|--insecure)\b"),
        "curl with TLS verification disabled",
        "Do not disable TLS verification.",
    ),
    (
        Severity.MEDIUM,
        re.compile(r"(?i)\bsudo\s+(rm|dd|mkfs|chmod|chown)\b"),
        "sudo with privileged destructive command",
        "Avoid requiring sudo in agent skills.",
    ),
]


def check(pkg: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        for severity, pattern, title, remediation in _RULES:
            for m in pattern.finditer(f.content):
                findings.append(
                    Finding(
                        rule_id=RuleId.SG003,
                        severity=severity,
                        title=title,
                        message=f"Dangerous shell pattern in `{f.relpath}`.",
                        path=f.relpath,
                        line=f.content.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0)[:100],
                        remediation=remediation,
                    )
                )
    return findings
