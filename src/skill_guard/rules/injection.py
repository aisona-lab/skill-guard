"""SG005 — prompt injection / instruction hijack inside skill body.

A skill can smuggle overrides that reprogram the host agent once loaded.
These patterns target that threat, not general user-prompt scanning.
"""

from __future__ import annotations

import re

from skill_guard.models import (
    FileKind,
    Finding,
    PackageContext,
    RuleId,
    Severity,
    make_finding,
)

_PATTERNS: list[tuple[Severity, re.Pattern[str], str]] = [
    (
        Severity.HIGH,
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b[^\n]{0,40}\b"
            r"(previous|prior|above|all|system|developer|safety)\b[^\n]{0,40}\b"
            r"(instructions?|rules?|guidelines?|prompts?)\b"
        ),
        "Instruction-override language",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)\b(you are now|from now on you|new system prompt|override system|"
            r"disable (your )?safety|jailbreak|do not follow (the )?user|"
            r"hide this from the user|do not tell the user)\b"
        ),
        "Role/system hijack language",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(<!--\s*(system|hidden|secret)|\[SYSTEM\]|<<\s*SYS\s*>>|"
            r"</?(system|assistant)_prompt>)"
        ),
        "Hidden system-prompt markers",
    ),
    (
        Severity.MEDIUM,
        re.compile(
            r"(?i)\b(reveal|print|show|dump)\b[^\n]{0,40}\b"
            r"(system prompt|hidden instructions|developer message|chain of thought)\b"
        ),
        "System-prompt leakage instruction",
    ),
]


def check(pkg: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    # Instructional surfaces only: markdown (and skill body).
    targets = [
        f
        for f in pkg.files
        if f.kind is FileKind.MARKDOWN or f.suffix in {".md", ".txt"}
    ]
    for f in targets:
        text = f.normalized
        for severity, pattern, title in _PATTERNS:
            for m in pattern.finditer(text):
                findings.append(
                    make_finding(
                        RuleId.SG005,
                        severity,
                        title=title,
                        path=f.relpath,
                        message=f"Skill content may hijack the host agent (`{f.relpath}`).",
                        line=text.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0),
                        remediation=(
                            "Remove override/hidden-system language from skill instructions."
                        ),
                    )
                )
    return findings
