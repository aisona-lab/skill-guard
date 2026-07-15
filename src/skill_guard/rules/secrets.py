"""SG002 — hardcoded secrets and credential material.

Patterns are high-precision. We never print full secret values in evidence.
"""

from __future__ import annotations

import re

from skill_guard.models import Finding, PackageContext, RuleId, Severity, make_finding

# Named patterns: (rule-sub, severity, regex, title)
# Order: more specific providers first.
_PATTERNS: list[tuple[str, Severity, re.Pattern[str], str]] = [
    (
        "anthropic",
        Severity.CRITICAL,
        re.compile(r"\bsk-ant-[a-zA-Z0-9\-_]{20,}\b"),
        "Anthropic API key",
    ),
    (
        "openai",
        Severity.CRITICAL,
        re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
        "OpenAI-style API key",
    ),
    (
        "github_pat",
        Severity.CRITICAL,
        re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
        "GitHub personal access token",
    ),
    (
        "github_fine",
        Severity.CRITICAL,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "GitHub fine-grained PAT",
    ),
    (
        "aws_access_key",
        Severity.CRITICAL,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS access key id",
    ),
    (
        "slack",
        Severity.CRITICAL,
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
        "Slack token",
    ),
    (
        "private_key",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private key material",
    ),
    (
        "generic_api_assign",
        Severity.HIGH,
        re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)"
            r"\s*[:=]\s*['\"][^'\"]{12,}['\"]"
        ),
        "Hardcoded secret assignment",
    ),
]

# Placeholders that look like secrets but are examples — suppress FP.
_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?api[_-]?key|xxx+|placeholder|example|changeme|insert[_-]?|<.*>|\$\{|process\.env|os\.environ|getenv)"
)


def check(pkg: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        # .env.example often has fake keys — still scan but skip generic assign if example-like
        is_example = "example" in f.relpath.lower() or f.relpath.endswith(".sample")
        for _sub, severity, pattern, title in _PATTERNS:
            for m in pattern.finditer(f.content):
                snippet = m.group(0)
                if _PLACEHOLDER.search(snippet) or _PLACEHOLDER.search(
                    f.content[max(0, m.start() - 40) : m.end() + 40]
                ):
                    continue
                if is_example and _sub == "generic_api_assign":
                    continue
                findings.append(
                    make_finding(
                        RuleId.SG002,
                        severity,
                        title=title,
                        path=f.relpath,
                        message=f"Possible secret material in `{f.relpath}`.",
                        line=_line_of(f.content, m.start()),
                        evidence=_mask(snippet),
                        remediation="Remove secrets; load from environment or a secret manager.",
                    )
                )
    return findings


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "…" + value[-2:]
