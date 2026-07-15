"""SG007 / SG010 — blast-radius permissions and enterprise policy.

SG007: broad tool permissions / write-escapes.
SG010: cloud metadata, corporate secret stores, CI token theft patterns.
"""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity, SkillPackage

_PERMISSION_PATTERNS: list[tuple[Severity, re.Pattern[str], str]] = [
    (
        Severity.HIGH,
        re.compile(
            r"(?i)allowed-tools:\s*.*\bBash\b(?!\()"
        ),
        "Unscoped Bash in allowed-tools",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(write|save|output)\s+(to\s+)?(/etc/|/usr/|/var/|"
            r"C:\\\\Windows|%SystemRoot%)"
        ),
        "Write outside user workspace into system paths",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(disable|bypass|skip)\s+(approval|permission|sandbox|confirm|"
            r"human[- ]in[- ]the[- ]loop|HITL)"
        ),
        "Instruction to bypass human approval / sandbox",
    ),
    (
        Severity.MEDIUM,
        re.compile(
            r"(?i)\b(chmod\s+-R|chown\s+-R)\s+[^\n]{0,40}(/(Users|home)|\$HOME|~)"
        ),
        "Recursive ownership/permission change under home",
    ),
]

_POLICY_PATTERNS: list[tuple[Severity, re.Pattern[str], str]] = [
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)(169\.254\.169\.254|metadata\.google\.internal|"
            r"metadata\.azure\.com|instance-data)"
        ),
        "Cloud instance metadata endpoint access",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)(\$\{\{\s*secrets\.|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|"
            r"AZURE_CLIENT_SECRET|GCLOUD_SERVICE_KEY)"
        ),
        "CI / cloud secret material reference",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(~\/\.aws\/credentials|~\/\.config\/gcloud|"
            r"~\/\.azure\/|application_default_credentials)"
        ),
        "Cloud credential file access",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(vault\s+kv\s+get|aws\s+secretsmanager\s+get-secret-value|"
            r"gcloud\s+secrets\s+versions\s+access)"
        ),
        "Secret-manager read without declared enterprise purpose",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(kubectl\s+.*(-n|--namespace)\s+kube-system|"
            r"docker\s+run\s+[^\n]*--privileged)"
        ),
        "Privileged cluster/container operation",
    ),
]


def check_permissions(pkg: SkillPackage) -> list[Finding]:
    return _scan(pkg, RuleId.SG007, _PERMISSION_PATTERNS)


def check_policy(pkg: SkillPackage) -> list[Finding]:
    return _scan(pkg, RuleId.SG010, _POLICY_PATTERNS)


def _scan(
    pkg: SkillPackage,
    rule_id: RuleId,
    patterns: list[tuple[Severity, re.Pattern[str], str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        for severity, pattern, title in patterns:
            for m in pattern.finditer(f.content):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        title=title,
                        message=f"Enterprise policy concern in `{f.relpath}`.",
                        path=f.relpath,
                        line=f.content.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0)[:120],
                        remediation="Remove or tightly scope privileged operations; document business need.",
                    )
                )
    return findings
