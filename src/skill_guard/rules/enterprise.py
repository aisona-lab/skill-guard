"""SG007 / SG010 — blast-radius permissions and enterprise policy."""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity, SkillPackage
from skill_guard.normalize import normalize_text
from skill_guard.paths import CLOUD_METADATA, find_sensitive_paths

_PERMISSION_PATTERNS: list[tuple[Severity, re.Pattern[str], str]] = [
    (
        Severity.HIGH,
        re.compile(r"(?i)allowed-tools:\s*.*\bBash\b(?!\()"),
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
        Severity.HIGH,
        re.compile(
            r"(?i)(\.\./|\.\.\\).{0,40}(\.ssh|authorized_keys|\.aws|credentials)"
        ),
        "Path traversal toward credential locations",
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
            r"(?i)(\$\{\{\s*secrets\.|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|"
            r"AZURE_CLIENT_SECRET|GCLOUD_SERVICE_KEY)"
        ),
        "CI / cloud secret material reference",
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
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)docker\b[^\n]{0,100}(docker\.sock|/var/run/docker\.sock)"
        ),
        "Docker socket mount/access",
    ),
]


def check_permissions(pkg: SkillPackage) -> list[Finding]:
    return _scan(pkg, RuleId.SG007, _PERMISSION_PATTERNS)


def check_policy(pkg: SkillPackage) -> list[Finding]:
    findings = _scan(pkg, RuleId.SG010, _POLICY_PATTERNS)
    # cloud metadata via shared catalog
    for f in pkg.files:
        norm = normalize_text(f.content)
        for pp, m in find_sensitive_paths(norm):
            if pp.id in {p.id for p in CLOUD_METADATA} or pp.id == "docker_sock":
                findings.append(
                    Finding(
                        rule_id=RuleId.SG010,
                        severity=Severity.CRITICAL,
                        title=pp.title,
                        message=f"Enterprise policy concern in `{f.relpath}`.",
                        path=f.relpath,
                        line=norm.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0)[:120],
                        remediation="Remove cloud metadata / docker.sock access from skills.",
                    )
                )
            if pp.id in {"aws_creds", "gcp_creds", "azure_creds"} and re.search(
                r"(?i)(cat|type|Get-Content|open\(|read_text|readFile)",
                norm[max(0, m.start() - 80) : m.end() + 80],
            ):
                findings.append(
                    Finding(
                        rule_id=RuleId.SG010,
                        severity=Severity.HIGH,
                        title=f"Cloud credential file access ({pp.id})",
                        message=f"Enterprise policy concern in `{f.relpath}`.",
                        path=f.relpath,
                        evidence=m.group(0)[:80],
                        remediation="Do not read cloud credential files from skills.",
                    )
                )
    return findings


def _scan(
    pkg: SkillPackage,
    rule_id: RuleId,
    patterns: list[tuple[Severity, re.Pattern[str], str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        text = normalize_text(f.content)
        for severity, pattern, title in patterns:
            for m in pattern.finditer(text):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        title=title,
                        message=f"Enterprise policy concern in `{f.relpath}`.",
                        path=f.relpath,
                        line=text.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0)[:120],
                        remediation=(
                            "Remove or tightly scope privileged operations; "
                            "document business need."
                        ),
                    )
                )
    return findings
