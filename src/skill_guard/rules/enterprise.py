"""SG007 / SG010 — blast-radius permissions and enterprise policy."""

from __future__ import annotations

import re

from skill_guard.models import Finding, PackageContext, RuleId, Severity, make_finding
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
        # Bare docs mentions of GITHUB_TOKEN are common in legitimate skills.
        # Critical only for Actions secret expansion or explicit AWS secret key name
        # in assignment-like contexts handled elsewhere; keep expansion critical.
        Severity.CRITICAL,
        re.compile(
            r"(?i)(\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}|AWS_SECRET_ACCESS_KEY\s*=)"
        ),
        "CI secret expansion or AWS secret key assignment",
    ),
    (
        Severity.MEDIUM,
        re.compile(
            r"(?i)\b(GITHUB_TOKEN|AZURE_CLIENT_SECRET|GCLOUD_SERVICE_KEY)\b"
        ),
        "CI / cloud secret identifier mentioned",
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


def check_permissions(ctx: PackageContext) -> list[Finding]:
    return _scan(ctx, RuleId.SG007, _PERMISSION_PATTERNS)


def check_policy(ctx: PackageContext) -> list[Finding]:
    findings = _scan(ctx, RuleId.SG010, _POLICY_PATTERNS)
    meta_ids = {p.id for p in CLOUD_METADATA}
    for f in ctx.files:
        norm = f.normalized
        for pp, m in find_sensitive_paths(norm):
            if pp.id in meta_ids or pp.id == "docker_sock":
                findings.append(
                    make_finding(
                        RuleId.SG010,
                        Severity.CRITICAL,
                        title=pp.title,
                        path=f.relpath,
                        message=f"Enterprise policy concern in `{f.relpath}`.",
                        evidence=m.group(0),
                        remediation="Remove cloud metadata / docker.sock access from skills.",
                        line=norm.count("\n", 0, m.start()) + 1,
                    )
                )
            if pp.id in {"aws_creds", "gcp_creds", "azure_creds"} and re.search(
                r"(?i)(cat|type|Get-Content|open\(|read_text|readFile)",
                norm[max(0, m.start() - 80) : m.end() + 80],
            ):
                findings.append(
                    make_finding(
                        RuleId.SG010,
                        Severity.HIGH,
                        title=f"Cloud credential file access ({pp.id})",
                        path=f.relpath,
                        message=f"Enterprise policy concern in `{f.relpath}`.",
                        evidence=m.group(0),
                        remediation="Do not read cloud credential files from skills.",
                    )
                )
    return findings


def _scan(
    ctx: PackageContext,
    rule_id: RuleId,
    patterns: list[tuple[Severity, re.Pattern[str], str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        text = f.normalized
        for severity, pattern, title in patterns:
            for m in pattern.finditer(text):
                findings.append(
                    make_finding(
                        rule_id,
                        severity,
                        title=title,
                        path=f.relpath,
                        message=f"Enterprise policy concern in `{f.relpath}`.",
                        evidence=m.group(0),
                        remediation=(
                            "Remove or tightly scope privileged operations; "
                            "document business need."
                        ),
                        line=text.count("\n", 0, m.start()) + 1,
                    )
                )
    return findings
