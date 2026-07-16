"""SG007 / SG010 — blast-radius permissions and enterprise policy."""

from __future__ import annotations

import re

from skill_guard.context_tone import (
    agent_policy_wording,
    cli_or_test_context,
    educational_context,
    secret_exfil_context,
)
from skill_guard.models import (
    FileKind,
    Finding,
    PackageContext,
    RuleId,
    Severity,
    make_finding,
)
from skill_guard.paths import CLOUD_METADATA, find_sensitive_paths
from skill_guard.surface import is_agent_policy_surface, is_test_path

# Patterns that never need CLI/test filtering.
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

# Agent-facing bypass only. "Skip sandbox/confirm" as CLI flags is filtered out.
_BYPASS_HITL = re.compile(
    r"(?i)\b(disable|bypass)\s+(?:the\s+|all\s+)?"
    r"(approval|permission|sandbox|confirm|"
    r"human[- ]in[- ]the[- ]loop|HITL)\b"
    r"|\bskip\s+(?:all\s+|the\s+)?"
    r"(approval|permission|sandbox|confirmations?|"
    r"human[- ]in[- ]the[- ]loop|HITL)\b"
)

_SECRETS_EXPANSION = re.compile(r"(?i)\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
_AWS_SECRET_ASSIGN = re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\s*=")

_POLICY_PATTERNS: list[tuple[Severity, re.Pattern[str], str]] = [
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
    findings = _scan(ctx, RuleId.SG007, _PERMISSION_PATTERNS)
    findings.extend(_bypass_hitl_findings(ctx))
    return findings


def _bypass_hitl_findings(ctx: PackageContext) -> list[Finding]:
    """Flag agent instructions to skip approval — not CLI/test flag plumbing."""
    findings: list[Finding] = []
    for f in ctx.files:
        if is_test_path(f.relpath):
            continue
        text = f.normalized
        for m in _BYPASS_HITL.finditer(text):
            if cli_or_test_context(text, m.start(), m.end()):
                continue
            if educational_context(text, m.start(), m.end()):
                continue
            # Markdown skill bodies are policy surface; .py needs agent wording.
            if not is_agent_policy_surface(f):
                if f.kind is FileKind.PYTHON and not agent_policy_wording(
                    text, m.start(), m.end()
                ):
                    continue
                if f.kind is not FileKind.PYTHON and f.kind is not FileKind.MARKDOWN:
                    continue
            findings.append(
                make_finding(
                    RuleId.SG007,
                    Severity.HIGH,
                    title="Instruction to bypass human approval / sandbox",
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


def check_policy(ctx: PackageContext) -> list[Finding]:
    findings = _scan(ctx, RuleId.SG010, _POLICY_PATTERNS)
    findings.extend(_secret_expansion_findings(ctx))
    meta_ids = {p.id for p in CLOUD_METADATA}
    for f in ctx.files:
        norm = f.normalized
        for pp, m in find_sensitive_paths(norm):
            if pp.id in meta_ids or pp.id == "docker_sock":
                # Security-training skills document IMDS attacks; skip edu tone.
                if educational_context(norm, m.start(), m.end(), radius=400):
                    continue
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
                if educational_context(norm, m.start(), m.end()):
                    continue
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


def _secret_expansion_findings(ctx: PackageContext) -> list[Finding]:
    """``${{ secrets.* }}``: CRITICAL only near exfil; else MEDIUM (CI docs)."""
    findings: list[Finding] = []
    for f in ctx.files:
        text = f.normalized
        for m in _SECRETS_EXPANSION.finditer(text):
            sev = (
                Severity.CRITICAL
                if secret_exfil_context(text, m.start(), m.end())
                else Severity.MEDIUM
            )
            findings.append(
                make_finding(
                    RuleId.SG010,
                    sev,
                    title="CI secret expansion or AWS secret key assignment",
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
        for m in _AWS_SECRET_ASSIGN.finditer(text):
            findings.append(
                make_finding(
                    RuleId.SG010,
                    Severity.CRITICAL,
                    title="CI secret expansion or AWS secret key assignment",
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
