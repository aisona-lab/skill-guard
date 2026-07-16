"""SG006 — supply-chain risks: remote code install, unpinned packages, postinstall.

Global-install MEDIUM only fires for *actionable* steps (fenced code or scripts/),
not prose tips like “update Claude with `npm install -g …`” (ponytail-help noise).
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

# High/critical patterns: always flag (match on normalized text).
_PATTERNS: list[tuple[Severity, re.Pattern[str], str, str]] = [
    (
        Severity.CRITICAL,
        # Require install arg that is a URL — not markdown "](https://…)" links.
        re.compile(
            r"(?i)\b(npm|pnpm|yarn)\s+install\b[^\n]{0,60}"
            r"(?<!\]\()(?<!\[)(https?://|git\+|github:[A-Za-z0-9_.-]+/|gist\.github)"
        ),
        "Install package from remote URL",
        "Pin to a registry package with version and integrity hash.",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)\bpip\s+install\b[^\n]{0,100}"
            r"(?<!\]\()(https?://|git\+https|git\+ssh|--index-url|--extra-index-url)"
        ),
        "pip install from remote URL or custom index",
        "Install from PyPI with a pinned version, or vendor the package.",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)\b(npm|pnpm|yarn)\s+install\b[^\n]{0,100}"
            r"(git\+ssh://|git\+https://|ssh://)"
        ),
        "Install package from git+ssh/https URL",
        "Pin to a registry package with version and integrity hash.",
    ),
    (
        Severity.HIGH,
        re.compile(r"(?i)\b(npx|bunx)\s+(-y\s+)?https?://"),
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
]

# Global / user-site installs — MEDIUM only when the skill asks the agent to run them.
_GLOBAL_INSTALL = re.compile(
    r"(?i)\b(npm\s+install\s+-g|pip\s+install\s+--user|cargo\s+install)\b"
)
_FENCE_RE = re.compile(r"```[\w+-]*\n[\s\S]*?```", re.MULTILINE)


def check(pkg: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        text = f.normalized
        for severity, pattern, title, remediation in _PATTERNS:
            for m in pattern.finditer(text):
                findings.append(
                    make_finding(
                        RuleId.SG006,
                        severity,
                        title=title,
                        path=f.relpath,
                        message=f"Supply-chain risk in `{f.relpath}`.",
                        line=text.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0),
                        remediation=remediation,
                    )
                )
        findings.extend(_global_install_findings(f.relpath, f.content, f.kind))
    return findings


def _global_install_findings(
    relpath: str, content: str, kind: FileKind
) -> list[Finding]:
    """Flag global installs only in fenced blocks or script files."""
    if not content:
        return []
    actionable = _is_actionable_file(relpath, kind)
    fence_spans = [(m.start(), m.end()) for m in _FENCE_RE.finditer(content)]
    out: list[Finding] = []
    for m in _GLOBAL_INSTALL.finditer(content):
        in_fence = any(a <= m.start() < b for a, b in fence_spans)
        if not (actionable or in_fence):
            # Prose / inline backticks only — host tips, dep lists, etc.
            continue
        out.append(
            make_finding(
                RuleId.SG006,
                Severity.MEDIUM,
                title="Global package install from skill",
                path=relpath,
                message=f"Supply-chain risk in `{relpath}`.",
                line=content.count("\n", 0, m.start()) + 1,
                evidence=m.group(0),
                remediation="Prefer project-local installs; document exact versions.",
            )
        )
    return out


def _is_actionable_file(relpath: str, kind: FileKind) -> bool:
    if relpath.startswith("scripts/") or "/scripts/" in relpath:
        return True
    return kind in {FileKind.SHELL, FileKind.POWERSHELL, FileKind.PYTHON, FileKind.JAVASCRIPT}
