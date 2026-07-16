"""Domain models for skill-guard.

Verdict/exit codes mirror lab convention (lazycoder): machine-readable gates.
Severities drive aggregation; rule IDs are stable for datasets and suppressions.

PackageContext is the single type rules consume: files are pre-normalized so
rules never re-run normalize/extract themselves.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Finding severity. critical/high block; medium warns; low is advisory."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    """Final package outcome for CI/install gates."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class RuleId(StrEnum):
    """Stable rule identifiers. Do not renumber — datasets depend on these."""

    SG001 = "SG001"  # structure / Agent Skills spec
    SG002 = "SG002"  # secrets
    SG003 = "SG003"  # dangerous shell
    SG004 = "SG004"  # exfiltration
    SG005 = "SG005"  # prompt injection / hijack in skill body
    SG006 = "SG006"  # supply chain
    SG007 = "SG007"  # blast-radius permissions
    SG008 = "SG008"  # token / context bloat
    SG009 = "SG009"  # identity spoofing
    SG010 = "SG010"  # enterprise policy


class FileKind(StrEnum):
    """Coarse kind for language-aware analysis. From extension / shebang only."""

    MARKDOWN = "markdown"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    POWERSHELL = "powershell"
    SHELL = "shell"
    OTHER = "other"


class CodeCandidate(BaseModel):
    """Fenced code (or full-file) blob with optional fence language tag.

    ``lang`` is a normalized label: python | javascript | shell | powershell | None.
    Built once at load — rules must not re-parse fences or sniff language.
    """

    text: str
    lang: str | None = None


class Finding(BaseModel):
    """One concrete issue found in a skill package."""

    rule_id: RuleId
    severity: Severity
    title: str
    message: str
    path: str | None = None
    line: int | None = None
    evidence: str | None = Field(
        default=None,
        description="Short snippet supporting the finding. Never a full secret.",
    )
    remediation: str | None = None

    def identity(self) -> tuple[Any, ...]:
        """Stable key for deduplication."""
        return (self.rule_id, self.path, self.title, self.line, self.message, self.evidence)

    def redacted(self) -> Finding:
        """Return a copy safe for logs (truncate evidence)."""
        if self.evidence and len(self.evidence) > 120:
            return self.model_copy(update={"evidence": self.evidence[:117] + "..."})
        return self


def make_finding(
    rule_id: RuleId,
    severity: Severity,
    *,
    title: str,
    path: str | None = None,
    message: str | None = None,
    evidence: str | None = None,
    remediation: str | None = None,
    line: int | None = None,
) -> Finding:
    """Canonical Finding constructor used by all rules."""
    ev = evidence[:120] if evidence and len(evidence) > 120 else evidence
    if message is not None:
        msg = message
    elif path:
        msg = f"{title} in `{path}`."
    else:
        msg = title
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=msg,
        path=path,
        line=line,
        evidence=ev,
        remediation=remediation,
    )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicate findings (same identity key)."""
    seen: set[tuple[Any, ...]] = set()
    out: list[Finding] = []
    for f in findings:
        key = f.identity()
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


class ScanResult(BaseModel):
    """Full scan report for one skill path."""

    target: str
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    skill_name: str | None = None
    files_scanned: int = 0
    rules_run: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        if self.verdict is Verdict.BLOCK:
            return 2
        if self.verdict is Verdict.WARN:
            return 1
        return 0

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]


def aggregate_verdict(findings: list[Finding]) -> Verdict:
    """Map findings → verdict. Conservative: any high/critical blocks."""
    if not findings:
        return Verdict.ALLOW
    ranks = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    worst = max(ranks[f.severity] for f in findings)
    if worst >= ranks[Severity.HIGH]:
        return Verdict.BLOCK
    if worst >= ranks[Severity.MEDIUM]:
        return Verdict.WARN
    return Verdict.ALLOW


class AnalyzedFile(BaseModel):
    """One package file after single-pass normalization (never executed)."""

    relpath: str
    content: str
    size: int
    normalized: str
    candidates: tuple[CodeCandidate, ...]
    kind: FileKind

    @property
    def suffix(self) -> str:
        return Path(self.relpath).suffix.lower()

    @property
    def is_script(self) -> bool:
        p = self.relpath.replace("\\", "/").lower()
        if p.startswith("scripts/") or "/scripts/" in f"/{p}":
            return True
        return self.kind in {
            FileKind.SHELL,
            FileKind.PYTHON,
            FileKind.JAVASCRIPT,
            FileKind.POWERSHELL,
        }


class PackageContext(BaseModel):
    """Pre-analyzed skill package — the only input rules should need."""

    root: str
    skill_md: AnalyzedFile | None = None
    frontmatter: dict[str, Any] = Field(default_factory=dict)
    body: str = ""
    files: list[AnalyzedFile] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def name(self) -> str | None:
        raw = self.frontmatter.get("name")
        return str(raw) if raw is not None else None

    def text_blob(self) -> str:
        """All normalized text joined — for package-wide pattern rules."""
        parts: list[str] = []
        for f in self.files:
            parts.append(f"\n# FILE: {f.relpath}\n{f.normalized}")
        return "\n".join(parts)

    def files_of(self, *kinds: FileKind) -> list[AnalyzedFile]:
        want = set(kinds)
        return [f for f in self.files if f.kind in want]


# Back-compat aliases used during migration of older call sites / docs.
SkillFile = AnalyzedFile
SkillPackage = PackageContext
