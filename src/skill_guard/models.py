"""Domain models for skill-guard.

Verdict/exit codes mirror lab convention (lazycoder): machine-readable gates.
Severities drive aggregation; rule IDs are stable for datasets and suppressions.
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

    def redacted(self) -> Finding:
        """Return a copy safe for logs (truncate evidence)."""
        if self.evidence and len(self.evidence) > 120:
            return self.model_copy(update={"evidence": self.evidence[:117] + "..."})
        return self


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
    ranks = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    worst = max(ranks[f.severity] for f in findings)
    if worst >= ranks[Severity.HIGH]:
        return Verdict.BLOCK
    if worst >= ranks[Severity.MEDIUM]:
        return Verdict.WARN
    return Verdict.ALLOW


class SkillFile(BaseModel):
    """One text file from a skill package (never executed)."""

    relpath: str
    content: str
    size: int

    @property
    def suffix(self) -> str:
        return Path(self.relpath).suffix.lower()

    @property
    def is_script(self) -> bool:
        p = self.relpath.replace("\\", "/").lower()
        if p.startswith("scripts/") or "/scripts/" in f"/{p}":
            return True
        return self.suffix in {".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".mjs", ".ts", ".rb"}


class SkillPackage(BaseModel):
    """Normalized skill package ready for rules."""

    root: str
    skill_md: SkillFile | None = None
    frontmatter: dict[str, Any] = Field(default_factory=dict)
    body: str = ""
    files: list[SkillFile] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def name(self) -> str | None:
        raw = self.frontmatter.get("name")
        return str(raw) if raw is not None else None

    def text_blob(self) -> str:
        """All text content joined — used by pattern rules that span files."""
        parts: list[str] = []
        if self.skill_md:
            parts.append(self.skill_md.content)
        for f in self.files:
            if f is self.skill_md:
                continue
            parts.append(f"\n# FILE: {f.relpath}\n{f.content}")
        return "\n".join(parts)
