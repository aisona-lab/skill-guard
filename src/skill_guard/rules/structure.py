"""SG001 — Agent Skills open-spec structure checks.

Spec: name/description required; name charset/length; name matches directory.
We only enforce what the public spec states — no invented fields.
"""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity, SkillPackage

_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def check(pkg: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []

    for err in pkg.parse_errors:
        findings.append(
            Finding(
                rule_id=RuleId.SG001,
                severity=Severity.HIGH,
                title="Skill package parse error",
                message=err,
                path="SKILL.md",
                remediation="Provide a valid SKILL.md with YAML frontmatter per agentskills.io/specification",
            )
        )

    if pkg.skill_md is None:
        return findings

    name = pkg.frontmatter.get("name")
    desc = pkg.frontmatter.get("description")

    if not name:
        findings.append(
            Finding(
                rule_id=RuleId.SG001,
                severity=Severity.HIGH,
                title="Missing required frontmatter field: name",
                message="Agent Skills spec requires `name` in YAML frontmatter.",
                path="SKILL.md",
                remediation="Add `name: your-skill-name` (lowercase, hyphens, ≤64 chars).",
            )
        )
    else:
        name_s = str(name)
        if len(name_s) > 64:
            findings.append(
                Finding(
                    rule_id=RuleId.SG001,
                    severity=Severity.HIGH,
                    title="name exceeds 64 characters",
                    message=f"name length is {len(name_s)}; spec max is 64.",
                    path="SKILL.md",
                )
            )
        if not _NAME_RE.fullmatch(name_s):
            findings.append(
                Finding(
                    rule_id=RuleId.SG001,
                    severity=Severity.HIGH,
                    title="Invalid name format",
                    message=(
                        "name must be lowercase alphanumeric with single hyphens, "
                        "not starting/ending with hyphen, no consecutive hyphens."
                    ),
                    path="SKILL.md",
                    evidence=name_s[:64],
                )
            )
        # Directory name match (when root is the skill folder)
        root_name = pkg.root.rstrip("/").split("/")[-1]
        if root_name and root_name not in {".", "fixtures"} and name_s != root_name:
            # Only warn when the parent looks like a skill dir (contains SKILL.md)
            findings.append(
                Finding(
                    rule_id=RuleId.SG001,
                    severity=Severity.MEDIUM,
                    title="name does not match directory name",
                    message=f"frontmatter name `{name_s}` != directory `{root_name}`.",
                    path="SKILL.md",
                    remediation="Rename directory or set name to match parent folder.",
                )
            )

    if not desc:
        findings.append(
            Finding(
                rule_id=RuleId.SG001,
                severity=Severity.HIGH,
                title="Missing required frontmatter field: description",
                message="Agent Skills spec requires `description` (what + when).",
                path="SKILL.md",
            )
        )
    else:
        desc_s = str(desc)
        if len(desc_s) > 1024:
            findings.append(
                Finding(
                    rule_id=RuleId.SG001,
                    severity=Severity.MEDIUM,
                    title="description exceeds 1024 characters",
                    message=f"description length is {len(desc_s)}; spec max is 1024.",
                    path="SKILL.md",
                )
            )
        if len(desc_s.strip()) < 20:
            findings.append(
                Finding(
                    rule_id=RuleId.SG001,
                    severity=Severity.LOW,
                    title="description is very short",
                    message="Description should explain what the skill does and when to use it.",
                    path="SKILL.md",
                )
            )

    compat = pkg.frontmatter.get("compatibility")
    if compat is not None and len(str(compat)) > 500:
        findings.append(
            Finding(
                rule_id=RuleId.SG001,
                severity=Severity.MEDIUM,
                title="compatibility exceeds 500 characters",
                message=f"compatibility length is {len(str(compat))}; spec max is 500.",
                path="SKILL.md",
            )
        )

    return findings
