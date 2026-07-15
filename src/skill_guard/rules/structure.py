"""SG001 — Agent Skills open-spec structure checks.

Spec: name/description required; name charset/length; name matches directory.
"""

from __future__ import annotations

import re

from skill_guard.models import Finding, PackageContext, RuleId, Severity, make_finding

_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def check(pkg: PackageContext) -> list[Finding]:
    findings: list[Finding] = []

    for err in pkg.parse_errors:
        findings.append(
            make_finding(
                RuleId.SG001,
                Severity.HIGH,
                title="Skill package parse error",
                path="SKILL.md",
                message=err,
                remediation=(
                    "Provide a valid SKILL.md with YAML frontmatter per "
                    "agentskills.io/specification"
                ),
            )
        )

    if pkg.skill_md is None:
        return findings

    name = pkg.frontmatter.get("name")
    desc = pkg.frontmatter.get("description")

    if not name:
        findings.append(
            make_finding(
                RuleId.SG001,
                Severity.HIGH,
                title="Missing required frontmatter field: name",
                path="SKILL.md",
                message="Agent Skills spec requires `name` in YAML frontmatter.",
                remediation="Add `name: your-skill-name` (lowercase, hyphens, ≤64 chars).",
            )
        )
    else:
        name_s = str(name)
        if len(name_s) > 64:
            findings.append(
                make_finding(
                    RuleId.SG001,
                    Severity.HIGH,
                    title="name exceeds 64 characters",
                    path="SKILL.md",
                    message=f"name length is {len(name_s)}; spec max is 64.",
                )
            )
        if not _NAME_RE.fullmatch(name_s):
            findings.append(
                make_finding(
                    RuleId.SG001,
                    Severity.MEDIUM,
                    title="Invalid name format",
                    path="SKILL.md",
                    message=(
                        "name must be lowercase alphanumeric with single hyphens, "
                        "not starting/ending with hyphen, no consecutive hyphens."
                    ),
                    evidence=name_s[:64],
                )
            )
        root_name = pkg.root.rstrip("/").split("/")[-1]
        skip_roots = {
            ".",
            "fixtures",
            "benign",
            "malicious",
            "borderline",
            "enterprise",
            "adversarial",
            "safe",
            "ood",
        }
        if root_name and root_name not in skip_roots and name_s != root_name:
            findings.append(
                make_finding(
                    RuleId.SG001,
                    Severity.LOW,
                    title="name does not match directory name",
                    path="SKILL.md",
                    message=f"frontmatter name `{name_s}` != directory `{root_name}`.",
                    remediation="Rename directory or set name to match parent folder.",
                )
            )

    if not desc:
        findings.append(
            make_finding(
                RuleId.SG001,
                Severity.HIGH,
                title="Missing required frontmatter field: description",
                path="SKILL.md",
                message="Agent Skills spec requires `description` (what + when).",
            )
        )
    else:
        desc_s = str(desc)
        if len(desc_s) > 1024:
            findings.append(
                make_finding(
                    RuleId.SG001,
                    Severity.MEDIUM,
                    title="description exceeds 1024 characters",
                    path="SKILL.md",
                    message=f"description length is {len(desc_s)}; spec max is 1024.",
                )
            )
        if len(desc_s.strip()) < 20:
            findings.append(
                make_finding(
                    RuleId.SG001,
                    Severity.LOW,
                    title="description is very short",
                    path="SKILL.md",
                    message=(
                        "Description should explain what the skill does and when to use it."
                    ),
                )
            )

    compat = pkg.frontmatter.get("compatibility")
    if compat is not None and len(str(compat)) > 500:
        findings.append(
            make_finding(
                RuleId.SG001,
                Severity.MEDIUM,
                title="compatibility exceeds 500 characters",
                path="SKILL.md",
                message=f"compatibility length is {len(str(compat))}; spec max is 500.",
            )
        )

    return findings
