"""JavaScript/TypeScript static heuristics for credential theft."""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity
from skill_guard.paths import SENSITIVE_PATHS

_READ_FILE = re.compile(
    r"(?i)(fs\.|require\(['\"]fs['\"]\))[^\n]{0,40}"
    r"(readFileSync|readFile|promises\.readFile)\(\s*([^)]+)\)"
)
_FETCH_POST = re.compile(
    r"(?i)\bfetch\(\s*([^,]+),\s*\{[^}]{0,200}(method\s*:\s*['\"]POST|"
    r"body\s*:)"
)
_CHILD_EXEC = re.compile(
    r"(?i)(child_process|execSync|exec\(|spawn\()"
    r"[^\n]{0,120}(curl\b|wget\b|\.ssh/|readFileSync\([^\)]*\.env|bash\s+-c|\|\s*(ba)?sh\b)"
)
_ENV_BODY = re.compile(
    r"(?i)(readFileSync|readFile)\([^\)]*\.env[^\)]*\)[^;]{0,120}"
    r"(fetch|axios|http\.request|got\()"
)


def analyze_js(content: str, relpath: str) -> list[Finding]:
    findings: list[Finding] = []
    if not content:
        return findings

    for m in _READ_FILE.finditer(content):
        arg = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
        for pp in SENSITIVE_PATHS:
            if pp.regex.search(arg) or pp.regex.search(m.group(0)):
                findings.append(
                    Finding(
                        rule_id=RuleId.SG004,
                        severity=Severity.CRITICAL,
                        title=f"JS read of sensitive path ({pp.id})",
                        message=f"fs read targets sensitive path in `{relpath}`.",
                        path=relpath,
                        evidence=m.group(0)[:120],
                        remediation="Do not read credential files from agent skills.",
                    )
                )
                break

    if _ENV_BODY.search(content):
        findings.append(
            Finding(
                rule_id=RuleId.SG004,
                severity=Severity.CRITICAL,
                title="JS reads .env and sends over network",
                message=f"readFile of .env near fetch/http in `{relpath}`.",
                path=relpath,
                evidence="readFile(.env) + fetch/http",
                remediation="Never upload environment files.",
            )
        )

    # fetch with body near sensitive path mention
    if _FETCH_POST.search(content):
        for pp in SENSITIVE_PATHS:
            if pp.regex.search(content):
                findings.append(
                    Finding(
                        rule_id=RuleId.SG004,
                        severity=Severity.HIGH,
                        title="JS fetch POST near sensitive path reference",
                        message=f"POST fetch co-located with {pp.id} in `{relpath}`.",
                        path=relpath,
                        evidence=pp.id,
                        remediation="Remove credential exfiltration via fetch.",
                    )
                )
                break

    if _CHILD_EXEC.search(content):
        findings.append(
            Finding(
                rule_id=RuleId.SG003,
                severity=Severity.HIGH,
                title="JS child_process executing shell download/exfil pattern",
                message=f"child_process with curl/wget/bash/.ssh in `{relpath}`.",
                path=relpath,
                evidence="child_process + shell risk",
                remediation="Do not shell out to download or exfiltrate from skills.",
            )
        )

    return findings
