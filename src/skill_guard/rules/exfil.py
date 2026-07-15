"""SG004 — data exfiltration patterns.

Targets instructions/scripts that read secrets or home files and send them out.
"""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity, SkillPackage

_PATTERNS: list[tuple[Severity, re.Pattern[str], str]] = [
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)(cat|type|Get-Content|head|tail)\s+[^\n]{0,40}"
            r"(\.ssh/|\.aws/|\.gnupg/|\.kube/|id_rsa|\.env\b|credentials)"
        ),
        "Read sensitive local credential paths",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)(curl|wget|fetch|Invoke-WebRequest|requests\.(post|put)|httpx\.(post|put)|urllib)"
            r"[^\n]{0,160}(api[_-]?key|token|password|secret|Authorization|Bearer)"
        ),
        "HTTP upload involving secrets/tokens",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)(curl|wget)\s+[^\n]{0,80}(-d|--data|--data-raw|-F|--form)\b[^\n]{0,80}"
            r"(HOME|\.ssh|\.env|id_rsa|credentials|passwd)"
        ),
        "curl/wget POST of sensitive paths",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(base64\s+.*\|.*curl|curl.*base64|"
            r"nc\s+-e\b|ncat\s+-e\b|bash\s+-i\s+>&\s+/dev/tcp/)"
        ),
        "Classic reverse-shell or encoded exfil pipeline",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(env\s*\|\s*curl|printenv\s*\||"
            r"process\.env[^\n]{0,40}(fetch|axios|http)|"
            r"os\.environ[^\n]{0,40}(requests|httpx|urlopen))"
        ),
        "Environment dump piped or sent over network",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)("
            # verb form + object: avoid matching security docs that name the threat class
            r"\bexfiltrate\s+(the\s+)?(secrets?|credentials?|keys?|tokens?|env(?:ironment)?|data)\b|"
            r"upload\s+(the\s+)?(secrets?|credentials?|api\s*keys?|ssh\s*keys?|tokens?|env(?:ironment)?\s*vars?)|"
            r"send\s+(the\s+)?(secrets?|credentials?|api\s*keys?|ssh\s*keys?|tokens?)\s+to"
            r")"
        ),
        "Explicit exfiltration language in skill instructions",
    ),
]


def check(pkg: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        for severity, pattern, title in _PATTERNS:
            for m in pattern.finditer(f.content):
                findings.append(
                    Finding(
                        rule_id=RuleId.SG004,
                        severity=severity,
                        title=title,
                        message=f"Possible data exfiltration behavior in `{f.relpath}`.",
                        path=f.relpath,
                        line=f.content.count("\n", 0, m.start()) + 1,
                        evidence=m.group(0)[:120],
                        remediation="Remove credential harvesting and outbound secret transmission.",
                    )
                )
    return findings
