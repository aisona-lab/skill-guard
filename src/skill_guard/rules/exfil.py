"""SG004 — data exfiltration: path registry + language readers + classic patterns."""

from __future__ import annotations

import re

from skill_guard.analysis.lang_js import analyze_js
from skill_guard.analysis.lang_powershell import analyze_powershell
from skill_guard.analysis.lang_python import analyze_python
from skill_guard.models import Finding, RuleId, Severity, SkillPackage
from skill_guard.normalize import extract_code_candidates, normalize_text
from skill_guard.paths import read_then_network_risk

_CLASSIC: list[tuple[Severity, re.Pattern[str], str]] = [
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)(cat|type|Get-Content|head|tail)\s+[^\n]{0,60}"
            r"(\.ssh/|\.aws/|\.gnupg/|\.kube/|id_rsa|\.env\b|credentials)"
        ),
        "Read sensitive local credential paths",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)(curl|wget)\s+[^\n]{0,100}(-d|--data|--data-raw|-F|--form)\b[^\n]{0,100}"
            r"(HOME|\.ssh|\.env|id_rsa|credentials|passwd)"
        ),
        "curl/wget POST of sensitive paths",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)(env\s*\|\s*curl|printenv\s*\|\s*curl|"
            r"process\.env[^\n]{0,40}(fetch|axios|http)|"
            r"os\.environ[^\n]{0,40}(requests|httpx|urlopen))"
        ),
        "Environment dump piped or sent over network",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)("
            r"\bexfiltrate\s+(the\s+)?(secrets?|credentials?|keys?|tokens?|env(?:ironment)?|data)\b|"
            r"upload\s+(the\s+)?(secrets?|credentials?|api\s*keys?|ssh\s*keys?|tokens?|env(?:ironment)?\s*vars?)|"
            r"send\s+(the\s+)?(secrets?|credentials?|api\s*keys?|ssh\s*keys?|tokens?)\s+to"
            r")"
        ),
        "Explicit exfiltration language in skill instructions",
    ),
    (
        Severity.CRITICAL,
        re.compile(
            r"(?i)\baws\s+s3\s+cp\s+s3://[^\s]+"
        ),
        "AWS S3 copy of remote/corp data",
    ),
    (
        Severity.HIGH,
        re.compile(
            r"(?i)\baws\s+sts\s+get-caller-identity\b"
        ),
        "AWS identity probe (often prelude to abuse)",
    ),
]


def check(pkg: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        for blob in extract_code_candidates(f.content):
            norm = normalize_text(blob)

            # classic patterns
            for severity, pattern, title in _CLASSIC:
                for m in pattern.finditer(norm):
                    findings.append(
                        Finding(
                            rule_id=RuleId.SG004,
                            severity=severity,
                            title=title,
                            message=f"Possible data exfiltration behavior in `{f.relpath}`.",
                            path=f.relpath,
                            line=_line(f.content, m.group(0)),
                            evidence=m.group(0)[:120],
                            remediation="Remove credential harvesting and outbound secret transmission.",
                        )
                    )

            # path registry: sensitive near network
            for pid in read_then_network_risk(norm):
                findings.append(
                    Finding(
                        rule_id=RuleId.SG004,
                        severity=Severity.CRITICAL,
                        title=f"Sensitive path + network sink ({pid})",
                        message=f"Credential path co-located with network activity in `{f.relpath}`.",
                        path=f.relpath,
                        evidence=pid,
                        remediation="Do not combine credential path access with network calls.",
                    )
                )

            # language-aware
            suffix = f.suffix.lower()
            if suffix == ".py" or "import " in blob or "def " in blob:
                findings.extend(analyze_python(blob, f.relpath))
            if suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"} or "require(" in blob or "readFileSync" in blob:
                findings.extend(analyze_js(blob, f.relpath))
            if suffix in {".ps1", ".psm1"} or "Invoke-" in blob or "Get-Content" in blob:
                findings.extend(analyze_powershell(blob, f.relpath))

            # pure path read of critical material even without network (still theft prep)
            if re.search(
                r"(?i)(Path\.home\(\).{0,40}\.ssh|open\(['\"].*\.ssh|"
                r"read_text\(\)|read_bytes\(\)).{0,40}(id_rsa|\.ssh)",
                norm,
            ) or re.search(
                r"(?i)Path\.home\(\)\s*/\s*['\"]\.ssh['\"]",
                norm,
            ):
                if not any(x.title.startswith("Python home SSH") for x in findings):
                    # covered by lang_python usually; keep generic fallback
                    if "Path.home()" in norm and ".ssh" in norm:
                        findings.append(
                            Finding(
                                rule_id=RuleId.SG004,
                                severity=Severity.HIGH,
                                title="Programmatic SSH path access",
                                message=f"Code references home .ssh paths in `{f.relpath}`.",
                                path=f.relpath,
                                evidence="Path.home() + .ssh",
                                remediation="Do not access SSH keys from skills.",
                            )
                        )

    return _dedupe(findings)


def _line(content: str, snippet: str) -> int | None:
    idx = content.lower().find(snippet.lower()[:40]) if snippet else -1
    if idx < 0:
        return None
    return content.count("\n", 0, idx) + 1


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.title, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
