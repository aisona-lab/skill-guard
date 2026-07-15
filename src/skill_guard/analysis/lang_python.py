"""Python static heuristics for credential theft (no AST exec, regex/structure).

Detects:
- Path.home() / expanduser + .ssh/.aws reads
- open('/.../.ssh...') 
- urllib/requests/httpx posting file contents
"""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity, make_finding
from skill_guard.paths import CLOUD_METADATA, NETWORK_SINK_HINTS, SENSITIVE_PATHS

_HOME_SSH = re.compile(
    r"(?i)(Path\.home\(\)\s*/\s*['\"]\.ssh['\"]|"
    r"Path\.home\(\)\s*\.\s*joinpath\([^)]*\.ssh|"
    r"expanduser\(\s*['\"]~/?\.ssh|"
    r"os\.path\.expanduser\(\s*['\"]~/?\.ssh)"
)
_OPEN_SENSITIVE = re.compile(
    r"(?i)open\(\s*['\"]([^'\"]+)['\"]"
)
_READ_METHODS = re.compile(
    r"(?i)\.(read_text|read_bytes|read)\(\s*\)"
)
_REQUESTS_POST_FILE = re.compile(
    r"(?i)(requests|httpx)\.(post|put|patch)\([^;]{0,200}"
    r"(files\s*=|data\s*=|json\s*=).{0,80}"
    r"(open\(|Path\(|read_bytes|read_text|\.ssh|\.aws|\.env)"
)
_URLLIB_POST = re.compile(
    r"(?i)(urlopen|urllib\.request)\([^;]{0,200}"
    r"(data\s*=|method\s*=\s*['\"]POST)[^;]{0,200}"
    r"(read_bytes|read_text|\.ssh|\.aws|Path\.home|open\()"
)
_PASSWD_OPEN = re.compile(
    r"(?i)open\(\s*['\"]/(etc/passwd|etc/shadow|etc/sudoers)"
)


def analyze_python(content: str, relpath: str) -> list[Finding]:
    findings: list[Finding] = []
    if not content:
        return findings

    if _HOME_SSH.search(content) and (
        _READ_METHODS.search(content) or NETWORK_SINK_HINTS.search(content)
    ):
        findings.append(
            _f(
                Severity.CRITICAL,
                "Python home SSH path read",
                relpath,
                "Path.home()/expanduser targeting .ssh with read or network sink",
            )
        )

    for m in _OPEN_SENSITIVE.finditer(content):
        path = m.group(1)
        for pp in SENSITIVE_PATHS + CLOUD_METADATA:
            if pp.regex.search(path):
                findings.append(
                    _f(
                        pp.severity if pp.severity is Severity.CRITICAL else Severity.HIGH,
                        f"Python open() of sensitive path ({pp.id})",
                        relpath,
                        path[:120],
                    )
                )
                break

    if _REQUESTS_POST_FILE.search(content):
        findings.append(
            _f(
                Severity.CRITICAL,
                "Python HTTP upload of file/secret material",
                relpath,
                "requests/httpx post with file or sensitive path context",
            )
        )

    if _URLLIB_POST.search(content):
        findings.append(
            _f(
                Severity.CRITICAL,
                "urllib POST of local file/secret material",
                relpath,
                "urlopen POST with read of local/sensitive content",
            )
        )

    if _PASSWD_OPEN.search(content):
        findings.append(
            _f(
                Severity.CRITICAL,
                "Python open of system password file",
                relpath,
                "/etc/passwd|/etc/shadow",
            )
        )

    return findings


def _f(sev: Severity, title: str, path: str, evidence: str) -> Finding:
    return make_finding(
        RuleId.SG004,
        sev,
        title=title,
        path=path,
        message=f"Language-aware Python credential-risk pattern in `{path}`.",
        evidence=evidence,
        remediation="Remove secret reads and outbound transmission of local credentials.",
    )
