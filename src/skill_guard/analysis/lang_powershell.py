"""PowerShell static heuristics for download cradles and destructive ops."""

from __future__ import annotations

import re

from skill_guard.models import Finding, RuleId, Severity

_IEX_DOWNLOAD = re.compile(
    r"(?i)(IEX|Invoke-Expression)\s*\(?\s*"
    r"(New-Object\s+Net\.WebClient|DownloadString|DownloadFile|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr\b|wget\b|curl\b)"
)
_WEBCLIENT = re.compile(
    r"(?i)(New-Object\s+Net\.WebClient).{0,80}(DownloadString|DownloadFile)"
)
_REMOVE_HOME = re.compile(
    r"(?i)Remove-Item\s+(-Recurse|-r)\b[^\n]{0,40}(-Force|-f)\b[^\n]{0,60}"
    r"(\$HOME|\$env:USERPROFILE|~\\)"
)
_GET_CONTENT_SSH = re.compile(
    r"(?i)(Get-Content|gc)\s+[^\n]{0,40}(\.ssh\\|id_rsa|id_ed25519|\.aws\\)"
)
_INVOKE_REST_SECRET = re.compile(
    r"(?i)(Invoke-RestMethod|Invoke-WebRequest).{0,120}"
    r"(-Body|-InFile).{0,80}(\.ssh|\.aws|\.env|Get-Content)"
)


def analyze_powershell(content: str, relpath: str) -> list[Finding]:
    findings: list[Finding] = []
    if not content:
        return findings

    if _IEX_DOWNLOAD.search(content) or _WEBCLIENT.search(content):
        findings.append(
            Finding(
                rule_id=RuleId.SG003,
                severity=Severity.CRITICAL,
                title="PowerShell download cradle (IEX/WebClient)",
                message=f"Remote code execution cradle in `{relpath}`.",
                path=relpath,
                evidence="IEX/DownloadString/WebClient",
                remediation="Remove remote script execution from skills.",
            )
        )

    if _REMOVE_HOME.search(content):
        findings.append(
            Finding(
                rule_id=RuleId.SG003,
                severity=Severity.HIGH,
                title="PowerShell recursive delete under home",
                message=f"Remove-Item -Recurse -Force on home in `{relpath}`.",
                path=relpath,
                evidence="Remove-Item -Recurse -Force $HOME",
                remediation="Scope deletes to workspace temp dirs only.",
            )
        )

    if _GET_CONTENT_SSH.search(content):
        findings.append(
            Finding(
                rule_id=RuleId.SG004,
                severity=Severity.CRITICAL,
                title="PowerShell read of SSH/AWS credential paths",
                message=f"Get-Content on credential paths in `{relpath}`.",
                path=relpath,
                evidence="Get-Content .ssh/.aws",
                remediation="Do not read credential files.",
            )
        )

    if _INVOKE_REST_SECRET.search(content):
        findings.append(
            Finding(
                rule_id=RuleId.SG004,
                severity=Severity.CRITICAL,
                title="PowerShell HTTP body from credential material",
                message=f"Invoke-WebRequest/RestMethod with secret body in `{relpath}`.",
                path=relpath,
                evidence="Invoke-* -Body/-InFile + secrets path",
                remediation="Remove credential upload.",
            )
        )

    return findings
