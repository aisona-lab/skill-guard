"""SG004 — data exfiltration via path registry + language readers + prose patterns.

Language analyzers: FileKind for native sources; fence ``lang`` tags for markdown.
No prose sniffing; no ``_looks_python`` / ``_looks_js``.
"""

from __future__ import annotations

import re

from skill_guard.analysis.lang_js import analyze_js
from skill_guard.analysis.lang_python import analyze_python
from skill_guard.models import (
    FileKind,
    Finding,
    PackageContext,
    RuleId,
    Severity,
    make_finding,
)
from skill_guard.paths import read_then_network_risk

# Light multi-lang patterns for fences without full analyzers (Ruby, etc.).
_RUBY_EXFIL = re.compile(
    r"(?is)Net::HTTP[^\n]{0,120}(File\.read|IO\.read|File\.open)"
    r"|File\.read[^\n]{0,80}(expand_path\(['\"]~|\.ssh|id_rsa)"
    r".{0,200}Net::HTTP"
)

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
        # Require real network APIs (not bare "http" in CORS defaults).
        # Match either order: process.env … fetch(  OR  fetch( … process.env
        re.compile(
            r"(?i)("
            r"env\s*\|\s*curl|printenv\s*\|\s*curl|"
            r"process\.env[^\n]{0,100}(fetch\s*\(|axios\.|http\.request|https\.request|"
            r"XMLHttpRequest|node-fetch|got\()|"
            r"(fetch\s*\(|axios\.|http\.request|https\.request|XMLHttpRequest)"
            r"[^\n]{0,120}process\.env|"
            r"os\.environ[^\n]{0,80}(requests\.(get|post|put)|httpx\.(get|post)|urlopen\()|"
            r"(requests\.(get|post|put)|httpx\.(get|post)|urlopen\()[^\n]{0,80}os\.environ"
            r")"
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
        re.compile(r"(?i)\baws\s+s3\s+cp\s+s3://[^\s]+"),
        "AWS S3 copy of remote/corp data",
    ),
    (
        Severity.HIGH,
        re.compile(r"(?i)\baws\s+sts\s+get-caller-identity\b"),
        "AWS identity probe (often prelude to abuse)",
    ),
]


def check(ctx: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        for severity, pattern, title in _CLASSIC:
            for m in pattern.finditer(f.normalized):
                findings.append(
                    make_finding(
                        RuleId.SG004,
                        severity,
                        title=title,
                        path=f.relpath,
                        message=f"Possible data exfiltration behavior in `{f.relpath}`.",
                        evidence=m.group(0),
                        remediation="Remove credential harvesting and outbound secret transmission.",
                        line=f.normalized.count("\n", 0, m.start()) + 1,
                    )
                )

        for cand in f.candidates:
            blob = cand.text
            for pid in read_then_network_risk(blob):
                findings.append(
                    make_finding(
                        RuleId.SG004,
                        Severity.CRITICAL,
                        title=f"Sensitive path + network sink ({pid})",
                        path=f.relpath,
                        message=(
                            f"Credential path co-located with network activity in `{f.relpath}`."
                        ),
                        evidence=pid,
                        remediation="Do not combine credential path access with network calls.",
                    )
                )
            # Markdown: only tagged fences; native sources use FileKind below.
            if f.kind is FileKind.MARKDOWN:
                if cand.lang == "python":
                    findings.extend(analyze_python(blob, f.relpath))
                elif cand.lang == "javascript":
                    findings.extend(analyze_js(blob, f.relpath))
            # Ruby (and untagged) light patterns — no full Ruby analyzer
            if cand.lang in (None, "ruby") or "Net::HTTP" in blob:
                if _RUBY_EXFIL.search(blob):
                    findings.append(
                        make_finding(
                            RuleId.SG004,
                            Severity.CRITICAL,
                            title="Ruby Net::HTTP credential path read",
                            path=f.relpath,
                            message=f"Possible Ruby exfil pattern in `{f.relpath}`.",
                            evidence="Net::HTTP + File.read/.ssh",
                            remediation="Do not upload local credential files.",
                        )
                    )

        if f.kind is FileKind.PYTHON:
            findings.extend(analyze_python(f.normalized, f.relpath))
        elif f.kind is FileKind.JAVASCRIPT:
            findings.extend(analyze_js(f.normalized, f.relpath))

    return findings
