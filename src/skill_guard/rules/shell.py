"""SG003 — dangerous shell / PowerShell / decode-exec pipelines.

Uses shell_tokens for flag-order independence and pipeline analysis.
"""

from __future__ import annotations

import re

from skill_guard.analysis.lang_powershell import analyze_powershell
from skill_guard.analysis.shell_tokens import (
    cmd_name,
    flags_of,
    join_stage,
    split_pipelines,
    stage_words,
)
from skill_guard.models import Finding, RuleId, Severity, SkillPackage
from skill_guard.normalize import extract_code_candidates, normalize_text

_SHELLS = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "powershell.exe",
}
_FETCHERS = {"curl", "wget", "fetch"}
_DECODERS = {"base64", "openssl", "xxd"}
_DANGEROUS_RM_TARGETS = re.compile(
    r"(?i)^(/|/\$?HOME|~|/home(/|$)|/Users(/|$)|/etc(/|$)|/var(/|$)|/\*|\$HOME|\.\.)$"
)
_SETUID = re.compile(r"(?i)\bchmod\s+(?:[0-7]*[46][0-7]{2,3}|\+s|--setuid)\b")
_DOCKER_SOCK = re.compile(
    r"(?i)docker\b[^\n]{0,120}(docker\.sock|/var/run/docker\.sock|-v\s+/:/)"
)
_CRON_PIPE = re.compile(r"(?i)crontab\b[^\n]{0,80}(curl|wget).{0,40}\|\s*(ba)?sh")
_WGET_AND_BASH = re.compile(
    r"(?i)\b(wget|curl)\b[^\n]{0,160}(&&|;)\s*(ba)?sh\b"
)
_VAR_PIPE_SHELL = re.compile(
    r"(?i)\|\s*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\b"
)


def check(pkg: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    for f in pkg.files:
        text = f.content
        norm = normalize_text(text)
        candidates = extract_code_candidates(text)

        for blob in candidates:
            findings.extend(_analyze_shell_blob(blob, f.relpath))
            if f.suffix in {".ps1", ".psm1"} or "powershell" in blob.lower() or "IEX" in blob:
                findings.extend(analyze_powershell(blob, f.relpath))

        # whole-file extras
        if _SETUID.search(norm):
            findings.append(
                _finding(
                    Severity.HIGH,
                    "chmod setuid / dangerous mode",
                    f.relpath,
                    "chmod +s or setuid mode",
                    "Avoid setuid binaries in skills.",
                )
            )
        if _DOCKER_SOCK.search(norm):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "Docker socket or host root mount",
                    f.relpath,
                    "docker.sock or -v /:/",
                    "Do not expose docker.sock or mount host root.",
                )
            )
        if _CRON_PIPE.search(norm):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "Cron persistence with remote shell pipe",
                    f.relpath,
                    "crontab + curl|sh",
                    "Remove persistence installers.",
                )
            )
        if _WGET_AND_BASH.search(norm):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "Download then execute with shell",
                    f.relpath,
                    "wget/curl && sh",
                    "Never download-and-execute remote scripts.",
                )
            )
        # variable pipe to shell (curl | $CMD)
        if _VAR_PIPE_SHELL.search(norm) and any(
            x in norm.lower() for x in ("curl", "wget", "fetch")
        ):
            findings.append(
                _finding(
                    Severity.HIGH,
                    "Pipeline into shell variable (evasion)",
                    f.relpath,
                    "| $CMD after fetcher",
                    "Do not pipe remote content into a shell variable.",
                )
            )

    return findings


def _analyze_shell_blob(blob: str, relpath: str) -> list[Finding]:
    findings: list[Finding] = []
    for stages in split_pipelines(blob):
        names = [cmd_name(s) for s in stages]
        # curl|wget | shell
        for i, name in enumerate(names):
            if name in _FETCHERS:
                # later stage is shell?
                for j in range(i + 1, len(names)):
                    if names[j] in _SHELLS or names[j] in {"env", "xargs"} and j + 1 < len(
                        names
                    ):
                        # xargs sh
                        if names[j] in _SHELLS or (
                            names[j] in {"env", "xargs"}
                            and any(names[k] in _SHELLS for k in range(j, len(names)))
                        ):
                            findings.append(
                                _finding(
                                    Severity.CRITICAL,
                                    "Pipe remote content into a shell",
                                    relpath,
                                    join_stage(stages[i]) + " | … | " + names[-1],
                                    "Never pipe curl/wget into sh/bash/zsh.",
                                )
                            )
                            break
                    if names[j] in _SHELLS:
                        findings.append(
                            _finding(
                                Severity.CRITICAL,
                                "Pipe remote content into a shell",
                                relpath,
                                f"{name} | {names[j]}",
                                "Never pipe curl/wget into a shell.",
                            )
                        )
                        break
                # curl | tar | sh already covered by shell stage

            # base64 -d | shell
            if name in _DECODERS:
                fl = flags_of(stages[i])
                decode = bool(fl & {"d", "D"}) or "--decode" in fl or name == "xxd"
                if name == "openssl" and any(
                    w in stage_words(stages[i]) for w in ("enc", "base64")
                ):
                    decode = True
                if decode:
                    for j in range(i + 1, len(names)):
                        if names[j] in _SHELLS:
                            findings.append(
                                _finding(
                                    Severity.CRITICAL,
                                    "Decode pipeline into a shell",
                                    relpath,
                                    f"{name} | {names[j]}",
                                    "Do not decode payloads into shell execution.",
                                )
                            )
                            break

            # rm with r+f and dangerous target
            if name == "rm":
                fl = flags_of(stages[i])
                if "r" in fl and "f" in fl:
                    for w in stage_words(stages[i])[1:]:
                        if w.startswith("-"):
                            continue
                        if _DANGEROUS_RM_TARGETS.match(w) or w in {
                            "$HOME/*",
                            "~/*",
                            "/*",
                            "/",
                        }:
                            findings.append(
                                _finding(
                                    Severity.CRITICAL,
                                    "Recursive force delete of sensitive path",
                                    relpath,
                                    join_stage(stages[i])[:100],
                                    "Remove destructive rm -rf of home/root paths.",
                                )
                            )
                            break
                    # also $HOME without regex match
                    joined = join_stage(stages[i])
                    if re.search(r"(?i)(\$HOME|~|/home/|/Users/|\.\.)", joined):
                        findings.append(
                            _finding(
                                Severity.HIGH,
                                "Recursive force delete under home/parent",
                                relpath,
                                joined[:100],
                                "Scope deletes to known workspace temp dirs.",
                            )
                        )

            # curl -k
            if name == "curl":
                fl = flags_of(stages[i])
                if "k" in fl or "--insecure" in fl:
                    findings.append(
                        _finding(
                            Severity.HIGH,
                            "curl with TLS verification disabled",
                            relpath,
                            join_stage(stages[i])[:100],
                            "Do not disable TLS verification.",
                        )
                    )

            # chmod 777
            if name == "chmod" and any(
                w in stage_words(stages[i]) for w in ("777", "a+rwx")
            ):
                findings.append(
                    _finding(
                        Severity.HIGH,
                        "World-writable chmod 777",
                        relpath,
                        join_stage(stages[i])[:100],
                        "Use least-privilege permissions.",
                    )
                )

            # sudo + destructive
            if name == "sudo" and len(stages[i]) > 1:
                inner = cmd_name(stages[i][1:])
                if inner in {"rm", "dd", "mkfs", "chmod", "chown", "mkfs.ext4"}:
                    findings.append(
                        _finding(
                            Severity.MEDIUM,
                            "sudo with privileged destructive command",
                            relpath,
                            join_stage(stages[i])[:100],
                            "Avoid requiring sudo in agent skills.",
                        )
                    )

            # dd / mkfs / fork bomb markers in stage text
            joined = join_stage(stages[i])
            if re.search(r"(?i)\b(mkfs\.|dd\s+if=)", joined):
                findings.append(
                    _finding(
                        Severity.HIGH,
                        "Disk wipe pattern",
                        relpath,
                        joined[:100],
                        "Remove destructive disk commands.",
                    )
                )
            if ":(){" in joined.replace(" ", "") or ":(){ :|:& };:" in joined.replace(
                " ", ""
            ):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "Fork bomb pattern",
                        relpath,
                        joined[:80],
                        "Remove fork bombs.",
                    )
                )

            # reverse shell /dev/tcp
            if re.search(r"(?i)/dev/tcp/|bash\s+-i", joined):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "Reverse shell pattern",
                        relpath,
                        joined[:100],
                        "Remove reverse shells.",
                    )
                )
            if name in {"nc", "ncat", "netcat"} and ("e" in flags_of(stages[i]) or "-e" in stage_words(stages[i])):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "netcat exec reverse shell",
                        relpath,
                        joined[:100],
                        "Remove nc -e shells.",
                    )
                )

            # scp of sensitive (also enterprise) — shell surface
            if name == "scp" and re.search(
                r"(?i)(\.ssh|\.aws|credentials|\.env)", joined
            ):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "scp of credential paths",
                        relpath,
                        joined[:100],
                        "Do not scp credential files.",
                    )
                )

    return findings


def _finding(
    severity: Severity,
    title: str,
    path: str,
    evidence: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=RuleId.SG003,
        severity=severity,
        title=title,
        message=f"Dangerous shell pattern in `{path}`.",
        path=path,
        evidence=evidence[:120],
        remediation=remediation,
    )
