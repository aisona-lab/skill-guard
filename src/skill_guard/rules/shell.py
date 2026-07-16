"""SG003 — dangerous shell / PowerShell / decode-exec pipelines.

Table-driven: pipeline matchers + whole-file matchers. No nested special-case
ladders. PowerShell lives only in lang_powershell (invoked by FileKind).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from skill_guard.analysis.lang_powershell import analyze_powershell
from skill_guard.analysis.shell_tokens import (
    cmd_name,
    flags_of,
    join_stage,
    split_pipelines,
    stage_words,
)
from skill_guard.models import (
    FileKind,
    Finding,
    PackageContext,
    RuleId,
    Severity,
    make_finding,
)

_SHELLS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "pwsh", "powershell", "powershell.exe"}
)
_FETCHERS = frozenset({"curl", "wget", "fetch"})
_DECODERS = frozenset({"base64", "openssl", "xxd"})
_HOMEISH = re.compile(r"(?i)(\$HOME|~|/home/|/Users/|\.\.)")


def _later_shell(names: list[str], start: int) -> str | None:
    """Return shell name if a later pipeline stage is a shell (or xargs/env → shell)."""
    for j in range(start + 1, len(names)):
        if names[j] in _SHELLS:
            return names[j]
        if names[j] in {"env", "xargs"}:
            for k in range(j + 1, len(names)):
                if names[k] in _SHELLS:
                    return names[k]
    return None


def _is_decode_stage(stage: list[str], name: str) -> bool:
    fl = flags_of(stage)
    if name == "xxd":
        return True
    if name == "base64" and (fl & {"d", "D"} or "--decode" in fl):
        return True
    if name == "openssl" and any(w in stage_words(stage) for w in ("enc", "base64")):
        return True
    return False


# --- Pipeline matchers: stages → evidence or None ---

PipelineMatcher = Callable[[list[list[str]]], str | None]


def _m_fetch_to_shell(stages: list[list[str]]) -> str | None:
    names = [cmd_name(s) for s in stages]
    for i, name in enumerate(names):
        if name not in _FETCHERS:
            continue
        shell = _later_shell(names, i)
        if shell:
            return f"{name} | … | {shell}"
    return None


def _m_decode_to_shell(stages: list[list[str]]) -> str | None:
    names = [cmd_name(s) for s in stages]
    for i, name in enumerate(names):
        if name not in _DECODERS or not _is_decode_stage(stages[i], name):
            continue
        shell = _later_shell(names, i)
        if shell:
            return f"{name} | {shell}"
    return None


def _m_rm_rf_dangerous(stages: list[list[str]]) -> str | None:
    for stage in stages:
        if cmd_name(stage) != "rm":
            continue
        fl = flags_of(stage)
        if "r" not in fl or "f" not in fl:
            continue
        joined = join_stage(stage)
        words = [w for w in stage_words(stage)[1:] if not w.startswith("-")]
        dangerous = {"/", "/*", "$HOME", "$HOME/*", "~", "~/*", "/etc", "/var"}
        if any(w in dangerous for w in words) or _HOMEISH.search(joined):
            return joined[:100]
    return None


def _m_curl_insecure(stages: list[list[str]]) -> str | None:
    for stage in stages:
        if cmd_name(stage) != "curl":
            continue
        fl = flags_of(stage)
        if "k" in fl or "--insecure" in fl:
            return join_stage(stage)[:100]
    return None


def _m_chmod_777(stages: list[list[str]]) -> str | None:
    for stage in stages:
        if cmd_name(stage) == "chmod" and any(
            w in stage_words(stage) for w in ("777", "a+rwx")
        ):
            return join_stage(stage)[:100]
    return None


def _m_sudo_destructive(stages: list[list[str]]) -> str | None:
    for stage in stages:
        if cmd_name(stage) != "sudo" or len(stage) < 2:
            continue
        inner = cmd_name(stage[1:])
        if inner in {"rm", "dd", "mkfs", "chmod", "chown", "mkfs.ext4"}:
            return join_stage(stage)[:100]
    return None


def _m_disk_wipe(stages: list[list[str]]) -> str | None:
    for stage in stages:
        joined = join_stage(stage)
        if re.search(r"(?i)\b(mkfs\.|dd\s+if=)", joined):
            return joined[:100]
    return None


def _m_fork_bomb(stages: list[list[str]]) -> str | None:
    for stage in stages:
        compact = join_stage(stage).replace(" ", "")
        if ":(){" in compact or ":(){:|:&};:" in compact:
            return join_stage(stage)[:80]
    return None


def _m_reverse_shell(stages: list[list[str]]) -> str | None:
    for stage in stages:
        joined = join_stage(stage)
        name = cmd_name(stage)
        if re.search(r"(?i)/dev/tcp/|bash\s+-i", joined):
            return joined[:100]
        if name in {"nc", "ncat", "netcat"} and (
            "e" in flags_of(stage) or "-e" in stage_words(stage)
        ):
            return joined[:100]
    return None


def _m_scp_creds(stages: list[list[str]]) -> str | None:
    for stage in stages:
        if cmd_name(stage) != "scp":
            continue
        joined = join_stage(stage)
        if re.search(r"(?i)(\.ssh|\.aws|credentials|\.env)", joined):
            return joined[:100]
    return None


@dataclass(frozen=True, slots=True)
class _PipeRule:
    severity: Severity
    title: str
    match: PipelineMatcher
    remediation: str


_PIPELINE_RULES: tuple[_PipeRule, ...] = (
    _PipeRule(
        Severity.CRITICAL,
        "Pipe remote content into a shell",
        _m_fetch_to_shell,
        "Never pipe curl/wget into sh/bash/zsh.",
    ),
    _PipeRule(
        Severity.CRITICAL,
        "Decode pipeline into a shell",
        _m_decode_to_shell,
        "Do not decode payloads into shell execution.",
    ),
    _PipeRule(
        Severity.CRITICAL,
        "Recursive force delete of sensitive path",
        _m_rm_rf_dangerous,
        "Scope deletes to known workspace temp dirs.",
    ),
    _PipeRule(
        Severity.HIGH,
        "curl with TLS verification disabled",
        _m_curl_insecure,
        "Do not disable TLS verification.",
    ),
    _PipeRule(
        Severity.HIGH,
        "World-writable chmod 777",
        _m_chmod_777,
        "Use least-privilege permissions.",
    ),
    _PipeRule(
        Severity.MEDIUM,
        "sudo with privileged destructive command",
        _m_sudo_destructive,
        "Avoid requiring sudo in agent skills.",
    ),
    _PipeRule(
        Severity.HIGH,
        "Disk wipe pattern",
        _m_disk_wipe,
        "Remove destructive disk commands.",
    ),
    _PipeRule(
        Severity.CRITICAL,
        "Fork bomb pattern",
        _m_fork_bomb,
        "Remove fork bombs.",
    ),
    _PipeRule(
        Severity.CRITICAL,
        "Reverse shell pattern",
        _m_reverse_shell,
        "Remove reverse shells.",
    ),
    _PipeRule(
        Severity.CRITICAL,
        "scp of credential paths",
        _m_scp_creds,
        "Do not scp credential files.",
    ),
)

# --- Whole-file matchers (non-pipeline) ---

WholeMatcher = Callable[[str], str | None]


@dataclass(frozen=True, slots=True)
class _WholeRule:
    severity: Severity
    title: str
    match: WholeMatcher
    remediation: str


def _w_setuid(text: str) -> str | None:
    # Only setuid/setgid/sticky (4-digit modes 4xxx-7xxx) or explicit +s.
    # Do NOT match chmod 600/644/755 (common hardening, not setuid).
    m = re.search(
        r"(?i)\bchmod\s+(?:[ugoa]*\+s|--setuid|0?[4-7][0-7]{3})\b",
        text,
    )
    if not m:
        return None
    # 0755 / 0755-like: first of 4 digits must indicate special bits (4-7)
    token = m.group(0)
    digits = re.search(r"([0-7]{3,4})\b", token)
    if digits and len(digits.group(1)) == 3:
        # three-digit modes are never setuid
        return None
    return token


def _w_docker_sock(text: str) -> str | None:
    m = re.search(
        r"(?i)docker\b[^\n]{0,120}(docker\.sock|/var/run/docker\.sock|-v\s+/:/)",
        text,
    )
    return m.group(0)[:100] if m else None


def _w_cron_pipe(text: str) -> str | None:
    m = re.search(r"(?i)crontab\b[^\n]{0,80}(curl|wget).{0,40}\|\s*(ba)?sh", text)
    return m.group(0)[:100] if m else None


def _w_download_and_exec(text: str) -> str | None:
    m = re.search(r"(?i)\b(wget|curl)\b[^\n]{0,160}(&&|;)\s*(ba)?sh\b", text)
    return m.group(0)[:100] if m else None


def _w_var_pipe_shell(text: str) -> str | None:
    if not re.search(r"(?i)\b(curl|wget|fetch)\b", text):
        return None
    m = re.search(r"(?i)\|\s*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\b", text)
    return m.group(0) if m else None


def _w_b64_decode_exec(text: str) -> str | None:
    """base64 -d | sh  or  $(echo … | base64 -d) as command substitution."""
    m = re.search(
        r"(?i)("
        r"base64\s+(?:-d|--decode|-[dD])[^\n]{0,40}\|\s*(?:ba)?sh\b"
        r"|\$\(\s*echo\s+[^\n]{0,80}\|\s*base64\s+(?:-d|--decode)"
        r"|FromBase64String[^\n]{0,80}(?:IEX|Invoke-Expression)"
        r")",
        text,
    )
    return m.group(0)[:120] if m else None


_WHOLE_RULES: tuple[_WholeRule, ...] = (
    _WholeRule(
        Severity.HIGH,
        "chmod setuid / dangerous mode",
        _w_setuid,
        "Avoid setuid binaries in skills.",
    ),
    _WholeRule(
        Severity.CRITICAL,
        "Docker socket or host root mount",
        _w_docker_sock,
        "Do not expose docker.sock or mount host root.",
    ),
    _WholeRule(
        Severity.CRITICAL,
        "Cron persistence with remote shell pipe",
        _w_cron_pipe,
        "Remove persistence installers.",
    ),
    _WholeRule(
        Severity.CRITICAL,
        "Download then execute with shell",
        _w_download_and_exec,
        "Never download-and-execute remote scripts.",
    ),
    _WholeRule(
        Severity.HIGH,
        "Pipeline into shell variable (evasion)",
        _w_var_pipe_shell,
        "Do not pipe remote content into a shell variable.",
    ),
    _WholeRule(
        Severity.HIGH,
        "Base64 decode into shell / IEX",
        _w_b64_decode_exec,
        "Do not decode-and-execute payloads in skills.",
    ),
)


_PS_MARKERS = re.compile(
    r"(?i)\b(IEX|Invoke-Expression|Net\.WebClient|Remove-Item)\b"
)


def check(ctx: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        for cand in f.candidates:
            blob = cand.text
            # Shell pipelines: tagged shell fences + untagged/full (legacy body).
            if cand.lang in (None, "shell", "powershell"):
                for stages in split_pipelines(blob):
                    for rule in _PIPELINE_RULES:
                        evidence = rule.match(stages)
                        if evidence:
                            findings.append(
                                make_finding(
                                    RuleId.SG003,
                                    rule.severity,
                                    title=rule.title,
                                    path=f.relpath,
                                    message=f"Dangerous shell pattern in `{f.relpath}`.",
                                    evidence=evidence,
                                    remediation=rule.remediation,
                                )
                            )
        norm = f.normalized
        for rule in _WHOLE_RULES:
            evidence = rule.match(norm)
            if evidence:
                findings.append(
                    make_finding(
                        RuleId.SG003,
                        rule.severity,
                        title=rule.title,
                        path=f.relpath,
                        message=f"Dangerous shell pattern in `{f.relpath}`.",
                        evidence=evidence,
                        remediation=rule.remediation,
                    )
                )
        if f.kind is FileKind.POWERSHELL:
            findings.extend(analyze_powershell(f.normalized, f.relpath))
        elif f.kind is FileKind.MARKDOWN:
            for cand in f.candidates:
                # Prefer fence lang; untagged fences with PS markers still analyzed.
                if cand.lang == "powershell" or (
                    cand.lang is None and _PS_MARKERS.search(cand.text)
                ):
                    findings.extend(analyze_powershell(cand.text, f.relpath))
    return findings
