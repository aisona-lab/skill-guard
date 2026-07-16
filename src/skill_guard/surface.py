"""Structural surface classifier for skill packages.

Prefer *where* text lives (fence / script / prose / test) over growing keyword
lists in ``context_tone``. Rules should call these helpers before regex.

Surfaces:
  fence  — markdown code fence body (tagged or untagged)
  script — scripts/ or native source FileKind
  prose  — narrative markdown / docs
  test   — tests/ tree
"""

from __future__ import annotations

import re
from enum import StrEnum

from skill_guard.models import AnalyzedFile, CodeCandidate, FileKind


class Surface(StrEnum):
    FENCE = "fence"
    SCRIPT = "script"
    PROSE = "prose"
    TEST = "test"


_CMD_LINE = re.compile(
    r"(?i)^\s*(?:"
    r"curl|wget|fetch|rm|chmod|chown|sudo|env|printenv|base64|openssl|"
    r"bash|sh|zsh|scp|rsync|docker|nc|ncat|mkfs|dd|"
    r"`[^`]+`"
    r")"
)


def norm_path(relpath: str) -> str:
    return relpath.replace("\\", "/")


def is_test_path(relpath: str) -> bool:
    p = norm_path(relpath)
    return p.startswith("tests/") or "/tests/" in f"/{p}" or p.startswith("test/")


def is_script_path(relpath: str) -> bool:
    p = norm_path(relpath)
    return p.startswith("scripts/") or "/scripts/" in f"/{p}"


def is_source_kind(kind: FileKind) -> bool:
    return kind in {
        FileKind.SHELL,
        FileKind.PYTHON,
        FileKind.JAVASCRIPT,
        FileKind.POWERSHELL,
    }


def file_surface(f: AnalyzedFile) -> Surface:
    """Primary surface for a whole file (not a fence)."""
    if is_test_path(f.relpath):
        return Surface.TEST
    if is_script_path(f.relpath) or is_source_kind(f.kind):
        return Surface.SCRIPT
    if f.kind is FileKind.MARKDOWN:
        return Surface.PROSE
    return Surface.PROSE


def candidate_surface(f: AnalyzedFile, cand: CodeCandidate) -> Surface:
    """Surface for one CodeCandidate relative to its file."""
    if is_test_path(f.relpath):
        return Surface.TEST
    # Full-file candidate on a source file
    if is_script_path(f.relpath) or (
        is_source_kind(f.kind) and cand.lang is None and cand.text.strip() == f.normalized.strip()
    ):
        return Surface.SCRIPT
    # Explicit fence language → fence
    if cand.lang is not None:
        return Surface.FENCE
    # Untagged fence body (not equal to full normalized prose dump)
    if f.kind is FileKind.MARKDOWN and cand.text.strip() != f.normalized.strip():
        return Surface.FENCE
    if f.kind is FileKind.MARKDOWN:
        return Surface.PROSE
    return file_surface(f)


def is_shell_lang(lang: str | None) -> bool:
    return lang in (None, "shell", "powershell")


def is_agent_policy_surface(f: AnalyzedFile) -> bool:
    """Surfaces where HITL/sandbox *policy for the agent* is written.

    True for skill markdown. False for tests/. Python only if under scripts
    is still usually CLI — callers add wording checks.
    """
    if is_test_path(f.relpath):
        return False
    return f.kind is FileKind.MARKDOWN


def commandish_shell_lines(text: str) -> str:
    """Pull runnable shell lines out of mixed markdown / danger lists."""
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"^[-*]\s+", s) and "(" in s:
            continue
        if re.match(r"^[-*]\s+(rm|chmod|chown)\b", s) and not re.search(
            r"[|/]|\.sh\b|https?://", s
        ):
            continue
        m = re.fullmatch(r"`([^`]+)`", s)
        if m:
            out.append(m.group(1))
            continue
        if _CMD_LINE.match(s) or re.search(r"\|\s*(ba)?sh\b", s, re.I):
            out.append(re.sub(r"^[-*]\s+", "", s))
    return "\n".join(out)


def shell_pipeline_text(f: AnalyzedFile, cand: CodeCandidate) -> str | None:
    """Text to feed shell pipeline rules, or None to skip this candidate.

    - Non-shell fence langs → skip
    - Markdown prose / untagged fences → commandish lines only
    - Shell-tagged fences and scripts → full body
    """
    if cand.lang not in (None, "shell", "powershell"):
        return None
    surf = candidate_surface(f, cand)
    if surf is Surface.TEST:
        return None
    if f.kind is FileKind.MARKDOWN and cand.lang is None:
        text = commandish_shell_lines(cand.text)
        return text if text.strip() else None
    if cand.lang == "shell" or cand.lang == "powershell":
        return cand.text
    if surf is Surface.SCRIPT:
        return cand.text
    # untagged on non-markdown source
    return cand.text
