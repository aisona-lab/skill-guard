"""Text normalization for detection.

Applied before rules so trivial evasions (unicode, line continuations,
markdown fences) do not bypass pattern and language analysis.

We deliberately do NOT:
- decode arbitrary base64 payloads (would explode false positives)
- execute or interpret code
"""

from __future__ import annotations

import re
import unicodedata

from skill_guard.models import CodeCandidate

# Capture optional fence language tag + body.
_FENCE_RE = re.compile(r"```([^\n`]*)\n([\s\S]*?)```", re.MULTILINE)
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_LINE_CONT_RE = re.compile(r"\\\n")
_MULTI_SPACE = re.compile(r"[ \t]+")

# First token of fence info string → normalized lang for analyzers.
_LANG_ALIASES: dict[str, str] = {
    "python": "python",
    "py": "python",
    "python3": "python",
    "py3": "python",
    "javascript": "javascript",
    "js": "javascript",
    "jsx": "javascript",
    "typescript": "javascript",
    "ts": "javascript",
    "tsx": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "node": "javascript",
    "bash": "shell",
    "sh": "shell",
    "zsh": "shell",
    "shell": "shell",
    "shellscript": "shell",
    "console": "shell",
    "powershell": "powershell",
    "ps1": "powershell",
    "pwsh": "powershell",
    "ps": "powershell",
}


def normalize_fence_lang(info: str) -> str | None:
    """Map fence info string (e.g. 'python', 'js title') to a lang label."""
    token = (info or "").strip().split()[0].lower() if (info or "").strip() else ""
    # strip common attributes: ```python{...} rare; keep simple token
    token = token.split("{", 1)[0]
    return _LANG_ALIASES.get(token)


def normalize_text(text: str) -> str:
    """Return a detection-oriented normalization of *text*.

    Steps:
    1. Unicode NFKC (collapses many homoglyphs / compatibility forms)
    2. Join shell line continuations (backslash-newline)
    3. Expand fenced and inline code into plain lines (keep content)
    4. Normalize newlines to \\n
    """
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = _LINE_CONT_RE.sub(" ", t)

    def _fence(m: re.Match[str]) -> str:
        return "\n" + m.group(2).rstrip() + "\n"

    t = _FENCE_RE.sub(_fence, t)
    t = _INLINE_CODE_RE.sub(r"\1", t)
    return t


def normalize_for_match(text: str) -> str:
    """Stronger form for pattern matching: lowercase + collapse whitespace."""
    t = normalize_text(text).lower()
    t = _MULTI_SPACE.sub(" ", t)
    return t


def extract_code_candidates(text: str) -> list[CodeCandidate]:
    """Fenced blocks (with lang tags) + full normalized text for multi-pass analysis."""
    raw = unicodedata.normalize("NFKC", text or "")
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    out: list[CodeCandidate] = []
    seen: set[tuple[str | None, str]] = set()

    for m in _FENCE_RE.finditer(raw):
        body = m.group(2).strip()
        if not body:
            continue
        lang = normalize_fence_lang(m.group(1))
        key = (lang, body)
        if key not in seen:
            seen.add(key)
            out.append(CodeCandidate(text=body, lang=lang))

    full = normalize_text(text).strip()
    if full and (None, full) not in seen:
        out.append(CodeCandidate(text=full, lang=None))
    return out
