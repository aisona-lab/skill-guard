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

_FENCE_RE = re.compile(r"```[\w+-]*\n([\s\S]*?)```", re.MULTILINE)
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_LINE_CONT_RE = re.compile(r"\\\n")
_MULTI_SPACE = re.compile(r"[ \t]+")


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

    # Lift fenced blocks: keep inner content as ordinary lines
    def _fence(m: re.Match[str]) -> str:
        return "\n" + m.group(1).rstrip() + "\n"

    t = _FENCE_RE.sub(_fence, t)
    t = _INLINE_CODE_RE.sub(r"\1", t)
    return t


def normalize_for_match(text: str) -> str:
    """Stronger form for pattern matching: lowercase + collapse whitespace."""
    t = normalize_text(text).lower()
    t = _MULTI_SPACE.sub(" ", t)
    return t


def extract_code_candidates(text: str) -> list[str]:
    """Return fenced blocks + full normalized text for multi-pass analysis."""
    raw = unicodedata.normalize("NFKC", text or "")
    blocks = [m.group(1) for m in _FENCE_RE.finditer(raw)]
    blocks.append(normalize_text(text))
    # de-dupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for b in blocks:
        b = b.strip()
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return out
