"""Single-pass file analysis: kind + normalize + candidates.

Rules must not re-normalize; they consume AnalyzedFile from PackageContext.
"""

from __future__ import annotations

from pathlib import Path

from skill_guard.models import AnalyzedFile, FileKind
from skill_guard.normalize import extract_code_candidates, normalize_text

_EXT_KIND: dict[str, FileKind] = {
    ".md": FileKind.MARKDOWN,
    ".markdown": FileKind.MARKDOWN,
    ".py": FileKind.PYTHON,
    ".js": FileKind.JAVASCRIPT,
    ".mjs": FileKind.JAVASCRIPT,
    ".cjs": FileKind.JAVASCRIPT,
    ".ts": FileKind.JAVASCRIPT,
    ".tsx": FileKind.JAVASCRIPT,
    ".jsx": FileKind.JAVASCRIPT,
    ".ps1": FileKind.POWERSHELL,
    ".psm1": FileKind.POWERSHELL,
    ".sh": FileKind.SHELL,
    ".bash": FileKind.SHELL,
    ".zsh": FileKind.SHELL,
}


def infer_kind(relpath: str, content: str) -> FileKind:
    """Infer FileKind from extension, then shebang. No prose sniffing."""
    name = Path(relpath).name
    if name.upper() == "SKILL.MD":
        return FileKind.MARKDOWN
    ext = Path(relpath).suffix.lower()
    if ext in _EXT_KIND:
        return _EXT_KIND[ext]
    first = content.lstrip().splitlines()[:1]
    if first and first[0].startswith("#!"):
        shebang = first[0].lower()
        if "python" in shebang:
            return FileKind.PYTHON
        if "node" in shebang:
            return FileKind.JAVASCRIPT
        if "pwsh" in shebang or "powershell" in shebang:
            return FileKind.POWERSHELL
        if any(s in shebang for s in ("bash", "sh", "zsh", "dash")):
            return FileKind.SHELL
    return FileKind.OTHER


def analyze_file(relpath: str, content: str, size: int | None = None) -> AnalyzedFile:
    """Build AnalyzedFile with normalized text and code candidates."""
    kind = infer_kind(relpath, content)
    normalized = normalize_text(content)
    candidates = tuple(extract_code_candidates(content))
    return AnalyzedFile(
        relpath=relpath,
        content=content,
        size=size if size is not None else len(content.encode("utf-8", errors="replace")),
        normalized=normalized,
        candidates=candidates,
        kind=kind,
    )
