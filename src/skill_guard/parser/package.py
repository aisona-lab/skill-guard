"""Load an Agent Skill package from disk without executing anything.

Produces PackageContext with AnalyzedFile entries (normalize once).
Spec: https://agentskills.io/specification
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from skill_guard.analyze import analyze_file
from skill_guard.models import PackageContext

_TEXT_SUFFIXES = {
    "",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".swift",
    ".pl",
    ".php",
    ".r",
    ".sql",
    ".env",
    ".env.example",
    ".gitignore",
    ".npmrc",
    ".dockerignore",
}

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}

_MAX_FILE_BYTES = 512_000
_MAX_FILES = 200

_FRONTMATTER_RE = re.compile(
    r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z",
    re.DOTALL,
)


def load_package(path: str | Path) -> PackageContext:
    """Load skill package from a directory or a SKILL.md file path."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        return PackageContext(root=str(p), parse_errors=[f"path does not exist: {p}"])

    if p.is_file():
        root = p.parent
        skill_path = p
    else:
        root = p
        skill_path = p / "SKILL.md"
        if not skill_path.is_file():
            alt = p / "skill.md"
            skill_path = alt if alt.is_file() else skill_path

    raw_files = _collect_raw(root)
    files = [analyze_file(rel, content, size) for rel, content, size in raw_files]

    skill_md = next(
        (f for f in files if Path(f.relpath).name.upper() == "SKILL.MD"),
        None,
    )
    if skill_md is None and skill_path.is_file():
        rel, content, size = _read_raw(skill_path, root)
        skill_md = analyze_file(rel, content, size)
        if not any(f.relpath == skill_md.relpath for f in files):
            files = [skill_md, *files]

    frontmatter: dict = {}
    body = ""
    errors: list[str] = []

    if skill_md is None:
        errors.append("missing SKILL.md")
    else:
        fm, body, fm_err = parse_skill_md(skill_md.content)
        frontmatter = fm
        if fm_err:
            errors.append(fm_err)

    return PackageContext(
        root=str(root),
        skill_md=skill_md,
        frontmatter=frontmatter,
        body=body,
        files=files if files else ([skill_md] if skill_md else []),
        parse_errors=errors,
    )


def parse_skill_md(content: str) -> tuple[dict, str, str | None]:
    """Split SKILL.md into frontmatter dict and body. Returns (fm, body, error)."""
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}, content, "SKILL.md missing YAML frontmatter (--- ... ---)"

    raw_yaml, body = match.group(1), match.group(2)
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        return {}, body, f"invalid YAML frontmatter: {exc}"

    if data is None:
        return {}, body, "empty YAML frontmatter"
    if not isinstance(data, dict):
        return {}, body, "frontmatter must be a YAML mapping"
    return data, body, None


def _collect_raw(root: Path) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() not in _TEXT_SUFFIXES and path.name not in {
            "SKILL.md",
            "skill.md",
            "Dockerfile",
            "Makefile",
            "LICENSE",
        }:
            if not (rel.startswith("scripts/") and _looks_text(path)):
                continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        size = len(raw)
        sample = raw[:_MAX_FILE_BYTES]
        try:
            text = sample.decode("utf-8")
        except UnicodeDecodeError:
            text = sample.decode("utf-8", errors="replace")
        out.append((rel, text, size))
        if len(out) >= _MAX_FILES:
            break
    return out


def _read_raw(path: Path, root: Path) -> tuple[str, str, int]:
    raw = path.read_bytes()
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
    text = raw[:_MAX_FILE_BYTES].decode("utf-8", errors="replace")
    return rel, text, len(raw)


def _looks_text(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:256]
    except OSError:
        return False
    return b"\x00" not in sample
