"""Load an Agent Skill package from disk without executing anything.

Spec reference: https://agentskills.io/specification
- A skill is a directory with SKILL.md (YAML frontmatter + markdown body).
- Optional: scripts/, references/, assets/.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from skill_guard.models import SkillFile, SkillPackage

# Skip binary/noise during text scan. Explicit allowlist for safety-relevant code.
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

# Hard cap per file to avoid loading multi-MB blobs into memory.
_MAX_FILE_BYTES = 512_000
_MAX_FILES = 200

_FRONTMATTER_RE = re.compile(
    r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z",
    re.DOTALL,
)


def load_package(path: str | Path) -> SkillPackage:
    """Load skill package from a directory or a SKILL.md file path."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        return SkillPackage(root=str(p), parse_errors=[f"path does not exist: {p}"])

    if p.is_file():
        root = p.parent
        skill_path = p
    else:
        root = p
        skill_path = p / "SKILL.md"
        if not skill_path.is_file():
            # Accept lowercase variant only as soft discovery; report missing properly.
            alt = p / "skill.md"
            skill_path = alt if alt.is_file() else skill_path

    files = _collect_files(root)
    skill_md = next((f for f in files if Path(f.relpath).name.upper() == "SKILL.MD"), None)

    # If caller pointed at a file not under root walk, load it explicitly.
    if skill_md is None and skill_path.is_file():
        skill_md = _read_file(skill_path, root)

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

    return SkillPackage(
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


def _collect_files(root: Path) -> list[SkillFile]:
    out: list[SkillFile] = []
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
            # Still include extensionless scripts with shebang under scripts/
            if not (rel.startswith("scripts/") and _looks_text(path)):
                continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if len(raw) > _MAX_FILE_BYTES:
            # Keep a truncated sample so size-based rules still fire.
            text = raw[:_MAX_FILE_BYTES].decode("utf-8", errors="replace")
            out.append(SkillFile(relpath=rel, content=text, size=len(raw)))
        else:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="replace")
            out.append(SkillFile(relpath=rel, content=text, size=len(raw)))
        if len(out) >= _MAX_FILES:
            break
    return out


def _read_file(path: Path, root: Path) -> SkillFile:
    raw = path.read_bytes()
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
    text = raw[:_MAX_FILE_BYTES].decode("utf-8", errors="replace")
    return SkillFile(relpath=rel, content=text, size=len(raw))


def _looks_text(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:256]
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    return True
