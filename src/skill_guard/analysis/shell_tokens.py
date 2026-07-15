"""Lightweight shell tokenization for security rules.

Not a full shell parser. Goal: survive flag reordering and simple pipelines
without the cost/fragility of a complete POSIX grammar.
"""

from __future__ import annotations

import re

_TOKEN_RE = re.compile(
    r"""
    (?:[^\s\\|;&<>'"`]+)   # bare word
    |'(?:[^']*)'           # single-quoted
    |"(?:[^"\\]|\\.)*"     # double-quoted (simple)
    |\|{1,2}|&&|;|<|>      # operators
    """,
    re.VERBOSE,
)


def tokenize_shell_line(line: str) -> list[str]:
    """Tokenize a single shell line into words/operators."""
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    return [m.group(0) for m in _TOKEN_RE.finditer(line)]


def split_pipelines(text: str) -> list[list[str]]:
    """Return pipelines as lists of stage token-lists.

    Example: ``curl u | bash`` -> [[["curl","u"], ["bash"]]]
    """
    pipelines: list[list[str]] = []
    for raw_line in text.splitlines():
        # strip comments
        if "#" in raw_line:
            in_s = in_d = False
            cut = len(raw_line)
            for i, ch in enumerate(raw_line):
                if ch == "'" and not in_d:
                    in_s = not in_s
                elif ch == '"' and not in_s:
                    in_d = not in_d
                elif ch == "#" and not in_s and not in_d:
                    cut = i
                    break
            raw_line = raw_line[:cut]
        tokens = tokenize_shell_line(raw_line)
        if not tokens:
            continue
        # split on ; and && into commands, then each on |
        commands: list[list[str]] = [[]]
        for t in tokens:
            if t in {";", "&&", "||"}:
                commands.append([])
            else:
                commands[-1].append(t)
        for cmd in commands:
            if not cmd:
                continue
            stages: list[list[str]] = [[]]
            for t in cmd:
                if t == "|":
                    stages.append([])
                else:
                    stages[-1].append(t)
            stages = [s for s in stages if s]
            if stages:
                pipelines.append(stages)
    return pipelines


# Common tools we care about — prefer these when prose prefixes appear
# ("Run: curl ..." should resolve to curl, not "run:").
_KNOWN_CMDS = {
    "curl",
    "wget",
    "fetch",
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "rm",
    "dd",
    "chmod",
    "chown",
    "sudo",
    "base64",
    "openssl",
    "xxd",
    "nc",
    "ncat",
    "netcat",
    "scp",
    "rsync",
    "docker",
    "kubectl",
    "aws",
    "pip",
    "npm",
    "pnpm",
    "yarn",
    "npx",
    "bunx",
    "python",
    "python3",
    "node",
    "env",
    "xargs",
    "tar",
    "crontab",
    "mkfs",
}


def cmd_name(stage: list[str]) -> str:
    """Best-effort command name for a stage.

    Skips assignments and prose labels (``Run:``). Prefers known security-relevant
    tools when present so markdown like ``Run: curl u | bash`` still detects.
    """
    candidates: list[str] = []
    for t in stage:
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            continue
        name = t.strip("'\"").rsplit("/", 1)[-1].lower()
        if not name or name.startswith("-"):
            continue
        if name.endswith(":"):
            continue
        candidates.append(name)
    for c in candidates:
        if c in _KNOWN_CMDS:
            return c
    return candidates[0] if candidates else ""


def flags_of(stage: list[str]) -> set[str]:
    """Collect short flags as individual letters and long flags as words."""
    flags: set[str] = set()
    for t in stage[1:]:
        if t.startswith("--"):
            flags.add(t.lower())
        elif t.startswith("-") and len(t) > 1 and not t[1].isdigit():
            for ch in t[1:]:
                if ch.isalpha():
                    flags.add(ch.lower())
    return flags


def stage_words(stage: list[str]) -> list[str]:
    return [t.strip("'\"") for t in stage]


def join_stage(stage: list[str]) -> str:
    return " ".join(stage)
