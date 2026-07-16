"""Lexical tone helpers — keep small; prefer ``surface`` for structure.

Educational / CLI windows only. Do not grow this list without a fixture
from a real-scan FP (see detector freeze in AGENTS.md).
"""

from __future__ import annotations

import re

# Compact edu lexicon — structural cases belong in surface.py
_EDU = re.compile(
    r"("
    r"\b("
    r"(?<!\.)example\b|e\.g\.|for example|such as|illustration|"
    r"do not|don't|never|avoid|anti-?pattern|bad practice|"
    r"should not|must not|malicious|attacker|"
    r"harden|mitigat|defense|prevent|warning|"
    r"block if|reject if|threat model|prompt injection|jailbreak|"
    r"ssrf|allowlist|cloud metadata|dangerous|forbidden"
    r")\b|"
    r"//\s*(bad|good)\b|"
    r"^\s*[-*]\s+(rm\s+-rf|chmod\s+777)\b"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

_CLI_OR_TEST = re.compile(
    r"(?i)("
    r"--skip[-_]?|add_argument|argparse|click\.option|typer\.Option|"
    r"help\s*=|pytest|unittest|@pytest|def\s+test_|if\s+__name__|"
    r"skip_confirm|skip_sandbox|skip_approval|store_true"
    r")"
)

_SECRET_EXFIL = re.compile(
    r"(?i)("
    r"curl\b|wget\b|fetch\s*\(|httpx\.|requests\.(get|post|put)|"
    r"Invoke-WebRequest|Invoke-RestMethod|"
    r"-d\s|--data|--form|-F\s|"
    r"Authorization:\s*Bearer"
    r")"
)

_AGENT_POLICY_WORDS = re.compile(
    r"(?i)\b(agent|skill|always|must|instruct|tell the model|allowed-tools)\b"
)


def educational_context(text: str, start: int, end: int, *, radius: int = 160) -> bool:
    if not text:
        return False
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    return _EDU.search(text[lo:hi]) is not None


def secret_exfil_context(text: str, start: int, end: int, *, radius: int = 200) -> bool:
    if not text:
        return False
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    return _SECRET_EXFIL.search(text[lo:hi]) is not None


def cli_or_test_context(text: str, start: int, end: int, *, radius: int = 120) -> bool:
    if not text:
        return False
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    return _CLI_OR_TEST.search(text[lo:hi]) is not None


def agent_policy_wording(text: str, start: int, end: int, *, radius: int = 80) -> bool:
    """Nearby words that mark agent policy (vs CLI help strings)."""
    if not text:
        return False
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    return _AGENT_POLICY_WORDS.search(text[lo:hi]) is not None
