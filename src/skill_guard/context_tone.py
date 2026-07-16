"""Lightweight window checks for educational / example tone.

Used to cut FPs when real skills *document* attacks (security training, CI
YAML samples) instead of instructing the agent to perform them.
"""

from __future__ import annotations

import re

# Prose that frames a match as example, warning, or anti-pattern.
_EDU = re.compile(
    r"("
    r"\b("
    # Avoid matching hostnames like evil.example.com ( (?<!\.) before example ).
    r"(?<!\.)\bexample\b|e\.g\.|eg\.|for example|such as|(?<!\.)\bsample\b|illustration|"
    r"do not|don't|dont|never|avoid|anti-?pattern|bad practice|"
    r"incorrect|wrong way|what not|should not|must not|shall not|"
    r"malicious|attacker|attack pattern|injection attempt|"
    r"security risk|harden|hardening|mitigat|defense|prevent|"
    r"warning|red team|how attackers|common mistake|"
    r"instead of|prefer not|refuse|block if|reject if|"
    r"documentation only|for illustration|"
    r"ssrf|allowlist|blocklist|denylist|private.?ip|link-local|"
    r"cloud metadata|ssrf target|toctou|unicast|"
    r"dangerous|forbidden|prohibited|deny list|block list|"
    r"especially|watch for|look for|"
    r"prompt injection|jailbreak|override attempt|"
    r"trading.?agent|security checklist|threat model"
    r")\b|"
    # Code comments / markdown bullets framing BAD vs GOOD patterns
    r"//\s*(bad|good|wrong|correct)\b|"
    r"#\s*(bad|good|wrong|correct)\b|"
    r"^\s*[-*]\s+(rm\s+-rf|chmod\s+777)\b"  # danger lists, not commands to run
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# CLI / test code talking about flags — not agent-bypass instructions.
_CLI_OR_TEST = re.compile(
    r"(?i)("
    r"--skip[-_]?|add_argument|argparse|click\.option|typer\.Option|"
    r"flags?\s*=|help\s*=|dest\s*=|"
    r"pytest|unittest|@pytest|def\s+test_|if\s+__name__|"
    r"skip_confirm|skip_sandbox|skip_approval|"
    r"option\(['\"]--|"
    r"store_true|action\s*="
    r")"
)

# Outbound exfil-ish use of CI secrets (keeps real leaks CRITICAL).
_SECRET_EXFIL = re.compile(
    r"(?i)("
    r"curl\b|wget\b|fetch\s*\(|httpx\.|requests\.(get|post|put)|"
    r"Invoke-WebRequest|Invoke-RestMethod|"
    r"-d\s|---data|--form|-F\s|"
    r"Authorization:\s*Bearer|"
    r"echo\s+.\$\{\{\s*secrets\.|print\s+.\$\{\{\s*secrets\."
    r")"
)


def educational_context(text: str, start: int, end: int, *, radius: int = 160) -> bool:
    """True if nearby text frames the match as example/warning/anti-pattern."""
    if not text:
        return False
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return _EDU.search(text[lo:hi]) is not None


def secret_exfil_context(text: str, start: int, end: int, *, radius: int = 200) -> bool:
    """True if CI secret expansion sits near an outbound/exfil sink."""
    if not text:
        return False
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return _SECRET_EXFIL.search(text[lo:hi]) is not None


def cli_or_test_context(text: str, start: int, end: int, *, radius: int = 120) -> bool:
    """True if match is argparse/pytest/flag plumbing, not agent policy."""
    if not text:
        return False
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return _CLI_OR_TEST.search(text[lo:hi]) is not None
