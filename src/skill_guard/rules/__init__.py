"""Rule registry. Each rule is a pure function over SkillPackage."""

from __future__ import annotations

from collections.abc import Callable

from skill_guard.models import Finding, SkillPackage
from skill_guard.rules import (
    bloat,
    enterprise,
    exfil,
    identity,
    injection,
    secrets,
    shell,
    structure,
    supply_chain,
)

RuleFn = Callable[[SkillPackage], list[Finding]]

# Order is report order only; engine never short-circuits.
DEFAULT_RULES: list[tuple[str, RuleFn]] = [
    ("SG001", structure.check),
    ("SG002", secrets.check),
    ("SG003", shell.check),
    ("SG004", exfil.check),
    ("SG005", injection.check),
    ("SG006", supply_chain.check),
    ("SG007", enterprise.check_permissions),
    ("SG008", bloat.check),
    ("SG009", identity.check),
    ("SG010", enterprise.check_policy),
]


def all_rules() -> list[tuple[str, RuleFn]]:
    return list(DEFAULT_RULES)
