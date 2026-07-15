"""Rule registry. Each rule is PackageContext → list[Finding]."""

from __future__ import annotations

from collections.abc import Callable

from skill_guard.models import Finding, PackageContext, RuleId
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

RuleFn = Callable[[PackageContext], list[Finding]]

DEFAULT_RULES: list[tuple[RuleId, RuleFn]] = [
    (RuleId.SG001, structure.check),
    (RuleId.SG002, secrets.check),
    (RuleId.SG003, shell.check),
    (RuleId.SG004, exfil.check),
    (RuleId.SG005, injection.check),
    (RuleId.SG006, supply_chain.check),
    (RuleId.SG007, enterprise.check_permissions),
    (RuleId.SG008, bloat.check),
    (RuleId.SG009, identity.check),
    (RuleId.SG010, enterprise.check_policy),
]


def all_rules() -> list[tuple[RuleId, RuleFn]]:
    return list(DEFAULT_RULES)
