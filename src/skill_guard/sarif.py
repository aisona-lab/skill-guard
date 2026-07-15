"""SARIF 2.1.0 subset for GitHub code scanning compatibility."""

from __future__ import annotations

import json
from typing import Any

from skill_guard import __version__
from skill_guard.models import ScanResult, Severity

_LEVEL = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules_meta: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in result.findings:
        rid = f.rule_id.value
        if rid not in rules_meta:
            rules_meta[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "help": {"text": f.remediation or f.message},
            }
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.path or result.target},
            }
        }
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append(
            {
                "ruleId": rid,
                "level": _LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.message}"},
                "locations": [loc],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skill-guard",
                        "version": __version__,
                        "informationUri": "https://github.com/aisona-lab/skill-guard",
                        "rules": list(rules_meta.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"skill-guard scan {result.target}",
                    }
                ],
            }
        ],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2)
