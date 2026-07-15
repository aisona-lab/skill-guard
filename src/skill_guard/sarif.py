"""SARIF 2.1.0 subset for GitHub code scanning compatibility."""

from __future__ import annotations

import json
from pathlib import Path
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
    """Single-target SARIF document."""
    return to_sarif_multi([result])


def to_sarif_multi(results: list[ScanResult]) -> dict[str, Any]:
    """One SARIF run covering one or more scan targets (valid for Code Scanning)."""
    rules_meta: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    targets: list[str] = []

    for result in results:
        targets.append(result.target)
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
            if f.path and len(results) > 1:
                uri = (Path(result.target) / f.path).as_posix()
            else:
                uri = f.path or result.target
            loc: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }
            if f.line:
                loc["physicalLocation"]["region"] = {"startLine": f.line}
            sarif_results.append(
                {
                    "ruleId": rid,
                    "level": _LEVEL[f.severity],
                    "message": {"text": f"{f.title}: {f.message}"},
                    "locations": [loc],
                }
            )

    cmdline = "skill-guard scan " + " ".join(targets)
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
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": cmdline,
                    }
                ],
            }
        ],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2)


def render_sarif_multi(results: list[ScanResult]) -> str:
    return json.dumps(to_sarif_multi(results), indent=2)
