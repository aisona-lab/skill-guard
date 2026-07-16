# Limitations

**Read this before citing accuracy or deploying as a sole control.**

skill-guard is a **static, offline** pre-install auditor for Agent Skill packages
(beta). It does **not** execute skill code and does **not** replace runtime controls.

**Install today:** GitHub release / source (`@v0.2.2`), not PyPI yet. Future
package name on PyPI will be `aisona-skill-guard` (the name `skill-guard` on
PyPI is a different package). CLI remains `skill-guard`.

## What it does not claim

| Claim | Reality |
|-------|---------|
| “Real-world 100% accuracy” | **core** fixtures are a regression suite. Use **ood** FPR + **adversarial** recall. |
| Zero false positives forever | OOD WARN rate is non-zero (~18% on the current corpus). Prefer `--fail-on block` in CI. |
| Catch every future evasion | New obfuscation will appear. Residual miss: concatenated secrets (`'sk'+'-ant-'+…`). |
| Runtime safety | No tool-call firewall, no network policy, no sandboxing of agents. |
| Full language AST analysis | Python/JS/PowerShell use heuristics, not full parsers. |
| MCP / plugin protocol audit | Skills only (`SKILL.md` packages), not arbitrary MCP servers. |

## GitHub Action paths

The `path` input is **newline-delimited**, not space-split. A single path may
contain spaces. Multiple paths:

```yaml
path: |
  ./skills/foo
  ./skills/bar with spaces
```

## Severity policy (default)

- **BLOCK** (exit 2 with `--fail-on block`): any `high` or `critical` finding  
- **WARN** (exit 1 with `--fail-on warn`): `medium` only  
- **ALLOW**: only `low` / no findings  

Tune with `.skill-guard.yml` suppressions and rule enable flags.

## Corpus honesty

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for suite definitions, thresholds, and the latest numbers.
Never cite core 100% as production accuracy.

## Security contact

Report vulnerabilities privately via GitHub Security Advisories on
[aisona-lab/skill-guard](https://github.com/aisona-lab/skill-guard) when available,
or open a private issue with the maintainers.
