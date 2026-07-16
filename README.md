# skill-guard

**Scan an Agent Skill before it runs on your machine.**  
Offline. Deterministic. No skill code executed. Exit codes for CI.

Beta. Not a runtime firewall. Not 100% detection. Details: [LIMITATIONS.md](LIMITATIONS.md).

[![CI](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![version](https://img.shields.io/badge/v0.2.1-beta-yellow)
[![release](https://img.shields.io/github/v/release/aisona-lab/skill-guard?display_name=tag)](https://github.com/aisona-lab/skill-guard/releases/tag/v0.2.1)

## Install

PyPI not published yet. CLI name is always `skill-guard` (future package name: `aisona-skill-guard` — PyPI `skill-guard` is someone else).

```bash
# one-shot
uvx --from "git+https://github.com/aisona-lab/skill-guard@v0.2.1" skill-guard scan ./my-skill

# or from a clone
uv sync && uv run skill-guard scan ./my-skill
```

## Use

```bash
skill-guard scan ./my-skill
skill-guard scan ./a ./b --json
skill-guard scan ./my-skill --sarif-file out.sarif
skill-guard scan ./my-skill --fail-on warn   # also fail on MEDIUM
skill-guard scan ./my-skill --pack strict    # same as fail-on warn
```

| Exit | Meaning |
|-----:|---------|
| 0 | ALLOW (default: WARN does not fail; only BLOCK does) |
| 1 | WARN (`--fail-on warn`) |
| 2 | BLOCK |
| 3 | bad usage |

Config (optional) `.skill-guard.yml`:

```yaml
pack: default   # or strict
fail_on: block  # overrides pack if set
suppress: [SG008]
```

CI Action:

```yaml
- uses: aisona-lab/skill-guard@v0.2.1
  with:
    path: ./skills/my-skill
    fail-on: block
```

Paths in the Action are **newline-separated** (spaces in paths OK).

## What it flags

| ID | Looks for |
|----|-----------|
| SG001 | Broken skill structure |
| SG002 | Hardcoded secrets |
| SG003 | Dangerous shell / PS |
| SG004 | Credential / env exfil |
| SG005 | Prompt hijack in body |
| SG006 | Risky installs (`npm -g`, remote pip…) |
| SG007 | Blast radius / path escape |
| SG008 | Token bloat |
| SG009 | Identity spoof |
| SG010 | Enterprise (docker.sock, IMDS, cloud creds…) |

Never runs the skill. Text + scripts only.

## Live check (real skills)

```bash
# ponytail pack — all ALLOW (prose npm -g tips are not WARN)
skill-guard scan ~/.claude/plugins/cache/ponytail/ponytail/*/skills/*

# fenced global install still WARNs
skill-guard scan dataset/ood/safe/vercel/deploy-to-vercel

# should BLOCK
skill-guard scan dataset/fixtures/malicious/curl-pipe-shell
```

## Eval (do not mix numbers)

| Suite | Measures | Gate |
|-------|----------|------|
| core | hand fixtures | recall ≥ 0.95, FPR ≤ 0.05 |
| adversarial | attack variants we wrote | recall ≥ 0.75 |
| ood | real safe skills | false BLOCK ≤ 0.05 |
| ood-unsafe | held-out attacks | recall ≥ 0.70, n ≥ 5 |

Reports **soft rule_recall** (any expected rule), **strict_rule_recall** (all expected), and **wrong_rule_block** (BLOCK without expected rule).

```bash
uv run python eval/selftest.py
uv run python eval/run_eval.py --suite all --check
uv run pytest -q
```

Protocol: [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Core 100% ≠ real-world accuracy.

## Improve next

Done this arc: SG006 context · fence-lang · live FPs · known misses · metrics honesty · ood-unsafe · policy packs.

Still open:

1. **PyPI** — publish `aisona-skill-guard` when ready  
2. Richer suppressions / more langs as real FPs appear  

## Not this tool

Runtime tool firewall · LLM-as-judge primary detector · MCP server audit · “catches every evasion”.

Sibling trust tools: [prompt-guard](https://github.com/aisona-lab/prompt-guard) · [OrcaI](https://github.com/aisona-lab/OrcaI) · [lazycoder](https://github.com/aisona-lab/lazycoder).

## Docs

[LIMITATIONS](LIMITATIONS.md) · [CHANGELOG](CHANGELOG.md) · [DECISIONS](docs/DECISIONS.md) · [BENCHMARKS](docs/BENCHMARKS.md)

## License

MIT © aisona-lab
