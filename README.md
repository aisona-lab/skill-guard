# skill-guard

Scan an [Agent Skill](https://agentskills.io/specification) **before** it runs on your machine.  
Offline. Deterministic. No skill code executed. Exit codes for CI.

Beta — not a runtime firewall. See [LIMITATIONS.md](LIMITATIONS.md).

[![CI](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aisona-skill-guard.svg)](https://pypi.org/project/aisona-skill-guard/)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![version](https://img.shields.io/badge/v0.2.2-beta-yellow)

## Install

PyPI package: **`aisona-skill-guard`** (name `skill-guard` is a different project). CLI: **`skill-guard`**.

```bash
pip install aisona-skill-guard
# or
uv tool install aisona-skill-guard

skill-guard scan ./my-skill
```

From git: `uvx --from "git+https://github.com/aisona-lab/skill-guard@v0.2.2" skill-guard scan ./my-skill`

## Use

```bash
skill-guard scan ./my-skill
skill-guard scan ./a ./b --json
skill-guard scan ./my-skill --sarif-file out.sarif
skill-guard scan ./my-skill --pack strict    # fail on WARN+
```

| Exit | Meaning |
|-----:|---------|
| 0 | ALLOW (default: WARN ok) |
| 1 | WARN (`--fail-on warn` / `--pack strict`) |
| 2 | BLOCK |
| 3 | usage error |

```yaml
# .skill-guard.yml
pack: default   # or strict
fail_on: block
suppress: [SG008]
```

```yaml
- uses: aisona-lab/skill-guard@v0.2.2
  with:
    path: ./skills/my-skill
    fail-on: block
```

Paths in the Action are **newline-separated**.

## Rules

| ID | Flags |
|----|--------|
| SG001 | Structure |
| SG002 | Secrets |
| SG003 | Dangerous shell / PS |
| SG004 | Exfil |
| SG005 | Prompt hijack |
| SG006 | Supply-chain install |
| SG007 | Blast radius / HITL bypass |
| SG008 | Bloat |
| SG009 | Identity spoof |
| SG010 | Enterprise (IMDS, docker.sock, CI secrets…) |

## Live check

```bash
skill-guard scan ~/.claude/plugins/cache/ponytail/ponytail/*/skills/*
skill-guard scan dataset/fixtures/malicious/curl-pipe-shell   # BLOCK
```

### Real-skill scan results (v0.2.2)

Default policy: **`--fail-on block`** (WARN does not fail).

| Corpus | n | ALLOW | WARN | BLOCK | Notes |
|--------|--:|------:|-----:|------:|-------|
| [ponytail](https://github.com/DietrichGebert/ponytail) plugin skills | 5–6 | ~100% | 0 | 0 | prose `npm -g` not WARN |
| In-repo **ood** safe (public skills vendored) | 73 | ~85% | ~15% | **0** | FPR gate |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | 24 | 23 | 1 | 0 | CI secrets → WARN only |
| [mvanhorn/last30days-skill](https://github.com/mvanhorn/last30days-skill) | 1 (116 files) | — | — | **1** | unscoped Bash + pack size |
| [affaan-m/ECC](https://github.com/affaan-m/ECC) `skills/` + `.agents/skills` | 282 | 236 | 44 | **2** | only unscoped `allowed-tools: Bash` |
| In-repo **ood-unsafe** (held-out attacks) | 8 | 0 | 0 | **8** | recall gate |

| Suite (CI) | Gate |
|------------|------|
| core | unsafe recall ≥ 0.95, safe FPR ≤ 0.05 |
| adversarial | attack recall ≥ 0.75 |
| ood | false BLOCK ≤ 0.05, n ≥ 40 |
| ood-unsafe | attack recall ≥ 0.70, n ≥ 5 |

```bash
uv run python eval/run_eval.py --suite all --check
uv run pytest -q
```

Details: [docs/BENCHMARKS.md](docs/BENCHMARKS.md) · [LIMITATIONS.md](LIMITATIONS.md)

## Not this

Runtime firewall · LLM-as-judge · MCP audit · perfect evasion coverage.

[prompt-guard](https://github.com/aisona-lab/prompt-guard) · [OrcaI](https://github.com/aisona-lab/OrcaI) · [lazycoder](https://github.com/aisona-lab/lazycoder)

## License

MIT © aisona-lab
