# skill-guard

**Audit Agent Skills before they touch your machine. Deterministic checks. Exit codes. No vibes.**

[![CI](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![version](https://img.shields.io/badge/version-0.2.0-informational)

Pre-install security linter for [Agent Skills](https://agentskills.io/specification) (`SKILL.md` packages). Scans the **whole package** (markdown + scripts) offline. Never executes skill code.

Part of [aisona-lab](https://github.com/aisona-lab) trust tooling next to [prompt-guard](https://github.com/aisona-lab/prompt-guard), [OrcaI](https://github.com/aisona-lab/OrcaI), [lazycoder](https://github.com/aisona-lab/lazycoder).

## Install

```bash
uv sync
uv run skill-guard scan ./path/to/skill

# or
pip install -e .
skill-guard scan ./path/to/skill
```

## Usage

```bash
skill-guard scan ./my-skill
skill-guard scan ./skill-a ./skill-b          # batch
skill-guard scan ./my-skill --json
skill-guard scan ./my-skill --sarif > out.sarif
skill-guard scan ./my-skill --fail-on warn
skill-guard scan ./my-skill --config .skill-guard.yml
skill-guard scan ./my-skill --rules SG002,SG004
```

### Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | ALLOW (default `--fail-on block` also treats WARN as success) |
| 1 | WARN (with `--fail-on warn`) |
| 2 | BLOCK |
| 3 | usage / missing path |

### Config (`.skill-guard.yml`)

```yaml
fail_on: block
suppress:
  - SG008
  - "SG001:SKILL.md"
rules:
  SG009:
    enabled: false
```

### GitHub Action

```yaml
- uses: aisona-lab/skill-guard@main
  with:
    path: ./skills/my-skill
    fail-on: block
    sarif: skill-guard.sarif
```

## What it checks

| ID | Family |
|----|--------|
| SG001 | Spec / structure (missing required fields) |
| SG002 | Secrets |
| SG003 | Dangerous shell / PowerShell / decode-exec (token pipeline engine) |
| SG004 | Exfiltration (path registry + Python/JS/PS readers) |
| SG005 | Prompt hijack in skill body |
| SG006 | Supply chain installs |
| SG007 | Blast radius / HITL bypass / path traversal |
| SG008 | Token bloat |
| SG009 | Identity spoof |
| SG010 | Enterprise policy (IMDS, CI secrets, docker.sock, cloud creds) |

## Architecture

```
path → load package (no exec)
     → normalize (NFKC, fences, line-cont)
     → rules (shell tokens, lang readers, patterns)
     → config suppressions
     → verdict → text | json | sarif
```

Design notes: [`docs/DECISIONS.md`](docs/DECISIONS.md) · P0 plan: [`docs/P0-WEEK1.md`](docs/P0-WEEK1.md)

## Evaluation (honest)

Two suites. **Do not conflate them.**

| Suite | Purpose | Gate |
|-------|---------|------|
| **core** (`dataset/catalog.jsonl`) | Regression on hand-labeled fixtures | unsafe recall ≥ 0.95, safe FPR ≤ 0.05 |
| **adversarial** (`dataset/adversarial_catalog.jsonl`) | Independent attack variants (shell reorder, PS cradles, pathlib, docker.sock, …) | attack recall ≥ 0.75, safe FPR ≤ 0.05 |

```bash
uv run python eval/selftest.py
uv run python eval/run_eval.py --suite all --check --details
uv run pytest -q
```

**Current local gates (v0.2.0):**

- core unsafe recall **17/17**, safe FPR **0/9**
- adversarial attack recall **25/25**, safe FPR **0/5**
- independent red-team (25 novel variants, not only catalog files): **24/25 (96%)**  
  residual miss: concatenated API key string (`'sk'+'-ant-'+…`) — documented, not claimed covered

Core metrics are a **regression guard**. Adversarial + independent red-team are the production bar.

## Non-goals

- Runtime tool-call firewall (separate product)
- LLM-as-judge as primary detector
- Executing skill scripts during audit
- 100% detection of all future evasions

## License

MIT © aisona-lab
