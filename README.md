# skill-guard

**Beta.** Static pre-install auditor for Agent Skills — not a runtime firewall and not “100% accuracy.” Read [LIMITATIONS.md](LIMITATIONS.md) first.

**Audit Agent Skills before they touch your machine. Deterministic checks. Exit codes. No vibes.**

[![CI](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![version](https://img.shields.io/badge/version-0.2.1-informational)
![status](https://img.shields.io/badge/status-beta-yellow)
[![PyPI](https://img.shields.io/pypi/v/aisona-skill-guard.svg)](https://pypi.org/project/aisona-skill-guard/)

Pre-install security linter for [Agent Skills](https://agentskills.io/specification) (`SKILL.md` packages). Scans the **whole package** (markdown + scripts) offline. Never executes skill code.

What this **does not** claim: real-world 100% detection, zero false positives, full multi-language AST, or runtime tool-call safety. See [LIMITATIONS.md](LIMITATIONS.md) and honest suites in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

Part of [aisona-lab](https://github.com/aisona-lab) trust tooling next to [prompt-guard](https://github.com/aisona-lab/prompt-guard), [OrcaI](https://github.com/aisona-lab/OrcaI), [lazycoder](https://github.com/aisona-lab/lazycoder).

## Install

PyPI distribution name is **`aisona-skill-guard`** (the name `skill-guard` is already taken on PyPI by an unrelated project). The CLI remains `skill-guard`.

```bash
pip install aisona-skill-guard
# or
uv tool install aisona-skill-guard

skill-guard scan ./path/to/skill

# from source
uv sync
uv run skill-guard scan ./path/to/skill
```

## Usage

```bash
skill-guard scan ./my-skill
skill-guard scan ./skill-a ./skill-b          # batch
skill-guard scan ./my-skill --json
skill-guard scan ./my-skill --sarif           # one SARIF doc (merges multi-target)
skill-guard scan ./my-skill --sarif-file out.sarif   # text + SARIF, single pass
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

Paths are **newline-separated** (not space-split), so paths with spaces work:

```yaml
- uses: aisona-lab/skill-guard@v0.2.1
  with:
    path: ./skills/my-skill
    fail-on: block
    sarif: skill-guard.sarif

# Multiple skills:
# path: |
#   ./skills/foo
#   ./skills/bar with spaces

# Optional: upload SARIF to GitHub code scanning
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: skill-guard.sarif
```

Limitations and non-claims: [`LIMITATIONS.md`](LIMITATIONS.md). Changelog: [`CHANGELOG.md`](CHANGELOG.md).  
Next-session handoff (agents/humans): [`docs/NEXT-SESSION.md`](docs/NEXT-SESSION.md).

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

Three suites. **Do not conflate them.** Full protocol: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

| Suite | Purpose | Gate |
|-------|---------|------|
| **core** | Hand-labeled fixtures (regression) | unsafe recall ≥ 0.95, safe FPR ≤ 0.05 |
| **adversarial** | Attack variants (shell reorder, PS, pathlib, docker.sock, …) | attack recall ≥ 0.75 |
| **ood** | **Real skills** from public repos (safe FPR) | false BLOCK ≤ 0.05, n ≥ 40 |

```bash
uv run python eval/selftest.py
uv run python eval/run_eval.py --suite all --check --details
uv run pytest -q
```

**Latest local snapshot (see BENCHMARKS.md for date):**

- core: unsafe **17/17**, safe FPR **0/9**
- adversarial: **25/25** attacks, **0/5** safe controls blocked
- **ood: 0 false BLOCKs on 73 vendored real safe skills** (WARN rate ~18%, not a hard gate)
- residual miss (not claimed): concatenated API keys (`'sk'+'-ant-'+…`)

Core 100% is **not** “real-world accuracy.” OOD FPR is the external credibility metric.

## Non-goals

- Runtime tool-call firewall (separate product)
- LLM-as-judge as primary detector
- Executing skill scripts during audit
- 100% detection of all future evasions

## License

MIT © aisona-lab
