# skill-guard

**Audit Agent Skills before they touch your machine. Deterministic checks. Exit codes. No vibes.**

[![CI](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Community skills install with the same privileges as your coding agent. Most “verifiers” are more LLM prose. **skill-guard is a linter**: pure functions over package files, offline, CI-native.

Part of the [aisona-lab](https://github.com/aisona-lab) trust layer next to [prompt-guard](https://github.com/aisona-lab/prompt-guard), [OrcaI](https://github.com/aisona-lab/OrcaI), and [lazycoder](https://github.com/aisona-lab/lazycoder).

## Install

```bash
# from repo
uv sync
uv run skill-guard scan ./path/to/skill

# or
pip install -e .
skill-guard scan ./path/to/skill
```

## Usage

```bash
skill-guard scan ./my-skill
skill-guard scan ./my-skill --json
skill-guard scan ./my-skill --fail-on warn    # WARN and BLOCK fail CI
skill-guard scan ./my-skill --rules SG002,SG004
```

### Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | ALLOW (or WARN when `--fail-on block`, the default) |
| 1 | WARN (only with `--fail-on warn`) |
| 2 | BLOCK |
| 3 | usage / missing path |

Verdict policy: any **high** or **critical** finding → `BLOCK`; only medium → `WARN`; low/none → `ALLOW`.

## What it checks

| ID | Family | Examples |
|----|--------|----------|
| SG001 | Spec / structure | missing `name`/`description`, invalid name charset |
| SG002 | Secrets | `sk-ant-…`, `ghp_…`, private keys, hardcoded tokens |
| SG003 | Dangerous shell | `curl \| bash`, `rm -rf $HOME`, fork bombs |
| SG004 | Exfiltration | `cat ~/.ssh` + curl, env dumps, reverse shells |
| SG005 | Prompt hijack | “ignore previous instructions”, hidden `[SYSTEM]` tags |
| SG006 | Supply chain | `npm install https://…`, `pip install git+…` |
| SG007 | Blast radius | bypass sandbox/HITL, system path writes |
| SG008 | Token bloat | oversized `SKILL.md` body |
| SG009 | Identity spoof | “official Anthropic skill” claims, lookalike names |
| SG010 | Enterprise policy | `169.254.169.254`, GHA secrets, privileged docker/k8s |

Rules scan the **whole package** (`SKILL.md` + `scripts/` + references), not just the markdown body. Multi-file attacks are first-class.

## Architecture (short)

```
path → load package (no exec) → rules (pure) → verdict → text|json
```

Design rationale lives in [`docs/DECISIONS.md`](docs/DECISIONS.md). Highlights:

- **Deterministic only in v0.1** — no LLM judge (offline, free, auditable).
- **Selftest before claims** — good fixtures must pass, bad must fail (`eval/selftest.py`).
- **Honest eval gates** — precision/recall on a labeled corpus; not a vanity 100%.

References for process: [ponytail](https://github.com/DietrichGebert/ponytail) benchmarks (`--selftest`, safety gates), lab siblings prompt-guard / OrcaI / lazycoder.

## Dataset

Enterprise-oriented fixtures under `dataset/`:

- **benign** — legitimate skills (ALLOW)
- **malicious** — clear attacks (BLOCK), including multi-file script-only malice
- **enterprise** — cloud metadata, CI tokens, vault, privileged k8s/docker
- **borderline** — soft tier (reported, not hard-gated)

```bash
uv run python eval/selftest.py
uv run python eval/run_eval.py --check --details
```

Core gates (CI):

- unsafe BLOCK recall ≥ 0.95  
- expected-rule recall ≥ 0.90  
- safe false-BLOCK rate ≤ 0.10  

These are **regression guards** on a corpus the rules know. Do not market them as universal detection rates.

## Agent skill wrapper

Thin progressive-disclosure skill (calls the CLI, does not reimplement rules):

```
skills/skill-guard/SKILL.md
```

## Tests

```bash
uv sync --all-extras
uv run pytest -q
uv run ruff check src tests eval
```

## Non-goals (v0.1)

- Runtime tool-call firewall (different product)
- MCP protocol proxy
- Auto-remediation / rewriting third-party skills
- Web UI

## License

MIT © aisona-lab
