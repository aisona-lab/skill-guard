# Benchmarks

Honest measurement protocol for skill-guard. **Do not conflate suites.**

Last local run: **2026-07-15** · skill-guard **0.2.1+** (feat/ood-corpus)

## Suites

| Suite | What it is | What it is **not** |
|-------|------------|---------------------|
| **core** | Hand-written fixtures in-repo; regression guard | External accuracy claim |
| **adversarial** | Attack variants written to stress detectors | Skills from the wild |
| **ood** | Vendored real skills from public repos | A malware corpus |

## Gates (CI)

| Suite | Metric | Threshold |
|-------|--------|-----------|
| core | unsafe BLOCK recall | ≥ 0.95 |
| core | safe false-BLOCK rate | ≤ 0.05 |
| adversarial | attack BLOCK recall | ≥ 0.75 |
| adversarial | safe control FPR | ≤ 0.05 |
| **ood** | **safe false-BLOCK rate** | **≤ 0.05** |
| ood | minimum safe sample size | ≥ 40 |

WARN on safe OOD skills is **reported but not a hard fail** (noise budget for bloat/global install tips).

## Reproduce

```bash
uv sync --all-extras
uv run python eval/selftest.py
uv run python eval/run_eval.py --suite all --check --details
uv run pytest -q
```

## Latest results (local)

### core

| Metric | Value |
|--------|-------|
| unsafe recall | 17/17 = 1.00 |
| safe FPR | 0/9 = 0.00 |

### adversarial

| Metric | Value |
|--------|-------|
| attack recall | 25/25 = 1.00 |
| safe control FPR | 0/5 = 0.00 |

### ood (real-world safe skills)

| Metric | Value |
|--------|-------|
| n (safe) | 73 |
| false BLOCK (FPR) | **0/73 = 0.00** |
| WARN rate (informational) | ~13/73 ≈ 0.18 |

**Sources (partial vendored packages):** obra/superpowers, DietrichGebert/ponytail, vercel-labs/agent-skills, anthropics/skills, ComposioHQ/awesome-claude-skills (non-composio top-level). See `dataset/ood/SOURCES.md`.

### Exclusions (documented)

| Skill | Why excluded from OOD-safe |
|-------|----------------------------|
| `anthropic/claude-api` | Large multi-language docs pack with migration text that looks like injection/secrets examples — not a typical single-purpose skill install |

### Known residual (detection)

- Concatenated secret tokens (`'sk'+'-ant-'+…`) — not claimed covered

## Independent red-team (not CI)

Ad-hoc 24–25 attack variants outside catalog files: ~96% BLOCK after P0 (see PR history). Re-run when changing detectors.

## FP fixes motivated by OOD

Scanning real skills drove these precision fixes (still green on adversarial):

1. `chmod 600` no longer flagged as setuid  
2. JS `child_process` requires strong sink (`curl`/`wget`/`bash -c`/`.ssh` read), not bare `sh`  
3. `.env` + network co-occurrence needs exfil-shaped context  
4. Bare `GITHUB_TOKEN` mention → MEDIUM; `${{ secrets.* }}` stays CRITICAL  

## How to refresh OOD samples

```bash
# 1. Clone upstreams (see scripts/refresh_ood.py when present)
# 2. Re-run vendor selection and scan
# 3. Update ood_catalog.jsonl + this file with date and n/FPR
```

Always record **date, commit, n, FPR, WARN rate**. Never publish core 100% as “real-world accuracy.”
