# P0 Week 1 — Production detector foundation

**Goal:** Turn skill-guard from circular-regex demo into a security linter that
survives independent adversarial attacks (≥75% attack recall) with low FPR
(≤5% on labeled safe), CI-gated, SARIF-ready.

**Baseline reality (pre-P0 red-team):** ~32% attack recall off-corpus; 100% on
self-written fixtures is circular and not shippable as a claim.

## Non-negotiables

1. Never execute skill code under audit.
2. Deterministic primary path (no LLM required for CI gates).
3. Adversarial suite is a **hard CI gate**, separate from regression fixtures.
4. Every rule change updates adversarial fixtures + expected labels.
5. No empty branches: every PR ships runnable code + tests.

## Architecture additions

```
load package
  → normalize each text file (NFKC, fences, line-cont)
  → build PackageContext (+ path hits index)
  → rules (shell engine, language readers, pattern rules)
  → aggregate verdict
  → report text | json | sarif
```

## PR Plan

### PR 1: Normalize + sensitive path registry
- **Description:** Shared foundation: text normalizer, sensitive path catalog, PackageContext enrichment. SG001 severity fix (invalid name → WARN not BLOCK unless missing skill).
- **Files/components affected:** `src/skill_guard/normalize.py`, `src/skill_guard/paths.py`, `src/skill_guard/parser/package.py`, `src/skill_guard/models.py`, `src/skill_guard/rules/structure.py`, `tests/test_normalize.py`, `tests/test_paths.py`
- **Dependencies:** None

### PR 2: Shell detection engine
- **Description:** Replace order-sensitive shell regex with token/flag analysis: curl|wget → shell, rm with r+f + dangerous targets, base64|decode|shell, PowerShell IEX/DownloadString, split-var evasion best-effort.
- **Files/components affected:** `src/skill_guard/rules/shell.py`, `src/skill_guard/analysis/shell_tokens.py`, `tests/test_shell_engine.py`, adversarial shell fixtures
- **Dependencies:** PR 1

### PR 3: Language-aware credential theft
- **Description:** Python/JS/PowerShell readers: sensitive path reads + network sinks; docker.sock; scp/aws exfil patterns using path registry.
- **Files/components affected:** `src/skill_guard/rules/exfil.py`, `src/skill_guard/rules/enterprise.py`, `src/skill_guard/analysis/lang_python.py`, `src/skill_guard/analysis/lang_js.py`, `src/skill_guard/analysis/lang_powershell.py`, `tests/test_lang_detectors.py`
- **Dependencies:** PR 1

### PR 4: Adversarial corpus + CI gates
- **Description:** Versioned adversarial fixtures (≥25 attacks from red-team + variants). Eval modes: regression vs adversarial. CI fails if adversarial recall < 0.75 or safe FPR > 0.05.
- **Files/components affected:** `dataset/adversarial/`, `dataset/adversarial_catalog.jsonl`, `eval/run_eval.py`, `eval/selftest.py`, `.github/workflows/ci.yml`, `tests/test_adversarial_gate.py`
- **Dependencies:** PR 2, PR 3

### PR 5: Production packaging
- **Description:** SARIF output, config file (`.skill-guard.yml`) with rule enable/severity/suppressions, GitHub Action for consumer repos, batch scan, honest README metrics.
- **Files/components affected:** `src/skill_guard/sarif.py`, `src/skill_guard/config.py`, `src/skill_guard/cli.py`, `action.yml`, `README.md`, `docs/DECISIONS.md`, `tests/test_sarif.py`, `tests/test_config.py`
- **Dependencies:** PR 4

## Success metrics (week 1 exit)

| Gate | Threshold |
|------|-----------|
| Adversarial attack BLOCK recall | ≥ 0.75 |
| Core safe false-BLOCK rate | ≤ 0.05 |
| Unit + selftest + eval in CI | green |
| SARIF valid against schema subset | pass |
| Dogfood: own skill + ponytail | ALLOW |

## Stack order (linear)

PR1 → (PR2 ∥ PR3) → PR4 → PR5
