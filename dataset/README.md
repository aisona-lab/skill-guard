# skill-guard dataset

Enterprise-oriented labeled fixtures for pre-install skill auditing.

## Layout

```
fixtures/
  benign/       # legitimate skills — expect ALLOW
  malicious/    # clear attacks — expect BLOCK
  enterprise/   # cloud/CI/k8s policy scenarios
  borderline/   # ambiguous; reported, not hard-gated in CI
catalog.jsonl   # labels + expected rules/verdicts
```

## Catalog schema

| field | meaning |
|---|---|
| `id` | stable fixture id |
| `path` | relative to `dataset/` |
| `label` | `safe` \| `unsafe` \| `borderline` |
| `expected_verdict` | `ALLOW` \| `WARN` \| `BLOCK` |
| `expected_rules` | rule ids that must fire (subset match for unsafe) |
| `category` | attack/family label |
| `tier` | `core` (CI gate) or `soft` (report only) |

## Honesty

Rules are developed against this corpus, so core metrics are a **regression
guard**, not an external accuracy claim. When we publish numbers, we say so.

## Run

```bash
uv run python eval/run_eval.py --check
uv run python eval/selftest.py
```
