# skill-guard — agent notes

## What this repo is

Deterministic **pre-install** auditor for [Agent Skills](https://agentskills.io/specification)
(`SKILL.md` packages). Offline, no skill execution, CI exit codes
`ALLOW=0 / WARN=1 / BLOCK=2`.

**Status (2026-07-15):** `0.2.1` Beta on `main`. Architecture + OOD gates + packaging
hygiene done. PyPI distribution name is **`aisona-skill-guard`** (not `skill-guard` — name taken).

Full handoff for a new session: **`docs/NEXT-SESSION.md`**.

## Commands

```bash
uv sync --all-extras
uv run skill-guard scan PATH
uv run skill-guard scan PATH --sarif-file out.sarif
uv run pytest -q
uv run python eval/selftest.py
uv run python eval/run_eval.py --suite all --check --details
uv build   # wheel smoke; CI job "package" also runs this
```

## Invariants

1. **Never execute** code from the skill under audit.
2. **No LLM-only primary detector** — deterministic rules first; optional LLM only later and offline-gated.
3. **Rule IDs `SG###` are stable** — do not renumber; append new IDs if needed.
4. Rule changes must update **fixtures + catalogs** and keep **core / adversarial / ood** gates green.
5. Document non-obvious choices in `docs/DECISIONS.md`.
6. Do not conflate suites: core ≠ adversarial ≠ ood (`docs/BENCHMARKS.md`).
7. Prefer `make_finding` / `PackageContext` — do not re-normalize inside rules.

## Layout

```
src/skill_guard/     # library + CLI (what ships on PyPI)
  analyze.py         # FileKind + normalize once
  models.py          # PackageContext, Finding, verdicts
  rules/             # SG001–SG010
  analysis/          # shell tokens, lang_* heuristics
dataset/
  fixtures/          # core regression
  adversarial/       # attack suite
  ood/safe/          # real-world safe skills (vendored partial)
  *_catalog.jsonl
eval/                # selftest + run_eval
tests/
action.yml           # composite Action (newline-delimited paths)
docs/
  NEXT-SESSION.md    # handoff for next agent/session
  DECISIONS.md
  BENCHMARKS.md
  P0-WEEK1.md        # completed plan
CHANGELOG.md
LIMITATIONS.md
```

## Next work (do not invent new scope)

Order matches README **Improve next**:

1. ~~SG006 context~~ **done** — global install MEDIUM only in fences/scripts.
2. **Fence language** on candidates → drop `_looks_python` / `_looks_js` in exfil.
3. Known misses: base64/exec, split secrets, non-py/js langs.
4. Metrics: wrong-rule BLOCK + strict rule recall.
5. OOD-unsafe suite; policy packs `default`/`strict`.
6. **PyPI deferred** — tag `v0.2.1` exists; publish `aisona-skill-guard` when token ready.
7. Only later: agent-firewall (runtime).

## Lab context

Sibling public tools: `prompt-guard`, `OrcaI`, `lazycoder` under `aisona-lab`.
skill-guard is the **skill supply-chain** door; keep the brand “trust layers,” not generic coding skills.
