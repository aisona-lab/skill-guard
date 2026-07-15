# skill-guard — agent notes

## What this repo is

Deterministic pre-install auditor for Agent Skills (`SKILL.md` packages).

## Commands

```bash
uv sync --all-extras
uv run skill-guard scan PATH
uv run pytest -q
uv run python eval/selftest.py
uv run python eval/run_eval.py --check
```

## Invariants

1. Never execute code from the skill under audit.
2. Never add an LLM-only rule without an offline deterministic counterpart.
3. Rule IDs (`SG###`) are stable; do not renumber.
4. If you change a rule, update fixtures + catalog expectations and keep eval gates green.
5. Document non-obvious choices in `docs/DECISIONS.md`.

## Layout

```
src/skill_guard/   # library + CLI
dataset/           # labeled fixtures + catalog.jsonl
eval/              # selftest + metrics harness
tests/             # unit + production-surface
skills/skill-guard # thin Agent Skill wrapper
docs/DECISIONS.md  # architecture rationale
```
