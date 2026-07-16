# Next session handoff — skill-guard

**Last updated:** 2026-07-16  
**Branch:** `main`  
**Version in tree:** `0.2.1` (Beta — future PyPI name **`aisona-skill-guard`**; CLI `skill-guard`)  
**Git tag / release:** `v0.2.1` published on GitHub  
**PyPI:** **deferred** (no token; do not advertise `pip install` until published)  
**Repo:** https://github.com/aisona-lab/skill-guard  
**Local path:** `/Users/carlos/Projects and Agents/skill-guard`

---

## One-line status

Beta **tagged** (`v0.2.1`). SG006 prose filter + fence-lang shipped. Next: known misses / metrics honesty. PyPI deferred.

---

## What we shipped this arc (PRs)

| PR | Title | Outcome |
|----|-------|---------|
| [#1](https://github.com/aisona-lab/skill-guard/pull/1) | P0 production detectors + adversarial gates | Merged |
| [#2](https://github.com/aisona-lab/skill-guard/pull/2) | PackageContext + table-driven shell | Merged |
| [#3](https://github.com/aisona-lab/skill-guard/pull/3) | OOD corpus (73 real skills) + FPR gate | Merged |
| [#4](https://github.com/aisona-lab/skill-guard/pull/4) | Pre-PyPI hygiene | Merged |
| [#5](https://github.com/aisona-lab/skill-guard/pull/5) | Action newline paths + JSON `result_dict` | Merged |

No open PRs at handoff time.

---

## Product position (aisona-lab)

Trust layer for AI agents (not another “superpowers”):

```
skill-guard  → pre-install supply chain of Agent Skills
prompt-guard → prompt/input surface
OrcaI        → output verification
lazycoder    → code review verdict gate
```

Future (not built): **agent-firewall** (runtime tool-call policy) — only after skill-guard has distribution/traction.

---

## Architecture (do not regress)

```
path → load_package (no exec)
     → AnalyzedFile / PackageContext  (normalize + candidates + FileKind once)
     → rules SG001–SG010
     → config suppressions
     → verdict ALLOW | WARN | BLOCK
     → text | json | sarif
```

Key modules:

| Module | Role |
|--------|------|
| `analyze.py` | FileKind + normalize once |
| `models.py` | `PackageContext`, `make_finding`, `dedupe_findings` |
| `rules/shell.py` | Table-driven pipeline + whole-file rules |
| `paths.py` | Shared sensitive-path catalog |
| `analysis/lang_*` | Python / JS / PowerShell heuristics |
| `eval/run_eval.py` | Suites: `core` \| `adversarial` \| `ood` \| `all` |

**Invariants** (also in `AGENTS.md`):

1. Never execute skill under audit  
2. No LLM-only primary detector  
3. Stable `SG###` IDs  
4. Rule change → update fixtures/catalogs + keep gates green  
5. Decisions in `docs/DECISIONS.md`

---

## Eval honesty (three suites)

| Suite | What | Gate |
|-------|------|------|
| **core** | Hand fixtures | unsafe recall ≥ 0.95, safe FPR ≤ 0.05 |
| **adversarial** | Attack variants we wrote | attack recall ≥ 0.75 |
| **ood** | Real public skills, labeled safe | false BLOCK ≤ 0.05, n ≥ 40 |

**Last known local numbers:**

- core: 17/17 unsafe, 0/9 FPR  
- adversarial: 25/25 attacks, 0/5 FPR  
- ood: **0/73 false BLOCKs** (WARN ~18% on safe — not a hard gate)  
- residual miss (documented): concatenated secrets `'sk'+'-ant-'+…`

Full protocol: `docs/BENCHMARKS.md`. Non-claims: `LIMITATIONS.md`.

---

## Commands (bootstrap next session)

```bash
cd "/Users/carlos/Projects and Agents/skill-guard"
git checkout main && git pull
uv sync --all-extras

uv run skill-guard scan PATH
uv run pytest -q
uv run python eval/selftest.py
uv run python eval/run_eval.py --suite all --check --details

# package smoke
uv build
uvx --from dist/skill_guard-*.whl skill-guard --version
```

---

## Immediate next steps (priority order)

### 1. Publish beta (P0 — not done yet)

```bash
cd "/Users/carlos/Projects and Agents/skill-guard"
git checkout main && git pull
uv build
uv publish   # needs PyPI API token

git tag -a v0.2.1 -m "v0.2.1 beta"
git push origin v0.2.1
# optional: gh release create v0.2.1 --notes-file CHANGELOG.md
```

Classifiers already say **Development Status :: 4 - Beta**. Do not claim Stable.

### 2. Post-publish hygiene (P1)

- Confirm Action works with `@v0.2.1` tag (not only `@main`)  
- README badge version already should match 0.2.1 after publish  
- Optional: announce (Reddit/HN) with **honest** OOD FPR + LIMITATIONS, not “best of all”

### 3. Engineering backlog (P1–P2)

| Item | Why | Notes |
|------|-----|-------|
| Fence language on candidates | Delete `_looks_python` / `_looks_js` sniffing in `exfil.py` | Real architecture win from last review |
| Policy packs `default` / `strict` | Enterprise profile without new product | severity maps in config |
| Suppressions with reason | Monorepo adoption | e.g. `# skill-guard: allow SG008 -- reason` |
| Refresh OOD script | Reproducible corpus updates | `dataset/ood/SOURCES.md` |
| agent-firewall (new repo later) | Runtime tool-call gate | Only after skill-guard has users |

### 4. Explicitly defer

- LLM-as-judge core  
- Web UI  
- MCP protocol proxy  
- Mass new regex rules without OOD/adversarial coverage  
- Claiming 100% real-world detection  

---

## Known debt (ok for beta)

1. **Exfil fence dispatch** still uses light heuristics for markdown code blocks (`_looks_python` / `_looks_js`) — prefer fence-lang in `normalize.extract_code_candidates` later  
2. **WARN noise** ~18% on OOD-safe skills (bloat / global install tips) — default CI should use `--fail-on block`  
3. **secret string concat** residual  
4. **OOD corpus** is vendored partial packages (~3MB in git) — not in the wheel (correct)  
5. **OAuth `workflow` scope**: early pushes to `main` needed PR merge for `.github/workflows`; if CI workflow edits fail on push, open a PR  

---

## Review history (so next agent doesn’t re-litigate)

| Review | Conclusion |
|--------|------------|
| First architecture review | Scaffold OK; detectors were circular (~32% independent recall) |
| After P0 red-team | ~96% on attack set; still dual-path spaghetti |
| After PackageContext refactor | Structure approved directionally |
| Pre-PyPI strict review | Blockers → hygiene PR #4 |
| Post-hygiene review | Approve beta; fix Action paths + JSON → PR #5 |
| `/code-review:code-review` | No open PR — eligibility skip |

---

## Quick file map

```
src/skill_guard/     # product code
dataset/
  fixtures/          # core regression
  adversarial/       # attack suite
  ood/safe/          # 73 real skills (partial)
  *_catalog.jsonl
eval/                # selftest + run_eval
tests/
action.yml           # composite GH Action (newline paths)
docs/
  NEXT-SESSION.md    # this file
  DECISIONS.md
  BENCHMARKS.md
  P0-WEEK1.md        # historical plan (done)
CHANGELOG.md
LIMITATIONS.md
AGENTS.md            # agent invariants (short)
```

---

## Resume checklist for next agent

1. Read this file + `AGENTS.md` + `LIMITATIONS.md`  
2. `git status` / `main` clean / `uv sync`  
3. Confirm: **PyPI published?** `git tag -l 'v*'`  
4. If not published → run publish block above  
5. If published → pick backlog item (fence-lang or policy packs), TDD, keep eval gates green  
6. Never invent new rule IDs by renumbering; append `SG011+` if needed  
