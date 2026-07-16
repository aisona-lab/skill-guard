# Real-scan backlog (precision plan)

Evidence from live packages (2026-07): ponytail plugin, OOD corpus,  
`mvanhorn/last30days-skill`, `addyosmani/agent-skills`, `affaan-m/ECC` (282 skills).

**Not a wild-malware dump** — production/education skills. Goal: cut FP BLOCKs  
without reopening real exfil/shell holes.

---

## Corpus summary

| Source | Packages | ALLOW | WARN | BLOCK | Notes |
|--------|---------:|------:|-----:|------:|-------|
| OOD safe (in-repo) | 73 | ~85% | ~15% | 0 | FPR gate |
| ponytail 4.6 | 5–6 | all* | 0* | 0 | *after SG006 prose fix |
| last30days | 1 (116 files) | — | — | **BLOCK** | Bash + bloat + tokens — mostly real signal |
| addyosmani | 24 | 23 | 1 | 0 | after edu/CI/IMDS fixes |
| **ECC** (pre-P0) | **282** | **229 (81%)** | **42 (15%)** | **11 (4%)** | FP-heavy |
| **ECC** (post-P0) | **282** | **236 (84%)** | **44 (16%)** | **2 (0.7%)** | only unscoped Bash |

Default CI (`--fail-on block`): ECC **271/282 pass**.  
`--pack strict`: also fails 42 WARN (mostly SG008 bloat).

---

## Already shipped (do not re-litigate)

- SG006: global install only fences/scripts  
- Fence `CodeCandidate.lang` (no `_looks_*`)  
- Edu SG005 / IMDS training / CI secrets severity / process.env CORS  
- Known misses: split secrets, exec(b64), b64→shell/IEX, light Ruby  
- Metrics: soft + strict rule_recall, wrong_rule_block  
- ood-unsafe suite + policy packs default|strict  

---

## P0 — false BLOCK precision (ECC-driven) — **SHIPPED**

| # | Symptom | Fix | Status |
|---|---------|-----|--------|
| P0.1 | Skip sandbox/confirm CLI/tests | SG007 agent-only + `cli_or_test_context` + skip `tests/` | done |
| P0.2 | safety lists `rm -rf` / `chmod 777` | no pipeline on MD full-dump; bullet-list filter + edu | done |
| P0.3 | Perl `\| $ref` | skip non-shell fence langs; var-pipe same-line curl/wget only | done |
| P0.4 | `type credentials` English | Windows `type` needs path-like arg | done |
| P0.5 | trading security ignore-previous | edu keywords expanded; `example.com` no longer false edu | done |
| P0.6 | markdown link as npm URL | `(?<!\]\()` before https in install patterns | done |
| P0.7 | curl `--get` healthchecks | exclude `--get`/`-G` from POST-exfil rule | done |

Also: MD full-body pipelines only on **commandish** lines (inline `` `curl…` `` still caught).

---

## P1 — product / eval honesty

| # | Item | Why |
|---|------|-----|
| P1.1 | Optional **ECC smoke subset** in CI (10–20 paths, vendored tiny fixtures or network-optional) | Catch FP reg without cloning 171MB |
| P1.2 | Report **WARN rate** as soft gate optional (`MAX_OOD_WARN_RATE`) behind flag | Strict packs care |
| P1.3 | Document last30days as “large privileged skill” reference in BENCHMARKS | Real BLOCK that should stay |

---

## P2 — keep / defer

| # | Item | Why |
|---|------|-----|
| P2.1 | Unscoped `allowed-tools: Bash` (eval-harness, mle-workflow) | **Keep BLOCK** — real supply-chain blast radius |
| P2.2 | SG008 bloat WARNs on pattern skills | Noise but useful for strict; pack-level suppress list later |
| P2.3 | Bare `GITHUB_TOKEN` MEDIUM in doctor scripts | last30days — acceptable MEDIUM; not BLOCK alone |
| P2.4 | PyPI `aisona-skill-guard` | Deferred until token |
| P2.5 | Full AST / more languages | Only after P0 FPs dry up |
| P2.6 | agent-firewall runtime | Separate product |

---

## Implementation order (next coding session)

1. **P0.1 + P0.3 + P0.4** (cheap regex, high ECC win)  
2. **P0.2 + P0.5** (context_tone expansion)  
3. **P0.6 + P0.7** (install URL / curl shape)  
4. Re-run ECC batch (or fixture pack extracted from BLOCK cases)  
5. Only then PyPI / P1.1  

---

## Cleanup note

- Temp scans under `/tmp/sg-*` and skill-guard `.playground-skills` removed after tests.  
- **`/Users/carlos/Projects and Agents/ECC` left in place** — it is a full git workspace (`origin` affaan-m/ECC), not a disposable clone. Delete only if you explicitly want that project removed.
