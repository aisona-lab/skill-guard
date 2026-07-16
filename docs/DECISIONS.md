# Architecture decisions

Every structural choice below has a concrete reason. If we cannot defend a line of
code against this document, it does not ship.

## Problem

Community Agent Skills install as folders with `SKILL.md` + optional scripts. They
run with the same privileges as the coding agent (shell, filesystem, network).
There is no widely adopted pre-install audit for this surface.

Reddit (2026): people refuse random skills; bad skills "quietly make the model
dumber"; pure-LLM verifiers draw skepticism ("half the value is the same model
judging itself").

## Non-goals (v0.1)

| Out of scope | Why |
|---|---|
| LLM-as-judge scanning | Determinism + offline + zero token cost first. LLM layer can come later as optional recall. |
| Runtime tool-call firewall | Different product (agent-firewall). Pre-install audit is a distinct gate. |
| MCP protocol proxy | Different attack surface; share patterns later, not code yet. |
| Web UI / marketplace | Distraction. CLI + exit codes + JSON win CI adoption. |
| Auto-remediation of skills | Audit only. Fix is the author's job. |

## Stack

| Choice | Reason |
|---|---|
| Python 3.12+ | Matches `lazycoder` / `OrcaI`. Security tooling ecosystem. `uv` packaging. |
| pydantic v2 | Typed report models, JSON schema for CI consumers. No home-grown serializers. |
| PyYAML | SKILL.md frontmatter is YAML. No custom YAML parser. |
| No network at scan time | Air-gapped enterprise. Dataset and rules ship in-repo. |

## Architecture (pipeline)

```
path → load package → normalize files → run rules → aggregate verdict → report
```

1. **Parser** reads a skill directory (or a single `SKILL.md`). Does not execute scripts.
2. **Rules** are pure functions: `PackageContext → list[Finding]`. Isolated, unit-tested.
3. **Engine** runs all enabled rules, never short-circuits (full report always).
4. **Aggregator** maps severities to `ALLOW | WARN | BLOCK` (exit 0/1/2).
5. **Report** is human text or JSON. JSON is the machine contract.

Borrowed from lab siblings:

- **lazycoder**: defensible verdict + exit codes for CI gates.
- **prompt-guard**: detector registry, curated regression dataset vs external OOD.
- **OrcaI**: evaluation harness with precision/recall, not vanity accuracy.
- **ponytail benchmarks**: `--selftest` before claims — good fixtures must pass,
  bad fixtures must be caught, or the rule is not trusted.

## Verdict policy

| Severity present | Verdict | Exit |
|---|---|---|
| any `critical` or `high` | `BLOCK` | 2 |
| only `medium` (and below) | `WARN` | 1 |
| only `low` / none | `ALLOW` | 0 |

Rationale: enterprise CI wants a hard fail on secrets/exfil/shell bombs, a soft
fail on bloat and style, and green on clean packages. Tunable later via config;
defaults stay conservative.

## Rule ID scheme

`SG###` — Skill Guard rule numbers. Stable IDs so CI suppressions and datasets
do not break across releases.

| ID | Family | Default severity |
|---|---|---|
| SG001 | Spec / structure | high (missing required) / medium (soft) |
| SG002 | Secrets | critical |
| SG003 | Dangerous shell | high–critical |
| SG004 | Data exfiltration | critical |
| SG005 | Prompt injection / instruction hijack in skill body | high |
| SG006 | Supply chain (remote code install) | high–critical; global install **medium only** if fenced or under `scripts/` (prose tips ignored) |
| SG007 | Blast-radius permissions | high |
| SG008 | Token / context bloat | medium |
| SG009 | Identity spoofing | medium–high |
| SG010 | Enterprise policy (creds, cloud metadata, write-escapes) | high–critical |

## Dataset design

Fixtures are **real skill directories**, not string snippets. Multi-file attacks
(malice only in `scripts/`) must be representable.

| Split | Purpose |
|---|---|
| `benign/` | Legitimate skills — must mostly ALLOW (precision) |
| `malicious/` | Clear attacks — must BLOCK (recall on unsafe) |
| `borderline/` | Ambiguous — documented expected outcomes; not used for hard F1 gates |
| `enterprise/` | Enterprise policy scenarios (SSO tokens, cloud metadata, monorepo write-escapes) |

`catalog.jsonl` labels each fixture:

```json
{"id":"...","path":"fixtures/malicious/...","label":"unsafe","expected_verdict":"BLOCK","expected_rules":["SG004"],"category":"exfil","tier":"core"}
```

Eval metrics (honest):

- On `label=unsafe` core tier: **recall** of BLOCK (or any finding in expected_rules)
- On `label=safe` core tier: **precision** / false-positive rate (ALLOW expected)
- Borderline never fails CI; reported for analysis only

CI gate (initial, conservative): core unsafe recall ≥ 0.95, core safe FPR ≤ 0.10.

## Testing layers

| Layer | What | When |
|---|---|---|
| Unit | Parser, each rule, aggregator | every PR |
| Selftest | per-rule good/bad mini-fixtures | every PR |
| Eval | full dataset precision/recall | every PR |
| Production-surface | `skill-guard scan` CLI on a fixture tree | every PR |

No live LLM tests in CI. If optional LLM mode is added later, mark
`@pytest.mark.integration` like lazycoder.

## Honesty rules (from ponytail + prompt-guard)

1. Never claim 100% on a set the rules were tuned against without saying so.
2. Selftest must run before any public accuracy claim.
3. Prefer false positives on critical classes over silent misses of exfil/secrets.
4. If a rule cannot be explained in one sentence, delete it.

## P0 hardening (v0.2)

After red-team showed ~32% recall on independent attacks (circular dataset), P0 added:

| Layer | Decision |
|-------|----------|
| `normalize.py` | NFKC + fence lift + line-cont so trivial evasion fails closed |
| `paths.py` | Single sensitive-path catalog shared by SG004/SG010/lang |
| `analysis/shell_tokens.py` | Pipeline/flag-set shell analysis (order-independent rm/curl\|zsh) |
| `analysis/lang_*.py` | Python/JS/PowerShell credential-theft heuristics (no code exec) |
| Adversarial suite | Separate CI gate; ≥0.75 attack recall required |
| SG001 severity | Invalid name is MEDIUM (WARN), not BLOCK — avoids signal pollution |
| SARIF + config | Production CI consumers need machine format + suppressions |

Residual known miss: split/concatenated secret tokens (`'sk'+'-ant-'+…`).
Documented; not papered over with a flaky regex.

## Refactor: PackageContext (v0.2.1)

Post-review structural cleanup (behavior preserved; gates still green):

| Change | Why |
|--------|-----|
| `AnalyzedFile` + `PackageContext` | Normalize + candidates + `FileKind` **once** at load |
| `analyze.py` | Single-pass kind inference from extension/shebang only |
| Table-driven `shell.py` | Pipeline + whole-file rule tables; no nested fetch/shell ladder |
| `make_finding` / `dedupe_findings` | One construction + one dedupe path |
| `RuleId` in registry | No string/enum drift |
| `PathPattern.severity: Severity` | Typed severities end-to-end |
| Config severity validation | No silent `except Exception` |
| PowerShell only via FileKind / markdown fence heuristics | No dual ownership shell+exfil |
| Deleted exfil Path.home fallback | Owned by `lang_python` |
