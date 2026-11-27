# skill-guard Architecture

**skill-guard** is a deterministic, offline, pre-install static auditor for [Agent Skill](https://agentskills.io/specification) packages (`SKILL.md` + supporting scripts/docs). It never executes skill code and makes zero network calls at scan time.

## Pipeline Overview

```text
path ─▶ load_package (no exec, capped)
     ─▶ analyze_file (FileKind + NFKC normalize + code candidates once)
     ─▶ PackageContext (immutable input to all rules)
     ─▶ rules SG001–SG010 (pure functions, never short-circuit)
     ─▶ dedupe_findings ─▶ apply_config_to_findings (.skill-guard.yml / packs)
     ─▶ aggregate_verdict (ALLOW | WARN | BLOCK)
     ─▶ text | JSON | SARIF 2.1.0 + CI exit code (0 / 1 / 2 / 3)
```

---

## 1. Single-Pass `PackageContext` & Normalization

Implemented in [`src/skill_guard/parser/package.py`](src/skill_guard/parser/package.py), [`src/skill_guard/analyze.py`](src/skill_guard/analyze.py), [`src/skill_guard/normalize.py`](src/skill_guard/normalize.py), and [`src/skill_guard/models.py`](src/skill_guard/models.py).

- **Load once**: `load_package(path)` reads `SKILL.md` YAML frontmatter (`yaml.safe_load`) and eligible text files into a single `PackageContext`.
- **Analyze once**: `analyze_file()` assigns `FileKind` (`markdown`, `python`, `javascript`, `powershell`, `shell`, `other`) strictly from filename/extension and `#!` shebangs (never prose sniffing), runs `normalize_text()`, and extracts `CodeCandidate` blocks.
- **Detection-oriented normalization**: `normalize_text()` applies Unicode NFKC (collapsing homoglyphs), normalizes CRLF/CR newlines, joins backslash line continuations (`\\\n`), and expands fenced/inline code blocks. Rules consume `AnalyzedFile.normalized` and `AnalyzedFile.candidates` directly and **never** re-normalize or re-parse markdown fences.

---

## 2. Structural Surface Classifier (`surface.py`)

Implemented in [`src/skill_guard/surface.py`](src/skill_guard/surface.py). Instead of growing fragile keyword allowlists in `context_tone.py`, rules route by **where** text appears:

| Surface | Meaning | Typical routing behavior |
|---|---|---|
| `fence` | Markdown code fence (`CodeCandidate`) | Dispatched by normalized `cand.lang` (`shell`, `python`, `javascript`, `powershell`, `ruby`) |
| `script` | Files under `scripts/` or native source `FileKind` | Full-body language & shell pipeline analysis; actionable for `SG006` global installs |
| `prose` | Narrative markdown outside fences | `SG003` extracts only `commandish_shell_lines`; `SG006` skips global install tips |
| `test` | Files under `tests/` or `test/` | Excluded from `SG003` shell pipelines and `SG007` HITL-bypass checks |

`context_tone.py` is reserved for bounded-window disambiguation (`educational_context`, `cli_or_test_context`, `secret_exfil_context`) when security-training or CI-example docs sit directly alongside dangerous patterns.

---

## 3. Tokenizers & Language Analyzers (`src/skill_guard/analysis/`)

- **Shell (`shell_tokens.py` + `rules/shell.py`)**: `tokenize_shell_line()` + `split_pipelines()` split lines on `;`, `&&`, `||`, and `|`; `flags_of()` unpacks combined short flags (`-rf` → `{'r', 'f'}`) and long flags; `cmd_name()` skips `VAR=val` prefixes and prose labels (`Run:`). Rules are table-driven (`_PIPELINE_RULES`, `_WHOLE_RULES`) so flag reordering does not evade detection.
- **Python (`lang_python.py`)**: Static regex/structural heuristics for `Path.home()` / `expanduser` + `.ssh`, `open()` against `paths.SENSITIVE_PATHS` / `/etc/{passwd,shadow,sudoers}`, `requests`/`httpx`/`urlopen` uploads of local reads, and `exec`/`eval(base64.b64decode(...))`.
- **JavaScript/TypeScript (`lang_js.py`)**: Static heuristics for `fs.readFile*` on sensitive paths, `.env` reads co-located with `fetch`/`axios`/`http.request`/`got`, `fetch(..., {method: 'POST'})` near sensitive paths, and `child_process`/`execSync`/`spawn` with strong shell/download sinks.
- **PowerShell (`lang_powershell.py`)**: Detects `IEX`/`Invoke-Expression` + `Net.WebClient`/`DownloadString`/`Invoke-WebRequest` cradles, `Remove-Item -Recurse -Force` on `$HOME`/`USERPROFILE`, `Get-Content` on `.ssh`/`.aws`, and `Invoke-RestMethod` credential uploads.

All credential and metadata paths share a single catalog in [`src/skill_guard/paths.py`](src/skill_guard/paths.py) (`SENSITIVE_PATHS`, `CLOUD_METADATA`, `read_then_network_risk`).

---

## 4. `SG001`–`SG010` vs. LLM-as-a-Judge Trade-Offs

| Rule | Domain | Primary severity |
|---|---|---|
| `SG001` | Agent Skills spec structure (`SKILL.md`, `name`, `description`) | `HIGH` / `MEDIUM` / `LOW` |
| `SG002` | Hardcoded secrets (`sk-ant-`, `ghp_`, `AKIA`, private keys) & split-token concat | `CRITICAL` / `HIGH` |
| `SG003` | Dangerous shell (`curl \| bash`, `rm -rf`, b64→shell, PS cradles, `exec(b64)`) | `CRITICAL` / `HIGH` / `MEDIUM` |
| `SG004` | Credential exfiltration (`.ssh`/`.aws`/`.env` + network sink) | `CRITICAL` / `HIGH` |
| `SG005` | Prompt injection & host-agent instruction hijack | `HIGH` / `MEDIUM` |
| `SG006` | Supply chain (`npm`/`pip install` remote URLs, `postinstall`, fenced global installs) | `CRITICAL` / `HIGH` / `MEDIUM` |
| `SG007` | Blast-radius permissions (`allowed-tools: Bash`, HITL/sandbox bypass, system writes) | `HIGH` / `MEDIUM` |
| `SG008` | Context / token bloat (`>500` lines or `>3,500` words in `SKILL.md`, `>20,000` pkg words) | `MEDIUM` / `LOW` |
| `SG009` | Identity spoofing & lookalike/vendor impersonation | `HIGH` |
| `SG010` | Enterprise policy (IMDS `169.254.169.254`, `docker.sock`, secret managers, `${{ secrets }}`) | `CRITICAL` / `HIGH` / `MEDIUM` |

**Why deterministic first over LLM-as-a-judge**:
- **Pros**: ~0.8–23 ms p50 scan latency (~0.8–248 ms p95 including multi-file OOD packages), `$0.000` per 1,000 scans, 100% air-gapped & reproducible, immune to prompt-injection of the judge itself.
- **Trade-offs**: Bounded syntactic coverage (see [`LIMITATIONS.md`](LIMITATIONS.md)). Highly novel multi-file runtime obfuscation or semantic intent outside `SG001`–`SG010` is out of reach without a fixture-backed rule or an optional secondary LLM tier.

---

## 5. `DETECTOR-FREEZE` Anti-Regression Discipline

Governed by [`docs/DETECTOR-FREEZE.md`](docs/DETECTOR-FREEZE.md) and [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md):
1. No new `SG###` pattern or `context_tone` keyword expansion without a captured fixture showing a real-scan FP or attack miss.
2. Rule IDs `SG001`–`SG010` never renumber (`SG011+` only by explicit product decision).
3. CI enforces four separate suites via `eval/run_eval.py` (`core`, `adversarial`, `ood` 73 real-world safe skills with `safe_fpr <= 0.05`, and `ood-unsafe` held-out attacks with `attack_recall >= 0.70`) plus `eval/selftest.py` and `eval/bench_latency.py`.

---

## 6. Policy Packs, Safety Caps, Idempotency & CI/SARIF

- **Policy packs & exit codes** (`config.py`, `cli.py`): Findings aggregate conservatively (`CRITICAL`/`HIGH` → `BLOCK`, `MEDIUM` → `WARN`, `LOW`/none → `ALLOW`). `.skill-guard.yml` supports `rules.<ID>.enabled`, severity overrides, `suppress` (`SG008` or `SG001:SKILL.md`), and `pack: default | strict`.
  - `--pack default` (`fail_on: block`): exit `0` on ALLOW/WARN, `2` on BLOCK.
  - `--pack strict` (`fail_on: warn`): exit `0` on ALLOW, `1` on WARN, `2` on BLOCK.
  - Usage / missing-path error: exit `3`.
- **Safety caps & bounds** (`parser/package.py`): Ingestion skips `.git`, `node_modules`, `.venv`, `venv`, caches, and build artifacts; caps per-file read at **512,000 bytes** (`_MAX_FILE_BYTES`) and **200 text files** (`_MAX_FILES`) per package; filters binary blobs by extension + 256-byte null-byte check (`_looks_text`). Patterns use bounded quantifiers (`{0,N}`) rather than unbounded catastrophic backtracking, avoiding per-rule subprocess timeouts while keeping execution purely in-process.
- **Idempotency**: `scan_path()` is a pure function of filesystem bytes and config (`Finding.identity()` deduplication produces deterministic sorted output and exit codes, safe for `:ro` mounts).
- **SARIF & CI integration** (`sarif.py`, `action.yml`, `Dockerfile`, `docker-compose.yml`): `--sarif` / `--sarif-file` emits a single merged SARIF 2.1.0 run across one or many targets (`LOW` → `note`, `MEDIUM` → `warning`, `HIGH`/`CRITICAL` → `error`). `action.yml` preserves newline-delimited paths (including spaces) in one pass; `Dockerfile` + `docker-compose.yml` package a non-root (`uid 10001`), read-only container image.
