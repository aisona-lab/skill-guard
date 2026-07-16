# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] — 2026-07-16

### Added

- **Eval honesty:** `strict_rule_recall` + `wrong_rule_block` in `eval/run_eval.py`
- **OOD-unsafe suite:** 8 held-out attack packs + CI gate (recall ≥ 0.70)
- **Policy packs:** `--pack default|strict` and `pack:` in `.skill-guard.yml`
- **Known-miss detectors:** split secrets, `exec(base64…)`, base64→shell/IEX, light Ruby Net::HTTP+.ssh
- **`surface.py`:** fence / script / prose / test classifier (prefer over keyword growth)
- **Detector freeze** policy: [`docs/DETECTOR-FREEZE.md`](docs/DETECTOR-FREEZE.md)
- Real-scan backlog: [`docs/REAL-SCAN-BACKLOG.md`](docs/REAL-SCAN-BACKLOG.md)

### Fixed

- **SG006 global install context:** MEDIUM only in fences/scripts; prose tips clean
- **SG006 markdown links:** `](https://…)` not treated as install URL
- **SG005 / SG010 / SG004 edu FPs:** educational windows; CI secrets severity; IMDS training; process.env CORS
- **SG007:** CLI/test “Skip sandbox|confirm” not agent-bypass BLOCK
- **SG003:** danger bullet lists; non-shell fences; var-pipe same-line only; commandish MD lines
- **SG004:** Windows `type` path-only; curl `--get` excluded from POST-exfil; `example.com` ≠ edu
- Fence language on candidates (`CodeCandidate.lang`); removed `_looks_python` / `_looks_js`

### Changed

- README shortened (ponytail-style install/use/eval/improve)
- `context_tone` thinned; structural routing moved to `surface`

## [0.2.1] — 2026-07-15

### Added

- Out-of-distribution corpus (`dataset/ood/`) with **73** real-world safe skills and CI FPR gate
- `docs/BENCHMARKS.md` honest multi-suite protocol (core / adversarial / ood)
- `--sarif-file PATH` for single-pass text + SARIF output
- Multi-target scans emit **one** merged SARIF document
- Pre-PyPI packaging metadata (classifiers, Issues/Changelog URLs)
- `LIMITATIONS.md` (linked from README top — beta honesty)
- `result_dict` / `render_json_multi` (no JSON serialize/parse round-trip)

### Packaging

- **PyPI name:** `aisona-skill-guard` (PyPI `skill-guard` is a different upstream; CLI entry point remains `skill-guard`)
- README install is **Git/source-first** while PyPI is deferred

### Fixed

- `make_finding` message default when `path` is omitted
- `chmod 600` no longer flagged as setuid
- JS `child_process` requires strong sinks (not bare `sh`)
- `.env` + network co-occurrence requires exfil-shaped context
- Bare `GITHUB_TOKEN` mention is MEDIUM; `${{ secrets.* }}` stays CRITICAL (later refined in 0.2.2)
- GitHub Action no longer double-scans when writing SARIF
- GitHub Action path parsing: newline-delimited (supports spaces)
- SARIF multi-target URIs use `Path` join

### Changed

- PackageContext / AnalyzedFile: normalize once at load
- Shell detection is table-driven (pipeline + whole-file rules)
- Action `path` input: newline-separated multi-path

## [0.2.0] — 2026-07-15

### Added

- P0 detectors: shell pipeline engine, language-aware Python/JS/PowerShell, path registry
- Adversarial suite and selftest gates
- SARIF 2.1 subset, `.skill-guard.yml` config, composite GitHub Action
- Batch `scan` of multiple paths

## [0.1.0] — 2026-07-15

### Added

- Initial deterministic skill package auditor (SG001–SG010)
