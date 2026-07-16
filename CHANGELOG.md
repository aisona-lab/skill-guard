# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **SG006 global install context:** `npm install -g` / `pip install --user` / `cargo install` are MEDIUM only inside fenced code or `scripts/` (and shell/source files). Prose tips (e.g. ponytail-help “update Claude”) no longer WARN. Remote URL installs stay CRITICAL/HIGH.

### Changed

- **Fence language on candidates:** `CodeCandidate {text, lang}` from markdown fence tags (` ```python `, ` ```js `, ` ```bash `, …). SG004 python/js analyzers use tags + `FileKind` only — removed `_looks_python` / `_looks_js` sniffing.

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
- README install is **Git/source-first** while PyPI is deferred (no broken `pip install` path; release badge instead of empty PyPI badge)
- README rewritten shorter (ponytail-style) + **Improve next** from real skill scans

### Fixed

- `make_finding` message default when `path` is omitted
- `chmod 600` no longer flagged as setuid
- JS `child_process` requires strong sinks (not bare `sh`)
- `.env` + network co-occurrence requires exfil-shaped context
- Bare `GITHUB_TOKEN` mention is MEDIUM; `${{ secrets.* }}` stays CRITICAL
- GitHub Action no longer double-scans when writing SARIF
- GitHub Action path parsing: newline-delimited (supports spaces); no bare word-split
- SARIF multi-target URIs use `Path` join instead of string `//` scrubbing

### Changed

- PackageContext / AnalyzedFile: normalize once at load (from 0.2.x refactor line)
- Shell detection is table-driven (pipeline + whole-file rules)
- Action `path` input: newline-separated multi-path (not space-separated)

## [0.2.0] — 2026-07-15

### Added

- P0 detectors: shell pipeline engine, language-aware Python/JS/PowerShell, path registry
- Adversarial suite and selftest gates
- SARIF 2.1 subset, `.skill-guard.yml` config, composite GitHub Action
- Batch `scan` of multiple paths

## [0.1.0] — 2026-07-15

### Added

- Initial deterministic skill package auditor (SG001–SG010)
- Core fixtures, CLI exit codes ALLOW/WARN/BLOCK

[0.2.1]: https://github.com/aisona-lab/skill-guard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/aisona-lab/skill-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/aisona-lab/skill-guard/releases/tag/v0.1.0
