---
name: changelog-writer
description: >
  Generate Keep-a-Changelog entries from git history between two refs.
  Use when preparing a release notes draft.
license: MIT
---

# Changelog Writer

1. Accept `from_ref` and `to_ref` (default: last tag → HEAD).
2. Collect commit subjects with `git log --oneline`.
3. Group into Added / Changed / Fixed / Security.
4. Output markdown only. Do not publish or tag releases.
