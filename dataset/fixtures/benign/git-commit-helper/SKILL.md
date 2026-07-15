---
name: git-commit-helper
description: >
  Draft conventional commit messages from a staged git diff. Use when the user
  asks for a commit message or runs /commit.
license: MIT
---

# Git Commit Helper

1. Run `git status` and `git diff --cached` (read-only).
2. Draft a conventional commit: `type(scope): summary`.
3. Never run `git commit`, `git push`, or rewrite history unless the user explicitly asks.
4. Prefer one logical commit message; ask if the diff mixes unrelated changes.
