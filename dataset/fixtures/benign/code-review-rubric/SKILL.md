---
name: code-review-rubric
description: >
  Review a diff against a fixed security and maintainability rubric and return
  APPROVE, REQUEST_CHANGES, or BLOCK with evidence. Use for PR review.
license: MIT
---

# Code Review Rubric

Check each changed hunk for:

- Secrets hardcoded in source
- Missing validation at trust boundaries
- Silent error swallowing
- Unsafe shell interpolation
- Tests for non-trivial branches

Return a structured verdict. Prefer evidence over style nits.
