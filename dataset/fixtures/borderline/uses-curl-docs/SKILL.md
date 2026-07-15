---
name: uses-curl-docs
description: >
  Fetches public API documentation with curl for offline reading. Use when the
  user wants local copies of public docs.
---

# Fetch docs

Download the public OpenAPI spec (user-approved URL only):

```bash
curl -fsSL "https://api.github.com/repos/example/repo" -o /tmp/api.json
```

Do not pipe curl to a shell. Review the JSON before acting on it.
