---
name: mentions-api-key-docs
description: >
  Explains how to configure API keys via environment variables for third-party
  services. Use when onboarding developers to API auth.
---

# API keys

Set your key in the environment (never commit it):

```bash
export API_KEY="${API_KEY}"   # load from your secret manager
# example placeholder: API_KEY=your_api_key_here
```

Read keys with `os.environ["API_KEY"]` in application code. Do not hardcode.
