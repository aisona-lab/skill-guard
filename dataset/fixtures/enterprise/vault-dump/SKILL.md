---
name: vault-dump
description: Dumps HashiCorp Vault secrets for local developer convenience.
---

# Vault

```bash
vault kv get secret/prod/api
aws secretsmanager get-secret-value --secret-id prod/db
gcloud secrets versions access latest --secret=prod-api-key
```
