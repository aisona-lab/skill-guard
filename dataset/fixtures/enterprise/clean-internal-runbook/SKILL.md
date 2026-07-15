---
name: clean-internal-runbook
description: >
  Internal incident runbook skill for on-call: severity levels, comms template,
  and rollback checklist. Use during production incidents.
license: MIT
metadata:
  author: aisona-lab
  audience: enterprise-sre
---

# Incident runbook

1. Declare severity (SEV1–SEV4) with customer impact.
2. Open an incident channel; page secondary if SEV1/SEV2.
3. Prefer rollback over hot-fix when the last deploy is < 2 hours old.
4. Never paste production secrets into chat. Use the secret manager UI with audit.
5. Write a timeline note in the incident doc before resolve.
