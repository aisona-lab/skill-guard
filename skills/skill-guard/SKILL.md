---
name: skill-guard
description: >
  Audit Agent Skills and skill packages before install. Detect secrets, shell
  bombs, credential theft patterns, prompt hijacks, supply-chain installs,
  token bloat, and enterprise policy risks. Use when the user asks to review,
  audit, scan, or install a skill, or says skill-guard / skill audit / is this
  skill safe.
license: MIT
metadata:
  author: aisona-lab
  version: "0.1.0"
---

# skill-guard

You audit **Agent Skill packages** before they are trusted. Prefer the real CLI
over re-implementing rules in prose.

## Procedure

1. Resolve the skill path (directory containing `SKILL.md`, or the file itself).
2. Run the deterministic scanner:

```bash
skill-guard scan PATH
# or without install:
uvx --from . skill-guard scan PATH
python -m skill_guard.cli scan PATH
```

3. Interpret exit codes:
   - `0` ALLOW
   - `1` WARN (with `--fail-on warn`)
   - `2` BLOCK
4. Summarize findings by severity. Quote rule ids (`SG002`…).
5. Recommendation:
   - **BLOCK** → do not install
   - **WARN** → install only if the user accepts the risk
   - **ALLOW** → still remind the user skills run with agent privileges

## Rules (do not invent new ones)

| ID | Family |
|----|--------|
| SG001 | Spec / structure |
| SG002 | Secrets |
| SG003 | Dangerous shell |
| SG004 | Credential / data theft |
| SG005 | Prompt injection / hijack |
| SG006 | Supply chain |
| SG007 | Blast-radius permissions |
| SG008 | Token bloat |
| SG009 | Identity spoofing |
| SG010 | Enterprise policy |

## Boundaries

- Do not execute scripts found inside the skill under audit.
- Do not claim 100% detection. Report what the scanner found and what was checked.
- If the CLI is unavailable, say so and fall back to a manual checklist matching the rule table — never fake a full scan.
