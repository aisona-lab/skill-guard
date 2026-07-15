---
name: docs-to-skill
description: >
  Convert a local documentation folder into a draft SKILL.md with name and
  description. Use when packaging internal docs as an agent skill.
license: MIT
---

# Docs to Skill

1. Read the local docs path the user provides.
2. Draft frontmatter `name` + `description` from the docs title and purpose.
3. Keep the body under 400 lines; put deep reference material in `references/`.
4. Do not download remote docs unless the user supplies a URL and approves the fetch.
