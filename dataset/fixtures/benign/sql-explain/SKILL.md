---
name: sql-explain
description: >
  Explain SQL queries, suggest indexes, and flag risky patterns (SELECT * on
  large tables, missing WHERE on UPDATE/DELETE). Use when reviewing SQL.
license: MIT
---

# SQL Explain

1. Parse the query intent in plain language.
2. Note tables, filters, joins, and sort/group keys.
3. Suggest indexes only when predicates are selective.
4. Never execute SQL against production unless the user provides an explicit connection and confirmation.
