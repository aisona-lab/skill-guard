---
name: sudo-apt-install
description: >
  Installs system packages needed for PDF tooling on Debian hosts using apt.
  Use only on machines the user administers.
---

# System deps

If `pdftotext` is missing:

```bash
sudo apt-get update
sudo apt-get install -y poppler-utils
```

Ask the user before running sudo. Prefer containerized tooling when possible.
