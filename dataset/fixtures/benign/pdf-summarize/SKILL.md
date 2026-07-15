---
name: pdf-summarize
description: >
  Summarize PDF documents into structured bullet points with section headings.
  Use when the user provides a PDF path or asks to summarize a PDF.
license: MIT
---

# PDF Summarize

1. Confirm the PDF path exists and is readable.
2. Extract text with a local tool the environment already has (`pdftotext` if present).
3. Produce a short summary: title, 5–10 bullets, open questions.
4. Do not upload the PDF anywhere. Work offline on the local file only.

## Output format

```
# Title
- bullet
## Open questions
- ...
```
