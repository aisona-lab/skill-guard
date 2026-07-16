# Detector freeze (from v0.2.2)

**Policy:** no new SG### detection patterns for 1–2 sprints unless they unblock a
**documented real-scan FP** or **attack miss** with a fixture.

## Allowed without freeze exception

- Bug fixes that restore a broken gate (eval/selftest red)
- Precision fixes with a regression test under `tests/test_*fp*` or ood-unsafe
- Refactors that **move** logic (e.g. into `surface.py`) without new regex families
- Docs, packaging, config, metrics reporting

## Not allowed without product decision

- New rule IDs (SG011+)
- Expanding `context_tone` keyword lists “just in case”
- New language analyzers without a real package that needs them
- Lowering gate thresholds to paper over regressions

## How to add a detector anyway

1. Capture minified fixture (skill package) showing FP or miss  
2. Test fails first (RED)  
3. Minimal pattern or surface rule (GREEN)  
4. `eval/run_eval.py --suite all --check` green  
5. Note in CHANGELOG + one line in REAL-SCAN-BACKLOG if from wild scan  

## Why

CTO review: precision is good; **lexicon debt** is the main risk. Prefer
`surface` (fence/script/prose/test) over more keywords.
