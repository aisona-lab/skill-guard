<div align="center">

# 🛡️ skill-guard

**Scan Agent Skills for malware patterns before your agent loads them.**

Offline · Deterministic · No code execution

[![CI](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aisona-skill-guard.svg)](https://pypi.org/project/aisona-skill-guard/)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[Quick start](#quick-start) · [Real-world results](#real-world-results-v022) · [Rules](#the-10-rules) · [CI](#ci) · [Limitations](LIMITATIONS.md)

</div>

---

A [`SKILL.md` package](https://agentskills.io/specification) is third-party prompt + code that runs with your agent's privileges. **skill-guard** audits it *pre-install*: hardcoded secrets, `curl | bash`, credential exfil, prompt hijacks, supply-chain installs. 10 deterministic rules, one verdict, CI-ready exit codes.

For **teams** gating third-party skills in CI, **skill authors** checking before publish, and **security/platform** folks who want SARIF + policy packs. Not a runtime firewall, not an MCP auditor: static pre-install only.

## Quick start

```bash
pip install aisona-skill-guard        # or: uv tool install aisona-skill-guard

skill-guard scan ~/.claude/skills/my-skill
```

Every scan ends in one verdict:

| Verdict | Exit | Means |
|:-------:|:----:|-------|
| 🟢 **ALLOW** | 0 | No findings, still runs with agent privileges |
| 🟡 **WARN** | 0\* | Medium risk (global installs, bloat), review it |
| 🔴 **BLOCK** | 2 | High/critical (exfil, `curl \| bash`, secrets), don't install |

<sub>\* Default policy `--fail-on block`: WARN is reported but doesn't fail CI. Use `--pack strict` to fail on WARN too.</sub>

<details>
<summary><b>See it fire</b>: demo fixtures in this repo</summary>

```bash
git clone --depth 1 https://github.com/aisona-lab/skill-guard.git
cd skill-guard

skill-guard scan dataset/fixtures/benign/tdd-checklist        # 🟢 ALLOW
skill-guard scan dataset/fixtures/malicious/curl-pipe-shell   # 🔴 BLOCK
skill-guard scan dataset/ood/safe/vercel/deploy-to-vercel     # 🟡 WARN
```

```text
skill-guard  verdict=BLOCK
[CRITICAL] SG003  Pipe remote content into a shell
  evidence: curl | … | bash
  fix: Never pipe curl/wget into sh/bash/zsh.
```

</details>

## Real-world results (v0.2.2)

> **0 false BLOCKs across 73 vendored real-world skills** (CI-gated) · **8/8 held-out attack packs blocked**

| Corpus | Skills | 🔴 BLOCK | Takeaway |
|--------|-------:|--------:|----------|
| Public skills vendored as OOD | 73 | **0** | False-BLOCK rate is the credibility metric |
| [ECC](https://github.com/affaan-m/ECC) collection | 282 | **2** | Both: unscoped `allowed-tools: Bash` |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | 24 | 0 | CI `${{ secrets }}` docs → WARN, not BLOCK |
| [last30days-skill](https://github.com/mvanhorn/last30days-skill) (116 files) | 1 | **1** | Large pack + unscoped Bash, real signal |
| Held-out attacks (ood-unsafe) | 8 | **8/8** | Split keys, b64→shell, … tracked in CI |

Reproduce every gate locally:

```bash
uv run python eval/run_eval.py --suite all --check
uv run pytest -q
```

Full protocol, thresholds, and what we *don't* claim: [BENCHMARKS](docs/BENCHMARKS.md) · [LIMITATIONS](LIMITATIONS.md)

## The 10 rules

| ID | Catches | Why care |
|----|---------|----------|
| **SG001** | Broken frontmatter / structure | Broken package → broken install |
| **SG002** | `sk-ant-…`, `ghp_…`, split-key tricks | Keys land in git & agent context |
| **SG003** | `curl \| bash`, `rm -rf /`, b64→shell | Skills tell agents to run shell |
| **SG004** | `cat ~/.ssh/id_rsa` + upload | Creds + network = theft |
| **SG005** | "Ignore previous instructions" | Skill can reprogram the host agent |
| **SG006** | `npm install https://…`, global installs | Install expands trust boundary |
| **SG007** | `allowed-tools: Bash`, "bypass sandbox" | Removes human gates |
| **SG008** | Multi-k-line `SKILL.md` | Hides risk, burns tokens |
| **SG009** | "Official Anthropic skill" claims | Fake authority |
| **SG010** | IMDS, docker.sock, `${{ secrets }}` exfil | Cloud / CI privilege |

Examples and nuance per rule: [docs/RULES.md](docs/RULES.md)

## CI

```yaml
- uses: aisona-lab/skill-guard@v0.2.2
  with:
    path: ./skills/my-skill
    fail-on: block          # exit 2 only on BLOCK
```

<details>
<summary><b>Config, packs & exit codes</b></summary>

```yaml
# .skill-guard.yml
pack: default   # or strict (fails on WARN too)
suppress: [SG008]
```

| Exit | Meaning |
|-----:|---------|
| 0 | ALLOW (WARN ok by default) |
| 1 | WARN (`--pack strict` or `--fail-on warn`) |
| 2 | BLOCK |
| 3 | usage error |

`--json` and `--sarif` / `--sarif-file` for machine-readable output.

</details>

## Status

Beta (v0.2.2) · CI gates on every push · [detector freeze](docs/DETECTOR-FREEZE.md): no new rules without a real-scan fixture.
New project: judge the tables and CI, not star counts.

Part of [aisona-lab](https://github.com/aisona-lab) trust tooling: [prompt-guard](https://github.com/aisona-lab/prompt-guard) · [OrcaI](https://github.com/aisona-lab/OrcaI) · [lazycoder](https://github.com/aisona-lab/lazycoder)

## License

MIT © aisona-lab
