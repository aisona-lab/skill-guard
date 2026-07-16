# skill-guard

**Pre-install security check for [Agent Skills](https://agentskills.io/specification).**  
Scan a `SKILL.md` package **before** your agent loads it. Offline, deterministic, no code execution.

Part of [aisona-lab](https://github.com/aisona-lab) trust tooling ([prompt-guard](https://github.com/aisona-lab/prompt-guard), [OrcaI](https://github.com/aisona-lab/OrcaI), [lazycoder](https://github.com/aisona-lab/lazycoder)).  
Beta · [LIMITATIONS](LIMITATIONS.md) · [CHANGELOG](CHANGELOG.md)

[![CI](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aisona-lab/skill-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aisona-skill-guard.svg)](https://pypi.org/project/aisona-skill-guard/)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)

## Who this is for

| You | Use it when |
|-----|-------------|
| **Teams / companies** installing third-party skills | Gate CI or a pre-install script before skills touch prod agents |
| **Skill authors** | Catch secrets, curl\|bash, and exfil patterns before you publish |
| **Security / platform** | Policy packs (`default` / `strict`), SARIF, exit codes 0/1/2 |

Not a runtime firewall. Not an MCP auditor. Static pre-install only.

## Try it in 30 seconds

```bash
# install CLI (package name on PyPI ≠ CLI name)
uv tool install aisona-skill-guard
# if PyPI is empty yet:
# uv tool install "git+https://github.com/aisona-lab/skill-guard@v0.2.2"

git clone --depth 1 https://github.com/aisona-lab/skill-guard.git /tmp/skill-guard
cd /tmp/skill-guard

skill-guard scan dataset/fixtures/benign/tdd-checklist
# → ALLOW  exit 0

skill-guard scan dataset/fixtures/malicious/curl-pipe-shell
# → BLOCK  exit 2  (SG003: curl | bash)

skill-guard scan dataset/ood/safe/vercel/deploy-to-vercel
# → WARN   (SG006: npm install -g in a fenced install step)
```

## What it looks like

**Malicious fixture** (`curl … | bash`):

```text
skill-guard  verdict=BLOCK  exit=2
[CRITICAL] SG003  Pipe remote content into a shell
  evidence: curl | … | bash
```

**Real public skill** (Vercel deploy — legitimate but global install):

```text
skill-guard  verdict=WARN  exit=1
[MEDIUM] SG006  Global package install from skill
  at: SKILL.md:141
  evidence: npm install -g
```

**Clean skill** (ponytail / in-repo benign):

```text
skill-guard  verdict=ALLOW  exit=0
No findings.
```

## Live results on real corpora (v0.2.2)

Policy: **`--fail-on block`** (WARN does not fail CI by default).

| Source | Skills scanned | ALLOW | WARN | BLOCK | What that means |
|--------|---------------:|------:|-----:|------:|-----------------|
| [ponytail](https://github.com/DietrichGebert/ponytail) | 5–6 | all | 0 | 0 | Docs-only `npm -g` tips stay quiet |
| Public skills vendored as **ood** | 73 | ~85% | ~15% | **0** | False BLOCK rate is the main credibility metric |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | 24 | 23 | 1 | 0 | CI `${{ secrets }}` examples → WARN, not BLOCK |
| [last30days-skill](https://github.com/mvanhorn/last30days-skill) | 1 (116 files) | — | — | **1** | Large pack + unscoped Bash — real pre-install signal |
| [ECC](https://github.com/affaan-m/ECC) `skills/` + `.agents/skills` | 282 | 236 | 44 | **2** | Remaining BLOCKs: `allowed-tools: Bash` unscoped |
| **ood-unsafe** held-out attacks (in-repo) | 8 | 0 | 0 | **8** | Evasions we track (split keys, b64→shell, …) |

Reproduce gates:

```bash
uv run python eval/run_eval.py --suite all --check
uv run pytest -q
```

## Rules (why they matter)

| ID | Why care | Typical hit |
|----|----------|-------------|
| **SG001** | Broken package → broken install | missing `name` / frontmatter |
| **SG002** | Keys in skills land in git & agent context | `sk-ant-…`, `"sk"+"-ant-"+…` |
| **SG003** | Skills tell agents to run shell | `curl \| bash`, `rm -rf /` |
| **SG004** | Creds + network = theft | `cat ~/.ssh/id_rsa` + upload |
| **SG005** | Skill can reprogram the host agent | “Ignore previous instructions” |
| **SG006** | Install expands trust boundary | `npm install https://…`, fenced `npm i -g` |
| **SG007** | Removes human gates | `allowed-tools: Bash`, “bypass sandbox” |
| **SG008** | Huge skills hide risk & burn tokens | multi-k line `SKILL.md` |
| **SG009** | Fake authority | “official Anthropic skill” |
| **SG010** | Cloud / CI privilege | IMDS, docker.sock, secret exfil |

Examples and nuance: [docs/RULES.md](docs/RULES.md).

## Install & CI

```bash
pip install aisona-skill-guard   # CLI: skill-guard
# package name on PyPI is aisona-skill-guard (skill-guard is unrelated)
```

| Exit | Meaning |
|-----:|---------|
| 0 | ALLOW (WARN ok by default) |
| 1 | WARN (`--pack strict` or `--fail-on warn`) |
| 2 | BLOCK |
| 3 | usage error |

```yaml
- uses: aisona-lab/skill-guard@v0.2.2
  with:
    path: ./skills/my-skill
    fail-on: block
```

```yaml
# .skill-guard.yml
pack: default   # or strict
suppress: [SG008]
```

## Status & maintenance

| | |
|--|--|
| **Stage** | Beta (v0.2.2), CI on every push |
| **Scope freeze** | No new detectors without a real-scan fixture — [DETECTOR-FREEZE](docs/DETECTOR-FREEZE.md) |
| **Lab** | Same org as prompt-guard / OrcaI / lazycoder (agent trust stack) |
| **Honest limits** | New project; stars ≠ quality. Judge the tables and CI, not vanity metrics. |

Issues and security notes: GitHub · [LIMITATIONS](LIMITATIONS.md) · [BENCHMARKS](docs/BENCHMARKS.md)

## License

MIT © aisona-lab
