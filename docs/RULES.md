# Rules (SG001–SG010)

Each rule is a **deterministic** check on skill package text (and scripts).  
Never executes the skill. Severity drives the verdict: **critical/high → BLOCK**, **medium → WARN**, **low → advisory**.

| ID | Why it matters | Example that fires |
|----|----------------|--------------------|
| **SG001** Structure | Broken skills fail install / confuse agents | missing `name` / invalid frontmatter |
| **SG002** Secrets | Hardcoded keys leak into repos and agent context | `sk-ant-…`, `ghp_…`, `"sk"+"-ant-"+…` |
| **SG003** Dangerous shell | Skills often tell the agent to run shell; pipes and wipe commands are high risk | `` curl … \| bash ``, `rm -rf /`, `base64 -d \| sh` |
| **SG004** Exfiltration | Credential paths + network = theft pattern | `cat ~/.ssh/id_rsa` + curl, `Path.home()/.ssh` + upload |
| **SG005** Prompt hijack | Skill body can reprogram the host agent after install | “Ignore all previous instructions…” |
| **SG006** Supply chain | Remote/global installs expand the trust boundary | `npm install https://…`, fenced `npm install -g …` |
| **SG007** Blast radius | Unscoped shell tools / “skip approval” remove human gates | `allowed-tools: Bash`, “bypass the sandbox” |
| **SG008** Bloat | Huge SKILL.md burns context and hides malice | multi-thousand-line bodies |
| **SG009** Identity spoof | Fake “official” branding | “official Anthropic skill” claims |
| **SG010** Enterprise policy | Cloud metadata, docker.sock, secret dumps | `169.254.169.254`, `${{ secrets.X }}` near curl |

Educational docs (security checklists, “never do this”) are filtered where possible — see [LIMITATIONS.md](../LIMITATIONS.md).

Reproduce fixtures:

```bash
skill-guard scan dataset/fixtures/malicious/curl-pipe-shell   # SG003
skill-guard scan dataset/fixtures/malicious/ssh-exfil         # SG004
skill-guard scan dataset/fixtures/malicious/prompt-hijack     # SG005
skill-guard scan dataset/ood/safe/vercel/deploy-to-vercel     # SG006 WARN
```
