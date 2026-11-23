# secure-code-scan: a Replit Agent skill for source-code vulnerability scanning

Replit Agent uses this skill to scan a folder from its root with no external scanners installed. It runs:
- **taint analysis** (source → sink, traced across files by the agent)
- an **OWASP secure-coding review** (Secure Coding Practices, ASVS 5.0, Top 10 2021 and 2025, CWE Top 25)
- **secrets, config, IaC and CI/CD checks**
- a **dependency CVE scan** (OSV.dev)

It produces an **Excel report** with vulnerability name, source file path and line, and sink file path and line.

## Install in a Replit project
1. In the Replit file tree, turn on **Show hidden files**.
2. Copy the `.agents/skills/secure-code-scan/` folder into the project root, so you end up with `/.agents/skills/secure-code-scan/SKILL.md`.
3. Ask the Agent, for example: *"Scan this project for vulnerabilities and give me the Excel report"* or *"Run secure-code-scan on the `server/` folder, offline"*.

The report is written to `security-report/vulnerability-report.xlsx`. Working files (inventory, hotspots, findings, deps) go in `security-report/work/`.

## Requirements
- Python 3.8+ (standard library only, no pip installs). Replit has it by default.
- Internet access is optional and used only for the OSV.dev dependency lookup, which sends package name, version and ecosystem. If the user asks for an offline scan, the agent runs `--offline`.

## What's inside
| Path | Purpose |
|---|---|
| `SKILL.md` | Workflow the agent follows (9 steps, ground rules, quality bar) |
| `references/taint-methodology.md` | How to trace source→sink, which sanitizers count for which sink, confidence and severity rubrics, false-positive rules |
| `references/languages/*.md` | Sources, sinks, sanitizers and framework rules: JS/TS, Python, Java/Kotlin, PHP, Go, C#/.NET, Ruby, C/C++, plus a method for any other language |
| `references/vulnerability-catalog.md` | Standard vulnerability names, CWE, confirm criteria, remediation |
| `references/secure-coding-checklist.md` | OWASP SCP / ASVS / Top 10 design and logic review (access control, auth, crypto, logic, LLM) |
| `references/config-iac-secrets.md` | Secrets, Docker, Kubernetes, Terraform, GitHub Actions, web server config, Replit specifics |
| `references/dependency-scan.md` | SCA usage, reachability, offline manual review |
| `references/remediation-guidelines.md` | How to write fixes: rules, P1–P4 fix priority, secure before/after code per vulnerability class and language, verification steps, dependency upgrade guidance |
| `references/finding-schema.md` | JSONL format the agent writes findings in (incl. `remediation`, `secure_example`, `verification`, `auth_required`) |
| `scripts/inventory.py` | Languages, frameworks, manifests, entry points, skipped files |
| `scripts/candidates.py` + `patterns.py` | 186 Semgrep-style hotspot patterns (sources, sinks, secrets, crypto, misconfig) across all languages |
| `scripts/deps.py` | Parses 20+ manifest and lockfile formats → OSV.dev CVEs, CVSS, fixed versions, manifest line |
| `scripts/validate_findings.py` | Anti-hallucination gate: checks every file and line and that the quoted code is really there; fixes line drift; de-duplicates; maps CWE → OWASP 2021/2025; rejects Critical/High findings without a secure code example; computes fix priority |
| `scripts/build_report.py` | Writes the `.xlsx` (no openpyxl needed): Summary (with remediation roadmap), Vulnerabilities (incl. Fix Priority, Remediation, Secure Code Example, How to Verify Fix), Remediation Plan (fixes grouped by type + dependency upgrade plan), Dependencies (with recommended upgrade), Dependency Inventory, Coverage. Masks secrets automatically |
| `scripts/cwe_map.py` | CWE → name, OWASP 2021, OWASP 2025, default severity |

`sample-output/JuiceShop-vulnerability-report.xlsx` is an example report produced by running the skill against OWASP Juice Shop (47 code findings, 43 dependency advisories).

## Honest limits
- The agent does the taint analysis by reading code, so depth depends on the agent's context budget. On very large repos it prioritises high-risk sinks and records anything it didn't review on the Coverage sheet.
- It is a static review: nothing is executed, and runtime or deployment configuration is not tested.
- The regex hotspot index guides the review; it is not a finding list. Entry-point (forward) tracing covers sinks the patterns miss.
