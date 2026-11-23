# Finding Schema (`security-report/work/findings.jsonl`)

Write **one JSON object per line** (JSON Lines). Append as you go, so progress survives context resets.
Paths are **relative to the project root**, with forward slashes. Lines are **1-based**.

```json
{"title": "SQL Injection", "category": "sql-injection", "cwe": "CWE-89", "severity": "High", "confidence": "High",
 "flow": "taint",
 "source": {"file": "src/routes/users.js", "line": 14, "expression": "req.query.id", "code": "const id = req.query.id;"},
 "sink":   {"file": "src/db/userRepo.js", "line": 31, "expression": "db.query(sql)", "code": "return db.query(sql);"},
 "path": [
   {"file": "src/routes/users.js", "line": 15, "note": "passed to userRepo.findById(id)", "code": "userRepo.findById(id)"},
   {"file": "src/db/userRepo.js", "line": 30, "note": "concatenated into SQL string", "code": "const sql = \"SELECT * FROM users WHERE id = \" + id;"}
 ],
 "description": "The `id` query parameter flows unvalidated into a SQL string built by concatenation and executed with db.query(). An attacker can inject SQL (e.g. `1 OR 1=1`) to read or modify any table.",
 "evidence": "Route GET /users/:id is registered without auth middleware (src/app.js:22). No cast or parameter binding on the path.",
 "remediation": "In userRepo.findById replace the string concatenation with a bound parameter, and validate id as a positive integer in the route.",
 "secure_example": "async function findById(id) {\n  return db.query('SELECT * FROM users WHERE id = ?', [Number(id)]);\n}",
 "verification": "GET /users?id=1%20OR%201=1 must return at most one row (or 400); add an integration test with ' OR '1'='1 and UNION payloads.",
 "auth_required": "none",
 "references": ["OWASP Cheat Sheet: SQL Injection Prevention", "ASVS 5.0 V1.2 Injection Prevention", "CWE-89"]}
```

Single-point finding (no data flow: secrets, weak crypto, misconfiguration, missing authorization):

```json
{"title": "Hard-coded AWS Access Key", "category": "hardcoded-secret", "cwe": "CWE-798", "severity": "Critical", "confidence": "High",
 "flow": "single",
 "sink": {"file": "config/aws.js", "line": 3, "code": "accessKeyId: 'AKIA...'"},
 "description": "A long-lived AWS access key ID and secret are committed to source control.",
 "remediation": "Revoke and rotate the key now, remove it from git history, and load credentials from the platform's secret store (Replit Secrets / env vars / IAM role).",
 "references": ["OWASP Secrets Management Cheat Sheet", "CWE-798"]}
```

## Fields

| Field | Required | Notes |
|---|---|---|
| `title` | yes | Vulnerability name shown in the report (use the names in `vulnerability-catalog.md`). |
| `cwe` | yes | `CWE-89` form. The validator fills in the OWASP 2021/2025 categories and the default severity from it. |
| `category` | recommended | Key from the catalog (e.g. `sql-injection`). Used for coverage stats. |
| `severity` | recommended | Critical / High / Medium / Low / Info. If omitted, the CWE default is used. |
| `confidence` | recommended | High / Medium / Low (rubric in `taint-methodology.md`). |
| `flow` | yes | `taint` (source→sink) or `single`. |
| `source` | taint: yes | `{file, line, expression?, code?}`. For `single`, the validator copies `sink` into `source`. |
| `sink` | yes | `{file, line, expression?, code?}`. **Put the exact text of that line (or a distinctive part of it) in `code`.** The validator checks it against the file, auto-corrects the line number by up to ±15 lines, and rejects the finding if the text isn't there. |
| `path` | optional | Intermediate hops `{file, line, note, code?}` in order. |
| `description` | yes | What is wrong, how it is exploitable, impact. 2 to 5 sentences. No speculation beyond the evidence. |
| `evidence` | optional | Reachability and auth context, why sanitizers are absent or insufficient. |
| `remediation` | yes | A concrete fix for this code (API, middleware or config to use), not generic advice. See `remediation-guidelines.md`. |
| `secure_example` | Critical/High: yes | The corrected code for the vulnerable lines (1 to 8 lines, project's language and framework). Use `\n` for newlines. |
| `verification` | recommended | The payload or test that proves the fix. |
| `auth_required` | recommended | `none` / `user` / `admin` / `unknown`: who can reach the flaw. Drives `fix_priority`. |
| `fix_priority` | optional | Override: `P1`..`P4`. Otherwise computed: P1 = Critical, or High with `auth_required: none`; P2 = High, or Medium with `none` + High confidence; P3 = Medium; P4 = Low/Info. |
| `effort` | optional | `S` / `M` / `L`: rough fix effort (shown in the Remediation Plan). |
| `references` | optional | OWASP cheat sheet / ASVS requirement / CWE. |

## `scan-notes.json` (optional, shown on the Coverage sheet)
```json
{"manual_checks": [{"check": "Authorization on all /admin routes", "result": "3 routes missing role check, reported VULN rows"},
                   {"check": "Password storage", "result": "bcrypt cost 12, OK"}],
 "not_reviewed": ["legacy/ (12k LOC, generated code) - hotspots only"],
 "limitations": ["Static review only; no runtime testing.", "..."]}
```
