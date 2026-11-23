# Configuration, IaC, CI/CD and Secrets Review

## Secrets (CWE-798 / CWE-321 / CWE-259)
`candidates.py` flags secrets in **all** text files, including `.env*`, config, notebooks and docs. For every hit:
1. **Is it real?** Discard placeholders (`changeme`, `your-key-here`, `xxx`, `<token>`, `${VAR}`, `process.env.X`, `os.environ[...]`, obvious test values in `tests/` fixtures, public publishable keys like `pk_live_`, Firebase web `apiKey` (public by design: Info at most), `NEXT_PUBLIC_*` values that are intentionally public).
2. **Is it committed?** `.env` in the repo (check `.gitignore`; if `.git` exists, `git ls-files .env` and `git log --all -- .env`). A secret removed from HEAD but present in history is still exposed. Report the history location when you know it.
3. **Severity**: cloud/root credentials, private keys, payment live keys, DB passwords for production hosts → **Critical**; third-party API tokens → **High**; internal/dev-only credentials → **Medium**.
4. **Never copy the full secret into the report.** In `sink.code` the validator stores the real line; in `description` mask it (e.g. `AKIA****WXYZ`).
5. Remediation must say: **revoke/rotate first**, then remove from code and history (`git filter-repo`/BFG), then move to Replit Secrets / env vars / a secret manager.

## Replit-specific
- `.replit` / `replit.nix`: secrets must be in the **Secrets** tool (env vars), never in `.replit` `[env]`.
- Deployments: check `run`/`deploymentTarget`; dev servers (`flask run --debug`, `next dev`, `php artisan serve`) used as the production run command → debug-enabled finding.
- Webview/public URL: apps bound to `0.0.0.0` are public on Replit; confirm admin routes are protected.

## Docker / containers
| Check | Finding |
|---|---|
| No `USER` instruction or `USER root` in the final stage | Container Runs as Root (Medium) |
| `FROM image` without a tag or `:latest` | Unpinned base image (Low, supply chain) |
| `ADD https://...` / `curl ... \| sh` in `RUN` | Unverified remote code (Medium) |
| `ENV/ARG *PASSWORD*/*SECRET*/*TOKEN*` with a value | Hard-coded secret in image (High) |
| `COPY . .` without `.dockerignore` excluding `.env`, `.git` | Secrets baked into image (Medium) |
| `docker-compose`: `privileged: true`, `network_mode: host`, `/var/run/docker.sock` mounted | Container escape risk (High) |
| Exposed DB ports (`5432:5432`, `3306:3306`, `27017:27017`, `6379:6379`) with default/no passwords | Exposed data store (High) |

## Kubernetes / Helm
`privileged: true`, `allowPrivilegeEscalation: true`, `runAsUser: 0`, `hostNetwork/hostPID/hostIPC: true`, `hostPath` mounts, added capabilities `SYS_ADMIN`/`NET_ADMIN`/`ALL`, no `resources.limits`, secrets in plain `ConfigMap`, `automountServiceAccountToken` default with RBAC `cluster-admin`, `Service type: LoadBalancer` for internal tools.

## Terraform / CloudFormation / Bicep
- Security groups/NSGs with `0.0.0.0/0` (or `::/0`) on 22, 3389, DB ports → High.
- S3: `acl = "public-read"`, missing `aws_s3_bucket_public_access_block`, no encryption, no versioning on critical buckets.
- RDS/SQL: `publicly_accessible = true`, `storage_encrypted = false`, hard-coded `password`.
- IAM: `"Action": "*"` / `"Resource": "*"` together → privilege escalation risk (High).
- Logging disabled (CloudTrail, flow logs) → A09 Low/Medium.
- Secrets in `*.tfvars` committed; state files (`*.tfstate`) committed (contain secrets): High.

## CI/CD (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines)
- `${{ github.event.issue.title }}` (or `.body`, `pull_request.title`/`body`/`head.ref`, `comment.body`, `head_commit.message`, `github.head_ref`) inside `run:` → **CI Script Injection** (High). Fix: pass through `env:` and reference `"$VAR"`.
- `on: pull_request_target` + `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` → untrusted code runs with secrets (Critical).
- Third-party actions pinned to a branch (`@main`/`@master`) instead of a commit SHA → supply chain (Medium; Low for actions by GitHub itself).
- `permissions: write-all` or no `permissions:` with default write token → Medium.
- Secrets echoed to logs, `set -x` with secrets, artifacts containing `.env`.
- GitLab: `CI_JOB_TOKEN` overreach, unprotected variables used on unprotected branches. Jenkins: `sh "... ${params.X}"` (Groovy interpolation into the shell).

## Web server / framework config
- nginx/Apache: `autoindex on`, `Options +Indexes`, `server_tokens on`, weak `ssl_protocols`, missing HSTS, `.git`/`.env` not denied, `alias` traversal (`location /static { alias /var/www/static/; }`: a missing trailing slash on the location gives off-by-slash traversal).
- `web.config`: `customErrors mode="Off"`, `debug="true"`, `requireSSL="false"`, `httpOnlyCookies="false"`.
- Framework debug flags in production config files: `APP_DEBUG=true`, `DEBUG=True`, `NODE_ENV=development`, `spring.h2.console.enabled=true`, `management.endpoints.web.exposure.include=*`.
- CORS config files (`cors.php` `'allowed_origins' => ['*']` with `'supports_credentials' => true`).
