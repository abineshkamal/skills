# Secure Coding Review Checklist

Condensed from the **OWASP Secure Coding Practices Quick Reference Guide**, **OWASP ASVS 5.0**, the **OWASP Top 10 (2021 & 2025)**, the **OWASP Cheat Sheet Series**, and the **CWE Top 25**.
Use it in Step 5 (design and logic review). Patterns can't find these issues; you find them by reading the routes, middleware, models and config.
Each confirmed gap becomes a finding (usually `flow: "single"`, sink = the line where the check is missing or wrong, e.g. the route declaration).

## 1. Access control (A01). Highest-yield manual check
- [ ] Build a route → guard table. Every non-public route has authentication. Compare siblings: one unguarded route in a guarded group is a finding.
- [ ] Authorization is enforced **server-side** on every action, deny by default. UI hiding is not authorization.
- [ ] Object-level checks: every lookup by ID is scoped to the current user/tenant (IDOR). Check `find(id)`, `findById`, `get_object_or_404(Model, pk=)`, `Model::find($id)`, and repository `getById`.
- [ ] Function-level checks: admin endpoints check role/permission, not just "logged in".
- [ ] Users cannot change `role`, `is_admin`, `tenant_id`, `owner_id`, `price`, `balance` through update payloads (mass assignment).
- [ ] File downloads and exports check ownership.
- [ ] CORS does not reflect arbitrary origins with credentials.
- [ ] Rate limiting on expensive or sensitive endpoints.
- [ ] SSRF controls on any server-side fetch (A01:2025 includes SSRF).

## 2. Authentication & session (A07)
- [ ] Passwords hashed with Argon2id / scrypt / bcrypt (cost ≥ 10) / PBKDF2-SHA256 ≥ 600k iterations. Never MD5/SHA*/plain text.
- [ ] Login, OTP, reset: rate limit or lockout; generic error messages (no user enumeration).
- [ ] Reset and verification tokens: CSPRNG, ≥128-bit, single-use, expiring, stored hashed.
- [ ] Session ID regenerated on login and privilege change; invalidated on logout; idle and absolute timeouts.
- [ ] Cookies: `Secure`, `HttpOnly`, `SameSite=Lax/Strict`.
- [ ] JWT: algorithm pinned, signature verified, `exp`/`nbf`/`aud`/`iss` validated, strong secret from env, no sensitive data in payload, refresh/revocation strategy.
- [ ] MFA available for admin accounts (ASVS L2). Missing MFA is an Info note, not a vulnerability.
- [ ] No default or hard-coded accounts, no backdoor debug login.

## 3. Input validation & output encoding (A03:2021 / A05:2025)
- [ ] Server-side validation with allow-lists (type, length, range, format) at trust boundaries; reject unexpected keys.
- [ ] All queries parameterized; all output encoded for its context (HTML, attribute, JS, URL, CSS).
- [ ] Rich text sanitized with an allow-list sanitizer.
- [ ] Uploads: size limit, content-type sniffing, generated filenames, stored outside webroot, not executable.
- [ ] Canonicalize before validating (paths, URLs, Unicode).

## 4. Cryptography (A02:2021 / A04:2025)
- [ ] TLS for all external traffic; certificate validation never disabled.
- [ ] Modern algorithms only (AES-GCM, ChaCha20-Poly1305, RSA-OAEP ≥ 2048, ECDSA P-256, SHA-256+). No ECB, no static IV/nonce reuse.
- [ ] Keys and secrets from a secret manager or env vars, never in code; rotated; separate per environment.
- [ ] CSPRNG for every security value (`crypto.randomBytes`, `secrets`, `SecureRandom`, `random_bytes`, `crypto/rand`, `RandomNumberGenerator`).
- [ ] Sensitive data at rest encrypted where required (PII, tokens, payment data). Card data never stored after authorization.

## 5. Error handling & logging (A09, A10:2025)
- [ ] No stack traces, SQL errors or framework debug pages to users (debug off in production config).
- [ ] Exceptions fail **closed**: a catch in an auth or permission path must deny, not continue.
- [ ] Null and edge-case handling around security decisions.
- [ ] Security events logged (login success/failure, access denied, admin actions, input validation failures) with user, time and IP, and **without** secrets, passwords, tokens or full card numbers.
- [ ] Log injection prevented (CR/LF encoding).

## 6. Data protection
- [ ] Sensitive data not in URLs (tokens in query strings get logged).
- [ ] `Cache-Control: no-store` on sensitive responses.
- [ ] API responses don't over-expose fields (password hashes, internal IDs, other users' PII). Serializers use explicit field lists.
- [ ] PII minimization; deletion on request where required.

## 7. Configuration (A05:2021 / A02:2025)
- [ ] Debug/dev mode off; default credentials removed; sample/test endpoints not deployed.
- [ ] Security headers: CSP, HSTS, X-Content-Type-Options `nosniff`, `frame-ancestors`/X-Frame-Options, Referrer-Policy.
- [ ] CSRF protection enabled for cookie-auth apps; exemptions justified.
- [ ] Containers: non-root user, no `--privileged`, pinned base images, no secrets in `ENV`/`ARG`.
- [ ] Cloud/IaC: no public buckets, no `0.0.0.0/0` admin ports, encryption on, least-privilege IAM (no `"Action": "*"`).
- [ ] `.env`, keys, DB dumps and backups not committed or served statically.

## 8. Supply chain & integrity (A06:2021, A03 & A08:2025)
- [ ] Lockfiles committed; dependencies pinned; no known-vulnerable versions (deps.py).
- [ ] No dependencies from git URLs or unpinned `latest`; no typosquat-looking names.
- [ ] CI: actions pinned to SHA or version, least `permissions:`, no untrusted `${{ }}` in `run:`, careful `pull_request_target`.
- [ ] Subresource Integrity on CDN scripts; no `curl | sh` in build.
- [ ] Deserialization only of trusted, signed data; auto-update channels verified.

## 9. Business logic (A04:2021 / A06:2025 Insecure Design)
- [ ] Prices, totals, discounts and quantities computed server-side; negative/zero/overflow values rejected.
- [ ] Multi-step flows (checkout, approval, KYC) can't be skipped or replayed.
- [ ] Concurrency: balance, stock, coupon and vote updates run in transactions with row locks or atomic updates (race conditions).
- [ ] Idempotency on payment callbacks; webhook signatures verified.
- [ ] Limits on resource consumption (pagination max, upload size, request timeouts, job queues).

## 10. LLM / AI features (when the app calls an LLM)
- [ ] User input concatenated into system prompts = prompt injection risk. Report as Insecure Design (CWE-1427 if available, otherwise CWE-20), Medium.
- [ ] LLM output treated as untrusted: never passed to eval/SQL/shell/HTML without the sanitizers for that sink. This is a taint source.
- [ ] Tool or function-calling scoped to least privilege; API keys server-side only.
