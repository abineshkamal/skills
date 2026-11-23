# Remediation Guidelines

Use this file when writing the `remediation`, `secure_example` and `verification` fields of every finding.
The report is read by developers who will fix the code, so each finding must tell them **exactly what to change, show the corrected code, and how to prove the fix works**.

## Rules for writing remediation

1. **Be specific to the code you read.** Name the exact API, parameter, middleware or config key, and use the project's own framework and variable names.
   - Weak: "Use parameterized queries."
   - Good: "Replace the template literal in `db.query` with `db.query('SELECT * FROM users WHERE id = ?', [id])`."
2. **Fix the root cause at the sink** (binding, encoding, allow-list). Add input validation at the source as defence in depth, never as the only fix.
3. **`secure_example`** is the corrected version of the vulnerable lines: 1 to 8 lines in the project's language and framework, ready to paste. It is **required for Critical and High** findings and recommended for the rest.
4. **`verification`** says how to prove the fix: a payload that must now fail, a unit or integration test to add, or a config check. One or two sentences.
5. **`auth_required`** records who can reach the flaw: `none` (anonymous), `user` (any logged-in user), `admin` (privileged only), or `unknown`. It drives the fix priority.
6. **Secrets:** always **revoke or rotate first**, then remove from code and git history, then move to a secret store. Deleting the line alone is not a fix.
7. **Dependencies:** give the minimum safe version, and say whether it is a major-version upgrade (breaking-change risk). If no fix exists, name a replacement package or a mitigation.
8. Keep framework idioms: Express middleware, Spring annotations, Laravel validation rules, Django ORM, and so on.
9. Don't recommend disabling a feature unless it is unused. If you do, say "remove" explicitly and why.

## Fix priority (computed by the validator; you can override with a `fix_priority` field)

| Priority | Rule | Meaning |
|---|---|---|
| **P1 – Fix immediately** | Critical; or High and `auth_required` = none | Exploitable now; block release / hot-fix |
| **P2 – Fix this sprint** | High (authenticated); or Medium and `auth_required` = none with High confidence | Schedule within the current iteration |
| **P3 – Fix next sprint** | Other Medium | Plan into the backlog with a date |
| **P4 – Backlog / hardening** | Low / Info | Defence in depth, hygiene |

---

## Injection

### SQL Injection (CWE-89)
**Fix:** bind values with placeholders or ORM parameters. For identifiers (column, table, `ORDER BY`), map the user value through an allow-list.

```js
// Node (mysql2/pg/sequelize)
db.query('SELECT * FROM users WHERE email = ? AND status = ?', [email, status])
sequelize.query('SELECT * FROM Products WHERE name LIKE :q', { replacements: { q: `%${q}%` } })
const col = { name: 'name', price: 'price' }[req.query.sort] ?? 'name'   // identifier allow-list
```
```python
cur.execute("SELECT * FROM users WHERE email = %s", (email,))            # DB-API
User.objects.filter(email=email)                                         # Django ORM
session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": id})      # SQLAlchemy
```
```java
PreparedStatement ps = con.prepareStatement("SELECT * FROM users WHERE name = ?"); ps.setString(1, name);
jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
```
```php
$stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?'); $stmt->execute([(int)$id]);
DB::select('SELECT * FROM users WHERE email = ?', [$email]);  // Laravel; or User::where('email', $email)
```
```go
db.Query("SELECT name FROM items WHERE name LIKE ?", "%"+q+"%")
```
```csharp
cmd.CommandText = "SELECT * FROM Users WHERE Name = @n"; cmd.Parameters.AddWithValue("@n", name);
ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");
```
**Verify:** `' OR '1'='1` and `' UNION SELECT ...--` must return no extra rows or a 400. Add an integration test with these payloads. Also run the app with a least-privilege DB user.

### NoSQL Injection (CWE-943)
**Fix:** cast inputs to scalars, reject objects and keys starting with `$`, and never use `$where` or `mapReduce` with input.
```js
const id = String(req.params.id); if (!/^[a-f0-9-]{1,40}$/.test(id)) return res.sendStatus(400)
orders.find({ orderId: id })                                   // instead of { $where: `this.orderId === '${id}'` }
app.use(require('express-mongo-sanitize')())                   // strips $ and . keys
```
**Verify:** `{"id":{"$ne":null}}` and `' || true || '` must not return or modify multiple documents.

### OS Command Injection (CWE-78) / Argument Injection (CWE-88)
**Fix:** avoid the shell. Call the binary with an argument array and allow-list validation, and put `--` before user arguments. Better still, use a library API instead of a process.
```js
execFile('ping', ['-c', '1', '--', host], cb)            // + /^[a-zA-Z0-9.-]{1,253}$/.test(host)
```
```python
subprocess.run(["ping", "-c", "1", "--", host], shell=False, check=True, timeout=5)
```
```java
new ProcessBuilder(List.of("ping", "-c", "1", "--", host)).start();
```
```go
exec.Command("nslookup", "--", target)
```
```php
$out = shell_exec('ping -c 1 ' . escapeshellarg($host));   // last resort; prefer Symfony new Process(['ping','-c','1',$host])
```
**Verify:** `127.0.0.1; id`, `$(id)` and `` `id` `` must not execute. Assert in a test that the command receives a single argument.

### Code Injection / eval (CWE-94/95), Sandbox Escape
**Fix:** remove `eval`, `new Function`, `vm`, `notevil` and `vm2` on user data. Parse data formats as data (`JSON.parse`) and validate them with a schema. Dispatch behaviour through a lookup table.
```js
const lines = OrderLines.parse(JSON.parse(body.orderLinesData))   // zod schema, no evaluation
const handlers = { sum: (a, b) => a + b }; handlers[op]?.(a, b)    // instead of eval(op)
```
**Verify:** payloads like `require('child_process').execSync('id')` and `while(true){}` must be rejected as invalid input.

### Server-Side Template Injection (CWE-1336) / EL Injection (CWE-917)
**Fix:** templates are static files. User data goes in only as context variables, never into the template source.
```js
const fn = pug.compileFile('views/userProfile.pug'); res.send(fn({ username: user.username }))
```
```python
return render_template_string("<p>Hi {{ n }}</p>", n=name)
```
```java
StandardEvaluationContext -> SimpleEvaluationContext.forReadOnlyDataBinding().build()
```
**Verify:** `#{7*7}`, `{{7*7}}` and `${7*7}` must render literally, not as `49`.

### LDAP / XPath Injection (CWE-90/643)
**Fix:** use the library's encoder (`ldap.filter.escape_filter_chars`, `ldap_escape($v, '', LDAP_ESCAPE_FILTER)`, Spring `LdapEncoder.filterEncode`) or a parameterized XPath variable resolver.
**Verify:** `*)(uid=*` must not widen the result set.

### XML External Entities (CWE-611) / Entity Expansion (CWE-776)
**Fix:** disable DOCTYPE and external entities.
```java
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); f.setExpandEntityReferences(false);
```
```python
from defusedxml.ElementTree import fromstring        # or lxml XMLParser(resolve_entities=False, no_network=True)
```
```js
libxmljs.parseXml(data, { noent: false, dtdload: false, nonet: true })
```
```php
$doc->loadXML($xml, LIBXML_NONET);   // never LIBXML_NOENT / LIBXML_DTDLOAD
```
**Verify:** an upload containing `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` must be rejected or must not expand `&e;`.

### Insecure Deserialization (CWE-502)
**Fix:** use JSON with explicit types and safe loaders, and never call native deserializers on client data.
```python
yaml.safe_load(data); json.loads(data)                       # not pickle.loads / yaml.load
```
```js
yaml.load(data)   // js-yaml >= 4 (safe by default); never node-serialize / funcster
```
```java
ObjectInputFilter.Config.setSerialFilter(ObjectInputFilter.Config.createFilter("com.acme.dto.*;!*"));
mapper.deactivateDefaultTyping();
```
```php
json_decode($s, true); unserialize($s, ['allowed_classes' => false]);
```
```csharp
JsonConvert.DeserializeObject<OrderDto>(s, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None });
```
**Verify:** a ysoserial / gadget payload or a `!!python/object` tag must be rejected. Also limit input size, which defends against YAML bombs.

---

## Web output, URLs and files

### Cross-Site Scripting (CWE-79)
**Fix:** rely on the framework's auto-escaping. Sanitize rich HTML with a maintained allow-list sanitizer. Set a CSP as defence in depth.
```ts
// Angular: bind text, remove bypassSecurityTrust*
<span>{{ searchValue }}</span>              // or [innerHTML] WITHOUT bypassSecurityTrustHtml (Angular sanitizes)
```
```jsx
<div>{comment}</div>                        // React; if HTML needed: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}}
```
```js
res.send(`<h1>Hello ${escapeHtml(name)}</h1>`)          // or a template engine with autoescape
```
```php
<?= htmlspecialchars($q, ENT_QUOTES, 'UTF-8') ?>        // Blade: {{ $q }} not {!! $q !!}
```
```python
{{ comment }}   # Jinja autoescape; never |safe / Markup() on user data; bleach/nh3 for rich text
```
Also: allow only `http`/`https` URL schemes in `href`/`src`, set `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'`, and mark session cookies `HttpOnly`.
**Verify:** `<img src=x onerror=alert(1)>` and `<iframe src="javascript:alert(1)">` must render as text or be stripped. Add a test that asserts the escaped output.

### Server-Side Request Forgery (CWE-918)
**Fix:** allow-list the destination hosts. Resolve DNS and block private, loopback, link-local and metadata ranges. Disable redirects, and set timeouts and size limits.
```js
const u = new URL(input); if (!['https:'].includes(u.protocol) || !ALLOWED_HOSTS.has(u.hostname)) throw 400
// or use request-filtering-agent / ssrf-req-filter for IP-range blocking; fetch(u, { redirect: 'manual' })
```
```python
# resolve, then ipaddress.ip_address(ip).is_private / is_loopback / is_link_local -> reject
```
**Verify:** `http://127.0.0.1:3000/`, `http://169.254.169.254/latest/meta-data/`, `http://[::1]/` and DNS-rebinding hosts must be refused.

### Open Redirect (CWE-601)
**Fix:** allow only relative paths, or compare the parsed URL exactly against an allow-list. Never use `includes` or `startsWith` on the raw string.
```js
const ok = to.startsWith('/') && !to.startsWith('//') && !to.startsWith('/\\')
const allowed = ALLOWLIST.has(new URL(to).href)
```
Framework helpers: Django `url_has_allowed_host_and_scheme`, ASP.NET `LocalRedirect` / `Url.IsLocalUrl`, Rails `url_from`.
**Verify:** `https://evil.com/?https://allowed.com`, `//evil.com` and `/\evil.com` must be rejected.

### Path Traversal / File Inclusion (CWE-22/73/98)
**Fix:** canonicalize the path, then enforce the base-directory prefix. Prefer mapping IDs to stored names. Decode the input before validating it, and reject NUL bytes.
```js
const base = path.resolve('ftp'); const p = path.resolve(base, name)
if (!p.startsWith(base + path.sep) || name.includes('\0')) return res.sendStatus(403)
```
```python
p = (BASE / name).resolve(); assert p.is_relative_to(BASE.resolve())      # or werkzeug secure_filename
```
```java
Path p = base.resolve(name).normalize(); if (!p.startsWith(base)) throw new SecurityException();
```
```php
$real = realpath($base . '/' . basename($name)); if (!$real || !str_starts_with($real, $base)) abort(403);
```
**Verify:** `../../etc/passwd`, `..%2f..%2f`, `file.md%2500.bak` and absolute paths must return 403.

### Unrestricted File Upload (CWE-434)
**Fix:** reject files whose extension and magic-byte content are not on the allow-list. Enforce size limits. Generate server-side file names and store uploads outside the webroot with no execute permission. Require authentication and AV-scan if possible.
**Verify:** `.php`/`.jsp`/`.html`/`.svg` uploads and oversized files must return 4xx.

### Prototype Pollution (CWE-1321)
**Fix:** reject `__proto__`, `constructor` and `prototype` keys. Use `Object.create(null)` or `Map`, upgrade lodash/merge libraries, and validate JSON with a strict schema.
**Verify:** after sending `{"__proto__":{"isAdmin":true}}`, `({}).isAdmin` must still be undefined.

---

## Access control, authentication, sessions

### Missing Authentication / Authorization (CWE-306/862/285)
**Fix:** deny by default. Put authentication middleware on the route group and an explicit role/permission check on each privileged action.
```js
router.put('/api/Products/:id', requireAuth, requireRole('admin'), updateProduct)
```
```java
@PreAuthorize("hasRole('ADMIN')") @PutMapping("/products/{id}")
```
```php
Route::middleware(['auth', 'can:update,product'])->put('/products/{product}', ...);
```
```python
@permission_classes([IsAdminUser])   # DRF; Django: @login_required + @permission_required
```
**Verify:** call the endpoint with no token and with a normal user's token. Expect 401/403. Add these as automated tests.

### Insecure Direct Object Reference (CWE-639)
**Fix:** scope every lookup to the current user or tenant, and return 404 for records the user doesn't own.
```js
Basket.findOne({ where: { id, UserId: req.user.id } })
```
```python
get_object_or_404(Order, pk=pk, owner=request.user)
```
```php
$request->user()->orders()->findOrFail($id);   // or a Policy: $this->authorize('view', $order)
```
**Verify:** user A requesting user B's ID must get 404/403.

### Mass Assignment / Privilege Escalation (CWE-915/269)
**Fix:** use explicit allow-lists of bindable fields (DTOs, `$fillable`, strong params, serializer `fields`). Set role, owner, price and balance server-side only.
```js
const { email, password } = RegisterDto.parse(req.body); User.create({ email, password, role: 'customer' })
```
```php
protected $fillable = ['name', 'email'];      // never $guarded = []
```
```ruby
params.require(:user).permit(:name, :email)   # never permit!
```
**Verify:** registering or updating with `"role":"admin"` or `"is_admin":true` must not change the role.

### CSRF (CWE-352)
**Fix:** use anti-CSRF tokens on cookie-authenticated, state-changing requests (`csrf-csrf`, Django/Laravel/Rails defaults, Spring Security CSRF). Set `SameSite=Lax/Strict` cookies. Don't use GET for state changes.
**Verify:** a cross-origin form POST without the token must return 403.

### Broken Authentication / JWT (CWE-287/347/620/307/384/613)
**Fix:**
- Pin JWT algorithms (`algorithms: ['RS256']`) on current libraries (jsonwebtoken ≥ 9, express-jwt ≥ 8) and validate `exp`/`aud`/`iss`.
- Require the current password for password changes.
- Rate-limit login, OTP and reset endpoints, and use generic error messages.
- Regenerate the session ID on login; set idle and absolute timeouts; invalidate the session on logout.
```js
jwt.verify(token, publicKey, { algorithms: ['RS256'], audience: 'app', issuer: 'auth' })
app.use('/rest/user/login', rateLimit({ windowMs: 15*60e3, max: 10 }))
```
**Verify:**
- An `alg:none` token and an HS256 token signed with the public key must be rejected.
- The 11th login attempt within the window must be throttled.
- A password change without the correct current password must fail.

### Type Juggling (PHP, CWE-697)
**Fix:** use `password_hash`/`password_verify` and `hash_equals`, `===`, and `in_array($v, $arr, true)`.
**Verify:** `0e`-prefixed magic hashes must not authenticate.

---

## Cryptography and secrets

### Hard-coded Secrets / Keys (CWE-798/321/259)
**Fix (in order):**
1. **Revoke or rotate** the credential or key now.
2. Remove it from the code **and from git history** (`git filter-repo --replace-text` or BFG); force-push and invalidate old clones and CI caches.
3. Load it at runtime from a secret store (Replit Secrets / environment variables / AWS Secrets Manager / Vault / Key Vault).
4. Add secret scanning to CI and a pre-commit hook.
```js
const privateKey = process.env.JWT_PRIVATE_KEY ?? (() => { throw new Error('JWT_PRIVATE_KEY missing') })()
```
**Verify:** grep the repo and its history for the old value (no matches), and confirm the old key or token is rejected by the provider.

### Weak Password Hashing (CWE-916/328/256)
**Fix:** use Argon2id, bcrypt (cost ≥ 12) or scrypt with a per-user salt, and rehash transparently on the next successful login.
```js
const hash = await bcrypt.hash(pw, 12); const ok = await bcrypt.compare(pw, hash)
```
```python
from argon2 import PasswordHasher; ph = PasswordHasher(); ph.verify(stored, pw)
```
```php
password_hash($pw, PASSWORD_ARGON2ID); password_verify($pw, $hash);
```
**Verify:** stored values start with `$2b$`/`$argon2id$`; no MD5/SHA1 hex strings remain in the users table.

### Weak Algorithms / Modes, Insecure Randomness (CWE-327/338)
**Fix:** use AES-256-GCM / ChaCha20-Poly1305 with a random nonce, and SHA-256+ for integrity. For security tokens use a CSPRNG: `crypto.randomBytes`, `secrets.token_urlsafe`, `SecureRandom`, `random_bytes`, `crypto/rand`, `RandomNumberGenerator`.
**Verify:** no ECB/DES/RC4/MD5 in the crypto code paths; tokens have ≥ 128 bits of entropy.

### TLS Verification Disabled (CWE-295) / Cleartext (CWE-319)
**Fix:** remove `verify=False`, `rejectUnauthorized:false` and `InsecureSkipVerify`. For private CAs, pass the CA bundle explicitly. Use `https://` everywhere and add HSTS.
**Verify:** a connection to a self-signed test endpoint must fail.

---

## Configuration and deployment

| Issue | Fix | Verify |
|---|---|---|
| Debug mode (CWE-489) | Drive it from the environment (`DEBUG=False`, `APP_DEBUG=false`, `NODE_ENV=production`); use the production error handler | Force an error: the response shows a generic message, no stack trace |
| Stack traces (CWE-209) | Generic error responses; log details server-side with a correlation ID | Same as above |
| Permissive CORS (CWE-942) | Explicit origin allow-list; never reflect `Origin` together with `credentials: true` | An `Origin: https://evil.com` request gets no ACAO header |
| Missing headers (CWE-693/1021) | `helmet()` / framework equivalents: CSP, HSTS, X-Content-Type-Options, frame-ancestors | Check response headers |
| Directory listing / exposed files (CWE-548/200) | Remove `serveIndex`/`autoindex`; serve only public assets; never serve keys, logs or backups over HTTP | Requests for `/ftp`, `/logs` and `/encryptionkeys` return 404 |
| Exposed metrics/admin (CWE-200) | Bind to an internal interface or require admin auth | An anonymous request returns 401/404 |
| Insecure cookie (CWE-614/1004) | `Secure; HttpOnly; SameSite=Lax` on session cookies | Check the `Set-Cookie` header |
| Container root (CWE-250) | Pinned slim base image (`node:22-alpine@sha256:…`), `USER node`, read-only FS, drop capabilities | `docker run … id` shows a non-root uid |
| CI script injection (CWE-78) | Pass `${{ }}` values via `env:` and quote `"$VAR"`; least-privilege `permissions:` | A PR title containing `$(id)` doesn't execute |
| Action pinned to branch (CWE-829) | Pin third-party actions to a full commit SHA; use Dependabot for updates | `uses:` lines contain 40-hex SHAs |
| Cloud exposure (CWE-284) | Private subnets, specific CIDRs, encryption on, least-privilege IAM | IaC scan / plan review |

## Business logic and resource limits
- **Client-controlled prices, amounts or quantities (CWE-840):** recompute totals server-side from the DB, reject values ≤ 0 or above limits, and credit wallets only after a verified payment callback (signature checked, idempotent).
- **Race conditions (CWE-362/367):** run balance, stock and coupon updates in transactions with row locks or atomic conditional updates (`UPDATE … SET stock = stock - 1 WHERE id = ? AND stock > 0`).
- **Resource exhaustion (CWE-400/770):** cap pagination, body and upload sizes, and regex input length; set timeouts on outbound calls; rate-limit expensive endpoints.

## Vulnerable dependencies (CWE-1395/1104)
- Upgrade to the **minimum fixed version** on the same major version where one exists. Otherwise plan a major upgrade and note the breaking-change risk.
- Commit a lockfile; use `overrides`/`resolutions`/`constraints` to force patched transitive versions.
- No fix published → replace the package (e.g. `marsdb` → a maintained DB, `vm2` → `isolated-vm`, `request` → `undici`/`axios`) or remove the vulnerable feature.
- **Verify:** re-run `deps.py` and the advisory no longer appears.
