# Dependency Scan (SCA)

## Automated: `scripts/deps.py`
Parses these manifests and lockfiles (lockfiles win over manifests in the same folder):

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 + berry), `pnpm-lock.yaml`, `package.json` (ranges; flagged "declared range") |
| PyPI | `requirements*.txt`, `constraints.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `pyproject.toml` (`==` pins) |
| Packagist | `composer.lock`, `composer.json` |
| Go | `go.mod` |
| Maven | `pom.xml` (resolves `${properties}`), `build.gradle(.kts)`, `gradle.lockfile` |
| RubyGems | `Gemfile.lock` |
| crates.io | `Cargo.lock` |
| NuGet | `*.csproj`, `packages.config`, `packages.lock.json`, `Directory.Packages.props` |
| Pub | `pubspec.lock` |

It sends **only** `{ecosystem, name, version}` to the public OSV.dev API (aggregates GitHub Advisories, PyPA, RustSec, Go vulndb, NVD-linked data, and others), then fetches each advisory for summary, CVE aliases, CVSS (v3 base score computed locally) and fixed versions.
If OSV.dev is unreachable or the user wants no network calls, run with `--offline`. `deps.json` then still lists every package with its manifest file and line.

## Interpreting results
- **Declared range** rows (from `package.json`/`composer.json` without a lockfile) use the minimum version of the range. The installed version may be newer, so mark confidence lower and tell the user to commit a lockfile.
- **Dev-only** dependencies (`scope: dev`) matter less for production. Keep the advisory's severity, but mention the scope in your summary.
- **Transitive** vulnerabilities (only in lockfiles) are fixed by upgrading the direct parent or adding `overrides`/`resolutions`/`constraints`.
- **Reachability** (optional, high value): for Critical/High advisories, grep the code for the vulnerable function or module named in the advisory summary (e.g. `lodash.template`, `_.merge`, `yaml.load`, `jsonwebtoken.verify`, `xml2js`, `Log4j JNDI lookup`). If the vulnerable API is used with untrusted input, add a **code finding** (`category: vulnerable-dependency`, `cwe: CWE-1395`) whose sink is the call site. That ties the CVE to a file and line.

## Manual review (always, and the only option when offline)
Check the package inventory for:
1. **Known-bad versions you recognise**. Examples: `log4j-core` < 2.17.1, `lodash` < 4.17.21, `minimist` < 1.2.6, `axios` < 1.6 (CSRF/SSRF advisories), `jsonwebtoken` < 9, `express` < 4.19.2 (open redirect), `next` < 14.2.25/15.2.3 (middleware auth bypass), `django`/`flask`/`laravel/framework`/`spring-core` with versions past end of life, `PyYAML` < 5.4, `pillow`, `urllib3`, `requests` < 2.32, `jinja2` < 3.1.5, `xmldom`, `node-serialize` (any version), `vm2` (any version, abandoned), `request` (deprecated). Report these from memory with `confidence: Medium` and "verify against the advisory database" in the description. Never invent CVE IDs; leave CVE empty if you are not certain.
2. **Abandoned or deprecated** packages (CWE-1104, Low): `request`, `node-uuid`, `crypto-js` (unmaintained), `mcrypt`, `PyCrypto` (use `pycryptodome`), `vm2`, `csurf`.
3. **Suspicious names** (typosquats such as `reqeusts`, `colourama`, `crossenv`), install scripts (`preinstall`/`postinstall` running curl or obfuscated code), git/URL/tarball dependencies, `latest`/`*` versions.
4. **Lockfile hygiene**: no lockfile committed = supply-chain risk (Low).

Record offline/manual dependency issues as normal code findings in `findings.jsonl` (`category: vulnerable-dependency`, sink = manifest file and line). They appear on the Vulnerabilities sheet; OSV results appear on the Dependencies sheet.
