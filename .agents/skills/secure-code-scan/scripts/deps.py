#!/usr/bin/env python3
"""Step 4 - Dependency (SCA) scan: parse manifests/lockfiles, look up known vulnerabilities in OSV.

Online mode (default) queries the public OSV.dev API (https://osv.dev, free, no key) with ONLY
package name + version + ecosystem. Use --offline when the network is unavailable or the user does
not want package lists sent anywhere; the package inventory is still produced, and the agent then
reviews it manually (references/dependency-scan.md).

Usage:
  python3 deps.py <project_root> [--out security-report/work/deps.json] [--offline]
                  [--exclude GLOB ...] [--keep DIRNAME ...]
"""
import argparse
import json
import math
import os
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
UA = {"User-Agent": "secure-code-scan-skill/1.0", "Content-Type": "application/json"}
LOCK_NEIGHBOURS = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
    "composer.json": ("composer.lock",),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock"),
    "pipfile": ("pipfile.lock",),
    "build.gradle": ("gradle.lockfile",),
    "build.gradle.kts": ("gradle.lockfile",),
    "cargo.toml": ("cargo.lock",),
    "gemfile": ("gemfile.lock",),
}
EXACT = re.compile(r"^v?\d+(\.\d+){0,3}([-+.][0-9A-Za-z.-]+)?$")


def pkg(eco, name, version, manifest, line, scope="", pinned=True):
    return {"ecosystem": eco, "name": name.strip(), "version": (version or "").strip(),
            "manifest": manifest, "line": line, "scope": scope, "pinned": pinned and bool(version)}


def line_of(lines, needle, start=0):
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return 1


def clean_range(v):
    """Turn a declared range (^1.2.3, ~=1.2, >=1.0) into a best-guess version; returns (ver, exact)."""
    v = (v or "").strip().strip('"\'')
    if EXACT.match(v):
        return v.lstrip("v"), True
    m = re.search(r"\d+(\.\d+){0,3}", v)
    return (m.group(0) if m else ""), False


# ----------------------------------------------------------------------------------- parsers
def p_package_lock(rel, lines, text):
    out, data = [], json.loads(text)
    keyline = {}
    for i, l in enumerate(lines):
        m = re.match(r'\s*"((?:[^"]*/)?node_modules/[^"]+)"\s*:\s*\{', l)
        if m:
            keyline[m.group(1)] = i + 1
    if isinstance(data.get("packages"), dict):
        for key, meta in data["packages"].items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict):
                continue
            if meta.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[1]
            out.append(pkg("npm", name, meta.get("version"), rel, keyline.get(key, 1),
                           "dev" if meta.get("dev") else "prod"))
    elif isinstance(data.get("dependencies"), dict):
        def walk(deps):
            for name, meta in deps.items():
                if isinstance(meta, dict):
                    out.append(pkg("npm", name, meta.get("version"), rel, line_of(lines, '"%s"' % name),
                                   "dev" if meta.get("dev") else "prod"))
                    if isinstance(meta.get("dependencies"), dict):
                        walk(meta["dependencies"])
        walk(data["dependencies"])
    return out


def p_yarn_lock(rel, lines, text):
    out, cur, cur_line = [], None, 0
    for i, l in enumerate(lines):
        if l and not l.startswith((" ", "#")) and l.rstrip().endswith(":"):
            spec = l.rstrip()[:-1].split(",")[0].strip().strip('"')
            at = spec.rfind("@")
            cur = spec[:at] if at > 0 else spec
            cur_line = i + 1
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', l)
        if m and cur:
            out.append(pkg("npm", cur, m.group(1), rel, cur_line))
            cur = None
    return out


def p_pnpm_lock(rel, lines, text):
    out, in_pk = [], False
    for i, l in enumerate(lines):
        if re.match(r"^packages:\s*$", l):
            in_pk = True
            continue
        if in_pk and re.match(r"^\S", l):
            in_pk = False
        if not in_pk:
            continue
        m = re.match(r"^  '?(/?[^\s':][^\s']*?)'?:\s*$", l)
        if not m:
            continue
        key = re.sub(r"\(.*\)$", "", m.group(1).lstrip("/"))
        if key.count("@") >= 1 and key.rfind("@") > 0:
            name, ver = key[:key.rfind("@")], key[key.rfind("@") + 1:]
        elif "/" in key:
            name, ver = key.rsplit("/", 1)
        else:
            continue
        out.append(pkg("npm", name, ver.split("_")[0], rel, i + 1))
    return out


def p_package_json(rel, lines, text):
    out, data = [], json.loads(text)
    for scope_key, scope in (("dependencies", "prod"), ("devDependencies", "dev"),
                             ("optionalDependencies", "prod"), ("peerDependencies", "peer")):
        for name, rng in (data.get(scope_key) or {}).items():
            if not isinstance(rng, str) or rng.startswith(("file:", "link:", "workspace:", "git", "http")):
                continue
            ver, exact = clean_range(rng)
            out.append(pkg("npm", name, ver, rel, line_of(lines, '"%s"' % name), scope, exact))
    return out


def p_requirements(rel, lines, text):
    out = []
    for i, l in enumerate(lines):
        s = l.split("#", 1)[0].strip()
        if not s or s.startswith(("-", "git+", "http")):
            continue
        s = s.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===?|~=|>=|<=|>|<|!=)?\s*([^\s,]*)", s)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(3), m.group(4)
        out.append(pkg("PyPI", name, ver if op in ("==", "===") else "", rel, i + 1, "", op in ("==", "===")))
    return out


def p_pipfile_lock(rel, lines, text):
    out, data = [], json.loads(text)
    for sec, scope in (("default", "prod"), ("develop", "dev")):
        for name, meta in (data.get(sec) or {}).items():
            v = (meta or {}).get("version", "")
            out.append(pkg("PyPI", name, v.lstrip("="), rel, line_of(lines, '"%s"' % name), scope))
    return out


def toml_packages(lines):
    """Minimal [[package]] block reader (poetry.lock, uv.lock, Cargo.lock, pdm.lock)."""
    blocks, cur = [], None
    for i, l in enumerate(lines):
        if l.strip() == "[[package]]":
            cur = {"_line": i + 1}
            blocks.append(cur)
            continue
        if l.startswith("["):
            cur = None if l.strip() != "[[package]]" else cur
            continue
        if cur is not None:
            m = re.match(r'^(name|version|source|category)\s*=\s*"([^"]*)"', l)
            if m:
                cur[m.group(1)] = m.group(2)
            elif re.match(r"^source\s*=\s*\{", l):
                cur["source"] = l
    return blocks


def p_poetry_uv(rel, lines, text):
    out = []
    for b in toml_packages(lines):
        if "name" in b and "version" in b:
            src = b.get("source", "")
            if "editable" in src or "virtual" in src or "directory" in src:
                continue
            out.append(pkg("PyPI", b["name"], b["version"], rel, b["_line"], b.get("category", "")))
    return out


def p_cargo_lock(rel, lines, text):
    return [pkg("crates.io", b["name"], b["version"], rel, b["_line"])
            for b in toml_packages(lines) if "name" in b and "registry" in b.get("source", "")]


def p_pyproject(rel, lines, text):
    out = []
    for i, l in enumerate(lines):
        for m in re.finditer(r'"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^";,\s]+)', l):
            out.append(pkg("PyPI", m.group(1), m.group(3), rel, i + 1))
    return out


def p_composer_lock(rel, lines, text):
    out, data = [], json.loads(text)
    for sec, scope in (("packages", "prod"), ("packages-dev", "dev")):
        for p in data.get(sec) or []:
            name = p.get("name")
            if name:
                out.append(pkg("Packagist", name, str(p.get("version", "")).lstrip("v"), rel,
                               line_of(lines, '"name": "%s"' % name), scope))
    return out


def p_composer_json(rel, lines, text):
    out, data = [], json.loads(text)
    for sec, scope in (("require", "prod"), ("require-dev", "dev")):
        for name, rng in (data.get(sec) or {}).items():
            if "/" not in name:
                continue                    # php, ext-* platform requirements
            ver, exact = clean_range(rng)
            out.append(pkg("Packagist", name, ver, rel, line_of(lines, '"%s"' % name), scope, exact))
    return out


def p_go_mod(rel, lines, text):
    out, block = [], False
    for i, l in enumerate(lines):
        s = l.split("//", 1)[0].strip() if "// indirect" not in l else l.strip()
        if s.startswith("require ("):
            block = True
            continue
        if block and s.startswith(")"):
            block = False
            continue
        m = None
        if block:
            m = re.match(r"^(\S+)\s+(v[^\s]+)", s)
        elif s.startswith("require "):
            m = re.match(r"^require\s+(\S+)\s+(v[^\s]+)", s)
        if m:
            out.append(pkg("Go", m.group(1), m.group(2).lstrip("v").replace("+incompatible", ""), rel, i + 1,
                           "indirect" if "indirect" in l else "direct"))
    return out


def p_pom(rel, lines, text):
    out = []
    props = dict(re.findall(r"<([\w.\-]+)>\s*([^<\s]+)\s*</\1>",
                            (re.search(r"<properties>(.*?)</properties>", text, re.S) or [None, ""])[1]
                            if re.search(r"<properties>(.*?)</properties>", text, re.S) else ""))
    pv = re.search(r"<project[^>]*>.*?<version>\s*([^<\s]+)\s*</version>", text, re.S)
    if pv:
        props.setdefault("project.version", pv.group(1))
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        body = m.group(1)
        g = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", body)
        a_ = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", body)
        v = re.search(r"<version>\s*([^<\s]+)\s*</version>", body)
        sc = re.search(r"<scope>\s*([^<\s]+)\s*</scope>", body)
        if not (g and a_):
            continue
        ver = v.group(1) if v else ""
        ver = re.sub(r"\$\{([^}]+)\}", lambda mm: props.get(mm.group(1), mm.group(0)), ver)
        line = text.count("\n", 0, m.start()) + 1
        exact = bool(ver) and "${" not in ver and not ver.startswith(("[", "("))
        out.append(pkg("Maven", g.group(1) + ":" + a_.group(1), ver if exact else "", rel, line,
                       sc.group(1) if sc else "", exact))
    return out


def p_gradle(rel, lines, text):
    out = []
    rx = re.compile(r"""\b(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile|"""
                    r"""classpath|kapt|ksp|annotationProcessor|developmentOnly)\s*\(?\s*['"]([^:'"\s]+):([^:'"\s]+):([^'"@\s]+)['"]""")
    for i, l in enumerate(lines):
        for m in rx.finditer(l):
            ver = m.group(4)
            exact = "$" not in ver and "+" not in ver
            out.append(pkg("Maven", m.group(2) + ":" + m.group(3), ver if exact else "", rel, i + 1,
                           m.group(1), exact))
    return out


def p_gradle_lock(rel, lines, text):
    out = []
    for i, l in enumerate(lines):
        m = re.match(r"^([^:#\s]+):([^:\s]+):([^=\s]+)=", l)
        if m:
            out.append(pkg("Maven", m.group(1) + ":" + m.group(2), m.group(3), rel, i + 1))
    return out


def p_gemfile_lock(rel, lines, text):
    out, in_specs = [], False
    for i, l in enumerate(lines):
        if l.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and l and not l.startswith(" "):
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$", l) if in_specs else None
        if m:
            ver = re.sub(r"-(x86|x64|arm|aarch|universal|java|mingw|mswin|darwin|linux)[\w-]*$", "", m.group(2))
            out.append(pkg("RubyGems", m.group(1), ver, rel, i + 1))
    return out


def p_csproj(rel, lines, text):
    out = []
    for i, l in enumerate(lines):
        m = re.search(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', l) or \
            re.search(r'<PackageReference\s+Version="([^"]+)"\s+Include="([^"]+)"', l)
        if m:
            name, ver = (m.group(1), m.group(2)) if "Include" in l.split("Version")[0] else (m.group(2), m.group(1))
            v, exact = clean_range(ver)
            out.append(pkg("NuGet", name, v, rel, i + 1, "", exact))
            continue
        m = re.search(r'<PackageReference\s+Include="([^"]+)"\s*>', l)
        if m:
            for j in range(i + 1, min(i + 5, len(lines))):
                mv = re.search(r"<Version>\s*([^<]+)\s*</Version>", lines[j])
                if mv:
                    v, exact = clean_range(mv.group(1))
                    out.append(pkg("NuGet", m.group(1), v, rel, i + 1, "", exact))
                    break
    return out


def p_packages_config(rel, lines, text):
    out = []
    for i, l in enumerate(lines):
        m = re.search(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', l)
        if m:
            out.append(pkg("NuGet", m.group(1), m.group(2), rel, i + 1))
    return out


def p_nuget_lock(rel, lines, text):
    out, data = [], json.loads(text)
    seen = set()
    for _fw, deps in (data.get("dependencies") or {}).items():
        for name, meta in (deps or {}).items():
            v = (meta or {}).get("resolved")
            if v and (name, v) not in seen:
                seen.add((name, v))
                out.append(pkg("NuGet", name, v, rel, line_of(lines, '"%s"' % name), (meta or {}).get("type", "")))
    return out


def p_pubspec_lock(rel, lines, text):
    out, cur, cur_line = [], None, 0
    for i, l in enumerate(lines):
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", l)
        if m:
            cur, cur_line = m.group(1), i + 1
            continue
        mv = re.match(r'^    version:\s*"?([^"\s]+)"?', l)
        if mv and cur:
            out.append(pkg("Pub", cur, mv.group(1), rel, cur_line))
            cur = None
    return out


PARSERS = {
    "package-lock.json": p_package_lock, "npm-shrinkwrap.json": p_package_lock, "yarn.lock": p_yarn_lock,
    "pnpm-lock.yaml": p_pnpm_lock, "package.json": p_package_json, "pipfile.lock": p_pipfile_lock,
    "poetry.lock": p_poetry_uv, "uv.lock": p_poetry_uv, "pdm.lock": p_poetry_uv, "pyproject.toml": p_pyproject,
    "composer.lock": p_composer_lock, "composer.json": p_composer_json, "go.mod": p_go_mod, "pom.xml": p_pom,
    "build.gradle": p_gradle, "build.gradle.kts": p_gradle, "gradle.lockfile": p_gradle_lock,
    "gemfile.lock": p_gemfile_lock, "cargo.lock": p_cargo_lock, "packages.config": p_packages_config,
    "packages.lock.json": p_nuget_lock, "pubspec.lock": p_pubspec_lock,
}


def parser_for(base):
    if base in PARSERS:
        return PARSERS[base]
    if re.match(r"requirements.*\.txt$", base) or base.endswith(".pip") or base == "constraints.txt":
        return p_requirements
    if base.endswith((".csproj", ".fsproj", ".vbproj")) or base == "directory.packages.props":
        return p_csproj
    return None


# ----------------------------------------------------------------------------------- CVSS + OSV
W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
     "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0}}


def roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        s_changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if s_changed else .62, "H": .5 if s_changed else .27}[m["PR"]]
        iss = 1 - (1 - W["CIA"][m["C"]]) * (1 - W["CIA"][m["I"]]) * (1 - W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if s_changed else 6.42 * iss
        expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * pr * W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return roundup(min(1.08 * (impact + expl), 10)) if s_changed else roundup(min(impact + expl, 10))
    except (KeyError, ValueError, IndexError):
        return None


def rating(score):
    if score is None:
        return None
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "Info"


def http_json(url, payload=None, timeout=40):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=UA, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def norm_name(eco, n):
    return re.sub(r"[-_.]+", "-", n.lower()) if eco == "PyPI" else n.lower()


def summarize_vuln(v, eco, name):
    sev, score, vector = None, None, ""
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            vector = s.get("score", "")
            score = cvss3_score(vector)
            sev = rating(score)
        elif not vector and str(s.get("type", "")).startswith("CVSS_V4"):
            vector = s.get("score", "")
    dbs = (v.get("database_specific") or {}).get("severity")
    if not sev and dbs:
        sev = {"MODERATE": "Medium", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical",
               "LOW": "Low"}.get(str(dbs).upper())
    fixed, last = [], []
    for aff in v.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("ecosystem", "").split(":")[0] != eco or norm_name(eco, p.get("name", "")) != norm_name(eco, name):
            continue
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
                if "last_affected" in ev and ev["last_affected"] not in last:
                    last.append(ev["last_affected"])
    aliases = v.get("aliases") or []
    refs = [r.get("url") for r in (v.get("references") or []) if r.get("type") in ("ADVISORY", "WEB", "FIX")]
    return {"id": v.get("id"), "aliases": aliases, "cve": ", ".join(a for a in aliases if a.startswith("CVE-")),
            "summary": (v.get("summary") or (v.get("details") or "")[:300]).strip(),
            "severity": sev or "Unrated", "cvss_score": score, "cvss_vector": vector,
            "fixed_versions": ", ".join(fixed) or ("none (last affected: %s)" % ", ".join(last) if last else "no fix published"),
            "url": "https://osv.dev/vulnerability/" + str(v.get("id")), "advisory_urls": refs[:3]}


def osv_lookup(unique):
    """unique: list of (eco, name, version). Returns {(eco,name,version): [vuln summaries]}."""
    results, ids_for = {}, {}
    for i in range(0, len(unique), 500):
        chunk = unique[i:i + 500]
        q = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}
        resp = http_json(OSV_BATCH, q)
        for key, r in zip(chunk, resp.get("results") or []):
            ids_for[key] = [x["id"] for x in (r.get("vulns") or [])]
    all_ids = sorted({i for ids in ids_for.values() for i in ids})
    details = {}

    def fetch(vid):
        try:
            return vid, http_json(OSV_VULN + vid)
        except Exception as e:  # noqa: BLE001
            return vid, {"id": vid, "summary": "details unavailable: %s" % e}

    with ThreadPoolExecutor(max_workers=8) as ex:
        for vid, d in ex.map(fetch, all_ids):
            details[vid] = d
    # Severity fallback: borrow from a GHSA alias when the primary record has none
    need = {a for d in details.values() if not d.get("severity") and not (d.get("database_specific") or {}).get("severity")
            for a in (d.get("aliases") or []) if a.startswith("GHSA-") and a not in details}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for vid, d in ex.map(fetch, sorted(need)):
            details[vid] = d
    for key, ids in ids_for.items():
        eco, name, _ver = key
        out = []
        for vid in ids:
            s = summarize_vuln(details.get(vid, {"id": vid}), eco, name)
            if s["severity"] == "Unrated":
                for a in s["aliases"]:
                    if a in details:
                        alt = summarize_vuln(details[a], eco, name)
                        if alt["severity"] != "Unrated":
                            s["severity"], s["cvss_score"], s["cvss_vector"] = alt["severity"], alt["cvss_score"], alt["cvss_vector"]
                            break
            out.append(s)
        results[key] = merge_aliases(out)
    return results


def merge_aliases(items):
    """Collapse advisories that describe the same issue (GHSA + PYSEC + CVE ids aliasing each other)."""
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unrated": 5}
    groups = []
    for s in items:
        keys = {s["id"], *s["aliases"]}
        for g in groups:
            if g["keys"] & keys:
                g["keys"] |= keys
                g["items"].append(s)
                break
        else:
            groups.append({"keys": keys, "items": [s]})
    merged = []
    for g in groups:
        its = sorted(g["items"], key=lambda s: (not s["id"].startswith("GHSA-"), rank.get(s["severity"], 9)))
        best = dict(its[0])
        others = [s["id"] for s in its[1:]]
        if others:
            best["id"] = best["id"] + " (also " + ", ".join(others) + ")"
        cves = sorted({a for s in its for a in s["aliases"] + [s["id"]] if a.startswith("CVE-")})
        best["cve"] = ", ".join(cves)
        sev = min(its, key=lambda s: rank.get(s["severity"], 9))
        if rank.get(sev["severity"], 9) < rank.get(best["severity"], 9):
            best["severity"], best["cvss_score"], best["cvss_vector"] = sev["severity"], sev["cvss_score"], sev["cvss_vector"]
        merged.append(best)
    return merged


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out", default="security-report/work/deps.json")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--keep", action="append", default=[])
    a = ap.parse_args()
    for k in a.keep:
        common.EXCLUDED_DIRS.discard(k)
        common.KEEP_GLOBS.add(k)
    root = os.path.abspath(a.root)

    manifests = []
    for abs_p, rel_p, reason, _lang in common.walk_files(root, a.exclude):
        if not reason and parser_for(os.path.basename(rel_p).lower()):
            manifests.append((abs_p, rel_p))
    present = {m[1].lower() for m in manifests}

    packages, parse_errors, used = [], [], []
    for abs_p, rel_p in manifests:
        base = os.path.basename(rel_p).lower()
        d = os.path.dirname(rel_p).lower()
        locks = LOCK_NEIGHBOURS.get(base, ())
        if any(((d + "/" if d else "") + l) in present for l in locks):
            continue                       # a lockfile in the same folder is more precise
        try:
            lines = common.read_lines(abs_p)
            found = parser_for(base)(rel_p, lines, "\n".join(lines))
            packages.extend(found)
            used.append({"manifest": rel_p, "packages": len(found)})
        except Exception as e:  # noqa: BLE001
            parse_errors.append({"manifest": rel_p, "error": str(e)})

    queryable = sorted({(p["ecosystem"], p["name"], p["version"]) for p in packages if p["version"]})
    vulns, status = [], "offline (--offline): no vulnerability lookup performed"
    if not a.offline and queryable:
        try:
            res = osv_lookup(queryable)
            status = "ok: %d unique package versions checked against OSV.dev" % len(queryable)
            for p in packages:
                for v in res.get((p["ecosystem"], p["name"], p["version"]), []):
                    vulns.append(dict(v, ecosystem=p["ecosystem"], package=p["name"], version=p["version"],
                                      manifest=p["manifest"], line=p["line"], scope=p["scope"],
                                      pinned=p["pinned"]))
        except (urllib.error.URLError, OSError, ValueError) as e:
            status = "failed: OSV.dev unreachable (%s) - fall back to manual review" % e
    elif not queryable:
        status = "no resolvable package versions found"

    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unrated": 5}
    vulns.sort(key=lambda v: (rank.get(v["severity"], 9), v["package"], v["id"]))
    out = {"osv_status": status, "manifests_parsed": used, "parse_errors": parse_errors,
           "package_count": len(packages), "unpinned": [p for p in packages if not p["pinned"]],
           "packages": packages, "vulnerabilities": vulns}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print("Manifests parsed: %d   packages: %d   unpinned/ranges: %d" % (len(used), len(packages), len(out["unpinned"])))
    print("OSV:", status)
    sev = {}
    for v in vulns:
        sev[v["severity"]] = sev.get(v["severity"], 0) + 1
    print("Vulnerable package findings: %d  (%s)" % (len(vulns), ", ".join("%s=%d" % kv for kv in sev.items()) or "-"))
    for e in parse_errors:
        print("  PARSE ERROR", e["manifest"], e["error"])
    print("Wrote", a.out)


if __name__ == "__main__":
    main()
