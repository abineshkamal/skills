#!/usr/bin/env python3
"""Step 5 - Validate agent findings against the real source tree (anti-hallucination gate).

Reads   security-report/work/findings.jsonl   (one JSON object per line, schema in
        references/finding-schema.md; a JSON array file is also accepted)
Writes  security-report/work/findings.validated.json

Checks for every finding:
  * required fields present; file paths are inside the project root and exist
  * line numbers are within the file
  * the quoted sink/source `code` really is on (or within +/-15 lines of) the stated line; if it
    is found nearby, the line number is corrected and a warning is emitted
  * CWE normalised; OWASP 2021/2025 + default severity filled from cwe_map
  * duplicates (same CWE + source + sink) merged
Exit code 1 when any finding is rejected (fix them and re-run), unless --allow-rejects.

Usage:
  python3 validate_findings.py <project_root> [--in security-report/work/findings.jsonl]
                               [--out security-report/work/findings.validated.json] [--allow-rejects]
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common   # noqa: E402
import cwe_map  # noqa: E402

SEV_RANK = {s: i for i, s in enumerate(cwe_map.SEVERITIES)}
CONF_RANK = {c: i for i, c in enumerate(cwe_map.CONFIDENCES)}
_cache = {}


def norm_ws(s):
    return re.sub(r"\s+", "", s or "").lower()


def load_lines(root, rel):
    if rel not in _cache:
        _cache[rel] = common.read_lines(os.path.join(root, rel))
    return _cache[rel]


def clean_path(root, p):
    if not p:
        return None, "missing file"
    p = str(p).strip().replace("\\", "/")
    if os.path.isabs(p):
        try:
            p = os.path.relpath(p, root).replace("\\", "/")
        except ValueError:
            return None, "absolute path outside project root: " + p
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    full = os.path.normpath(os.path.join(root, p))
    try:
        inside = os.path.commonpath([full, os.path.normpath(root)]) == os.path.normpath(root)
    except ValueError:
        inside = False
    if not inside:
        return None, "path escapes project root: " + p
    if not os.path.isfile(full):
        return None, "file not found: " + p
    return p, None


def check_location(root, loc, label, warnings):
    """Validate {file,line,code?}; returns (loc, error). Mutates loc (normalised + snippet)."""
    if not isinstance(loc, dict):
        return None, label + " must be an object with file/line"
    rel, err = clean_path(root, loc.get("file"))
    if err:
        return None, "%s: %s" % (label, err)
    loc["file"] = rel
    try:
        line = int(loc.get("line"))
    except (TypeError, ValueError):
        return None, "%s: line is not an integer (%r)" % (label, loc.get("line"))
    lines = load_lines(root, rel)
    if line < 1 or line > len(lines):
        return None, "%s: line %d out of range (file has %d lines)" % (label, line, len(lines))
    claimed = loc.get("code")
    if claimed:
        want = norm_ws(claimed)[:120]
        actual = norm_ws(lines[line - 1])
        # match = claimed snippet is on the line, or (multi-line claim) the non-trivial line is inside it
        matches = want in actual or (len(actual) >= 8 and actual in want)
        if want and not matches:
            found = None
            for d in range(1, 16):
                for cand in (line - d, line + d):
                    if 1 <= cand <= len(lines) and want in norm_ws(lines[cand - 1]):
                        found = cand
                        break
                if found:
                    break
            if found:
                warnings.append("%s %s: line corrected %d -> %d (code matched)" % (label, rel, line, found))
                line = found
            else:
                return None, "%s: quoted code not found at %s:%d (+/-15 lines): %r" % (
                    label, rel, line, claimed[:100])
    loc["line"] = line
    loc["code"] = lines[line - 1].strip()[:500]
    return loc, None


def norm_choice(value, allowed, default):
    if not value:
        return default
    v = str(value).strip().lower()
    aliases = {"moderate": "medium", "informational": "info", "information": "info", "none": "info",
               "crit": "critical", "med": "medium"}
    v = aliases.get(v, v)
    for a in allowed:
        if a.lower() == v:
            return a
    return default


PRIORITY_LABEL = {"P1": "P1 - Fix immediately", "P2": "P2 - Fix this sprint",
                  "P3": "P3 - Fix next sprint", "P4": "P4 - Backlog / hardening"}


def normalise_priority(p):
    if not p:
        return None
    m = re.match(r"\s*P?([1-4])", str(p), re.I)
    return PRIORITY_LABEL["P" + m.group(1)] if m else None


def compute_priority(sev, conf, auth):
    if sev == "Critical" or (sev == "High" and auth == "none"):
        return PRIORITY_LABEL["P1"]
    if sev == "High" or (sev == "Medium" and auth == "none" and conf == "High"):
        return PRIORITY_LABEL["P2"]
    if sev == "Medium":
        return PRIORITY_LABEL["P3"]
    return PRIORITY_LABEL["P4"]


def read_findings(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return [], []
    if text.startswith("["):
        return json.loads(text), []
    items, errors = [], []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError as e:
            errors.append("findings line %d: invalid JSON (%s)" % (n, e))
    return items, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--in", dest="inp", default="security-report/work/findings.jsonl")
    ap.add_argument("--out", default="security-report/work/findings.validated.json")
    ap.add_argument("--allow-rejects", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.root)

    if not os.path.exists(a.inp):
        print("No findings file at %s - writing an empty validated set." % a.inp)
        raw, parse_errors = [], []
    else:
        raw, parse_errors = read_findings(a.inp)

    accepted, rejected, warnings = [], [], []
    for i, f in enumerate(raw, 1):
        tag = "finding #%d (%s)" % (i, (f.get("title") or "untitled")[:60] if isinstance(f, dict) else "?")
        if not isinstance(f, dict):
            rejected.append({"finding": f, "errors": ["not a JSON object"]})
            continue
        errs = []
        for field in ("title", "cwe", "sink", "description", "remediation"):
            if not f.get(field):
                errs.append("missing required field '%s'" % field)
        flow = str(f.get("flow") or ("taint" if f.get("source") else "single")).lower()
        flow = "taint" if flow.startswith("taint") else "single"
        f["flow"] = flow
        sink, err = (check_location(root, f.get("sink"), "sink", warnings) if f.get("sink") else (None, None))
        if err:
            errs.append(err)
        if flow == "taint":
            if not f.get("source"):
                errs.append("taint finding needs a 'source' location")
            else:
                src, err = check_location(root, f.get("source"), "source", warnings)
                if err:
                    errs.append(err)
                else:
                    f["source"] = src
        elif sink and not f.get("source"):
            f["source"] = dict(sink)
        elif f.get("source"):
            src, err = check_location(root, f.get("source"), "source", warnings)
            if err:
                errs.append(err)
        steps = []
        for j, step in enumerate(f.get("path") or [], 1):
            st, err = check_location(root, dict(step) if isinstance(step, dict) else step, "path[%d]" % j, warnings)
            if err:
                warnings.append("%s: dropped invalid path step - %s" % (tag, err))
            else:
                st["note"] = (step.get("note") or "") if isinstance(step, dict) else ""
                steps.append(st)
        f["path"] = steps
        if errs:
            rejected.append({"finding": f, "errors": errs})
            continue

        cls = cwe_map.classify(f.get("cwe"), f.get("category"))
        f["cwe"] = cls["cwe"]
        f.setdefault("cwe_name", cls["cwe_name"] or "")
        if not f.get("owasp_2021"):
            f["owasp_2021"] = cls["owasp_2021"]
        if not f.get("owasp_2025"):
            f["owasp_2025"] = cls["owasp_2025"]
        f["severity"] = norm_choice(f.get("severity"), cwe_map.SEVERITIES, cls["default_severity"])
        f["confidence"] = norm_choice(f.get("confidence"), cwe_map.CONFIDENCES, "Medium")
        refs = f.get("references") or []
        f["references"] = refs if isinstance(refs, list) else [str(refs)]

        # ---- remediation quality gate
        if f["severity"] in ("Critical", "High") and not str(f.get("secure_example") or "").strip():
            rejected.append({"finding": f, "errors": [
                "%s finding needs 'secure_example' (corrected code) - see references/remediation-guidelines.md" % f["severity"]]})
            continue
        if len(str(f.get("remediation", "")).strip()) < 25:
            warnings.append("%s: remediation is very short - make it specific to the code" % tag)
        if not f.get("verification"):
            warnings.append("%s: no 'verification' (how to prove the fix)" % tag)
        auth = str(f.get("auth_required") or "unknown").strip().lower()
        f["auth_required"] = auth if auth in ("none", "user", "admin", "unknown") else "unknown"
        f["fix_priority"] = normalise_priority(f.get("fix_priority")) or compute_priority(
            f["severity"], f["confidence"], f["auth_required"])
        accepted.append(f)

    # De-duplicate
    merged = {}
    for f in accepted:
        key = (f["cwe"], f["source"]["file"], f["source"]["line"], f["sink"]["file"], f["sink"]["line"])
        if key in merged:
            old = merged[key]
            if (SEV_RANK[f["severity"]], CONF_RANK[f["confidence"]]) < (SEV_RANK[old["severity"]], CONF_RANK[old["confidence"]]):
                merged[key] = f
            warnings.append("duplicate merged: %s %s:%d" % (f["cwe"], f["sink"]["file"], f["sink"]["line"]))
        else:
            merged[key] = f
    final = sorted(merged.values(), key=lambda f: (SEV_RANK[f["severity"]], CONF_RANK[f["confidence"]],
                                                  f["sink"]["file"], f["sink"]["line"]))
    for n, f in enumerate(final, 1):
        f["id"] = "VULN-%04d" % n

    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump({"findings": final, "rejected": rejected, "warnings": warnings,
                   "parse_errors": parse_errors}, fh, indent=2)

    sev = {}
    for f in final:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    print("Accepted: %d  Rejected: %d  Warnings: %d" % (len(final), len(rejected), len(warnings)))
    print("By severity:", ", ".join("%s=%d" % (s, sev[s]) for s in cwe_map.SEVERITIES if s in sev) or "none")
    for w in warnings[:50]:
        print("  WARN", w)
    for e in parse_errors:
        print("  ERROR", e)
    for r in rejected:
        t = r["finding"].get("title", "?") if isinstance(r["finding"], dict) else "?"
        print("  REJECTED %s -> %s" % (t, "; ".join(r["errors"])))
    print("Wrote", a.out)
    if (rejected or parse_errors) and not a.allow_rejects:
        print("Fix or remove the rejected findings in the .jsonl and re-run (or pass --allow-rejects).")
        sys.exit(1)


if __name__ == "__main__":
    main()
