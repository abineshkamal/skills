#!/usr/bin/env python3
"""Step 2 - Build a hotspot index (sources, sinks, secrets, weak crypto, misconfig).

The output is a *work list for the agent*, NOT a list of vulnerabilities. Every hit must be
confirmed or discarded by tracing data flow (references/taint-methodology.md).

Usage:
  python3 candidates.py <project_root> [--out security-report/work/candidates.json]
                        [--exclude GLOB ...] [--keep DIRNAME ...] [--max-per-file 200]

Prints a per-category / per-file summary so the agent can plan its review order.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common    # noqa: E402
import patterns  # noqa: E402

SEVERITY_ORDER = ["command-injection", "code-injection", "sql-injection", "insecure-deserialization",
                  "file-inclusion", "template-injection", "xxe", "ssrf", "path-traversal",
                  "nosql-injection", "ldap-injection", "xss", "hardcoded-secret", "broken-authentication",
                  "mass-assignment", "open-redirect", "prototype-pollution", "unrestricted-upload",
                  "ci-script-injection"]

PLACEHOLDER = re.compile(r"(?i)(changeme|change_me|your[_-]?|example|sample|dummy|placeholder|xxxx|\*\*\*\*|<[^>]+>|"
                         r"\$\{|\{\{|%\(|process\.env|os\.environ|getenv|env\(|config\(|settings\.|"
                         r"test|fake|mock|redacted|none|null|undefined|todo|password123?)")


def compile_patterns():
    out = []
    for pid, langs, kind, cat, cwe, rx in patterns.PATTERNS:
        try:
            out.append((pid, set(langs), kind, cat, cwe, re.compile(rx)))
        except re.error as e:
            print("WARNING: pattern %s failed to compile: %s" % (pid, e), file=sys.stderr)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out", default="security-report/work/candidates.json")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--keep", action="append", default=[])
    ap.add_argument("--max-per-file", type=int, default=200)
    a = ap.parse_args()
    for k in a.keep:
        common.EXCLUDED_DIRS.discard(k)
        common.KEEP_GLOBS.add(k)

    compiled = compile_patterns()
    root = os.path.abspath(a.root)
    hits = []
    files_scanned = 0
    per_file = {}

    for abs_p, rel_p, reason, lang in common.walk_files(root, a.exclude):
        if reason:
            continue
        try:
            lines = common.read_lines(abs_p)
        except OSError:
            continue
        if common.is_minified(rel_p, lines):
            continue
        lang = lang or "other"
        files_scanned += 1
        applicable = [p for p in compiled if "*" in p[1] or lang in p[1]]
        n = 0
        for idx, line in enumerate(lines, 1):
            if len(line) > 4000:
                line = line[:4000]
            for pid, _langs, kind, cat, cwe, rx in applicable:
                m = rx.search(line)
                if not m:
                    continue
                likely_placeholder = kind == "secret" and bool(PLACEHOLDER.search(line))
                hits.append({
                    "file": rel_p, "line": idx, "language": lang, "kind": kind, "category": cat,
                    "cwe": cwe, "pattern": pid, "match": m.group(0)[:160], "code": line.strip()[:300],
                    "likely_placeholder": likely_placeholder,
                })
                n += 1
                if n >= a.max_per_file:
                    break
            if n >= a.max_per_file:
                hits.append({"file": rel_p, "line": idx, "language": lang, "kind": "note",
                             "category": "truncated", "cwe": "", "pattern": "max-per-file",
                             "match": "", "code": "hit limit reached - review this file manually",
                             "likely_placeholder": False})
                break
        if n:
            per_file[rel_p] = n

    by_kind, by_cat = {}, {}
    for h in hits:
        by_kind[h["kind"]] = by_kind.get(h["kind"], 0) + 1
        if h["kind"] != "source":
            by_cat[h["category"]] = by_cat.get(h["category"], 0) + 1

    def cat_rank(c):
        return SEVERITY_ORDER.index(c) if c in SEVERITY_ORDER else len(SEVERITY_ORDER)

    # Files ranked by: number of sinks that share the file with a source (likely taint), then total.
    file_rank = {}
    for h in hits:
        r = file_rank.setdefault(h["file"], {"sources": 0, "sinks": 0, "other": 0})
        key = "sources" if h["kind"] == "source" else "sinks" if h["kind"] == "sink" else "other"
        r[key] += 1
    ranked_files = sorted(file_rank.items(),
                          key=lambda kv: (-(kv[1]["sources"] > 0 and kv[1]["sinks"] > 0),
                                          -kv[1]["sinks"], -kv[1]["other"]))

    out = {
        "project_root": root,
        "files_scanned": files_scanned,
        "patterns_loaded": len(compiled),
        "counts_by_kind": by_kind,
        "counts_by_category": dict(sorted(by_cat.items(), key=lambda kv: (cat_rank(kv[0]), -kv[1]))),
        "review_order": [{"file": f, **c} for f, c in ranked_files],
        "hits": hits,
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print("Files scanned: %d   patterns: %d   hits: %d" % (files_scanned, len(compiled), len(hits)))
    print("By kind:", ", ".join("%s=%d" % kv for kv in sorted(by_kind.items())))
    print("Sink/secret/crypto/config categories (highest risk first):")
    for c, n in out["counts_by_category"].items():
        print("  %-28s %d" % (c, n))
    print("Top files to review (sources+sinks in same file first):")
    for f, c in ranked_files[:25]:
        print("  %-60s src=%d sink=%d other=%d" % (f[-60:], c["sources"], c["sinks"], c["other"]))
    print("Wrote", a.out)


if __name__ == "__main__":
    main()
