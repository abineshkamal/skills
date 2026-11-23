#!/usr/bin/env python3
"""Step 1 - Inventory the project: languages, frameworks, manifests, entry points, skipped files.

Usage:
  python3 inventory.py <project_root> [--out security-report/work/inventory.json]
                       [--exclude GLOB ...] [--keep DIRNAME ...]

--exclude  extra glob(s) to skip (matched against relative path and basename)
--keep     un-exclude a default-excluded directory name (e.g. --keep bin --keep build)
"""
import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

MANIFESTS = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "pipfile",
    "pipfile.lock", "poetry.lock", "uv.lock", "setup.py", "setup.cfg", "composer.json",
    "composer.lock", "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
    "gradle.lockfile", "gemfile", "gemfile.lock", "cargo.toml", "cargo.lock", "packages.config",
    "packages.lock.json", "pubspec.yaml", "pubspec.lock", "mix.exs", "mix.lock", "podfile.lock",
    "conanfile.txt", "vcpkg.json",
}

# (framework label, regex searched inside manifest text)
FRAMEWORK_HINTS = [
    ("Express", r'"express"\s*:'), ("Next.js", r'"next"\s*:'), ("React", r'"react"\s*:'),
    ("Vue", r'"vue"\s*:'), ("Angular", r'"@angular/core"\s*:'), ("NestJS", r'"@nestjs/core"\s*:'),
    ("Koa", r'"koa"\s*:'), ("Fastify", r'"fastify"\s*:'), ("Hapi", r'"@hapi/hapi"\s*:'),
    ("Svelte/SvelteKit", r'"(svelte|@sveltejs/kit)"\s*:'), ("Nuxt", r'"nuxt"\s*:'),
    ("Electron", r'"electron"\s*:'), ("Prisma", r'"(prisma|@prisma/client)"\s*:'),
    ("Sequelize", r'"sequelize"\s*:'), ("Mongoose", r'"mongoose"\s*:'), ("TypeORM", r'"typeorm"\s*:'),
    ("Django", r'(?im)^\s*django\b'), ("Flask", r'(?im)^\s*flask\b'), ("FastAPI", r'(?im)^\s*fastapi\b'),
    ("SQLAlchemy", r'(?im)^\s*sqlalchemy\b'), ("Django REST Framework", r'(?im)^\s*djangorestframework\b'),
    ("Laravel", r'"laravel/framework"'), ("Symfony", r'"symfony/(framework-bundle|http-kernel)"'),
    ("CodeIgniter", r'"codeigniter4?/framework"'), ("WordPress", r'(?i)wordpress'),
    ("Spring Boot", r'spring-boot'), ("Spring Security", r'spring-security|spring-boot-starter-security'),
    ("Struts", r'struts2?-core'), ("Hibernate", r'hibernate-core'), ("Jakarta/Servlet", r'(servlet-api|jakarta\.servlet)'),
    ("Gin", r'github\.com/gin-gonic/gin'), ("Echo", r'github\.com/labstack/echo'),
    ("Fiber", r'github\.com/gofiber/fiber'), ("Gorilla Mux", r'github\.com/gorilla/mux'), ("GORM", r'gorm\.io/gorm'),
    ("Ruby on Rails", r'(?m)^\s*(gem\s+["\']rails["\']|rails\s+\()'), ("Sinatra", r'sinatra'),
    ("ASP.NET Core", r'Microsoft\.AspNetCore'), ("Entity Framework", r'Microsoft\.EntityFrameworkCore'),
    ("Actix", r'actix-web'), ("Axum", r'(?m)^\s*axum\s*='), ("Rocket", r'(?m)^\s*rocket\s*='),
    ("Flutter", r'(?m)^\s*flutter:'), ("Phoenix", r':phoenix\b'),
]

ENTRY_HINT = re.compile(
    r"(?i)(^|/)(app|server|main|index|routes?|urls|views?|controllers?|api|handlers?|wsgi|asgi|"
    r"program|startup|web|router|endpoints?|resolvers?|middleware)(\.[a-z]+|/)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out", default="security-report/work/inventory.json")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--keep", action="append", default=[])
    a = ap.parse_args()

    for k in a.keep:
        common.EXCLUDED_DIRS.discard(k)
        common.KEEP_GLOBS.add(k)
    root = os.path.abspath(a.root)
    if not os.path.isdir(root):
        sys.exit("Not a directory: " + root)

    files, skipped = [], []
    by_lang, lines_by_lang = {}, {}
    manifests, entry_candidates = [], []
    framework_text = []

    for abs_p, rel_p, reason, lang in common.walk_files(root, a.exclude):
        if reason:
            skipped.append({"path": rel_p, "reason": reason})
            continue
        try:
            lines = common.read_lines(abs_p)
        except OSError:
            skipped.append({"path": rel_p, "reason": "unreadable"})
            continue
        if common.is_minified(rel_p, lines):
            skipped.append({"path": rel_p, "reason": "minified"})
            continue
        lang = lang or "other"
        files.append({"path": rel_p, "language": lang, "lines": len(lines)})
        by_lang[lang] = by_lang.get(lang, 0) + 1
        lines_by_lang[lang] = lines_by_lang.get(lang, 0) + len(lines)
        base = os.path.basename(rel_p).lower()
        if base in MANIFESTS or base.endswith((".csproj", ".fsproj", ".vbproj")) or \
                re.match(r"requirements.*\.txt$", base):
            manifests.append(rel_p)
            if len(framework_text) < 200:
                framework_text.append("\n".join(lines[:3000]))
        if lang not in ("config", "template", "other", "sql") and ENTRY_HINT.search(rel_p):
            entry_candidates.append(rel_p)

    blob = "\n".join(framework_text)
    frameworks = sorted({name for name, rx in FRAMEWORK_HINTS if re.search(rx, blob)})

    reason_counts = {}
    for s in skipped:
        reason_counts[s["reason"]] = reason_counts.get(s["reason"], 0) + 1

    inv = {
        "project_root": root,
        "project_name": os.path.basename(root.rstrip("\\/")) or root,
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files_analyzed": len(files),
        "total_lines": sum(f["lines"] for f in files),
        "languages": {k: {"files": by_lang[k], "lines": lines_by_lang[k]}
                      for k in sorted(by_lang, key=lambda x: -by_lang[x])},
        "frameworks_detected": frameworks,
        "manifests": manifests,
        "entry_point_candidates": entry_candidates[:300],
        "skipped_summary": reason_counts,
        "skipped": skipped,
        "files": files,
        "extra_excludes": a.exclude,
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=2)

    print("Project:", root)
    print("Files analysed: %d  (lines: %d)" % (inv["total_files_analyzed"], inv["total_lines"]))
    print("Languages:", ", ".join("%s=%d" % (k, v["files"]) for k, v in inv["languages"].items()) or "none")
    print("Frameworks:", ", ".join(frameworks) or "none detected")
    print("Manifests (%d):" % len(manifests), ", ".join(manifests[:25]) + (" ..." if len(manifests) > 25 else ""))
    print("Entry-point candidates: %d" % len(entry_candidates))
    print("Skipped:", ", ".join("%s=%d" % kv for kv in reason_counts.items()) or "none")
    print("Wrote", a.out)


if __name__ == "__main__":
    main()
