"""Shared helpers: file walking, exclusions, language detection.

Standard library only (Python 3.8+). No third-party packages required.
"""
import fnmatch
import os

# Directories never scanned (dependencies, build output, VCS, IDE, Replit runtime, this skill).
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages", "vendor",
    "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit", ".output", ".turbo",
    "__pycache__", ".venv", "venv", "env", ".env.d", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "site-packages", "coverage", ".nyc_output", "htmlcov", ".idea", ".vscode",
    ".gradle", ".m2", "bin", "obj", "Pods", "DerivedData", ".dart_tool", ".pub-cache",
    ".terraform", ".serverless", ".cache", ".pythonlibs", ".upm", ".local", ".config", ".npm",
    ".yarn", ".pnpm-store", ".agents", "security-report",
}

# Generated / cached code (relative-path globs; also matched one level deep for monorepos).
DEFAULT_EXCLUDE_GLOBS = [
    "storage/framework", "bootstrap/cache", "public/build", "public/vendor", "public/hot",
    "var/cache", "tmp/cache", "*/storage/framework", "*/bootstrap/cache", "*/public/build",
    "*_pb2.py", "*_pb2_grpc.py", "*.pb.go", "*.g.dart", "*.freezed.dart", "*.Designer.cs",
    "*.designer.cs", "*.generated.*", "*.min.css", "*.map",
]

KEEP_GLOBS = set()                 # filled by --keep to re-include a default-excluded glob

MAX_FILE_BYTES = 2 * 1024 * 1024   # skip files larger than 2 MB
MINIFIED_LINE_LEN = 1000            # a line longer than this in a .js/.css file => minified

LANG_BY_EXT = {
    # JavaScript / TypeScript
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mts": "javascript", ".cts": "javascript",
    ".vue": "javascript", ".svelte": "javascript", ".astro": "javascript",
    # Python
    ".py": "python", ".pyw": "python", ".pyi": "python",
    # JVM
    ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java", ".groovy": "java",
    ".jsp": "java", ".jspx": "java",
    # PHP
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".inc": "php",
    # Go
    ".go": "go",
    # .NET
    ".cs": "csharp", ".cshtml": "csharp", ".razor": "csharp", ".vb": "csharp", ".aspx": "csharp",
    ".ascx": "csharp", ".fs": "csharp",
    # Ruby
    ".rb": "ruby", ".erb": "ruby", ".rake": "ruby", ".haml": "ruby", ".slim": "ruby",
    # C / C++ / Objective-C
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c", ".hh": "c",
    ".m": "c", ".mm": "c",
    # Others handled by generic rules + methodology
    ".rs": "rust", ".swift": "swift", ".dart": "dart", ".lua": "lua", ".pl": "perl",
    ".pm": "perl", ".r": "r", ".ex": "elixir", ".exs": "elixir", ".erl": "erlang",
    ".clj": "clojure", ".hs": "haskell", ".sol": "solidity", ".zig": "zig", ".nim": "nim",
    ".cr": "crystal", ".jl": "julia", ".coffee": "javascript",
    # Templates
    ".html": "template", ".htm": "template", ".ejs": "template", ".hbs": "template",
    ".handlebars": "template", ".mustache": "template", ".njk": "template", ".jinja": "template",
    ".jinja2": "template", ".j2": "template", ".twig": "template", ".liquid": "template",
    ".pug": "template", ".jade": "template", ".tpl": "template", ".vm": "template",
    ".ftl": "template",
    # Shell / scripting
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "shell", ".psm1": "shell",
    ".bat": "shell", ".cmd": "shell",
    # SQL
    ".sql": "sql",
    # Config / IaC
    ".yml": "config", ".yaml": "config", ".json": "config", ".xml": "config", ".ini": "config",
    ".cfg": "config", ".conf": "config", ".properties": "config", ".toml": "config",
    ".env": "config", ".tf": "config", ".tfvars": "config", ".hcl": "config", ".bicep": "config",
    ".config": "config", ".plist": "config", ".gradle": "config", ".csproj": "config",
    ".htaccess": "config", ".nginx": "config",
}

# Filenames (no/odd extension) mapped to a language.
LANG_BY_NAME = {
    "dockerfile": "config", "containerfile": "config", "makefile": "shell", "jenkinsfile": "java",
    "vagrantfile": "ruby", "gemfile": "ruby", "rakefile": "ruby", "procfile": "config",
    ".htaccess": "config", "web.config": "config", "nginx.conf": "config",
    "docker-compose.yml": "config", "docker-compose.yaml": "config", ".replit": "config",
    "replit.nix": "config", "go.mod": "config", "go.sum": "config", "requirements.txt": "config",
    "requirements-dev.txt": "config", "constraints.txt": "config", "pipfile": "config",
    "gemfile.lock": "config", "yarn.lock": "config", "cargo.lock": "config", "poetry.lock": "config",
    "uv.lock": "config", "gradle.lockfile": "config", "mix.lock": "config",
}

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".tiff", ".psd",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".gz", ".tgz", ".bz2",
    ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".ear", ".class", ".dll", ".exe", ".so",
    ".dylib", ".o", ".a", ".lib", ".pyc", ".pyo", ".whl", ".egg", ".woff", ".woff2", ".ttf",
    ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac", ".ogg", ".webm", ".db",
    ".sqlite", ".sqlite3", ".bin", ".dat", ".iso", ".dmg", ".apk", ".ipa", ".map", ".lock.bin",
}


def detect_language(path):
    name = os.path.basename(path).lower()
    if name in LANG_BY_NAME:
        return LANG_BY_NAME[name]
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "config"
    if name.startswith(".env"):          # .env, .env.local, .env.production ...
        return "config"
    if name.endswith(".blade.php"):
        return "php"
    _, ext = os.path.splitext(name)
    return LANG_BY_EXT.get(ext)


def is_binary(path):
    _, ext = os.path.splitext(path.lower())
    if ext in BINARY_EXT:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
        return b"\x00" in chunk
    except OSError:
        return True


def read_lines(path):
    """Return file lines (no newline chars). Decodes UTF-8, falls back to latin-1."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    if text.startswith("﻿"):
        text = text[1:]
    return text.splitlines()


def is_minified(path, lines):
    low = path.lower()
    if ".min." in low or low.endswith(("-min.js", ".bundle.js", ".chunk.js")):
        return True
    if low.endswith((".js", ".css", ".mjs", ".cjs")):
        return any(len(l) > MINIFIED_LINE_LEN for l in lines[:50])
    return False


def walk_files(root, extra_excludes=None):
    """Yield (abs_path, rel_path, skip_reason_or_None, language_or_None).

    rel_path always uses forward slashes, relative to root.
    """
    extra_excludes = list(extra_excludes or []) + [g for g in DEFAULT_EXCLUDE_GLOBS if g not in KEEP_GLOBS]
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        keep = []
        for d in dirnames:
            rel_d = d if rel_dir == "." else rel_dir + "/" + d
            if d in EXCLUDED_DIRS or any(fnmatch.fnmatch(rel_d, g) or fnmatch.fnmatch(d, g)
                                         for g in extra_excludes):
                yield os.path.join(dirpath, d), rel_d + "/", "excluded-dir", None
                continue
            keep.append(d)
        dirnames[:] = sorted(keep)
        for f in sorted(filenames):
            abs_p = os.path.join(dirpath, f)
            rel_p = f if rel_dir == "." else rel_dir + "/" + f
            if any(fnmatch.fnmatch(rel_p, g) or fnmatch.fnmatch(f, g) for g in extra_excludes):
                yield abs_p, rel_p, "excluded-pattern", None
                continue
            if os.path.islink(abs_p):
                yield abs_p, rel_p, "symlink", None
                continue
            try:
                size = os.path.getsize(abs_p)
            except OSError:
                yield abs_p, rel_p, "unreadable", None
                continue
            if size > MAX_FILE_BYTES:
                yield abs_p, rel_p, "too-large", None
                continue
            if is_binary(abs_p):
                yield abs_p, rel_p, "binary", None
                continue
            yield abs_p, rel_p, None, detect_language(abs_p)
