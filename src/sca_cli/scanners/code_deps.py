"""
Code-level dependency analyzer.

Scans source files for require()/import statements to extract dependencies
that may not be declared in manifest files (package.json / pyproject.toml).

This is essential for skills and plugins whose manifest files are incomplete
or don't declare runtime dependencies.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import IO

from sca_cli.normalize.findings import Component

# ---------------------------------------------------------------------------
# Node.js / JavaScript built-in modules — never report as external deps
# ---------------------------------------------------------------------------
NODEJS_BUILTINS: set[str] = {
    "assert", "async_hooks", "buffer", "child_process", "cluster",
    "console", "constants", "crypto", "dgram", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module",
    "net", "os", "path", "perf_hooks", "process", "punycode",
    "querystring", "readline", "repl", "stream", "string_decoder",
    "timers", "tls", "trace_events", "tty", "url", "util", "v8",
    "vm", "wasi", "worker_threads", "zlib",
}

# ---------------------------------------------------------------------------
# Python stdlib modules — never report as external deps
# ---------------------------------------------------------------------------
PYTHON_STDLIB: set[str] = {
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "audioop", "base64", "bdb", "binascii",
    "binhex", "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb",
    "chunk", "cmath", "cmd", "code", "codecs", "codeop", "collections",
    "colorsys", "compileall", "concurrent", "configparser", "contextlib",
    "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
    "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
    "difflib", "dis", "distutils", "doctest", "email", "encodings",
    "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
    "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
    "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
    "imp", "importlib", "inspect", "io", "ipaddress", "itertools",
    "json", "keyword", "lib2to3", "linecache", "locale", "logging",
    "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
    "mmap", "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
    "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib",
    "pdb", "pickle", "pickletools", "pipe", "pkgutil", "platform",
    "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
    "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue",
    "quopri", "random", "re", "readline", "reprlib", "resource",
    "rlcompleter", "runpy", "sched", "secrets", "select", "selectors",
    "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib",
    "sndhdr", "socket", "socketserver", "sqlite3", "ssl", "stat",
    "statistics", "string", "stringprep", "struct", "subprocess",
    "sunau", "symtable", "sys", "sysconfig", "syslog", "tabnanny",
    "tarfile", "telnetlib", "tempfile", "termios", "test", "textwrap",
    "threading", "time", "timeit", "tkinter", "token", "tokenize",
    "tomllib", "trace", "traceback", "tracemalloc", "tty", "turtle",
    "turtledemo", "types", "typing", "unicodedata", "unittest",
    "urllib", "urllib.error", "urllib.parse", "urllib.request",
    "urllib.response", "urllib.robotparser", "uu", "uuid", "venv",
    "warnings", "wave", "weakref", "webbrowser", "winreg", "winsound",
    "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile",
    "zipimport", "zlib", "zoneinfo",
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# CommonJS: require('foo') or require("foo"); also require("foo").bar
_RE_COMMONJS = re.compile(
    r"""require\s*\(\s*['"]([a-zA-Z0-9_@][a-zA-Z0-9_./-]*)['"]\s*\)""",
)

# ES Module: import foo from 'bar'; import 'bar'
# Captures the module specifier, ignoring 'as' and destructured imports
_RE_ESM = re.compile(
    r"""import\s+(?:(?:[\w*{}\s,]+)\s+from\s+)?['"]([a-zA-Z0-9_@][a-zA-Z0-9_./-]*)['"]""",
)

# Python: import foo; import foo.bar; from foo import bar
_RE_PYTHON_IMPORT = re.compile(
    r"""^(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_.]*)""",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Scoped package detection
# ---------------------------------------------------------------------------
_RE_SCOPED = re.compile(r"^@[a-zA-Z0-9_-]+/")


def scan_code_dependencies(root: Path) -> list[Component]:
    """
    Scan all source files under *root* for require/import statements and
    return a list of discovered dependencies not declared in manifest files.
    """
    seen: set[tuple[str, str]] = set()
    components: list[Component] = []

    # Pattern: (glob, ecosystem, handler_fn)
    scanners = [
        ("**/*.js", "npm", _collect_js_deps),
        ("**/*.jsx", "npm", _collect_js_deps),
        ("**/*.mjs", "npm", _collect_js_deps),
        ("**/*.cjs", "npm", _collect_js_deps),
        ("**/*.ts", "npm", _collect_js_deps),
        ("**/*.tsx", "npm", _collect_js_deps),
        ("**/*.py", "pypi", _collect_py_deps),
    ]

    for glob_pattern, ecosystem, handler in scanners:
        for filepath in sorted(root.rglob(glob_pattern)):
            # Skip node_modules, .git, __pycache__, etc.
            if _is_ignored(filepath):
                continue
            try:
                text = filepath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for name in handler(text):
                key = (ecosystem, name.lower())
                if key in seen:
                    continue
                seen.add(key)
                relative = _relative(root, filepath)
                components.append(
                    Component(
                        ecosystem=ecosystem,
                        name=name,
                        version=None,  # Code analysis can't determine version
                        purl=f"pkg:{ecosystem}/{name}",
                        type="library",
                        evidence=f"code:{relative}",
                        source="code-analyzer",
                    )
                )

    return sorted(components, key=lambda c: (c.ecosystem, c.name))


def _collect_js_deps(text: str) -> list[str]:
    """Extract npm dependency names from JS/TS source code."""
    names: list[str] = []
    seen_local: set[str] = set()

    for match in _RE_COMMONJS.finditer(text):
        name = _normalize_js_module(match.group(1))
        if name and name not in seen_local:
            seen_local.add(name)
            names.append(name)

    for match in _RE_ESM.finditer(text):
        name = _normalize_js_module(match.group(1))
        if name and name not in seen_local:
            seen_local.add(name)
            names.append(name)

    return names


def _collect_py_deps(text: str) -> list[str]:
    """Extract PyPI dependency names from Python source code."""
    names: list[str] = []
    seen_local: set[str] = set()

    for match in _RE_PYTHON_IMPORT.finditer(text):
        full = match.group(1)
        # Take the top-level package name (e.g. 'os.path' -> 'os')
        top_level = full.split(".")[0]
        if top_level and top_level not in seen_local and top_level not in PYTHON_STDLIB:
            seen_local.add(top_level)
            names.append(top_level)

    return names


def _normalize_js_module(name: str) -> str | None:
    """Filter out local paths, built-ins, and partial references."""
    if not name:
        return None
    # Local file reference: starts with ./
    if name.startswith("."):
        return None
    # Relative reference: starts with /
    if name.startswith("/"):
        return None
    # Node.js built-in
    if name in NODEJS_BUILTINS:
        return None
    # Scoped package — keep as-is
    if _RE_SCOPED.match(name):
        return name
    # Non-scoped: only the first segment before /
    first = name.split("/")[0]
    if not first or not first[0].isalpha() and first[0] != "@":
        return None
    return first


def _is_ignored(path: Path) -> bool:
    """Check if a path should be skipped during scanning."""
    parts = path.parts
    for part in parts:
        if part in {
            "node_modules",
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".venv",
            "venv",
            "env",
            ".tox",
            "dist",
            "build",
            "egg-info",
            ".eggs",
            "site-packages",
        }:
            return True
    return False


def _relative(root: Path, path: Path) -> str:
    """Return a portable relative path string."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


# ---------------------------------------------------------------------------
# External system tool dependency detection
# ---------------------------------------------------------------------------

# Known external system tools referenced in code/scripts/docs.
# Maps tool name → (category, description)
EXTERNAL_SYSTEM_TOOLS: dict[str, tuple[str, str]] = {
    # Database
    "pg_dump": ("database", "PostgreSQL backup dump tool"),
    "pg_restore": ("database", "PostgreSQL restore tool"),
    "psql": ("database", "PostgreSQL interactive terminal"),
    "pg_isready": ("database", "PostgreSQL connection health check"),
    "mysql": ("database", "MySQL CLI client"),
    "mysqldump": ("database", "MySQL backup dump tool"),
    "sqlite3": ("database", "SQLite CLI tool"),
    "redis-cli": ("database", "Redis CLI client"),
    "mongod": ("database", "MongoDB daemon"),
    "mongo": ("database", "MongoDB CLI client"),
    # Compression
    "gzip": ("compression", "GNU zip compression tool"),
    "gunzip": ("compression", "GNU zip decompression tool"),
    "tar": ("compression", "Tape archive tool"),
    "zip": ("compression", "Zip compression tool"),
    "unzip": ("compression", "Zip decompression tool"),
    "bzip2": ("compression", "Bzip2 compression tool"),
    "xz": ("compression", "XZ compression tool"),
    # Container / Orchestration
    "docker": ("container", "Docker container engine"),
    "docker-compose": ("container", "Docker Compose orchestrator"),
    "kubectl": ("container", "Kubernetes CLI"),
    "helm": ("container", "Kubernetes Helm package manager"),
    # Runtimes
    "node": ("runtime", "Node.js JavaScript runtime"),
    "npm": ("runtime", "Node.js package manager"),
    "npx": ("runtime", "Node.js package runner"),
    "python3": ("runtime", "Python 3 interpreter"),
    "python": ("runtime", "Python interpreter"),
    "pip": ("runtime", "Python package installer"),
    "java": ("runtime", "Java runtime"),
    "go": ("runtime", "Go language toolchain"),
    "rustc": ("runtime", "Rust compiler"),
    # General / DevOps
    "git": ("devops", "Git version control"),
    "curl": ("devops", "HTTP request CLI tool"),
    "wget": ("devops", "HTTP download tool"),
    "ssh": ("devops", "Secure Shell client"),
    "scp": ("devops", "Secure copy tool"),
    "rsync": ("devops", "Remote sync tool"),
    "make": ("devops", "Make build system"),
    "gcc": ("devops", "GNU C compiler"),
    "openssl": ("devops", "OpenSSL cryptography toolkit"),
    "envsubst": ("devops", "Environment variable substitution"),
    # Security
    "openssl": ("security", "OpenSSL CLI toolkit"),
    "gpg": ("security", "GnuPG encryption tool"),
}

# Regex patterns to find external tool references in source text
_RE_EXTERNAL_TOOL = re.compile(
    r"(?:^|\s|[`\"'(=])(%s)(?:\s|[`\"').,;:]|$|\|)"
    % "|".join(re.escape(name) for name in EXTERNAL_SYSTEM_TOOLS),
    re.MULTILINE,
)

# Shell exec patterns: exec(), spawn(), execSync(), run(), system()
_RE_SHELL_EXEC = re.compile(
    r"""(?:exec|spawn|execSync|execFile|system|popen|subprocess\.run)\s*[(\[]"""
    r"""\s*['\"]([^'\"]+)['\"]""",
    re.MULTILINE,
)


def scan_external_system_deps(root: Path) -> list[Component]:
    """Scan source files for references to external system tool dependencies.

    Detects well-known CLI tools (pg_dump, gzip, docker, etc.) appearing in
    comments, documentation, string literals, and shell exec calls.
    Components are returned with type="application" and an
    sca-cli:dep-type="external-system" property so consumers can distinguish
    them from library dependencies.
    """
    seen: dict[str, str] = {}  # tool_name → first_evidence_file
    found_in_exec: set[str] = set()

    for filepath in sorted(root.rglob("*")):
        if not filepath.is_file() or _is_ignored(filepath):
            continue
        ext = filepath.suffix.lower()
        if ext not in {".js", ".ts", ".py", ".sh", ".md", ".txt", ".yaml", ".yml", ".json", ".sql"}:
            continue
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Pattern 1: direct mention of known tool names
        for match in _RE_EXTERNAL_TOOL.finditer(text):
            name = match.group(1)
            if name in EXTERNAL_SYSTEM_TOOLS and name not in seen:
                seen[name] = _relative(root, filepath)

        # Pattern 2: shell exec/spawn calls
        for exec_match in _RE_SHELL_EXEC.finditer(text):
            cmd = exec_match.group(1)
            for name in EXTERNAL_SYSTEM_TOOLS:
                if name in cmd and name not in found_in_exec:
                    found_in_exec.add(name)
                    if name not in seen:
                        seen[name] = _relative(root, filepath)

    components: list[Component] = []
    for name, evidence_file in sorted(seen.items()):
        category, description = EXTERNAL_SYSTEM_TOOLS[name]
        components.append(
            Component(
                ecosystem="external",
                name=name,
                version=None,
                purl=f"pkg:generic/{name}",
                type="application",
                evidence=evidence_file,
                source="external-system",
                licenses=[],
            )
        )

    return components
