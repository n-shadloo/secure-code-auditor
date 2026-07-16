#!/usr/bin/env python3
"""
dangerous_patterns.py - read-only risky-pattern indicator scan.

Walks a directory and greps Python files for patterns that often indicate a
security issue (string-built SQL, shell=True, insecure deserialization, wildcard
serializers, open CORS, etc.). It is a TRIAGE aid: every hit is a lead to verify,
not a confirmed finding.

It reads files only. It makes NO network calls, imports nothing from the target
project, and never modifies anything.

Usage:
    python scripts/dangerous_patterns.py path/to/project
    python scripts/dangerous_patterns.py .            # current directory

Exit code is always 0.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
             "__pycache__", ".mypy_cache", ".tox", "build", "dist", ".eggs"}

# (compiled regex, category, severity hint, note)
PATTERNS = [
    (re.compile(r"\.raw\s*\("), "sql", "HIGH", "raw() - ensure parameters, not string formatting"),
    (re.compile(r"\.extra\s*\("), "sql", "MEDIUM", "extra() is legacy and injection-prone"),
    (re.compile(r"RawSQL\s*\("), "sql", "HIGH", "RawSQL - verify it is parameterized"),
    (re.compile(r"\.execute\s*\(\s*f[\"']"), "sql", "HIGH", "cursor.execute with an f-string"),
    (re.compile(r"\.execute\s*\([^)]*%[^)]*\)"), "sql", "HIGH", "cursor.execute with % formatting"),
    (re.compile(r"\.execute\s*\([^)]*\.format\s*\("), "sql", "HIGH", "cursor.execute with .format()"),
    (re.compile(r"order_by\s*\(\s*request\."), "sql", "MEDIUM", "order_by on request data - allowlist the column"),
    (re.compile(r"filter\s*\(\s*\*\*\s*request\."), "sql", "HIGH", "filter(**request...) dict expansion from client"),
    (re.compile(r"annotate\s*\(\s*\*\*"), "sql", "MEDIUM", "annotate(**...) - verify aliases are not client-controlled"),
    (re.compile(r"mark_safe\s*\("), "xss", "MEDIUM", "mark_safe - confirm the content is not user-controlled"),
    (re.compile(r"\|\s*safe\b"), "xss", "MEDIUM", "|safe filter disables autoescaping"),
    (re.compile(r"format_html\s*\(\s*f[\"']"), "xss", "MEDIUM", "format_html with an f-string defeats its escaping"),
    (re.compile(r"autoescape\s*=\s*False"), "xss", "HIGH", "autoescape disabled (Jinja2?)"),
    (re.compile(r"shell\s*=\s*True"), "command", "HIGH", "subprocess shell=True with dynamic input is command injection"),
    (re.compile(r"\bos\.system\s*\("), "command", "HIGH", "os.system - avoid; use subprocess arg lists"),
    (re.compile(r"\beval\s*\("), "command", "HIGH", "eval on any dynamic input is dangerous"),
    (re.compile(r"\bexec\s*\("), "command", "HIGH", "exec on any dynamic input is dangerous"),
    (re.compile(r"pickle\.loads?\s*\("), "deser", "HIGH", "pickle on untrusted data is RCE"),
    (re.compile(r"yaml\.load\s*\((?!.*(SafeLoader|safe_load))"), "deser", "HIGH", "yaml.load without SafeLoader"),
    (re.compile(r"CELERY_TASK_SERIALIZER\s*=\s*[\"']pickle[\"']"), "deser", "HIGH", "Celery pickle serializer"),
    (re.compile(r"fields\s*=\s*[\"']__all__[\"']"), "drf", "MEDIUM", "serializer fields='__all__' over-exposes model fields"),
    (re.compile(r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True"), "config", "MEDIUM", "open CORS - use an allowlist"),
    (re.compile(r"DEBUG\s*=\s*True"), "config", "HIGH", "DEBUG=True (verify this is not production)"),
    (re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']"), "config", "MEDIUM", "ALLOWED_HOSTS=['*']"),
    (re.compile(r"@csrf_exempt"), "csrf", "MEDIUM", "csrf_exempt on a state-changing view is a red flag"),
    (re.compile(r"verify\s*=\s*False"), "tls", "HIGH", "TLS verification disabled (requests verify=False)"),
    (re.compile(r"(SECRET_KEY|SIGNING_KEY|API_KEY|PASSWORD|TOKEN)\s*=\s*[\"'][^\"']{8,}[\"']"),
     "secret", "HIGH", "possible hardcoded secret (heuristic - confirm it is not a placeholder)"),
]

_DYNAMIC_SECRET_OK = re.compile(r"=\s*(os\.environ|env\(|config\(|get_secret|getenv)")


def iter_py_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def scan_file(path: str):
    hits = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return hits
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for rx, category, sev, note in PATTERNS:
            if rx.search(line):
                if category == "secret" and _DYNAMIC_SECRET_OK.search(line):
                    continue  # loaded from env - fine
                hits.append((lineno, sev, category, note, stripped[:160]))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only risky-pattern indicator scan.")
    parser.add_argument("path", nargs="?", default=".", help="Directory (or file) to scan")
    args = parser.parse_args()

    targets = []
    if os.path.isfile(args.path):
        targets = [args.path]
    elif os.path.isdir(args.path):
        targets = list(iter_py_files(args.path))
    else:
        print(f"Not a file or directory: {args.path}", file=sys.stderr)
        return 0

    total = 0
    by_sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for path in sorted(targets):
        hits = scan_file(path)
        if not hits:
            continue
        print(f"\n{path}")
        for lineno, sev, category, note, snippet in hits:
            total += 1
            by_sev[sev] = by_sev.get(sev, 0) + 1
            print(f"  {path}:{lineno}: [{sev}] ({category}) {note}")
            print(f"      | {snippet}")

    print(f"\n# {total} indicator(s): "
          f"{by_sev.get('HIGH', 0)} high, {by_sev.get('MEDIUM', 0)} medium, {by_sev.get('LOW', 0)} low.")
    print("# Indicators are leads, not confirmed findings. Verify each by reading the code and tracing the data flow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
