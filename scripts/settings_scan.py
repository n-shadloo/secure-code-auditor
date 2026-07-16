#!/usr/bin/env python3
"""
settings_scan.py - read-only Django settings posture check.

Parses a Django settings file with the ast module and reports on security-
relevant settings. It NEVER imports or executes the target project, makes NO
network calls, and only reads the file you point it at.

Because it reads literal assignments statically, values computed at runtime
(e.g. env("DEBUG"), os.environ[...]) are reported as "dynamic - verify manually"
rather than guessed. That avoids false positives; confirm dynamic values by hand.

Usage:
    python scripts/settings_scan.py path/to/settings.py

Exit code is always 0; this is a triage aid, not a gate.
"""
from __future__ import annotations

import argparse
import ast
import sys

# setting -> (insecure_literal_value, human note). We only judge literals.
BOOL_TRUE_BAD = "insecure if this is the production value"

CHECKS = {
    "DEBUG": ("must be False in production", True),
    "SECURE_SSL_REDIRECT": ("should be True (unless the proxy redirects)", False),
    "SECURE_HSTS_SECONDS": ("should be a positive int in production", 0),
    "SECURE_CONTENT_TYPE_NOSNIFF": ("should be True", False),
    "SESSION_COOKIE_SECURE": ("should be True", False),
    "SESSION_COOKIE_HTTPONLY": ("should be True", False),
    "CSRF_COOKIE_SECURE": ("should be True", False),
    "SECURE_HSTS_INCLUDE_SUBDOMAINS": ("should be True with HSTS", False),
}


def literal(node: ast.AST):
    """Return the literal value of a node, or a sentinel for non-literals."""
    try:
        return ast.literal_eval(node)
    except Exception:
        return _DYNAMIC


class _Dynamic:
    def __repr__(self):
        return "<dynamic>"


_DYNAMIC = _Dynamic()


def collect_assignments(tree: ast.Module) -> dict[str, ast.AST]:
    found: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                found[node.target.id] = node.value
    return found


def report(line: str, tag: str) -> None:
    print(f"[{tag}] {line}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Django settings posture check.")
    parser.add_argument("path", help="Path to a Django settings .py file")
    args = parser.parse_args()

    try:
        with open(args.path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        print(f"Cannot read {args.path}: {exc}", file=sys.stderr)
        return 0

    try:
        tree = ast.parse(source, filename=args.path)
    except SyntaxError as exc:
        print(f"Could not parse {args.path}: {exc}", file=sys.stderr)
        return 0

    assigns = collect_assignments(tree)
    print(f"# settings_scan: {args.path}\n")

    # DEBUG / ALLOWED_HOSTS
    if "DEBUG" in assigns:
        val = literal(assigns["DEBUG"])
        if val is True:
            report("DEBUG = True  -> must be False in production", "HIGH")
        elif val is _DYNAMIC:
            report("DEBUG is dynamic - verify it is False in production", "INFO")
        else:
            report(f"DEBUG = {val!r}", "OK")
    else:
        report("DEBUG not set in this file (may be in a base/module import)", "INFO")

    if "ALLOWED_HOSTS" in assigns:
        val = literal(assigns["ALLOWED_HOSTS"])
        if val is _DYNAMIC:
            report("ALLOWED_HOSTS is dynamic - verify it is set and not '*'", "INFO")
        elif not val:
            report("ALLOWED_HOSTS is empty - required when DEBUG=False", "MEDIUM")
        elif "*" in val:
            report("ALLOWED_HOSTS contains '*' - do not use in production", "MEDIUM")
        else:
            report(f"ALLOWED_HOSTS = {val!r}", "OK")
    else:
        report("ALLOWED_HOSTS not set in this file", "INFO")

    # SECRET_KEY
    if "SECRET_KEY" in assigns:
        node = assigns["SECRET_KEY"]
        val = literal(node)
        if isinstance(val, str):
            if val.startswith("django-insecure-"):
                report("SECRET_KEY uses the 'django-insecure-' dev prefix", "HIGH")
            else:
                report("SECRET_KEY is a hardcoded string literal - load it from the environment", "HIGH")
        elif val is _DYNAMIC:
            report("SECRET_KEY is dynamic (good if from env/secrets manager)", "OK")

    # boolean-ish security flags
    for name, (note, bad_default) in CHECKS.items():
        if name == "DEBUG":
            continue
        if name not in assigns:
            report(f"{name} not set - {note}", "LOW")
            continue
        val = literal(assigns[name])
        if val is _DYNAMIC:
            report(f"{name} is dynamic - verify: {note}", "INFO")
            continue
        if name == "SECURE_HSTS_SECONDS":
            if isinstance(val, int) and val > 0:
                report(f"{name} = {val}", "OK")
            else:
                report(f"{name} = {val!r} - {note}", "LOW")
            continue
        if val is True:
            report(f"{name} = True", "OK")
        else:
            report(f"{name} = {val!r} - {note}", "LOW")

    # X_FRAME_OPTIONS
    if "X_FRAME_OPTIONS" in assigns:
        val = literal(assigns["X_FRAME_OPTIONS"])
        if isinstance(val, str) and val.upper() != "DENY":
            report(f"X_FRAME_OPTIONS = {val!r} - 'DENY' is the safer default", "LOW")

    # CORS
    if "CORS_ALLOW_ALL_ORIGINS" in assigns:
        if literal(assigns["CORS_ALLOW_ALL_ORIGINS"]) is True:
            creds = literal(assigns.get("CORS_ALLOW_CREDENTIALS", ast.Constant(False)))
            tag = "HIGH" if creds is True else "MEDIUM"
            report("CORS_ALLOW_ALL_ORIGINS = True - use an allowlist"
                   + (" (with credentials: dangerous)" if creds is True else ""), tag)

    if "CSRF_TRUSTED_ORIGINS" not in assigns:
        report("CSRF_TRUSTED_ORIGINS not set in this file - needed for cross-origin POSTs", "INFO")

    print("\n# Done. Findings are indicators; confirm each by reading the code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
