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


def dict_items(node: ast.AST | None) -> dict[str, ast.AST] | None:
    """Map the literal string keys of an ast.Dict to their value nodes.

    Returns None when the node is not a dict literal, so a DATABASES entry whose
    password comes from the environment is still readable for the keys that are
    literal. We never evaluate anything; non-literal values stay <dynamic>.
    """
    if not isinstance(node, ast.Dict):
        return None
    out: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            out[key.value] = value
    return out


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


def check_databases(assigns: dict[str, ast.AST]) -> None:
    """DATABASES: transport verification, pooling, and per-alias ATOMIC_REQUESTS."""
    aliases = dict_items(assigns.get("DATABASES"))
    if aliases is None:
        if "DATABASES" in assigns:
            report("DATABASES is dynamic - verify sslmode, pooling, and CONN_MAX_AGE by hand", "INFO")
        return

    for alias, alias_node in aliases.items():
        conf = dict_items(alias_node)
        if conf is None:
            report(f"DATABASES['{alias}'] is dynamic - verify sslmode and pooling by hand", "INFO")
            continue

        engine = literal(conf["ENGINE"]) if "ENGINE" in conf else _DYNAMIC
        options = dict_items(conf.get("OPTIONS"))
        options_dynamic = "OPTIONS" in conf and options is None
        if options_dynamic:
            report(f"DATABASES['{alias}'] OPTIONS is dynamic - verify sslmode and pooling by hand", "INFO")

        # data-layer-and-database.md: only verify-ca/verify-full validate the
        # server certificate; "require" encrypts and accepts whatever answers.
        if isinstance(engine, str) and "postgresql" in engine and not options_dynamic:
            sslmode = literal(options["sslmode"]) if options and "sslmode" in options else None
            if sslmode in ("verify-full", "verify-ca"):
                report(f"DATABASES['{alias}'] sslmode = {sslmode!r}", "OK")
            elif sslmode is _DYNAMIC:
                report(f"DATABASES['{alias}'] sslmode is dynamic - verify it is 'verify-full'", "INFO")
            else:
                shown = "not set" if sslmode is None else repr(sslmode)
                report(f"DATABASES['{alias}'] sslmode {shown} - only 'verify-ca'/'verify-full' validate "
                       "the server certificate (data-layer-and-database.md)", "MEDIUM")

        # data-layer-and-database.md: the built-in pool requires CONN_MAX_AGE = 0
        # or Django raises ImproperlyConfigured at startup.
        if options and "pool" in options:
            conn_max_age = literal(conf["CONN_MAX_AGE"]) if "CONN_MAX_AGE" in conf else 0
            if conn_max_age is _DYNAMIC:
                report(f"DATABASES['{alias}'] uses OPTIONS['pool'] and CONN_MAX_AGE is dynamic - "
                       "verify it is 0", "INFO")
            elif conn_max_age != 0:
                report(f"DATABASES['{alias}'] uses OPTIONS['pool'] with CONN_MAX_AGE = {conn_max_age!r} - "
                       "pooling requires 0 or Django raises ImproperlyConfigured "
                       "(data-layer-and-database.md)", "MEDIUM")

        # a10-exceptional-conditions.md: informational - a resource cost to know
        # about, not an error.
        if "ATOMIC_REQUESTS" in conf and literal(conf["ATOMIC_REQUESTS"]) is True:
            report(f"DATABASES['{alias}'] ATOMIC_REQUESTS = True - holds a connection and an open "
                   "transaction for every view; exclude long-running, streaming, and external-call "
                   "views (a10-exceptional-conditions.md)", "INFO")


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

    check_databases(assigns)

    # a02-security-misconfiguration.md / deployment-and-runtime.md: a settings
    # check cannot tell a safe proxy header from a spoofable one.
    if "SECURE_PROXY_SSL_HEADER" in assigns:
        report("SECURE_PROXY_SSL_HEADER is set - only safe if the proxy sets that header "
               "unconditionally and strips any client-supplied copy "
               "(a02-security-misconfiguration.md, deployment-and-runtime.md)", "INFO")

    # deployment-and-runtime.md: development tooling must not be importable in
    # production. A top-level entry is unconditional; an `if DEBUG:` append is
    # not a top-level assignment and is deliberately not reported here.
    if "INSTALLED_APPS" in assigns:
        installed = literal(assigns["INSTALLED_APPS"])
        if installed is _DYNAMIC:
            report("INSTALLED_APPS is dynamic - verify debug_toolbar/silk/django_extensions are "
                   "absent from production", "INFO")
        else:
            dev_apps = {"debug_toolbar", "silk", "django_extensions"}
            found = [app for app in installed
                     if isinstance(app, str) and app.split(".")[0] in dev_apps]
            if found:
                report(f"INSTALLED_APPS installs development tooling unconditionally: {found!r} - "
                       "it must not be importable in production "
                       "(deployment-and-runtime.md)", "HIGH")

    # a10-exceptional-conditions.md: the module-level form, for projects that
    # merge it into DATABASES later.
    if "ATOMIC_REQUESTS" in assigns and literal(assigns["ATOMIC_REQUESTS"]) is True:
        report("ATOMIC_REQUESTS = True - holds a connection and an open transaction for every "
               "view; exclude long-running, streaming, and external-call views "
               "(a10-exceptional-conditions.md)", "INFO")

    # a04-cryptographic-failures.md: Django ships PBKDF2 first and Argon2 third,
    # so an unset PASSWORD_HASHERS is the finding on its own.
    if "PASSWORD_HASHERS" not in assigns:
        report("PASSWORD_HASHERS not set in this file - Django's default order puts PBKDF2 first "
               "and Argon2 third, so installing argon2-cffi does not change the hasher "
               "(a04-cryptographic-failures.md)", "MEDIUM")
    else:
        hashers = literal(assigns["PASSWORD_HASHERS"])
        if hashers is _DYNAMIC:
            report("PASSWORD_HASHERS is dynamic - verify a memory-hard hasher is first", "INFO")
        elif hashers and isinstance(hashers[0], str):
            if "argon2" in hashers[0].lower():
                report(f"PASSWORD_HASHERS starts with {hashers[0]!r}", "OK")
            else:
                report(f"PASSWORD_HASHERS starts with {hashers[0]!r} - verify the first entry is "
                       "memory-hard; Argon2id is the preferred choice "
                       "(a04-cryptographic-failures.md)", "MEDIUM")

    # a08-integrity-and-deserialization.md: pickle sessions were removed in
    # Django 5.0, so any pickle serializer here is a custom one.
    if "SESSION_SERIALIZER" in assigns:
        val = literal(assigns["SESSION_SERIALIZER"])
        if isinstance(val, str) and "pickle" in val.lower():
            report(f"SESSION_SERIALIZER = {val!r} - a pickle-based session serializer turns "
                   "SECRET_KEY disclosure into code execution "
                   "(a08-integrity-and-deserialization.md)", "HIGH")

    print("\n# Done. Findings are indicators; confirm each by reading the code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
