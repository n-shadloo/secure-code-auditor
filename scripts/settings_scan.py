#!/usr/bin/env python3
"""
settings_scan.py - read-only Django settings posture check.

Parses a Django settings module - or a whole settings package - with the ast
module and reports on security-relevant settings. It NEVER imports or executes
the target project, makes NO network calls, and only reads the files you point
it at.

The dominant Django layout is a package rather than a file: a base module and
per-environment modules that star-import it. Given a directory, this resolves
every module directly inside it, follows `from .base import *`, `from .base
import NAME`, and the equivalent absolute forms, merges the assignments with
later-wins semantics, and prints the module each effective value came from. A
setting that is safe in base.py and overridden in production.py is the case a
single-file scan cannot express: pointed at the override module alone it
reports most of its checks as unset, which reads exactly like a genuinely empty
module.

An import is followed only inside the package root the module belongs to - the
nearest ancestor directory without an `__init__.py` - so nothing outside that
package is ever opened. An unresolvable import is reported as such and the scan
continues; an import cycle is reported and stopped rather than recursed.

Because it reads literal assignments statically, values computed at runtime
(e.g. env("DEBUG"), os.environ[...]) are reported as "dynamic - verify manually"
rather than guessed. That avoids false positives; confirm dynamic values by hand.
A setting assigned inside an `if` is reported as conditional with the module it
appears in, because the scan reads the assignment and not the condition.

Usage:
    python scripts/settings_scan.py path/to/settings.py
    python scripts/settings_scan.py path/to/settings/
    python scripts/settings_scan.py path/to/settings/ --json

Requires Python 3.9 or later. Exit code is always 0; this is a triage aid, not
a gate.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from collections import namedtuple

# The reference file that owns the follow-up for each check, carried as a field
# so an agent can route from a finding to the rules without guessing.
A02 = "a02-security-misconfiguration.md"
A04 = "a04-cryptographic-failures.md"
A08 = "a08-integrity-and-deserialization.md"
A10 = "a10-exceptional-conditions.md"
DATA = "data-layer-and-database.md"
DEPLOY = "deployment-and-runtime.md"
SECRETS = "service-identity-and-secrets.md"
A07 = "a07-authentication-failures.md"
DRF = "api-drf-specific.md"

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

# An HSTS companion setting does nothing while SECURE_HSTS_SECONDS is absent
# or zero. Judge one only when HSTS is on, or when the scan cannot read it.
HSTS_COMPANIONS = ("SECURE_HSTS_INCLUDE_SUBDOMAINS", "SECURE_HSTS_PRELOAD")

# Settings whose Django default already equals the value the check expects.
# Verified against django/conf/global_settings.py in Django 6.0. The absence of
# one of these is a fact to know, not a weakness, so it is reported as INFO.
SAFE_DEFAULTS = {
    "SECURE_CONTENT_TYPE_NOSNIFF": "True",
    "SESSION_COOKIE_HTTPONLY": "True",
}

UNSET = "not set in this module or anything it imports"

# One effective value: the node it was assigned, the module that assignment
# survived from, and whether it sat inside an `if`.
Effective = namedtuple("Effective", "node origin line conditional")
# One resolved settings entry point: the module asked for, every module merged
# into it (base first), the effective assignments, augmentations seen, notes,
# and modules that could not be read.
Resolution = namedtuple("Resolution", "target modules assigns augments notes unparsed")
Augment = namedtuple("Augment", "origin line conditional")
Finding = namedtuple("Finding", "setting severity message reference origin line conditional")
_Context = namedtuple("_Context", "modules notes unparsed")


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


# --- resolving a settings module, and the package it may live in ------------


def package_root(path: str) -> str:
    """The nearest ancestor of `path` that is not a Python package.

    That is the directory an absolute import inside the module resolves
    against. The walk stops at the first directory without an `__init__.py`, so
    resolution never reaches outside the package the module belongs to. Paths
    stay in the form they were given, so what is reported is as short as what
    was asked for.
    """
    directory = os.path.dirname(path) or "."
    for _ in range(32):
        if not os.path.isfile(os.path.join(directory, "__init__.py")):
            break
        directory = os.path.normpath(os.path.join(directory, os.pardir))
    return directory


def module_file(root: str, parts: list[str]) -> str | None:
    base = os.path.join(root, *parts) if parts else root
    for candidate in (base + ".py", os.path.join(base, "__init__.py")):
        if os.path.isfile(candidate):
            return candidate
    return None


def import_target(current: str, node: ast.ImportFrom, root: str) -> str | None:
    """The file an ImportFrom names, when it lies inside the package root."""
    if node.level:
        directory = os.path.dirname(current) or "."
        for _ in range(node.level - 1):
            directory = os.path.normpath(os.path.join(directory, os.pardir))
        return module_file(directory, node.module.split(".") if node.module else [])
    if not node.module:
        return None
    return module_file(root, node.module.split("."))


def _resolve(path: str, root: str, chain: list[str], ctx: _Context, augments: dict):
    """The effective assignments of one module, with its imports merged first.

    Later wins, in source order: a module's own assignment overrides whatever a
    module it imported above that line had set, which is the order Python
    itself would run.
    """
    real = os.path.realpath(path)
    if real in chain:
        ctx.notes.append(("MEDIUM", "import cycle at %s - stopped rather than recursing; the "
                                    "effective value of anything it sets is not decidable here"
                          % path))
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        ctx.unparsed.append((path, str(exc)))
        return {}
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        ctx.unparsed.append((path, exc.msg or "syntax error"))
        return {}

    chain = chain + [real]
    assigns: dict[str, Effective] = {}

    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            starred = any(alias.name == "*" for alias in node.names)
            target = import_target(path, node, root)
            if target is not None:
                child = _resolve(target, root, chain, ctx, augments)
                if starred:
                    assigns.update(child)
                else:
                    for alias in node.names:
                        if alias.name in child:
                            assigns[alias.asname or alias.name] = child[alias.name]
            elif starred or node.level:
                ctx.notes.append(("MEDIUM", "%s: cannot resolve `from %s%s import %s` inside the "
                                            "package root - whatever it sets is invisible to this "
                                            "scan"
                                  % (path, "." * node.level, node.module or "",
                                     ", ".join(alias.name for alias in node.names))))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns[target.id] = Effective(node.value, path, node.lineno, False)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                assigns[node.target.id] = Effective(node.value, path, node.lineno, False)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            augments.setdefault(node.target.id, []).append(Augment(path, node.lineno, False))
        elif isinstance(node, ast.If):
            _merge_conditional(node, assigns, augments, path)

    # Appended after the walk so the list reads in merge order: every module
    # this one imported, then this one, which is the order later-wins applies.
    ctx.modules.append(path)
    return assigns


def _merge_conditional(node: ast.If, assigns: dict, augments: dict, path: str) -> None:
    """Record what an `if` block assigns, marked conditional.

    The value is still carried so the module it lives in can be named; the
    conditional flag is what stops it being read as the effective literal.
    """
    for branch in (node.body, node.orelse):
        for stmt in branch:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        assigns[target.id] = Effective(stmt.value, path, stmt.lineno, True)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                if stmt.value is not None:
                    assigns[stmt.target.id] = Effective(stmt.value, path, stmt.lineno, True)
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                augments.setdefault(stmt.target.id, []).append(Augment(path, stmt.lineno, True))
            elif isinstance(stmt, ast.If):
                _merge_conditional(stmt, assigns, augments, path)


def resolve_settings(path: str) -> Resolution:
    """Resolve one settings module together with everything it imports."""
    ctx = _Context([], [], [])
    augments: dict[str, list] = {}
    assigns = _resolve(path, package_root(path), [], ctx, augments)
    return Resolution(path, ctx.modules, assigns, augments, ctx.notes, ctx.unparsed)


def resolve_package(directory: str):
    """Resolve every module directly inside a settings package.

    Modules another module in the package imports are folded into that
    importer's chain rather than scanned on their own, so pointing at
    `config/settings/` reports the environment modules with base merged in
    rather than reporting base three times. A module that assigns nothing - the
    usual empty `__init__.py` - is named rather than scanned: running the
    checks against it would print a page of "not set" that reads exactly like a
    settings module with everything missing.
    """
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(".py"))
    except OSError as exc:
        return [], [], [], [(directory, str(exc))]
    resolutions = [resolve_settings(os.path.join(directory, name)) for name in names]
    imported = set()
    for resolution in resolutions:
        own = os.path.realpath(resolution.target)
        for module in resolution.modules:
            if os.path.realpath(module) != own:
                imported.add(os.path.realpath(module))
    roots = [r for r in resolutions if os.path.realpath(r.target) not in imported]
    # A module that could not be read or parsed is never "assigns nothing": it
    # is reported, because a silent skip looks exactly like a clean result.
    empty = [r.target for r in roots if not (r.assigns or r.unparsed or r.notes)]
    roots = [r for r in roots if r.assigns or r.unparsed or r.notes]
    folded = [os.path.join(directory, name) for name in names
              if os.path.realpath(os.path.join(directory, name)) in imported]
    return roots, folded, empty, []


# --- the checks -------------------------------------------------------------


class Report:
    """Collects findings against one resolved settings entry point."""

    def __init__(self, resolution: Resolution):
        self.resolution = resolution
        self.findings: list[Finding] = []

    def emit(self, setting: str, severity: str, message: str, reference: str) -> None:
        effective = self.resolution.assigns.get(setting)
        self.findings.append(Finding(
            setting, severity, message, reference,
            effective.origin if effective else None,
            effective.line if effective else 0,
            bool(effective and effective.conditional)))

    def conditional(self, setting: str, reference: str) -> bool:
        """Report a conditionally assigned setting as such, and decline to read it."""
        effective = self.resolution.assigns.get(setting)
        if effective is None or not effective.conditional:
            return False
        self.emit(setting, "INFO",
                  "%s is assigned inside a conditional - the scan reads the assignment, not the "
                  "condition, so confirm which branch runs in production" % setting, reference)
        return True


def check_databases(assigns: dict[str, ast.AST], report: Report) -> None:
    """DATABASES: transport verification, pooling, and per-alias ATOMIC_REQUESTS."""
    aliases = dict_items(assigns.get("DATABASES"))
    if aliases is None:
        if "DATABASES" in assigns:
            report.emit("DATABASES", "INFO",
                        "DATABASES is dynamic - verify sslmode, pooling, and CONN_MAX_AGE by hand",
                        DATA)
        return

    for alias, alias_node in aliases.items():
        conf = dict_items(alias_node)
        if conf is None:
            report.emit("DATABASES", "INFO",
                        "DATABASES['%s'] is dynamic - verify sslmode and pooling by hand" % alias,
                        DATA)
            continue

        engine = literal(conf["ENGINE"]) if "ENGINE" in conf else _DYNAMIC
        options = dict_items(conf.get("OPTIONS"))
        options_dynamic = "OPTIONS" in conf and options is None
        if options_dynamic:
            report.emit("DATABASES", "INFO",
                        "DATABASES['%s'] OPTIONS is dynamic - verify sslmode and pooling by hand"
                        % alias, DATA)

        # data-layer-and-database.md: only verify-ca/verify-full validate the
        # server certificate; "require" encrypts and accepts whatever answers.
        postgres = isinstance(engine, str) and ("postgresql" in engine
                                                or engine.endswith("postgis"))
        if postgres and not options_dynamic:
            sslmode = literal(options["sslmode"]) if options and "sslmode" in options else None
            if sslmode in ("verify-full", "verify-ca"):
                report.emit("DATABASES", "OK",
                            "DATABASES['%s'] sslmode = %r" % (alias, sslmode), DATA)
            elif sslmode is _DYNAMIC:
                report.emit("DATABASES", "INFO",
                            "DATABASES['%s'] sslmode is dynamic - verify it is 'verify-full'"
                            % alias, DATA)
            else:
                shown = "not set" if sslmode is None else repr(sslmode)
                report.emit("DATABASES", "MEDIUM",
                            "DATABASES['%s'] sslmode %s - only 'verify-ca'/'verify-full' validate "
                            "the server certificate" % (alias, shown), DATA)

        # data-layer-and-database.md: MySQL/MariaDB verify the server only when
        # OPTIONS['ssl'] supplies a CA; without it the connection is unencrypted
        # or unverified depending on the server's default.
        if isinstance(engine, str) and engine.rsplit(".", 1)[-1] in ("mysql",) \
                and not options_dynamic:
            if not options or "ssl" not in options:
                report.emit("DATABASES", "MEDIUM",
                            "DATABASES['%s'] has no OPTIONS['ssl'] - supply the CA so the MySQL "
                            "server is verified, not merely dialed" % alias, DATA)

        # data-layer-and-database.md: the built-in pool requires CONN_MAX_AGE = 0
        # or Django raises ImproperlyConfigured at startup.
        # Django reads the value for truth, so a literal `"pool": False` and an
        # empty dict are not a pool.
        pool = literal(options["pool"]) if options and "pool" in options else False
        if pool is _DYNAMIC or pool:
            conn_max_age = literal(conf["CONN_MAX_AGE"]) if "CONN_MAX_AGE" in conf else 0
            if conn_max_age is _DYNAMIC:
                report.emit("DATABASES", "INFO",
                            "DATABASES['%s'] uses OPTIONS['pool'] and CONN_MAX_AGE is dynamic - "
                            "verify it is 0" % alias, DATA)
            elif conn_max_age != 0:
                report.emit("DATABASES", "MEDIUM",
                            "DATABASES['%s'] uses OPTIONS['pool'] with CONN_MAX_AGE = %r - pooling "
                            "requires 0 or Django raises ImproperlyConfigured"
                            % (alias, conn_max_age), DATA)

        # a10-exceptional-conditions.md: informational - a resource cost to know
        # about, not an error.
        if "ATOMIC_REQUESTS" in conf and literal(conf["ATOMIC_REQUESTS"]) is True:
            report.emit("DATABASES", "INFO",
                        "DATABASES['%s'] ATOMIC_REQUESTS = True - holds a connection and an open "
                        "transaction for every view; exclude long-running, streaming, and "
                        "external-call views" % alias, A10)


def scan(resolution: Resolution) -> Report:
    report = Report(resolution)
    assigns = {name: effective.node for name, effective in resolution.assigns.items()}

    # DEBUG / ALLOWED_HOSTS
    if not report.conditional("DEBUG", A02):
        if "DEBUG" in assigns:
            val = literal(assigns["DEBUG"])
            if val is True:
                report.emit("DEBUG", "HIGH", "DEBUG = True  -> must be False in production", A02)
            elif val is _DYNAMIC:
                report.emit("DEBUG", "INFO",
                            "DEBUG is dynamic - verify it is False in production", A02)
            else:
                report.emit("DEBUG", "OK", "DEBUG = %r" % val, A02)
        else:
            report.emit("DEBUG", "INFO", "DEBUG %s" % UNSET, A02)

    if not report.conditional("ALLOWED_HOSTS", A02):
        if "ALLOWED_HOSTS" in assigns:
            val = literal(assigns["ALLOWED_HOSTS"])
            if val is _DYNAMIC:
                report.emit("ALLOWED_HOSTS", "INFO",
                            "ALLOWED_HOSTS is dynamic - verify it is set and not '*'", A02)
            elif not val:
                report.emit("ALLOWED_HOSTS", "MEDIUM",
                            "ALLOWED_HOSTS is empty - required when DEBUG=False", A02)
            elif "*" in val:
                report.emit("ALLOWED_HOSTS", "MEDIUM",
                            "ALLOWED_HOSTS contains '*' - do not use in production", A02)
            else:
                report.emit("ALLOWED_HOSTS", "OK", "ALLOWED_HOSTS = %r" % val, A02)
        else:
            report.emit("ALLOWED_HOSTS", "INFO", "ALLOWED_HOSTS %s" % UNSET, A02)

    # SECRET_KEY
    if "SECRET_KEY" in assigns and not report.conditional("SECRET_KEY", SECRETS):
        val = literal(assigns["SECRET_KEY"])
        if isinstance(val, str):
            if val.startswith("django-insecure-"):
                report.emit("SECRET_KEY", "HIGH",
                            "SECRET_KEY uses the 'django-insecure-' dev prefix", SECRETS)
            else:
                report.emit("SECRET_KEY", "HIGH",
                            "SECRET_KEY is a hardcoded string literal - load it from the "
                            "environment", SECRETS)
        elif val is _DYNAMIC:
            report.emit("SECRET_KEY", "INFO",
                        "SECRET_KEY is dynamic - confirm the source is the environment or a "
                        "secrets manager", SECRETS)

    # boolean-ish security flags
    hsts = literal(assigns["SECURE_HSTS_SECONDS"]) if "SECURE_HSTS_SECONDS" in assigns else 0
    hsts_on = hsts is _DYNAMIC or (isinstance(hsts, int) and hsts > 0)
    for name, (note, bad_default) in CHECKS.items():
        if name == "DEBUG":
            continue
        if report.conditional(name, A02):
            continue
        if name in HSTS_COMPANIONS and not hsts_on:
            continue
        if name not in assigns:
            if name in SAFE_DEFAULTS:
                report.emit(name, "INFO",
                            "%s not set - Django's default is %s, which is already the expected "
                            "value" % (name, SAFE_DEFAULTS[name]), A02)
            else:
                report.emit(name, "LOW", "%s not set - %s" % (name, note), A02)
            continue
        val = literal(assigns[name])
        if val is _DYNAMIC:
            report.emit(name, "INFO", "%s is dynamic - verify: %s" % (name, note), A02)
            continue
        if name == "SECURE_HSTS_SECONDS":
            if isinstance(val, int) and val > 0:
                report.emit(name, "OK", "%s = %d" % (name, val), A02)
            else:
                report.emit(name, "LOW", "%s = %r - %s" % (name, val, note), A02)
            continue
        if val is True:
            report.emit(name, "OK", "%s = True" % name, A02)
        else:
            report.emit(name, "LOW", "%s = %r - %s" % (name, val, note), A02)

    # X_FRAME_OPTIONS
    if "X_FRAME_OPTIONS" in assigns and not report.conditional("X_FRAME_OPTIONS", A02):
        val = literal(assigns["X_FRAME_OPTIONS"])
        if isinstance(val, str) and val.upper() != "DENY":
            report.emit("X_FRAME_OPTIONS", "LOW",
                        "X_FRAME_OPTIONS = %r - 'DENY' is the safer default" % val, A02)

    # CORS
    if "CORS_ALLOW_ALL_ORIGINS" in assigns and not report.conditional("CORS_ALLOW_ALL_ORIGINS", A02):
        if literal(assigns["CORS_ALLOW_ALL_ORIGINS"]) is True:
            creds = literal(assigns.get("CORS_ALLOW_CREDENTIALS", ast.Constant(False)))
            tag = "HIGH" if creds is True else "MEDIUM"
            report.emit("CORS_ALLOW_ALL_ORIGINS", tag,
                        "CORS_ALLOW_ALL_ORIGINS = True - use an allowlist"
                        + (" (with credentials: dangerous)" if creds is True else ""), A02)

    if "CSRF_TRUSTED_ORIGINS" not in assigns:
        report.emit("CSRF_TRUSTED_ORIGINS", "INFO",
                    "CSRF_TRUSTED_ORIGINS %s - needed for cross-origin POSTs" % UNSET, A02)

    check_databases(assigns, report)

    # a02-security-misconfiguration.md / deployment-and-runtime.md: a settings
    # check cannot tell a safe proxy header from a spoofable one.
    if "SECURE_PROXY_SSL_HEADER" in assigns:
        report.emit("SECURE_PROXY_SSL_HEADER", "INFO",
                    "SECURE_PROXY_SSL_HEADER is set - only safe if the proxy sets that header "
                    "unconditionally and strips any client-supplied copy", DEPLOY)

    # deployment-and-runtime.md: development tooling must not be importable in
    # production. A top-level entry is unconditional; an `if DEBUG:` append is
    # not a top-level assignment and is reported as an augmentation instead.
    if "INSTALLED_APPS" in assigns and not report.conditional("INSTALLED_APPS", DEPLOY):
        installed = literal(assigns["INSTALLED_APPS"])
        if installed is _DYNAMIC:
            report.emit("INSTALLED_APPS", "INFO",
                        "INSTALLED_APPS is dynamic - verify debug_toolbar/silk/django_extensions "
                        "are absent from production", DEPLOY)
        else:
            dev_apps = {"debug_toolbar", "silk", "django_extensions"}
            found = [app for app in installed
                     if isinstance(app, str) and app.split(".")[0] in dev_apps]
            if found:
                report.emit("INSTALLED_APPS", "HIGH",
                            "INSTALLED_APPS installs development tooling unconditionally: %r - it "
                            "must not be importable in production" % (found,), DEPLOY)

    for name, entries in sorted(resolution.augments.items()):
        for entry in entries:
            report.findings.append(Finding(
                name, "INFO",
                "%s is extended with += %s - the scan reads the assignment, not the condition, so "
                "confirm what the branch adds and when it runs"
                % (name, "inside a conditional" if entry.conditional else "at module level"),
                DEPLOY, entry.origin, entry.line, entry.conditional))

    # a10-exceptional-conditions.md: the module-level form, for projects that
    # merge it into DATABASES later.
    if "ATOMIC_REQUESTS" in assigns and literal(assigns["ATOMIC_REQUESTS"]) is True:
        report.emit("ATOMIC_REQUESTS", "INFO",
                    "ATOMIC_REQUESTS = True - holds a connection and an open transaction for every "
                    "view; exclude long-running, streaming, and external-call views", A10)

    # a04-cryptographic-failures.md: Django ships PBKDF2 first and Argon2 third,
    # so an unset PASSWORD_HASHERS is the finding on its own.
    if "PASSWORD_HASHERS" not in assigns:
        report.emit("PASSWORD_HASHERS", "MEDIUM",
                    "PASSWORD_HASHERS %s - Django's default order puts PBKDF2 first and Argon2 "
                    "third, so installing argon2-cffi does not change the hasher" % UNSET, A04)
    elif not report.conditional("PASSWORD_HASHERS", A04):
        hashers = literal(assigns["PASSWORD_HASHERS"])
        if hashers is _DYNAMIC:
            report.emit("PASSWORD_HASHERS", "INFO",
                        "PASSWORD_HASHERS is dynamic - verify a memory-hard hasher is first", A04)
        elif hashers and isinstance(hashers[0], str):
            if "argon2" in hashers[0].lower():
                report.emit("PASSWORD_HASHERS", "OK",
                            "PASSWORD_HASHERS starts with %r" % hashers[0], A04)
            else:
                report.emit("PASSWORD_HASHERS", "MEDIUM",
                            "PASSWORD_HASHERS starts with %r - verify the first entry is "
                            "memory-hard; Argon2id is the preferred choice" % hashers[0], A04)

    # a02-security-misconfiguration.md: middleware membership, judged only on a
    # literal list with no later `+=` - an augmented list may add what the
    # literal lacks, and asserting an absence there would be a false positive.
    if "MIDDLEWARE" in assigns and not report.conditional("MIDDLEWARE", A02):
        if "MIDDLEWARE" in resolution.augments:
            report.emit("MIDDLEWARE", "INFO",
                        "MIDDLEWARE is extended with += - membership is not judged; confirm "
                        "Security/Csrf/XFrameOptions middleware by hand", A02)
        else:
            mw = literal(assigns["MIDDLEWARE"])
            if mw is _DYNAMIC:
                report.emit("MIDDLEWARE", "INFO",
                            "MIDDLEWARE is dynamic - verify SecurityMiddleware, "
                            "CsrfViewMiddleware, and XFrameOptionsMiddleware are present", A02)
            elif isinstance(mw, (list, tuple)):
                entries = [m for m in mw if isinstance(m, str)]

                def present(suffix):
                    return any(entry.endswith(suffix) for entry in entries)

                if not present("CsrfViewMiddleware"):
                    report.emit("MIDDLEWARE", "HIGH",
                                "MIDDLEWARE has no CsrfViewMiddleware - cookie-authenticated "
                                "state changes run with no CSRF check", A02)
                if not present("SecurityMiddleware"):
                    report.emit("MIDDLEWARE", "MEDIUM",
                                "MIDDLEWARE has no SecurityMiddleware - the SECURE_* header and "
                                "redirect settings are inert without it", A02)
                if not present("XFrameOptionsMiddleware"):
                    report.emit("MIDDLEWARE", "LOW",
                                "MIDDLEWARE has no XFrameOptionsMiddleware - X_FRAME_OPTIONS "
                                "emits no header without it", A02)
                csp_settings = [name for name in ("SECURE_CSP", "SECURE_CSP_REPORT_ONLY")
                                if name in assigns]
                if csp_settings and not present("ContentSecurityPolicyMiddleware") \
                        and not any("csp" in entry.lower() for entry in entries):
                    report.emit("MIDDLEWARE", "MEDIUM",
                                "%s set but no CSP middleware is installed - the setting is "
                                "inert without django.middleware.csp."
                                "ContentSecurityPolicyMiddleware (Django 6.0+) or django-csp's "
                                "middleware before it" % " and ".join(csp_settings), A02)

    # a07-authentication-failures.md: signed_cookies holds no server-side
    # record, so nothing can revoke one session early.
    if "SESSION_ENGINE" in assigns and not report.conditional("SESSION_ENGINE", A07):
        val = literal(assigns["SESSION_ENGINE"])
        if isinstance(val, str) and val.endswith("signed_cookies"):
            report.emit("SESSION_ENGINE", "MEDIUM",
                        "SESSION_ENGINE is signed_cookies - the server holds no session record, "
                        "so logout clears the browser copy only and a captured cookie stays "
                        "valid until SESSION_COOKIE_AGE runs out; the payload is signed, not "
                        "encrypted", A07)

    # a02-security-misconfiguration.md: SameSite weakened. Django's default is
    # 'Lax'; Python None removes the attribute, the string "None" opts into
    # cross-site sending and requires Secure to be accepted at all.
    for name in ("SESSION_COOKIE_SAMESITE", "CSRF_COOKIE_SAMESITE"):
        if name in assigns and not report.conditional(name, A02):
            val = literal(assigns[name])
            if val is None:
                report.emit(name, "LOW",
                            "%s = None removes the SameSite attribute - Django's default is "
                            "'Lax'" % name, A02)
            elif val == "None":
                secure_name = name.replace("_SAMESITE", "_SECURE")
                secure = assigns.get(secure_name)
                severity = "LOW" if secure is not None and literal(secure) is True else "MEDIUM"
                report.emit(name, severity,
                            "%s = 'None' opts into cross-site sending%s" % (
                                name,
                                "" if severity == "LOW"
                                else " and %s is not True, so browsers drop the cookie "
                                     "entirely" % secure_name), A02)

    # a02-security-misconfiguration.md: SecurityMiddleware sends
    # Cross-Origin-Opener-Policy: same-origin by default; None or 'unsafe-none'
    # switches that isolation off.
    if "SECURE_CROSS_ORIGIN_OPENER_POLICY" in assigns \
            and not report.conditional("SECURE_CROSS_ORIGIN_OPENER_POLICY", A02):
        val = literal(assigns["SECURE_CROSS_ORIGIN_OPENER_POLICY"])
        if val is None or val == "unsafe-none":
            report.emit("SECURE_CROSS_ORIGIN_OPENER_POLICY", "LOW",
                        "SECURE_CROSS_ORIGIN_OPENER_POLICY weakened to %r - the 'same-origin' "
                        "default keeps other origins from holding a handle to this window"
                        % val, A02)

    # deployment-and-runtime.md: same trust rule as SECURE_PROXY_SSL_HEADER -
    # only the proxy can make this safe, and every absolute URL Django builds
    # from the request believes the forwarded host. A password reset link is
    # one of them only where django.contrib.sites is absent, because
    # get_current_site() otherwise returns the Site row.
    if "USE_X_FORWARDED_HOST" in assigns \
            and literal(assigns["USE_X_FORWARDED_HOST"]) is True:
        report.emit("USE_X_FORWARDED_HOST", "INFO",
                    "USE_X_FORWARDED_HOST = True - only safe if the proxy sets X-Forwarded-Host "
                    "unconditionally and strips any client-supplied copy", DEPLOY)

    # api-drf-specific.md: DRF's own default permission is AllowAny, so a
    # REST_FRAMEWORK block that leaves DEFAULT_PERMISSION_CLASSES unset makes
    # every view that declares nothing public.
    if "REST_FRAMEWORK" in assigns and not report.conditional("REST_FRAMEWORK", DRF):
        conf = dict_items(assigns["REST_FRAMEWORK"])
        if conf is None:
            report.emit("REST_FRAMEWORK", "INFO",
                        "REST_FRAMEWORK is dynamic - verify DEFAULT_PERMISSION_CLASSES and "
                        "DEFAULT_AUTHENTICATION_CLASSES by hand", DRF)
        else:
            if "DEFAULT_PERMISSION_CLASSES" not in conf:
                report.emit("REST_FRAMEWORK", "MEDIUM",
                            "REST_FRAMEWORK sets no DEFAULT_PERMISSION_CLASSES - DRF defaults "
                            "to AllowAny, so every view that declares nothing is public", DRF)
            else:
                perms = literal(conf["DEFAULT_PERMISSION_CLASSES"])
                if perms is _DYNAMIC:
                    report.emit("REST_FRAMEWORK", "INFO",
                                "DEFAULT_PERMISSION_CLASSES is dynamic - verify the default "
                                "denies", DRF)
                elif isinstance(perms, (list, tuple)) and any(
                        isinstance(p, str) and p.endswith("AllowAny") for p in perms):
                    report.emit("REST_FRAMEWORK", "MEDIUM",
                                "DEFAULT_PERMISSION_CLASSES is AllowAny - every view that "
                                "declares nothing is public", DRF)
            if "DEFAULT_AUTHENTICATION_CLASSES" not in conf:
                report.emit("REST_FRAMEWORK", "INFO",
                            "REST_FRAMEWORK sets no DEFAULT_AUTHENTICATION_CLASSES - views fall "
                            "back on session and basic authentication", DRF)

    # a08-integrity-and-deserialization.md: pickle sessions were removed in
    # Django 5.0, so any pickle serializer here is a custom one.
    if "SESSION_SERIALIZER" in assigns and not report.conditional("SESSION_SERIALIZER", A08):
        val = literal(assigns["SESSION_SERIALIZER"])
        if isinstance(val, str) and "pickle" in val.lower():
            report.emit("SESSION_SERIALIZER", "HIGH",
                        "SESSION_SERIALIZER = %r - a pickle-based session serializer turns "
                        "SECRET_KEY disclosure into code execution" % val, A08)

    return report


# --- output -----------------------------------------------------------------


def print_text(resolution: Resolution, report: Report) -> None:
    print("# settings_scan: %s" % resolution.target)
    if len(resolution.modules) > 1:
        print("# merged, base first: %s" % ", ".join(resolution.modules))
    print()
    for severity, message in resolution.notes:
        print("[%s] %s" % (severity, message))
    for path, error in resolution.unparsed:
        print("[MEDIUM] %s could not be parsed and was NOT scanned: %s" % (path, error))
    for finding in report.findings:
        origin = "  [from %s]" % finding.origin if finding.origin else ""
        print("[%s] %s (%s)%s" % (finding.severity, finding.message, finding.reference, origin))
    print()


def print_json(resolution: Resolution, report: Report) -> None:
    for severity, message in resolution.notes:
        print(json.dumps({"kind": "note", "file": resolution.target,
                          "severity": severity, "message": message}, sort_keys=True))
    for path, error in resolution.unparsed:
        print(json.dumps({"kind": "unparsed", "file": path, "line": 0, "column": 0,
                          "error": error}, sort_keys=True))
    for finding in report.findings:
        print(json.dumps({
            "kind": "setting",
            "file": resolution.target,
            "origin": finding.origin,
            "line": finding.line,
            "setting": finding.setting,
            "severity": finding.severity,
            "message": finding.message,
            "reference": finding.reference,
            "conditional": finding.conditional,
        }, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Django settings posture check.")
    parser.add_argument("path", help="A Django settings .py file, or a settings package directory")
    parser.add_argument("--json", action="store_true",
                        help="Emit one JSON object per record, one per line")
    args = parser.parse_args()

    discovered = 0
    missing = False
    if os.path.isdir(args.path):
        resolutions, folded, empty, walk_errors = resolve_package(args.path)
        discovered = len(resolutions) + len(folded) + len(empty)
    elif os.path.isfile(args.path):
        resolutions, folded, empty, walk_errors = [resolve_settings(args.path)], [], [], []
        discovered = 1
    else:
        resolutions, folded, empty, walk_errors = [], [], [], []
        missing = True
        if not args.json:
            print("Cannot read %s: not a file or directory" % args.path, file=sys.stderr)

    scanned = set(folded) | set(empty)
    unparsed_total = 0
    findings_total = 0
    for resolution in resolutions:
        # Nothing parsed, so there is nothing to judge: report the failure
        # rather than a page of checks reading "not set".
        report = Report(resolution) if resolution.unparsed and not resolution.assigns \
            else scan(resolution)
        scanned.update(resolution.modules)
        unparsed_total += len(resolution.unparsed)
        findings_total += len(report.findings)
        if args.json:
            print_json(resolution, report)
        else:
            print_text(resolution, report)

    if args.json:
        if missing:
            print(json.dumps({"kind": "error", "file": args.path,
                              "error": "not a file or directory"}, sort_keys=True))
        for path in folded:
            print(json.dumps({"kind": "note", "file": path, "severity": "INFO",
                              "message": "folded in as an imported base rather than scanned on "
                                         "its own"}, sort_keys=True))
        for path in empty:
            print(json.dumps({"kind": "note", "file": path, "severity": "INFO",
                              "message": "assigns nothing - named rather than scanned"},
                             sort_keys=True))
        for directory, error in walk_errors:
            print(json.dumps({"kind": "note", "file": directory, "severity": "MEDIUM",
                              "message": "could not be read and was NOT scanned: %s" % error},
                             sort_keys=True))
        # The stream always ends here, so a reader that gets no summary knows
        # the scan stopped rather than finding nothing.
        print(json.dumps({
            "kind": "summary",
            "path": args.path,
            "files_discovered": discovered,
            "files_scanned": len(scanned),
            "files_unparsed": unparsed_total,
            "findings": findings_total,
            "walk_errors": len(walk_errors),
        }, sort_keys=True))
        return 0

    if folded:
        print("# folded in as an imported base rather than scanned on its own: %s"
              % ", ".join(folded))
    if empty:
        print("# assigns nothing, so named rather than scanned: %s" % ", ".join(empty))
    for directory, error in walk_errors:
        print("# %s could not be read and was NOT scanned: %s" % (directory, error))
    if not resolutions:
        print("# no module in %s assigns anything - nothing was scanned." % args.path)
    print("# %d module(s) discovered, %d scanned, %d unparsed; %d finding(s); %d traversal "
          "error(s)." % (discovered, len(scanned), unparsed_total, findings_total,
                         len(walk_errors)))
    print("# Done. Findings are indicators; confirm each by reading the code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
