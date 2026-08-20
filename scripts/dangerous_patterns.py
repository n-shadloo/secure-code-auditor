#!/usr/bin/env python3
"""
dangerous_patterns.py - read-only risky-pattern indicator scan.

Parses every .py file in a tree with the ast module and reports structural
matches for patterns that often indicate a security issue: SQL text built by
interpolation, client-controlled ORM identifier positions, shell and code
execution, unsafe deserialization, unescaped template output, disabled TLS
verification, non-cryptographic randomness, over-permissive configuration, and
hardcoded secrets.

Because it parses rather than greps it can tell a string literal from an
expression, a call carrying a parameter sequence from one that does not, a
local rebinding from a module constant, and a real call from the same text
inside a docstring. Parameterized SQL - the correct form - is not reported.

It reads files only. It makes NO network calls, imports nothing from the target
project, and never modifies anything. Every hit is a TRIAGE lead to verify, not
a confirmed finding.

Usage:
    python scripts/dangerous_patterns.py path/to/project
    python scripts/dangerous_patterns.py .                     # current dir
    python scripts/dangerous_patterns.py . --min-severity MEDIUM
    python scripts/dangerous_patterns.py . --json
    python scripts/dangerous_patterns.py --selftest

Requires Python 3.9 or later. Exit code is always 0.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections import namedtuple

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
             "__pycache__", ".mypy_cache", ".tox", "build", "dist", ".eggs"}

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

Hit = namedtuple("Hit", "path line column rule severity category message reference snippet")
Unparsed = namedtuple("Unparsed", "path line column error")

# Rule identifiers are stable: a prefix and a number, chosen once and never
# reused for a different rule. rule -> (category, default severity, owning
# reference file, default message). Severity may be raised or lowered per hit
# where the rule says it turns on something structural; the identifier does not
# change with it.
RULES = {
    "SQL001": ("sql", "HIGH", "a05-injection.md",
               "SQL text is built by string interpolation - pass values as parameters instead"),
    "SQL002": ("sql", "MEDIUM", "a05-injection.md",
               "SQL text comes from an unresolved expression - confirm it is a literal and that "
               "values are passed as parameters"),
    "IDN001": ("sql", "HIGH", "a05-injection.md",
               "mapping expanded into an ORM identifier position derives from request data - "
               "the ORM does not parameterize identifiers"),
    "IDN002": ("sql", "MEDIUM", "a05-injection.md",
               "column identifier derives from request data - allowlist the accepted columns"),
    "CMD001": ("command", "HIGH", "a05-injection.md",
               "os.system/os.popen runs its argument through a shell - use a subprocess "
               "argument list"),
    "CMD002": ("command", "HIGH", "a05-injection.md",
               "shell=True with a command that is not a constant - whether any element of it "
               "comes from outside the source file decides whether the shell is handed input "
               "to re-parse"),
    "CMD003": ("command", "HIGH", "a05-injection.md",
               "eval/exec/compile evaluates source at runtime"),
    "DES001": ("deser", "HIGH", "a08-integrity-and-deserialization.md",
               "pickle reconstructs arbitrary Python objects - who can write the bytes it reads "
               "decides whether that is remote code execution"),
    "DES002": ("deser", "HIGH", "a08-integrity-and-deserialization.md",
               "yaml.load without a safe Loader constructs arbitrary Python objects"),
    "DES003": ("deser", "HIGH", "a08-integrity-and-deserialization.md",
               "marshal parses untrusted code objects and is not a safe format"),
    "DES004": ("deser", "HIGH", "a08-integrity-and-deserialization.md",
               "jsonpickle reconstructs arbitrary Python objects from JSON"),
    "DES005": ("deser", "HIGH", "a08-integrity-and-deserialization.md",
               "Celery pickle serializer turns a broker message into code execution"),
    "DES006": ("deser", "HIGH", "a08-integrity-and-deserialization.md",
               "Celery accept_content admits pickle - it decides what a worker will execute, "
               "whatever the producers send"),
    "TPL001": ("xss", "MEDIUM", "a05-injection.md",
               "mark_safe on a value that is not a constant disables autoescaping"),
    "TPL002": ("xss", "MEDIUM", "a05-injection.md",
               "format_html given an already-interpolated first argument (f-string, %, or "
               ".format) - the values were inserted before escaping ran"),
    "TPL003": ("xss", "HIGH", "a05-injection.md",
               "template compiled from a value that is not a constant - where that source comes "
               "from decides whether a caller can author template code"),
    "TPL004": ("xss", "HIGH", "a05-injection.md",
               "autoescape disabled - every variable in the template is emitted raw"),
    "NET001": ("tls", "HIGH", "a04-cryptographic-failures.md",
               "verify=False disables TLS certificate verification on an outbound call"),
    "RND001": ("crypto", "LOW", "a04-cryptographic-failures.md",
               "random.* is a statistical PRNG reconstructible from its output - verify this "
               "value is not a secret, a token, or an identifier (use secrets)"),
    "CFG001": ("drf", "MEDIUM", "api-drf-specific.md",
               "fields='__all__' on a serializer or ModelForm Meta exposes every model field, "
               "including ones added later"),
    "CFG002": ("config", "MEDIUM", "a02-security-misconfiguration.md",
               "CORS_ALLOW_ALL_ORIGINS = True - use an allowlist"),
    "CFG003": ("config", "HIGH", "a02-security-misconfiguration.md",
               "DEBUG = True - verify this module is not the production settings"),
    "CFG004": ("config", "MEDIUM", "a02-security-misconfiguration.md",
               "ALLOWED_HOSTS contains '*' - do not use in production"),
    "CFG005": ("csrf", "MEDIUM", "api-drf-specific.md",
               "csrf_exempt on this view - what authentication_classes resolves to decides "
               "whether a check was removed, since DRF enforces CSRF inside SessionAuthentication "
               "rather than the middleware"),
    "CFG006": ("graphql", "HIGH", "graphql-and-alternative-api-surfaces.md",
               "graphene bypass_get_queryset makes traversal skip get_queryset, so the resolver "
               "opts out of every scope its type declares"),
    "SEC001": ("secret", "HIGH", "service-identity-and-secrets.md",
               "secret-shaped name assigned a string literal - load it from the environment "
               "(heuristic: confirm it is not a placeholder)"),
    "SEC002": ("secret", "HIGH", "service-identity-and-secrets.md",
               "jwt.decode with signature verification disabled accepts any caller-minted "
               "token - verify the signature and pin algorithm, issuer, and audience"),
    "NET002": ("tls", "HIGH", "a04-cryptographic-failures.md",
               "TLS certificate verification disabled at the ssl layer - the connection "
               "trusts whoever answers"),
    "NET003": ("ssrf", "MEDIUM", "a01-broken-access-control.md",
               "outbound HTTP call whose URL derives from request data - apply the "
               "destination allowlist, the post-resolution address check, and bounded "
               "redirects at the call"),
}

# --- SQL -------------------------------------------------------------------

# DB-API cursor methods. `.execute` is also a common name on objects that have
# nothing to do with a database, so an unresolved query is only reported there
# when the receiver names a cursor or a connection; an interpolated query is
# reported whatever the receiver is.
CURSOR_METHODS = {"execute", "executemany", "callproc"}
CURSORISH = ("cursor", "conn", "connection", "connections", "cur", "db")

# QuerySet.extra(select, where, params, tables, order_by, select_params): the
# positions that carry SQL. params/select_params are the parameter sequences.
EXTRA_SQL_POSITIONS = {0: "select", 1: "where", 3: "tables", 4: "order_by"}
EXTRA_SQL_KEYWORDS = {"select", "where", "tables", "order_by"}

# Methods whose **-expansion lands in an identifier position.
IDENT_EXPANSION_METHODS = {"annotate", "aggregate", "alias", "values", "values_list",
                           "filter", "exclude", "Q", "order_by"}
# Methods whose positional arguments are column names rather than values. A
# positional argument to filter()/Q() is an expression, not an identifier, so
# `filter(user=request.user)` is correct code and is deliberately not reported.
IDENT_POSITIONAL_METHODS = {"order_by", "values", "values_list"}

# --- classification of a query expression ----------------------------------

CONSTANT = "constant"
INTERPOLATED = "interpolated"
UNRESOLVED = "unresolved"

SECRET_SUFFIXES = ("SECRET", "SECRET_KEY", "SIGNING_KEY", "API_KEY", "ACCESS_KEY",
                   "PRIVATE_KEY", "PASSWORD", "PASSWD", "PASSPHRASE", "TOKEN")

PICKLE_CONTENT = ("pickle", "application/x-python-serialize")

# Outbound HTTP call sites whose URL argument is worth reading when it derives
# from request data. Resolved through imports, so `import requests as rq` and
# `from httpx import get` both land here; a bare `session.get` on an arbitrary
# receiver deliberately does not, because the receiver is unresolvable.
HTTP_FETCHERS = frozenset(
    "%s.%s" % (module, method)
    for module in ("requests", "httpx")
    for method in ("get", "post", "put", "patch", "delete", "head", "options", "request")
) | {"urllib.request.urlopen"}

# A source line goes into the report and into the JSON stream as it is. A
# control byte or an ANSI escape in that line acts on the terminal that prints
# the report, so every snippet is cleaned first. A tab becomes one space, which
# keeps the words apart.
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
CONTROL_BYTES = {code: None for code in range(32) if code != 9}
CONTROL_BYTES[9] = " "
CONTROL_BYTES[127] = None

# A SEC001 hit names a secret-shaped literal. Its snippet holds the literal, so
# the report would print the secret back. SEC001 gets this fixed text instead.
SECRET_SNIPPET = "<redacted: secret-shaped literal>"


def _walk_scope(body):
    """Yield the statements of a scope, stopping at a nested def or class."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for field in ("body", "orelse", "finalbody"):
            inner = getattr(stmt, field, None)
            if isinstance(inner, list):
                for nested in _walk_scope(inner):
                    yield nested
        for handler in getattr(stmt, "handlers", None) or []:
            for nested in _walk_scope(handler.body):
                yield nested


def _mentions_request(node, tainted):
    """True when the expression is rooted in the request or in a name bound to it."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and (sub.id == "request" or sub.id in tainted):
            return True
        if isinstance(sub, ast.Attribute) and sub.attr == "request":
            return True
    return False


def _collect_scope(body):
    """Map the names bound in a scope to their value nodes, and the request-derived ones.

    Bindings are collected flow-insensitively: a name assigned twice keeps both
    values, and the worst classification of the two wins. That is deliberate -
    a name rebound from a literal to an f-string must not read as a literal.
    """
    bindings = {}
    assignments = []
    for stmt in _walk_scope(body):
        if isinstance(stmt, ast.Assign):
            names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            for name in names:
                bindings.setdefault(name, []).append(stmt.value)
            assignments.append((names, stmt.value))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None:
                bindings.setdefault(stmt.target.id, []).append(stmt.value)
                assignments.append(([stmt.target.id], stmt.value))
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            names = [n.id for n in ast.walk(stmt.target) if isinstance(n, ast.Name)]
            assignments.append((names, stmt.iter))

    tainted = set()
    for _ in range(4):
        grew = False
        for names, value in assignments:
            if _mentions_request(value, tainted):
                for name in names:
                    if name not in tainted:
                        tainted.add(name)
                        grew = True
        if not grew:
            break
    return bindings, tainted


def _all_constant(nodes):
    """True when every node is a literal, looking inside list and tuple displays."""
    for node in nodes:
        if isinstance(node, ast.Constant):
            continue
        if isinstance(node, (ast.List, ast.Tuple)) and _all_constant(node.elts):
            continue
        if isinstance(node, ast.JoinedStr) and not any(
                isinstance(v, ast.FormattedValue) for v in node.values):
            continue
        return False
    return True


def _literal(node):
    """Return the literal value of a node, or None when it is not one."""
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _sanitize(text):
    """Remove the ANSI escapes and the control bytes from one snippet."""
    return ANSI_ESCAPE.sub("", text).translate(CONTROL_BYTES)


def _target_name(node):
    """The bound name of an assignment target, whether plain or an attribute."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class Scanner(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.hits = []
        self.imported = {}
        self.scopes = []

    # -- infrastructure ----------------------------------------------------

    def run(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.imported[alias.asname] = alias.name
                    else:
                        # `import a.b` binds the name `a`, and `a` is the
                        # package `a`. A map from `a` to `a.b` makes a chain
                        # resolve with the second part twice.
                        top = alias.name.split(".")[0]
                        self.imported[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    self.imported[alias.asname or alias.name] = "%s.%s" % (node.module, alias.name)
        self.scopes.append(_collect_scope(tree.body))
        self.generic_visit(tree)
        return self.hits

    def _snippet(self, lineno):
        if 1 <= lineno <= len(self.lines):
            return _sanitize(self.lines[lineno - 1].strip()[:160])
        return ""

    def _emit(self, node, rule, severity=None, message=None):
        category, default_severity, reference, default_message = RULES[rule]
        snippet = SECRET_SNIPPET if rule == "SEC001" else self._snippet(node.lineno)
        self.hits.append(Hit(self.path, node.lineno, node.col_offset + 1, rule,
                             severity or default_severity, category,
                             message or default_message, reference, snippet))

    def _dotted(self, node):
        """The dotted path of a name or attribute chain, resolved through imports."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(node.id)
        parts.reverse()
        head = self.imported.get(parts[0])
        if head:
            parts[0:1] = head.split(".")
        return ".".join(parts)

    def _lookup(self, name):
        for bindings, _ in reversed(self.scopes):
            if name in bindings:
                return bindings[name]
        return None

    def _tainted(self, node):
        names = set()
        for _, tainted in self.scopes:
            names |= tainted
        return _mentions_request(node, names)

    # -- classification ----------------------------------------------------

    def _classify(self, node, depth=0):
        """Decide whether an expression is a literal, interpolated, or unknown."""
        if node is None or depth > 4:
            return UNRESOLVED
        if isinstance(node, ast.Constant):
            return CONSTANT if isinstance(node.value, (str, bytes)) else UNRESOLVED
        if isinstance(node, ast.JoinedStr):
            return INTERPOLATED if any(isinstance(v, ast.FormattedValue)
                                       for v in node.values) else CONSTANT
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mod):
                return INTERPOLATED
            if isinstance(node.op, ast.Add):
                sides = (self._classify(node.left, depth + 1),
                         self._classify(node.right, depth + 1))
                return CONSTANT if sides == (CONSTANT, CONSTANT) else INTERPOLATED
            return UNRESOLVED
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "format":
                return INTERPOLATED
            return UNRESOLVED
        if isinstance(node, ast.Name):
            values = self._lookup(node.id)
            if not values:
                return UNRESOLVED
            kinds = {self._classify(value, depth + 1) for value in values}
            if INTERPOLATED in kinds:
                return INTERPOLATED
            if UNRESOLVED in kinds:
                return UNRESOLVED
            return CONSTANT
        return UNRESOLVED

    def _report_query(self, node, query, sink, allow_unresolved=True):
        kind = self._classify(query)
        if kind == INTERPOLATED:
            self._emit(node, "SQL001",
                       message="%s: SQL text is built by string interpolation - pass values as "
                               "parameters instead" % sink)
        elif kind == UNRESOLVED and allow_unresolved:
            self._emit(node, "SQL002",
                       message="%s: SQL text comes from an unresolved expression - confirm it is "
                               "a literal and that values are passed as parameters" % sink)

    # -- scopes ------------------------------------------------------------

    def _visit_scoped(self, node):
        self._check_decorators(node)
        self.scopes.append(_collect_scope(node.body))
        self.generic_visit(node)
        self.scopes.pop()

    visit_FunctionDef = _visit_scoped
    visit_AsyncFunctionDef = _visit_scoped

    def visit_ClassDef(self, node):
        self._check_decorators(node)
        self.generic_visit(node)

    def _check_decorators(self, node):
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
            if name == "csrf_exempt":
                self._emit(decorator, "CFG005")
            elif name == "bypass_get_queryset":
                self._emit(decorator, "CFG006")

    # -- assignments -------------------------------------------------------

    def visit_Assign(self, node):
        for target in node.targets:
            self._check_assignment(target, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._check_assignment(node.target, node.value, node)
        self.generic_visit(node)

    def _check_assignment(self, target, value, node):
        name = _target_name(target)
        if not name:
            return
        upper = name.upper()

        if upper == "DEBUG" and _literal(value) is True:
            self._emit(node, "CFG003")
        elif upper == "CORS_ALLOW_ALL_ORIGINS" and _literal(value) is True:
            self._emit(node, "CFG002")
        elif upper == "ALLOWED_HOSTS":
            hosts = _literal(value)
            if isinstance(hosts, (list, tuple)) and "*" in hosts:
                self._emit(node, "CFG004")
        elif upper == "FIELDS" and _literal(value) == "__all__":
            self._emit(node, "CFG001")
        elif upper == "BYPASS_GET_QUERYSET" and _literal(value) is True:
            self._emit(node, "CFG006")
        elif upper == "CHECK_HOSTNAME" and _literal(value) is False:
            self._emit(node, "NET002",
                       message="check_hostname = False stops matching the certificate to the "
                               "server it came from")
        elif upper == "VERIFY_MODE" and (self._dotted(value) or "").endswith("CERT_NONE"):
            self._emit(node, "NET002",
                       message="verify_mode = ssl.CERT_NONE disables certificate verification "
                               "on this context")
        elif upper in ("CELERY_TASK_SERIALIZER", "CELERY_RESULT_SERIALIZER",
                       "TASK_SERIALIZER", "RESULT_SERIALIZER"):
            if _literal(value) == "pickle":
                self._emit(node, "DES005")
        elif upper.endswith("ACCEPT_CONTENT"):
            accepted = _literal(value)
            if isinstance(accepted, (list, tuple, set)) and any(
                    isinstance(item, str) and item.lower() in PICKLE_CONTENT for item in accepted):
                self._emit(node, "DES006")

        # A secret is a literal only when the value is a string constant, so an
        # assignment from os.environ, env(), or any other call is structurally
        # excluded rather than pattern-matched out.
        if any(upper.endswith(suffix) for suffix in SECRET_SUFFIXES):
            literal = value.value if isinstance(value, ast.Constant) else None
            if isinstance(literal, (str, bytes)) and len(literal) >= 8:
                self._emit(node, "SEC001")

    # -- calls -------------------------------------------------------------

    def visit_Call(self, node):
        func = node.func
        attr = func.attr if isinstance(func, ast.Attribute) else None
        bare = func.id if isinstance(func, ast.Name) else None
        dotted = self._dotted(func)

        self._check_sql(node, attr, bare, func)
        self._check_identifier_positions(node, attr, bare)
        self._check_execution(node, bare, dotted)
        self._check_deserialization(node, dotted)
        self._check_output(node, attr, bare)
        self._check_keywords(node)
        if dotted in ("random.random", "random.randint", "random.choice", "random.shuffle",
                      "random.sample", "random.Random"):
            self._emit(node, "RND001")
        if dotted == "ssl._create_unverified_context":
            self._emit(node, "NET002")
        if dotted == "jwt.decode":
            self._check_jwt_decode(node)
        if dotted in HTTP_FETCHERS:
            self._check_outbound_url(node, dotted)
        self.generic_visit(node)

    def _check_jwt_decode(self, node):
        for kw in node.keywords:
            if kw.arg == "verify" and _literal(kw.value) is False:
                self._emit(node, "SEC002")
                return
            if kw.arg == "options":
                options = _literal(kw.value)
                if isinstance(options, dict) and options.get("verify_signature") is False:
                    self._emit(node, "SEC002")
                    return

    def _check_outbound_url(self, node, dotted):
        index = 1 if dotted.endswith(".request") else 0
        url = None
        if len(node.args) > index:
            url = node.args[index]
        else:
            for kw in node.keywords:
                if kw.arg == "url":
                    url = kw.value
        if url is not None and self._tainted(url):
            self._emit(node, "NET003")

    def _check_sql(self, node, attr, bare, func):
        if attr in CURSOR_METHODS and node.args:
            if attr == "execute" and not self._cursorish(func.value):
                # Report only an interpolated query on an unrecognized receiver:
                # `.execute` is a common method name outside a DB-API cursor.
                if self._classify(node.args[0]) == INTERPOLATED:
                    self._report_query(node, node.args[0], "%s()" % attr)
            else:
                self._report_query(node, node.args[0], "%s()" % attr)
        elif attr == "raw" and node.args:
            self._report_query(node, node.args[0], "raw()")
        elif (bare == "RawSQL" or attr == "RawSQL") and node.args:
            self._report_query(node, node.args[0], "RawSQL()")
        elif attr == "extra":
            for fragment in self._extra_fragments(node):
                self._report_query(node, fragment, "extra()")

    @staticmethod
    def _cursorish(node):
        for sub in ast.walk(node):
            name = None
            if isinstance(sub, ast.Name):
                name = sub.id.lower()
            elif isinstance(sub, ast.Attribute):
                name = sub.attr.lower()
            if name and (name in CURSORISH or "cursor" in name):
                return True
        return False

    @staticmethod
    def _extra_fragments(node):
        carriers = []
        for index, arg in enumerate(node.args):
            if index in EXTRA_SQL_POSITIONS:
                carriers.append(arg)
        for keyword in node.keywords:
            if keyword.arg in EXTRA_SQL_KEYWORDS:
                carriers.append(keyword.value)
        fragments = []
        for carrier in carriers:
            if isinstance(carrier, (ast.List, ast.Tuple, ast.Set)):
                fragments.extend(carrier.elts)
            elif isinstance(carrier, ast.Dict):
                fragments.extend(carrier.values)
            else:
                fragments.append(carrier)
        return fragments

    def _check_identifier_positions(self, node, attr, bare):
        name = attr or bare
        if name not in IDENT_EXPANSION_METHODS:
            return
        for keyword in node.keywords:
            # `arg is None` is the ** form; a named keyword is a value position.
            if keyword.arg is None and self._tainted(keyword.value):
                self._emit(node, "IDN001")
        if name in IDENT_POSITIONAL_METHODS:
            for arg in node.args:
                if self._tainted(arg):
                    self._emit(node, "IDN002")

    def _check_execution(self, node, bare, dotted):
        if dotted in ("os.system", "os.popen"):
            if _all_constant(node.args):
                self._emit(node, "CMD001", severity="LOW",
                           message="os.system/os.popen with a constant command - hygiene: use a "
                                   "subprocess argument list, which never reaches a shell")
            else:
                self._emit(node, "CMD001")
        # eval is flagged only as a bare name. An attribute call named eval
        # belongs to an unrelated object - a model, an expression tree, a
        # PyTorch module - and is not the builtin.
        if bare in ("eval", "exec", "compile") and dotted == bare:
            if _all_constant(node.args):
                self._emit(node, "CMD003", severity="LOW",
                           message="%s() on constant arguments - hygiene: it still invokes the "
                                   "interpreter at runtime" % bare)
            else:
                self._emit(node, "CMD003",
                           message="%s() evaluates source at runtime and one of its arguments is "
                                   "not a constant" % bare)

    def _check_deserialization(self, node, dotted):
        if dotted in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
                      "_pickle.load", "_pickle.loads", "dill.load", "dill.loads",
                      "cloudpickle.load", "cloudpickle.loads", "joblib.load"):
            self._emit(node, "DES001")
        elif dotted in ("marshal.load", "marshal.loads"):
            self._emit(node, "DES003")
        elif dotted in ("jsonpickle.decode", "jsonpickle.loads"):
            self._emit(node, "DES004")
        elif dotted in ("yaml.unsafe_load", "yaml.unsafe_load_all"):
            self._emit(node, "DES002",
                       message="yaml.unsafe_load constructs arbitrary Python objects - use "
                               "yaml.safe_load")
        elif dotted in ("yaml.full_load", "yaml.full_load_all"):
            self._emit(node, "DES002", severity="MEDIUM",
                       message="yaml.full_load constructs a wider object set than safe_load - "
                               "use yaml.safe_load unless the wider set is deliberate")
        elif dotted in ("yaml.load", "yaml.load_all"):
            loader = None
            for keyword in node.keywords:
                if keyword.arg == "Loader":
                    loader = keyword.value
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            if loader is None:
                self._emit(node, "DES002",
                           message="yaml.load without a Loader argument constructs arbitrary "
                                   "Python objects - use yaml.safe_load")
            else:
                named = self._dotted(loader) or ""
                if not named.split(".")[-1].endswith("SafeLoader"):
                    self._emit(node, "DES002",
                               message="yaml.load with a Loader that is not a SafeLoader "
                                       "constructs arbitrary Python objects")

    def _check_output(self, node, attr, bare):
        name = attr or bare
        if name == "mark_safe" and node.args:
            if self._classify(node.args[0]) != CONSTANT:
                self._emit(node, "TPL001")
        elif name == "format_html" and node.args:
            if self._classify(node.args[0]) == INTERPOLATED:
                self._emit(node, "TPL002")
        elif name in ("Template", "from_string") and node.args:
            if name == "Template" and self._dotted(node.func) == "string.Template":
                return
            if self._classify(node.args[0]) != CONSTANT:
                self._emit(node, "TPL003")

    def _check_keywords(self, node):
        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            value = _literal(keyword.value)
            if keyword.arg == "verify" and value is False:
                self._emit(node, "NET001")
            elif keyword.arg == "autoescape" and value is False:
                self._emit(node, "TPL004")
            elif keyword.arg == "bypass_get_queryset" and value is True:
                self._emit(node, "CFG006")
            elif keyword.arg == "shell" and value is True:
                if not _all_constant(node.args):
                    self._emit(node, "CMD002")


def scan_source(path, source):
    """Return (hits, unparsed) for one module's source text."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [], Unparsed(path, exc.lineno or 0, exc.offset or 0, exc.msg or "syntax error")
    except ValueError as exc:
        return [], Unparsed(path, 0, 0, str(exc))
    return Scanner(path, source.splitlines()).run(tree), None


def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as exc:
        return [], Unparsed(path, 0, 0, str(exc))
    return scan_source(path, source)


def iter_py_files(root, errors=None):
    """Yield every .py file under root, recording the directories it cannot read."""
    def record(exc):
        if errors is not None:
            errors.append((getattr(exc, "filename", None) or root, str(exc)))

    for dirpath, dirnames, filenames in os.walk(root, onerror=record):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


# --- self-test fixtures ----------------------------------------------------
#
# Source strings, not files: the self-test writes nothing and reads nothing.
# Each fixture states the rule identifiers it must produce, exactly. A negative
# fixture states none, and a negative fixture that produces any hit is a
# regression on correct code, which is the failure this scanner exists to
# avoid.

FIXTURES = [
    ("SQL001 interpolated cursor.execute", {"SQL001"}, '''
from django.db import connection

def lookup(user_id):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM app_user WHERE id = {user_id}")
'''),
    ("SQL001 query name rebound to an f-string", {"SQL001"}, '''
from django.db import connection

def lookup(user_id):
    sql = f"SELECT * FROM app_user WHERE id = {user_id}"
    with connection.cursor() as cursor:
        cursor.execute(sql)
'''),
    ("SQL002 unresolved query source", {"SQL002"}, '''
from django.db import connection

def lookup(name):
    sql = build_query(name)
    with connection.cursor() as cursor:
        cursor.execute(sql)
'''),
    ("IDN001 dict expansion from request data", {"IDN001"}, '''
def listing(request):
    return Article.objects.filter(**request.GET.dict())
'''),
    ("IDN002 order_by from request data", {"IDN002"}, '''
def listing(request):
    return Article.objects.order_by(request.GET["sort"])
'''),
    ("CMD001 os.system with interpolation", {"CMD001"}, '''
import os

def purge(target):
    os.system("rm -rf " + target)
'''),
    ("CMD002 shell=True with a variable command", {"CMD002"}, '''
import subprocess

def run(cmd):
    subprocess.run(cmd, shell=True)
'''),
    ("CMD003 eval on request data", {"CMD003"}, '''
def calculate(request):
    return eval(request.GET["expr"])
'''),
    ("DES001 pickle.loads", {"DES001"}, '''
import pickle

def restore(payload):
    return pickle.loads(payload)
'''),
    ("DES002 yaml.load without a Loader", {"DES002"}, '''
import yaml

def restore(payload):
    return yaml.load(payload)
'''),
    ("DES003 marshal.loads", {"DES003"}, '''
import marshal

def restore(payload):
    return marshal.loads(payload)
'''),
    ("DES004 jsonpickle.decode", {"DES004"}, '''
import jsonpickle

def restore(payload):
    return jsonpickle.decode(payload)
'''),
    ("DES005 Celery pickle serializer", {"DES005"}, '''
CELERY_TASK_SERIALIZER = "pickle"
'''),
    ("DES006 Celery accept_content admits pickle", {"DES006"}, '''
CELERY_ACCEPT_CONTENT = ["json", "pickle"]
'''),
    ("TPL001 mark_safe on a variable", {"TPL001"}, '''
from django.utils.safestring import mark_safe

def render(value):
    return mark_safe(value)
'''),
    ("TPL002 format_html with an f-string", {"TPL002"}, '''
from django.utils.html import format_html

def render(name):
    return format_html(f"<b>{name}</b>")
'''),
    ("TPL003 Template from a variable", {"TPL003"}, '''
from django.template import Template

def render(source):
    return Template(source)
'''),
    ("TPL004 autoescape disabled", {"TPL004"}, '''
from jinja2 import Environment

env = Environment(autoescape=False)
'''),
    ("NET001 verify=False", {"NET001"}, '''
import requests

def fetch(url):
    return requests.get(url, verify=False)
'''),
    ("RND001 random.choice", {"RND001"}, '''
import random

def token(alphabet):
    return "".join(random.choice(alphabet) for _ in range(32))
'''),
    ("CFG001 serializer fields __all__", {"CFG001"}, '''
class ArticleSerializer(ModelSerializer):
    class Meta:
        model = Article
        fields = "__all__"
'''),
    ("CFG002 open CORS", {"CFG002"}, '''
CORS_ALLOW_ALL_ORIGINS = True
'''),
    ("CFG003 DEBUG on", {"CFG003"}, '''
DEBUG = True
'''),
    ("CFG004 wildcard ALLOWED_HOSTS", {"CFG004"}, '''
ALLOWED_HOSTS = ["*"]
'''),
    ("CFG005 csrf_exempt view", {"CFG005"}, '''
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def webhook(request):
    return None
'''),
    ("CFG006 graphene bypass_get_queryset", {"CFG006"}, '''
from graphene_django.filter.utils import bypass_get_queryset

@bypass_get_queryset
def resolve_articles(root, info):
    return Article.objects.all()
'''),
    ("SEC001 hardcoded secret literal", {"SEC001"}, '''
SECRET_KEY = "django-insecure-7pq2m4x9v0zc1b8n"
'''),

    # Negative fixtures: correct code that the previous line-oriented scanner
    # reported, plus the cases most likely to regress.
    ("negative: parameterized cursor.execute", set(), '''
from django.db import connection

def correct(user_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM app_user WHERE id = %s", [user_id])
        return cursor.fetchall()
'''),
    ("negative: Manager.raw with params", set(), '''
def correct(pk):
    return Entry.objects.raw("SELECT * FROM blog_entry WHERE id = %s", [pk])
'''),
    ("negative: fully literal shell command", set(), '''
import subprocess

def disk_usage():
    return subprocess.run("df -h | tail -n +2", shell=True, capture_output=True)
'''),
    ("negative: mark_safe on a constant", set(), '''
from django.utils.safestring import mark_safe

BADGE = mark_safe("<span class='badge'>new</span>")
'''),
    ("negative: yaml.load with SafeLoader", set(), '''
import yaml

def correct(payload):
    return yaml.load(payload, Loader=yaml.SafeLoader)
'''),
    ("negative: secret from the environment", set(), '''
import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
API_TOKEN = os.environ.get("API_TOKEN", "")
'''),
    ("negative: literal dict expanded into filter", set(), '''
DEFAULTS = {"is_active": True}

def correct():
    return Article.objects.filter(**DEFAULTS)
'''),
    ("negative: module-level SQL constant", set(), '''
from django.db import connection

ACTIVE_USERS = "SELECT id FROM app_user WHERE is_active = true"

def correct():
    with connection.cursor() as cursor:
        cursor.execute(ACTIVE_USERS)
'''),
    ("negative: eval as an attribute, SystemRandom, secrets", set(), '''
import secrets
from random import SystemRandom

def correct(model, expression):
    model.eval()
    expression.eval(strict=True)
    return secrets.token_urlsafe(32), SystemRandom().choice("abc")
'''),
    ("negative: dangerous text inside a docstring", set(), '''
def documented():
    """Never write os.system("rm -rf /") or eval(user_input) here.

    Nor cursor.execute("SELECT * FROM t WHERE id = %s" % pk).
    """
    return None
'''),
    ("DES002 yaml.unsafe_load", {"DES002"}, '''
import yaml

def parse(payload):
    return yaml.unsafe_load(payload)
'''),
    ("DES002 yaml.full_load through from-import", {"DES002"}, '''
from yaml import full_load

def parse(payload):
    return full_load(payload)
'''),
    ("DES001 joblib.load", {"DES001"}, '''
import joblib

def restore(path):
    return joblib.load(path)
'''),
    ("TPL002 format_html on a percent-formatted template", {"TPL002"}, '''
from django.utils.html import format_html

def row(value):
    return format_html("<td>%s</td>" % value)
'''),
    ("SEC002 jwt.decode with verification off", {"SEC002"}, '''
import jwt

def read_token(token, key):
    return jwt.decode(token, key, options={"verify_signature": False})
'''),
    ("NET002 unverified ssl context", {"NET002"}, '''
import ssl

def insecure_context():
    context = ssl._create_unverified_context()
    context.check_hostname = False
    return context
'''),
    ("NET003 fetch of a request-derived URL", {"NET003"}, '''
import requests

def preview(request):
    target = request.GET["url"]
    return requests.get(target, timeout=5)
'''),
    ("NET003 urlopen of a request-derived URL", {"NET003"}, '''
import urllib.request

def preview(request):
    return urllib.request.urlopen(request.GET["url"])
'''),
    ("negative: string.Template from a bare import", set(), '''
from string import Template

def greeting(name):
    return Template("Hello, $name").substitute(name=name)
'''),
    ("negative: fetch of an operator-configured URL", set(), '''
import requests

WEBHOOK_URL = "https://hooks.internal.example/notify"

def notify(payload):
    return requests.post(WEBHOOK_URL, json=payload, timeout=5)
'''),
    ("negative: jwt.decode with verification on", set(), '''
import jwt

def read_token(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], audience="api")
'''),
    ("negative: format_html with a placeholder template", set(), '''
from django.utils.html import format_html

def row(value):
    return format_html("<td>{}</td>", value)
'''),
]


def selftest():
    print("# selftest: dangerous_patterns.py")
    positive = sum(1 for _, expected, _ in FIXTURES if expected)
    print("# %d fixture(s): %d positive, %d negative\n"
          % (len(FIXTURES), positive, len(FIXTURES) - positive))

    failures = []
    passed = 0
    for name, expected, source in FIXTURES:
        hits, unparsed = scan_source("<%s>" % name, source)
        produced = {hit.rule for hit in hits}
        if unparsed is not None:
            failures.append("%s: fixture did not parse (%s)" % (name, unparsed.error))
            status, produced_text = "FAIL", "unparsed"
        else:
            produced_text = ", ".join(sorted(produced)) or "-"
            if produced == expected:
                status = "ok"
                passed += 1
            else:
                status = "FAIL"
                failures.append(
                    "%s: expected {%s}, got {%s}"
                    % (name, ", ".join(sorted(expected)) or "-", produced_text))
        print("[%-4s] %-46s expected: %-10s got: %s"
              % (status, name, ", ".join(sorted(expected)) or "-", produced_text))

    covered = set()
    for _, expected, _ in FIXTURES:
        covered |= expected
    missing = sorted(set(RULES) - covered)
    print("\n# rule coverage: %d/%d rules have a positive fixture" % (len(covered), len(RULES)))
    if missing:
        failures.append("no positive fixture for: %s" % ", ".join(missing))
        print("# uncovered rules: %s" % ", ".join(missing))

    # A SEC001 snippet must never carry the literal it reports. The canary is
    # scanned here rather than in FIXTURES, because a fixture states rules and
    # this check states the text of a snippet.
    canary = "CANARY-9f4k2m8q1x"
    canary_hits, _ = scan_source("<redaction>", 'SECRET_KEY = "%s"\n' % canary)
    leaked = [hit for hit in canary_hits if canary in hit.snippet]
    if not canary_hits:
        failures.append("redaction: the canary assignment produced no hit to redact")
    if leaked:
        failures.append("redaction: the secret literal reached %d snippet(s)" % len(leaked))
    print("# redaction: %s"
          % ("FAILED" if leaked or not canary_hits
             else "the secret literal is absent from every snippet"))

    print("# %d fixture(s) passed, %d check(s) failed." % (passed, len(failures)))
    if failures:
        print("\n# FAILURES")
        for failure in failures:
            print("#   %s" % failure)
    else:
        print("# every negative fixture produced no hit.")
    # The self-test is the one path where a nonzero exit is part of the
    # contract: CI reads it as the gate on this scanner.
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(
        description="Read-only, AST-based risky-pattern indicator scan.")
    parser.add_argument("path", nargs="?", help="Directory (or file) to scan; defaults to .")
    parser.add_argument("--json", action="store_true",
                        help="Emit one JSON object per record, one per line")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
                        help="Suppress hits below this severity (default: LOW)")
    parser.add_argument("--selftest", action="store_true",
                        help="Run the embedded fixtures and exit; takes no path")
    args = parser.parse_args()

    if args.selftest:
        if args.path:
            print("--selftest runs alone; ignoring %s" % args.path, file=sys.stderr)
        return selftest()

    path = args.path or "."
    walk_errors = []
    missing = False
    if os.path.isfile(path):
        targets = [path]
    elif os.path.isdir(path):
        targets = list(iter_py_files(path, walk_errors))
    else:
        targets = []
        missing = True
        if not args.json:
            print("Not a file or directory: %s" % path, file=sys.stderr)

    threshold = SEVERITY_ORDER[args.min_severity]
    per_file = []
    unparsed = []
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total = 0
    for target in sorted(targets):
        hits, failure = scan_file(target)
        if failure is not None:
            unparsed.append(failure)
            continue
        kept = [hit for hit in hits if SEVERITY_ORDER[hit.severity] >= threshold]
        kept.sort(key=lambda hit: (hit.line, hit.column, hit.rule))
        if kept:
            per_file.append((target, kept))
            total += len(kept)
            for hit in kept:
                counts[hit.severity] += 1

    if args.json:
        if missing:
            print(json.dumps({"kind": "error", "file": path,
                              "error": "not a file or directory"}, sort_keys=True))
        for target, hits in per_file:
            for hit in hits:
                print(json.dumps({
                    "kind": "hit",
                    "file": hit.path,
                    "line": hit.line,
                    "column": hit.column,
                    "rule": hit.rule,
                    "severity": hit.severity,
                    "category": hit.category,
                    "message": hit.message,
                    "reference": hit.reference,
                    "snippet": hit.snippet,
                }, sort_keys=True))
        for failure in unparsed:
            print(json.dumps({
                "kind": "unparsed",
                "file": failure.path,
                "line": failure.line,
                "column": failure.column,
                "error": failure.error,
            }, sort_keys=True))
        # The stream always ends here, so a reader that gets no summary knows
        # the scan stopped rather than finding nothing.
        print(json.dumps({
            "kind": "summary",
            "path": path,
            "files_discovered": len(targets),
            "files_scanned": len(targets) - len(unparsed),
            "files_unparsed": len(unparsed),
            "hits": total,
            "walk_errors": len(walk_errors),
        }, sort_keys=True))
        return 0

    for target, hits in per_file:
        print("\n%s" % target)
        for hit in hits:
            print("  %s:%d:%d: [%s] %s (%s) %s (%s)"
                  % (hit.path, hit.line, hit.column, hit.severity, hit.rule,
                     hit.category, hit.message, hit.reference))
            print("      | %s" % hit.snippet)

    if unparsed:
        print("\n# unparsed")
        for failure in unparsed:
            print("  %s: %s" % (failure.path, failure.error))

    if walk_errors:
        print("\n# not traversed")
        for directory, error in walk_errors:
            print("  %s: %s" % (directory, error))

    print("\n# %d indicator(s): %d high, %d medium, %d low."
          % (total, counts["HIGH"], counts["MEDIUM"], counts["LOW"]))
    print("# %d file(s) discovered, %d scanned, %d unparsed; %d traversal error(s)."
          % (len(targets), len(targets) - len(unparsed), len(unparsed), len(walk_errors)))
    if unparsed:
        print("# %d file(s) could not be parsed and were NOT scanned - a silent skip would look "
              "like a clean result." % len(unparsed))
    if walk_errors:
        print("# %d director(ies) could not be read and were NOT scanned - a silent skip would "
              "look like a clean result." % len(walk_errors))
    print("# Indicators are leads, not confirmed findings. Verify each by reading the code and "
          "tracing the data flow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
