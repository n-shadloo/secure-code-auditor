#!/usr/bin/env python3
"""
entrypoint_inventory.py - read-only inventory of where execution enters.

Parses every .py file in a tree with the ast module and reports every declared
way execution begins on input the application did not author: URL routes
resolved through their include() chain to the full prefix, DRF routers,
viewsets and views, @action methods, Django Ninja operations, GraphQL schemas
and resolvers, gRPC servicers, Channels routing and consumers, Celery tasks and
beat entries, management commands, signal receivers, admin registrations, and -
when a settings path is supplied - MIDDLEWARE in declared order.

It is an inventory, not a judgement. It reports what a module declares; whether
a declaration is right for the surface it sits on is a question for the
reference file each family names, answered by reading the code. The
authorization column says where a declaration is, never whether it is correct,
and it separates "inherited, so not visible from here" from "absent" because
collapsing those two rebuilds the false positive this exists to avoid.

It finds declarations. A route registered at runtime, a viewset assembled by a
factory, a task registered from a loop - none of them appears here, and closing
that gap is what reading the code is for.

It reads files only. It makes NO network calls, imports nothing from the target
project, and never modifies anything.

Usage:
    python scripts/entrypoint_inventory.py path/to/project
    python scripts/entrypoint_inventory.py . --settings config/settings
    python scripts/entrypoint_inventory.py . --kind url,drf,action
    python scripts/entrypoint_inventory.py . --json

Requires Python 3.9 or later. Exit code is always 0.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from collections import namedtuple

# settings_scan.py ships beside this file and owns the settings-package
# resolution both scripts need. Only --settings depends on it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from settings_scan import resolve_package, resolve_settings
except ImportError:  # pragma: no cover - only when the file is copied out alone
    resolve_package = resolve_settings = None

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
             "__pycache__", ".mypy_cache", ".tox", "build", "dist", ".eggs"}

# family -> (heading, the reference file that owns its rules)
FAMILIES = {
    "url": ("URL routing", "authorization-architecture.md"),
    "drf": ("DRF routers, viewsets, and views", "api-drf-specific.md"),
    "action": ("Viewset @action methods", "api-drf-specific.md"),
    "ninja": ("Django Ninja APIs, routers, and operations",
              "graphql-and-alternative-api-surfaces.md"),
    "graphql": ("GraphQL schemas, types, and resolvers",
                "graphql-and-alternative-api-surfaces.md"),
    "grpc": ("gRPC servicers", "graphql-and-alternative-api-surfaces.md"),
    "channels": ("Channels routing and consumers", "async-and-channels.md"),
    "celery": ("Celery tasks and beat schedules", "a08-integrity-and-deserialization.md"),
    "command": ("Management commands", "a05-injection.md"),
    "signal": ("Signal receivers", "a09-logging-and-alerting.md"),
    "admin": ("Admin registrations and actions", "authorization-architecture.md"),
    "middleware": ("Middleware, in declared order", "authorization-architecture.md"),
}

# The three states of the authorization column, and nothing else.
#   DECLARED  - this site declares it, and the value is printed beside the row.
#   INHERITED - this site declares nothing and something upstream supplies it:
#               a base class, a framework default, a router-level auth. Not
#               visible from here, which is a different fact from its absence.
#   ABSENT    - this site declares nothing and the construct has no default
#               that would supply one. Middleware or an in-body check may still
#               apply; this column looks for neither.
DECLARED = "declared"
INHERITED = "inherited"
ABSENT = "absent"

ROUTE_FUNCTIONS = {"path", "re_path", "url"}
ROUTER_CONSTRUCTORS = {"DefaultRouter", "SimpleRouter", "BulkRouter", "NestedDefaultRouter",
                       "NestedSimpleRouter", "ExtendedDefaultRouter", "ExtendedSimpleRouter"}

DRF_VIEW_BASES = {"APIView", "GenericAPIView", "ViewSet", "GenericViewSet", "ModelViewSet",
                  "ReadOnlyModelViewSet", "ViewSetMixin"}
PLAIN_VIEW_BASES = {"View", "TemplateView", "ListView", "DetailView", "CreateView", "UpdateView",
                    "DeleteView", "FormView", "RedirectView", "object"}
AUTH_MIXINS = {"LoginRequiredMixin", "PermissionRequiredMixin", "UserPassesTestMixin",
               "AccessMixin"}
AUTH_DECORATORS = {"login_required", "permission_required", "user_passes_test",
                   "staff_member_required", "permission_classes"}

# Declared on a view class, reported with their literal values where present.
VIEW_ATTRIBUTES = ("permission_classes", "authentication_classes", "throttle_classes",
                   "queryset", "serializer_class")
# Overridden on a view class, reported by name: each one moves a decision from
# the class attribute to code that has to be read.
VIEW_OVERRIDES = ("get_queryset", "get_object", "get_serializer_class", "perform_create",
                  "check_object_permissions")

NINJA_OPERATIONS = {"get", "post", "put", "patch", "delete", "api_operation"}
GRAPHQL_TYPE_BASES = {"ObjectType", "DjangoObjectType", "Mutation", "ClientIDMutation",
                      "DjangoObjectTypeOptions", "Subscription"}

Entry = namedtuple("Entry", "family path line column label detail authz")
Unparsed = namedtuple("Unparsed", "path line column error")
Decl = namedtuple("Decl", "line column pattern view name include")
Include = namedtuple("Include", "kind value")
Registration = namedtuple("Registration", "line column prefix viewset basename router")
View = namedtuple("View", "name path line kind authz detail")


# --- small ast helpers ------------------------------------------------------


def tail(node):
    """The last component of a name or attribute chain, or None."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def dotted(node):
    """The dotted path of a name or attribute chain, or None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    parts.reverse()
    return ".".join(parts)


def literal(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def render(node):
    """A short rendering of an expression, for reporting only."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else repr(node.value)
    name = dotted(node)
    if name:
        return name
    if isinstance(node, ast.Call):
        called = dotted(node.func)
        return "%s(...)" % called if called else "<call>"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return "[%s]" % ", ".join(render(element) or "?" for element in node.elts)
    if isinstance(node, ast.Dict):
        return "{...}"
    return "<expression>"


def view_target(node):
    """The view an entry in a URLconf names: Foo.as_view(), views.foo, or a name."""
    if node is None:
        return None
    if isinstance(node, ast.Call):
        if tail(node.func) == "as_view":
            return render(node.func.value)
        return render(node)
    return render(node)


def keyword(call, name):
    for entry in call.keywords:
        if entry.arg == name:
            return entry.value
    return None


def has_keyword(call, name):
    return any(entry.arg == name for entry in call.keywords)


def statements(body):
    """Module-level statements, descending into if/try so a conditional
    urlpatterns block is still enumerated."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, (ast.If, ast.Try)):
            for field in ("body", "orelse", "finalbody"):
                for nested in statements(getattr(stmt, field, []) or []):
                    yield nested
            for handler in getattr(stmt, "handlers", []) or []:
                for nested in statements(handler.body):
                    yield nested


def decorator_names(node):
    """Every decorator on a definition, as (name, call_node_or_None)."""
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            yield tail(decorator.func), decorator
        else:
            yield tail(decorator), None


# --- one module -------------------------------------------------------------


class ModuleScan:
    """Everything one module declares. Nothing here crosses a file boundary."""

    def __init__(self, path, module, tree):
        self.path = path
        self.module = module
        self.tree = tree
        self.imports = set()
        self.routes = {}        # name -> [Decl], in source order
        self.routers = {}       # router variable -> [Registration]
        self.ninja = {}         # api/router variable -> auth declared at construction
        self.views = {}         # class or function name -> View
        self.entries = []       # everything not resolved through the URLconf
        self._consumed = set()  # nodes already accounted for as an include target

    # -- entry ---------------------------------------------------------------

    def collect(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.imports.add(node.module.split(".")[0])

        self._collect_constructions()
        self._collect_registrations()
        for node in statements(self.tree.body):
            if isinstance(node, ast.ClassDef):
                self._class(node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(node)
        self._collect_routes()
        self._collect_signal_connects()
        self._collect_command()
        return self

    def add(self, family, node, label, detail=None, authz=None):
        self.entries.append(Entry(family, self.path, node.lineno, node.col_offset + 1,
                                  label, detail or {}, authz))

    # -- constructions bound to a name ---------------------------------------

    def _collect_constructions(self):
        for node in statements(self.tree.body):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            called = tail(node.value.func)
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if called in ROUTER_CONSTRUCTORS:
                    self.routers.setdefault(target.id, [])
                    self.add("drf", node, "%s = %s()" % (target.id, called),
                             {"router": called,
                              "note": "DefaultRouter also mounts an API root and format-suffixed "
                                      "variants of every route"
                                      if called.endswith("DefaultRouter") else None})
                elif called == "NinjaAPI" or (called == "Router" and "ninja" in self.imports):
                    declared = has_keyword(node.value, "auth")
                    self.ninja[target.id] = declared
                    self.add("ninja", node, "%s = %s()" % (target.id, called),
                             {"auth": render(keyword(node.value, "auth")) if declared else None},
                             DECLARED if declared else ABSENT)
                elif called == "Schema" and self.imports & {"graphene", "strawberry", "ariadne"}:
                    self.add("graphql", node, "%s = Schema()" % target.id,
                             {"query": render(keyword(node.value, "query")),
                              "mutation": render(keyword(node.value, "mutation"))})

    # -- calls anywhere in the module ----------------------------------------

    def _collect_registrations(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            called = tail(node.func)
            if called == "register" and isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if isinstance(receiver, ast.Name) and receiver.id in self.routers and node.args:
                    self.routers[receiver.id].append(Registration(
                        node.lineno, node.col_offset + 1,
                        render(node.args[0]),
                        render(node.args[1]) if len(node.args) > 1 else
                        render(keyword(node, "viewset")),
                        render(keyword(node, "basename")), receiver.id))
                elif dotted(node.func) in ("admin.site.register", "site.register") and node.args:
                    self.add("admin", node, "admin.site.register(%s)" % render(node.args[0]),
                             {"admin_class": render(node.args[1]) if len(node.args) > 1 else None},
                             INHERITED)
            elif called == "ProtocolTypeRouter" and node.args:
                self._protocol_router(node)
            elif called == "URLRouter" and node.args:
                for decl in self._decls(node.args[0]):
                    self.add("channels", node, decl.pattern or "?",
                             {"consumer": decl.view, "name": decl.name}, INHERITED)

    def _protocol_router(self, node):
        mapping = node.args[0]
        if not isinstance(mapping, ast.Dict):
            self.add("channels", node, "ProtocolTypeRouter(<dynamic>)", {}, INHERITED)
            return
        for key, value in zip(mapping.keys, mapping.values):
            protocol = literal(key) or "?"
            wrapper = render(value) or "<expression>"
            authenticated = "AuthMiddleware" in ast.dump(value)
            self.add("channels", node, "ProtocolTypeRouter[%s]" % protocol,
                     {"stack": wrapper}, DECLARED if authenticated else ABSENT)

    def _collect_signal_connects(self):
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Call) and tail(node.func) == "connect"
                    and isinstance(node.func, ast.Attribute) and node.args):
                signal = render(node.func.value)
                if not signal:
                    continue
                self.add("signal", node, "%s.connect(%s)" % (signal, render(node.args[0])),
                         {"signal": signal, "sender": render(keyword(node, "sender"))})

    # -- definitions ---------------------------------------------------------

    def _class(self, node):
        bases = [render(base) for base in node.bases]
        base_tails = {tail(base) for base in node.bases if tail(base)}
        body_names = {stmt.name for stmt in node.body
                      if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))}
        attributes = self._class_attributes(node)
        decorators = dict(decorator_names(node))

        if any(name.endswith("Servicer") for name in base_tails):
            self.add("grpc", node, node.name,
                     {"bases": bases, "methods": sorted(body_names)}, ABSENT)
            return

        if any(name.endswith("Consumer") for name in base_tails):
            self.add("channels", node, node.name,
                     {"bases": bases, "methods": sorted(body_names)}, INHERITED)
            return

        if any(name.endswith("ModelAdmin") for name in base_tails) or "register" in decorators:
            registered = decorators.get("register")
            declares = any(name.startswith("has_") and name.endswith("_permission")
                           for name in body_names)
            self.add("admin", node, node.name,
                     {"model": render(registered.args[0]) if registered and registered.args
                              else None,
                      "actions": attributes.get("actions"),
                      "overrides": sorted(name for name in body_names
                                          if name.startswith("has_"))},
                     DECLARED if declares else INHERITED)
            return

        if node.name in ("Query", "Mutation", "Subscription") or base_tails & GRAPHQL_TYPE_BASES \
                or set(decorators) & {"type", "input", "interface"}:
            if self.imports & {"graphene", "strawberry", "ariadne", "graphql"}:
                resolvers = sorted(name for name in body_names
                                   if name.startswith("resolve_") or name.startswith("mutate"))
                self.add("graphql", node, node.name, {"bases": bases, "resolvers": resolvers})
                for stmt in node.body:
                    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                            and (stmt.name.startswith("resolve_")
                                 or stmt.name.startswith("mutate")):
                        names = {name for name, _ in decorator_names(stmt)}
                        self.add("graphql", stmt, "%s.%s" % (node.name, stmt.name), {},
                                 DECLARED if names & AUTH_DECORATORS else INHERITED)
                return

        drf = bool(base_tails & DRF_VIEW_BASES) or any(
            name.endswith("ViewSet") or name.endswith("APIView") for name in base_tails)
        plain = bool(base_tails & PLAIN_VIEW_BASES)
        if not (drf or plain or base_tails & AUTH_MIXINS):
            return

        authz = self._class_authz(base_tails, attributes, decorators, drf)
        detail = {"bases": bases}
        for name in VIEW_ATTRIBUTES:
            detail[name] = attributes.get(name)
        detail["overrides"] = sorted(name for name in VIEW_OVERRIDES if name in body_names)
        self.views[node.name] = View(node.name, self.path, node.lineno,
                                     "drf" if drf else "django", authz, detail)
        # A plain Django view is not a row of its own: it reaches the inventory
        # through the route that names it, carrying the state recorded here.
        if drf:
            self.add("drf", node, node.name, detail, authz)
        self._actions(node)

    def _class_attributes(self, node):
        found = {}
        for stmt in node.body:
            targets = []
            if isinstance(stmt, ast.Assign):
                targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                value = stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                targets, value = [stmt.target.id], stmt.value
            else:
                continue
            for name in targets:
                found[name] = render(value)
        return found

    @staticmethod
    def _class_authz(base_tails, attributes, decorators, drf):
        if "permission_classes" in attributes or base_tails & AUTH_MIXINS \
                or set(decorators) & AUTH_DECORATORS:
            return DECLARED
        if drf:
            return INHERITED  # DEFAULT_PERMISSION_CLASSES, or a project base class
        if base_tails - PLAIN_VIEW_BASES:
            return INHERITED  # a base this file does not define
        return ABSENT

    def _actions(self, node):
        for stmt in node.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for name, call in decorator_names(stmt):
                if name != "action" or call is None:
                    continue
                declared = keyword(call, "permission_classes")
                self.add("action", stmt, "%s.%s" % (node.name, stmt.name),
                         {"detail": render(keyword(call, "detail")),
                          "methods": render(keyword(call, "methods")),
                          "url_path": render(keyword(call, "url_path")),
                          "permission_classes": render(declared)},
                         DECLARED if declared is not None else INHERITED)

    def _function(self, node):
        decorators = dict(decorator_names(node))
        names = set(decorators)

        if "shared_task" in names or any(
                tail(d.func if isinstance(d, ast.Call) else d) == "task"
                for d in node.decorator_list):
            call = decorators.get("shared_task") or decorators.get("task")
            self.add("celery", node, "%s.%s" % (self.module, node.name) if self.module
                     else node.name,
                     {"name": render(keyword(call, "name")) if call else None,
                      "bind": render(keyword(call, "bind")) if call else None,
                      "queue": render(keyword(call, "queue")) if call else None})
            return

        if "receiver" in names:
            call = decorators["receiver"]
            self.add("signal", node, node.name,
                     {"signal": render(call.args[0]) if call and call.args else None,
                      "sender": render(keyword(call, "sender")) if call else None})
            return

        for name, call in decorator_names(node):
            receiver = call.func.value if call is not None and isinstance(call.func,
                                                                         ast.Attribute) else None
            if name in NINJA_OPERATIONS and isinstance(receiver, ast.Name) \
                    and receiver.id in self.ninja:
                declared = has_keyword(call, "auth")
                self.add("ninja", node, "%s %s" % (name.upper(),
                                                   render(call.args[0]) if call.args else "?"),
                         {"operation": node.name,
                          "auth": render(keyword(call, "auth")) if declared else None,
                          "mounted_on": receiver.id},
                         DECLARED if declared
                         else (INHERITED if self.ninja[receiver.id] else ABSENT))
                return

        arguments = [argument.arg for argument in node.args.args]
        if arguments and arguments[0] == "request":
            if names & AUTH_DECORATORS:
                authz = DECLARED
            elif "api_view" in names:
                authz = INHERITED  # DRF applies DEFAULT_PERMISSION_CLASSES
            else:
                authz = ABSENT
            self.views[node.name] = View(node.name, self.path, node.lineno, "function", authz,
                                         {"decorators": sorted(names)})

    def _collect_command(self):
        parts = os.path.normpath(self.path).split(os.sep)
        if "management" not in parts or "commands" not in parts:
            return
        for node in statements(self.tree.body):
            if isinstance(node, ast.ClassDef) and node.name == "Command":
                name = os.path.splitext(os.path.basename(self.path))[0]
                arguments = any(isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                                and stmt.name == "add_arguments" for stmt in node.body)
                self.add("command", node, "manage.py %s" % name,
                         {"bases": [render(base) for base in node.bases],
                          "add_arguments": arguments})

    # -- routes --------------------------------------------------------------

    def _collect_routes(self):
        for node in statements(self.tree.body):
            targets, value = [], None
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                value = node.value
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                targets, value = [node.target.id], node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets, value = [node.target.id], node.value
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) \
                    and tail(node.value.func) == "extend":
                receiver = node.value.func.value
                if isinstance(receiver, ast.Name) and node.value.args:
                    targets, value = [receiver.id], node.value.args[0]
            if not targets or value is None:
                continue
            decls = self._decls(value) + self._bare_router_mounts(value)
            if decls:
                decls.sort(key=lambda decl: (decl.line, decl.column))
                for name in targets:
                    self.routes.setdefault(name, []).extend(decls)

            if isinstance(value, ast.Dict) and targets \
                    and targets[0].upper().endswith("BEAT_SCHEDULE"):
                self._beat_schedule(node, value)

        for node in statements(self.tree.body):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "beat_schedule":
                        self._beat_schedule(node, node.value)

    def _beat_schedule(self, node, mapping):
        for key, value in zip(mapping.keys, mapping.values):
            entry = value if isinstance(value, ast.Dict) else None
            task = schedule = None
            if entry is not None:
                for inner_key, inner_value in zip(entry.keys, entry.values):
                    if literal(inner_key) == "task":
                        task = render(inner_value)
                    elif literal(inner_key) == "schedule":
                        schedule = render(inner_value)
            self.add("celery", node, "beat: %s" % (literal(key) or render(key)),
                     {"task": task, "schedule": schedule})

    def _decls(self, node):
        decls = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and tail(sub.func) in ROUTE_FUNCTIONS and sub.args:
                decls.append(self._decl(sub))
        decls.sort(key=lambda decl: (decl.line, decl.column))
        return decls

    def _decl(self, call):
        pattern = render(call.args[0])
        target = call.args[1] if len(call.args) > 1 else keyword(call, "view")
        include = self._include(target)
        return Decl(call.lineno, call.col_offset + 1, pattern,
                    None if include else view_target(target),
                    render(keyword(call, "name")), include)

    def _include(self, node):
        if not (isinstance(node, ast.Call) and tail(node.func) == "include" and node.args):
            return None
        argument = node.args[0]
        self._consumed.add(id(argument))
        if isinstance(argument, (ast.Tuple, ast.List)) and argument.elts:
            argument = argument.elts[0]
            self._consumed.add(id(argument))
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            return Include("module", argument.value)
        if isinstance(argument, ast.Attribute) and argument.attr == "urls" \
                and isinstance(argument.value, ast.Name) and argument.value.id in self.routers:
            return Include("router", argument.value.id)
        if isinstance(argument, ast.Name):
            return Include("local", argument.id)
        return Include("unresolved", render(argument))

    def _bare_router_mounts(self, node):
        """`urlpatterns += router.urls`, which is an include with no prefix."""
        mounts = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr == "urls" \
                    and isinstance(sub.value, ast.Name) and sub.value.id in self.routers \
                    and id(sub) not in self._consumed:
                mounts.append(Decl(sub.lineno, sub.col_offset + 1, "", None, None,
                                   Include("router", sub.value.id)))
        return mounts


# --- the project ------------------------------------------------------------


def iter_py_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def module_name(root, path):
    relative = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root))
    parts = [part for part in os.path.splitext(relative)[0].split(os.sep) if part != "."]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class Project:
    def __init__(self, root):
        self.root = root
        self.modules = []
        self.unparsed = []
        self.by_dotted = {}
        self.views = {}
        self.notes = []

    def load(self):
        for path in iter_py_files(self.root):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    source = fh.read()
            except OSError as exc:
                self.unparsed.append(Unparsed(path, 0, 0, str(exc)))
                continue
            try:
                tree = ast.parse(source, filename=path)
            except (SyntaxError, ValueError) as exc:
                line = getattr(exc, "lineno", 0) or 0
                column = getattr(exc, "offset", 0) or 0
                self.unparsed.append(Unparsed(path, line, column,
                                              getattr(exc, "msg", None) or str(exc)))
                continue
            self.modules.append(ModuleScan(path, module_name(self.root, path), tree).collect())

        for scan in self.modules:
            for key in self._keys(scan.module):
                self.by_dotted.setdefault(key, []).append(scan)
            for name, view in scan.views.items():
                self.views.setdefault(name, []).append(view)
        return self

    @staticmethod
    def _keys(dotted_name):
        parts = dotted_name.split(".") if dotted_name else []
        return [".".join(parts[index:]) for index in range(len(parts))]

    def find(self, dotted_name):
        candidates = self.by_dotted.get(dotted_name, [])
        return candidates[0] if len(candidates) == 1 else None

    def view_authz(self, name):
        """The authorization state of the view a route names, if it is visible here."""
        if not name:
            return INHERITED
        candidates = self.views.get(name.split(".")[-1], [])
        if len(candidates) != 1:
            return INHERITED  # not defined in this tree, or defined more than once
        return candidates[0].authz


# --- resolving the URLconf --------------------------------------------------


def resolve_urls(project, root_urlconf=None):
    """Walk every URLconf root, carrying the prefix each include() contributes."""
    entries = []
    mounted = {}

    included = set()
    for scan in project.modules:
        for decls in scan.routes.values():
            for decl in decls:
                if decl.include and decl.include.kind == "module":
                    target = project.find(decl.include.value)
                    if target is not None:
                        included.add(target.path)

    roots = [scan for scan in project.modules
             if "urlpatterns" in scan.routes and scan.path not in included]
    if root_urlconf:
        declared = project.find(root_urlconf)
        if declared is not None and declared not in roots:
            roots.insert(0, declared)

    for scan in roots:
        _walk(project, scan, "urlpatterns", "", [], entries, mounted)
    return entries, mounted, roots


def _walk(project, scan, list_name, prefix, chain, entries, mounted):
    key = (scan.path, list_name)
    if key in chain:
        entries.append(Entry("url", scan.path, 0, 0, prefix,
                             {"include": "cycle", "note": "include chain returns to a module "
                                                          "already on it; stopped"}, None))
        return
    chain = chain + [key]

    for decl in scan.routes.get(list_name, []):
        route = prefix + (decl.pattern or "")
        if decl.include is None:
            entries.append(Entry("url", scan.path, decl.line, decl.column, route,
                                 {"view": decl.view, "name": decl.name},
                                 project.view_authz(decl.view)))
            continue
        if decl.include.kind == "module":
            target = project.find(decl.include.value)
            if target is None:
                entries.append(Entry("url", scan.path, decl.line, decl.column, route,
                                     {"include": decl.include.value,
                                      "note": "include target is not a module in this tree - the "
                                              "routes under it are not enumerated here"}, None))
                continue
            _walk(project, target, "urlpatterns", route, chain, entries, mounted)
        elif decl.include.kind == "local":
            if decl.include.value in scan.routes:
                _walk(project, scan, decl.include.value, route, chain, entries, mounted)
            else:
                entries.append(Entry("url", scan.path, decl.line, decl.column, route,
                                     {"include": decl.include.value,
                                      "note": "include names a value this module does not build "
                                              "as a route list"}, None))
        elif decl.include.kind == "router":
            registrations = scan.routers.get(decl.include.value, [])
            entries.append(Entry("url", scan.path, decl.line, decl.column, route,
                                 {"include": "%s.urls" % decl.include.value,
                                  "registrations": len(registrations)}, None))
            for registration in registrations:
                mounted.setdefault((scan.path, registration.line, registration.column), []).append(
                    route + (registration.prefix or ""))
        else:
            entries.append(Entry("url", scan.path, decl.line, decl.column, route,
                                 {"include": decl.include.value,
                                  "note": "include target cannot be resolved statically"}, None))


# --- settings context -------------------------------------------------------


def settings_context(path):
    """ROOT_URLCONF, MIDDLEWARE, and the DRF default permissions, or empty."""
    if resolve_settings is None:
        return {}, ["--settings needs settings_scan.py beside this file; skipped"]
    if os.path.isdir(path):
        resolutions = resolve_package(path)[0]
    elif os.path.isfile(path):
        resolutions = [resolve_settings(path)]
    else:
        return {}, ["--settings path is neither a file nor a directory: %s" % path]

    context, notes = {}, []
    for resolution in resolutions:
        for name, effective in resolution.assigns.items():
            if name in ("ROOT_URLCONF", "MIDDLEWARE", "REST_FRAMEWORK") and name not in context:
                context[name] = (effective, resolution.target)
        for severity, message in resolution.notes:
            notes.append("%s: %s" % (severity, message))
    return context, notes


def middleware_entries(context):
    if "MIDDLEWARE" not in context:
        return []
    effective, _ = context["MIDDLEWARE"]
    declared = literal(effective.node)
    if not isinstance(declared, (list, tuple)):
        return [Entry("middleware", effective.origin, effective.line, 1,
                      "MIDDLEWARE is dynamic",
                      {"note": "read the declared order by hand"}, None)]
    return [Entry("middleware", effective.origin, effective.line, 1, str(item),
                  {"order": index}, None)
            for index, item in enumerate(declared) if isinstance(item, str)]


def default_permissions(context):
    if "REST_FRAMEWORK" not in context:
        return None
    effective, _ = context["REST_FRAMEWORK"]
    settings = literal(effective.node)
    if isinstance(settings, dict):
        value = settings.get("DEFAULT_PERMISSION_CLASSES")
        if value is not None:
            return repr(value)
    if isinstance(effective.node, ast.Dict):
        for key, node in zip(effective.node.keys, effective.node.values):
            if literal(key) == "DEFAULT_PERMISSION_CLASSES":
                return render(node)
    return None


# --- output -----------------------------------------------------------------


def detail_text(detail):
    parts = []
    for key, value in detail.items():
        if value is None or value == [] or value == "":
            continue
        parts.append("%s=%s" % (key, value if not isinstance(value, list)
                                else ",".join(str(item) for item in value)))
    return " ".join(parts)


def print_text(root, entries, unparsed, families, context, notes, roots):
    print("# entrypoint_inventory: %s" % root)
    if context:
        described = []
        if "ROOT_URLCONF" in context:
            described.append("ROOT_URLCONF = %s" % render(context["ROOT_URLCONF"][0].node))
        permissions = default_permissions(context)
        if permissions:
            described.append("DEFAULT_PERMISSION_CLASSES = %s" % permissions)
        if described:
            print("# settings: %s" % "; ".join(described))
    print("# URLconf roots walked: %s" % (", ".join(scan.path for scan in roots) or "none found"))
    for note in notes:
        print("# %s" % note)

    grouped = {}
    for entry in entries:
        grouped.setdefault(entry.family, []).append(entry)

    for family in FAMILIES:
        if family not in families:
            continue
        rows = grouped.get(family, [])
        heading, reference = FAMILIES[family]
        print("\n## %s - %d (%s)" % (heading, len(rows), reference))
        for entry in rows:
            authz = " [authz: %s]" % entry.authz if entry.authz else ""
            print("  %s%s" % (entry.label, authz))
            detail = detail_text(entry.detail)
            print("      | %s:%d:%d%s" % (entry.path, entry.line, entry.column,
                                          "  " + detail if detail else ""))

    if unparsed:
        print("\n# unparsed")
        for failure in unparsed:
            print("  %s: %s" % (failure.path, failure.error))

    found = [family for family in FAMILIES if grouped.get(family) and family in families]
    looked = [family for family in FAMILIES
              if family in families and not grouped.get(family) and family != "middleware"]
    print("\n# %d entry point(s) across %d of %d families looked for."
          % (len(entries), len(found), len(families)))
    print("# Found: %s" % (", ".join(found) or "none"))
    print("# Looked for and not found: %s" % (", ".join(looked) or "none"))
    if "middleware" in families and not grouped.get("middleware"):
        print("# Not examined: middleware - it is only collected when --settings names the "
              "module or package that declares MIDDLEWARE.")
    if unparsed:
        print("# %d file(s) could not be parsed and were NOT scanned - a silent skip would look "
              "like a complete inventory." % len(unparsed))
    print("# An inventory, not a judgement: every row is a declaration to read, and the "
          "authorization column says where a declaration is, never whether it is right.")


def print_json(entries, unparsed):
    for entry in entries:
        print(json.dumps({
            "kind": "entry",
            "family": entry.family,
            "file": entry.path,
            "line": entry.line,
            "column": entry.column,
            "label": entry.label,
            "authorization": entry.authz,
            "reference": FAMILIES[entry.family][1],
            "detail": {key: value for key, value in entry.detail.items() if value is not None},
        }, sort_keys=True))
    for failure in unparsed:
        print(json.dumps({
            "kind": "unparsed",
            "file": failure.path,
            "line": failure.line,
            "column": failure.column,
            "error": failure.error,
        }, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(
        description="Read-only, AST-based inventory of application entry points.")
    parser.add_argument("path", nargs="?", help="Directory (or file) to inventory; defaults to .")
    parser.add_argument("--settings", help="Settings module or package, for the middleware and "
                                           "default-permission context")
    parser.add_argument("--kind", action="append", default=None,
                        help="Restrict to one or more families, comma-separated; repeatable")
    parser.add_argument("--json", action="store_true",
                        help="Emit one JSON object per record, one per line")
    args = parser.parse_args()

    families = list(FAMILIES)
    if args.kind:
        requested = [name.strip() for value in args.kind for name in value.split(",")
                     if name.strip()]
        unknown = [name for name in requested if name not in FAMILIES]
        if unknown:
            print("Unknown famil(ies): %s. Valid: %s"
                  % (", ".join(unknown), ", ".join(FAMILIES)), file=sys.stderr)
            return 0
        families = [name for name in FAMILIES if name in requested]

    root = args.path or "."
    if not os.path.exists(root):
        print("Not a file or directory: %s" % root, file=sys.stderr)
        return 0

    context, notes = ({}, [])
    if args.settings:
        context, notes = settings_context(args.settings)

    project = Project(root).load()
    root_urlconf = None
    if "ROOT_URLCONF" in context:
        root_urlconf = literal(context["ROOT_URLCONF"][0].node)
    url_entries, mounted, roots = resolve_urls(project, root_urlconf)

    entries = list(url_entries)
    for scan in project.modules:
        entries.extend(scan.entries)
        for name, registrations in scan.routers.items():
            for registration in registrations:
                prefixes = mounted.get((scan.path, registration.line, registration.column))
                entries.append(Entry(
                    "drf", scan.path, registration.line, registration.column,
                    "; ".join(prefixes) if prefixes else (registration.prefix or "?"),
                    {"router": name,
                     "prefix": registration.prefix,
                     "viewset": registration.viewset,
                     "basename": registration.basename,
                     "mounted": "resolved through include()" if prefixes
                                else "not reached from a URLconf root in this tree"},
                    project.view_authz(registration.viewset)))
    entries.extend(middleware_entries(context))

    entries = [entry for entry in entries if entry.family in families]
    order = list(FAMILIES)
    # Middleware sorts on its declared position; every other family sorts on
    # the label, which is the identity a reader looks it up by.
    entries.sort(key=lambda entry: (order.index(entry.family),
                                    entry.detail.get("order", -1) if entry.family == "middleware"
                                    else -1,
                                    entry.label, entry.path, entry.line))

    if args.json:
        print_json(entries, project.unparsed)
    else:
        print_text(root, entries, project.unparsed, families, context, notes, roots)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
