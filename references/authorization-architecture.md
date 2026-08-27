# Authorization Architecture and the Privilege Model

A01 covers individual access-control *failures*. This file covers the *model*
that produces them. It covers the structure of privileges, and what the Django
permission layer does. It covers where DRF and the admin enforce object
access, and where they do not.

It covers how to make deny-by-default enforceable. It also covers how to test
an authorization model, so that the suite is worth trust.

Read this file with four others. `a01-broken-access-control.md` owns
per-request enforcement, and `api-drf-specific.md` owns serializer shape.
`privileged-access-and-impersonation.md` owns operator privilege.
`data-layer-and-database.md` owns database-enforced isolation as a mechanism
under this model. Maps to OWASP A01:2025 and API1/API3/API5:2023, ASVS 5.0 V8,
and CWE-862, CWE-863, CWE-639, CWE-269, and CWE-284.

## Contents
- [Principle](#principle)
- [Choosing a privilege model](#choosing-a-privilege-model)
- [Django's permission layer: what it actually does](#djangos-permission-layer-what-it-actually-does)
- [Django views: permission_required and PermissionRequiredMixin](#django-views-permission_required-and-permissionrequiredmixin)
- [DRF: where the object check actually runs](#drf-where-the-object-check-actually-runs)
- [Django admin: the permission surface](#django-admin-the-permission-surface)
- [Default-deny architecture](#default-deny-architecture)
- [Field-level authorization (BOPLA)](#field-level-authorization-bopla)
- [Search indexes and denormalized copies](#search-indexes-and-denormalized-copies)
- [Authorization test suites](#authorization-test-suites)
- [Permission-model decay and access review](#permission-model-decay-and-access-review)
- [Identity lifecycle and provisioning desynchronization](#identity-lifecycle-and-provisioning-desynchronization)
- [Review checklist](#review-checklist)

## Principle

A privilege model is the design. A permission check is the enforcement. Most
authorization defects are not a missing `if`. They are a model that cannot
express the rule that the business has, so each view invents its own. Three
properties separate a model that holds from a model that decays:

1. **Declarative and enumerable.** You can list every privilege and who holds
   it, and you do not read every view. Where the answer to "who can delete an
   invoice?" needs a grep, periodic access review is impossible.
2. **Derived from server-side identity state.** The decision reads the
   authenticated principal and the stored relationships. It never reads a
   role, a tenant, or an owner id that the client supplied.
3. **Fail closed.** An unknown role, a null tenant, a new endpoint, or an
   unmapped state denies. A path that nobody reviewed eventually reaches
   anything that defaults to allow.

ASVS 5.0 V8 splits authorization into three levels. A model that answers only
the first level is incomplete:

| Level | Question | Failure |
|---|---|---|
| Function | may this principal call this operation at all? | BFLA / API5 |
| Data | may it act on *this object*? | IDOR / BOLA / API1 |
| Field | may it read or write *this property*? | BOPLA / API3 |

## Choosing a privilege model

| Model | Decision is based on | Fits |
|---|---|---|
| **RBAC** | roles held by the principal | fixed job functions; small, stable permission sets |
| **ABAC** | attributes of principal, object, and context | rules like "same department and not archived" |
| **ReBAC** | the relationship graph between principal and object | nested hierarchies, sharing, resharing |

Most Django SaaS needs tenant isolation, a few roles, and ownership. RBAC plus
queryset scoping is sufficient there. It is also cheaper and much easier to
audit. Use a relationship engine only where authorization depends on arbitrary
graphs. Three such cases are nested folder and document inheritance,
user-to-user resharing, and cross-service authorization. See
`security-hardening-libraries.md` for vetted engine choices and their
operational cost.

Each model has a characteristic decay:

- **RBAC** decays in three ways. It decays into **role explosion**, which is a
  new role for each customer or permutation. It decays into
  **roles-as-permissions**, which are roles named after a single action, such
  as `can_export_csv`. It also decays into **boolean flags on the user
  model**, such as `is_manager` and `is_reviewer`, which do not compose.
- **ABAC** decays into attribute sprawl and implicit precedence. Allow and
  deny rules then conflict, and nobody can say which rule wins. ABAC also
  decays into attributes taken from request input rather than from server
  state, which is worse.
- **ReBAC** decays into relationship drift and stale membership. The usual
  cause is that each feature writes its own recursive membership query. A
  revocation that removes one edge is the second cause. A reshare below that
  edge keeps its own access. Recompute reachability for every descendant on an
  edge removal, or do not offer a reshare at all.

Code smells to grep for during review, each a lead rather than a finding:

- `BooleanField` role flags on the user or profile model.
- `if user.role == "..."` or long `if/elif` role ladders inside views.
- permission codenames that are really feature flags.
- an authorization decision that reads `request.data`, `request.GET`, or a
  client-controlled header, and does not validate the value against
  server-side state.
- hand-rolled recursive membership or ancestry queries duplicated per feature.

## Django's permission layer: what it actually does

### Object permissions are a no-op by default

`ModelBackend._get_permissions()` returns an **empty set** whenever `obj` is
not `None`. `has_perm()` consults `get_all_permissions()`. An object argument
therefore yields an empty permission set, and the check returns `False`. That
happens for every non-superuser, including one who holds the model-level
permission.

```python
# Misleading: with only ModelBackend installed this is False for every
# non-superuser, including one who holds documents.change_document.
if user.has_perm("documents.change_document", document):
    ...
```

It does not "fall back" to the model permission. It does the opposite. The
dangerous shape is code that reads as an object check, and denies every
principal in production. That code appears to work in development, because the
developer is a superuser. See below. Pick one enforcement path and apply it
consistently:

- **queryset scoping** — the default recommendation (`a01-broken-access-control.md`);
- **django-guardian** — object ACL rows, when grants are per-object data;
- **django-rules** — predicate functions, when the rule is computable.

Only the second and the third make `user.has_perm(perm, obj)` meaningful. Each
one needs its backend in `AUTHENTICATION_BACKENDS` first. This is their
minimal wiring, for the cases where queryset scoping does not fit:

```python
# django-guardian: the grant is a row.
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
]

from guardian.shortcuts import assign_perm

assign_perm("documents.change_document", user, document)
```

```python
# django-rules: the grant is a predicate.
AUTHENTICATION_BACKENDS = [
    "rules.permissions.ObjectPermissionBackend",
    "django.contrib.auth.backends.ModelBackend",
]

@rules.predicate
def is_document_owner(user, document):
    # rules pads a missing object with None; without this guard a
    # model-level has_perm() raises AttributeError instead of denying.
    return document is not None and document.owner_id == user.id

rules.add_perm("documents.change_document", is_document_owner)
```

Keep `ModelBackend` in the list in both cases. Neither object backend answers
a model-level check. They add object decisions, and do not replace the
model-level ones.

### Superuser short-circuits everything

`PermissionsMixin.has_perm()` returns `True` for any active superuser, before
Django consults the backends. `has_module_perms()` behaves the same way. It
otherwise returns `True` where the user holds *any* permission in the app
label.

Two consequences matter in review. A superuser fixture exercises no
authorization logic at all. See [test suites](#authorization-test-suites).
Every superuser account also reaches everything, which
`privileged-access-and-impersonation.md` covers.

### The permission cache is per-instance and sticky

`ModelBackend` caches permissions on the user object for the life of that
instance. It uses `_perm_cache`, `_user_perm_cache`, and `_group_perm_cache`.
A permission change during the request does not reach that cache.
**`User.refresh_from_db()` does not rebuild the cache.** Only a new query or a
new instance rebuilds it.

```python
# After changing group membership or permissions, re-fetch the user.
# refresh_from_db() will not rebuild the permission cache.
user = User.objects.get(pk=user.pk)
```

The security-relevant case is **revocation**. A request or worker can remove a
permission and then continue with the same user object. That code continues to
see the old answer. A long-lived user object in a Celery task, a management
command, or a Channels consumer is where this happens. A test that asserts a
revocation without a new fetch has the same defect.

### Async permission APIs

- Django 5.0: `HttpRequest.auser()`, `aauthenticate()`, `aget_user()`,
  `alogin()`, `alogout()`.
- Django 5.1: async `login_required`, `permission_required`,
  `user_passes_test`.
- Django 5.2: `ahas_perm()`, `ahas_perms()`, `ahas_module_perms()`,
  `aget_all_permissions()`, `aget_user_permissions()`,
  `aget_group_permissions()` on both `PermissionsMixin` and `ModelBackend`
  (confirmed in the 5.2 release notes).

Below 5.2 there is no async permission API. A call to the sync API from async
context is the usual source of `SynchronousOnlyOperation`. A developer then
"fixes" that error by a move of the check to a place where it no longer runs.
Do not carry a cached user object across awaits or connections; see
`async-and-channels.md`.

## Django views: permission_required and PermissionRequiredMixin

Both check **model-level** permissions only. The `has_permission()` of the
mixin has no object parameter. No supported way to pass one exists.

Their failure behavior differs, and the difference is the more common bug.
`AccessMixin.handle_no_permission()` raises `PermissionDenied` when
`self.raise_exception or self.request.user.is_authenticated`. The **mixin**
therefore already returns 403 to an authenticated-but-unauthorized user. Only
an anonymous user gets the login redirect.

The **decorator** has no such clause. Its `check_perms()` returns `False`
unless `raise_exception=True`. `user_passes_test()` then redirects always, and
sends an authenticated user to a login page they already passed. That is the
classic redirect loop, and it breaks an API client.

```python
class InvoiceUpdateView(PermissionRequiredMixin, UpdateView):
    permission_required = "billing.change_invoice"
    raise_exception = True  # 403 for anonymous requests too, not a redirect

    def get_queryset(self):
        return Invoice.objects.filter(account=self.request.user.account)
```

Set `raise_exception=True` on both, for different reasons. On the decorator it
is what produces a 403. On the mixin it removes the remaining redirect for an
anonymous request.

The queryset supplies the object-level decision. The mixin never supplies it.
On Django 5.1+, `LoginRequiredMiddleware` makes authentication a project-wide
default. The declaration of a view is then only about authorization.

## DRF: where the object check actually runs

`check_object_permissions()` — which invokes `has_object_permission()` — runs
only where `get_object()` runs:

| Path | `has_object_permission` called? |
|---|---|
| `get_object()` on a generic detail/update/destroy view | yes |
| list actions | **no** — "for performance reasons the generic views will not automatically apply object level permissions to each instance in a queryset" |
| create | **no** — "because the `get_object()` method is not called" |
| your own `Model.objects.get(...)` | no |
| an overridden `get_object()` that omits `self.check_object_permissions(request, obj)` | no |

A filter on the queryset must therefore secure a list endpoint. The serializer
or `perform_create()` must restrict creation. A `has_object_permission` that
forbids a write to the record of another principal does not stop a client from
a create against another owner.

Two defaults compound this:

- **Both `BasePermission` hooks return `True`.** A custom class that
  implements only `has_permission` therefore grants object access to every
  principal that clears the view-level check. A custom class that implements
  only `has_object_permission` is the same defect reversed, and it is the
  worse one: `has_permission` then answers `True` for every caller, and the
  list and create paths never reach the object hook at all. A
  `permission_classes` list on the view also *replaces* the default list, so
  the restrictive project default is gone as well. Such a viewset answers an
  unauthenticated list and an unauthenticated create, while the code reads as
  ownership enforcement. Implement both hooks on every custom permission
  class, even where one of them returns a deliberate `True`.
- No provided class except `DjangoObjectPermissions` implements an
  object-permission method. `IsAuthenticated` authorizes the view, and never
  the object.

```python
# Wrong: the object hook silently inherits BasePermission's True.
class IsEditor(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name="editors").exists()
```

```python
# Correct: state the object decision explicitly.
class IsEditorOfObject(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name="editors").exists()

    def has_object_permission(self, request, view, obj):
        return obj.account_id == request.user.account_id
```

`DjangoModelPermissions` requires an authenticated user. It maps an HTTP
method to the model add, change, and delete permissions. It does not require
`view` for GET. `authenticated_users_only`, which defaults to `True`, decides
whether DRF rejects an unauthenticated user immediately. This class grants no
object-level control.

`DjangoObjectPermissions` extends that class per object, and needs an
object-permission backend. Read its `perms_map` before you depend on it. The
stock map holds an empty permission list for `GET`, `HEAD`, and `OPTIONS`. A
safe request therefore checks no object permission. Read access is view-level
only until you subclass the map:

```python
from rest_framework.permissions import DjangoObjectPermissions


class ViewDjangoObjectPermissions(DjangoObjectPermissions):
    perms_map = {
        **DjangoObjectPermissions.perms_map,
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "HEAD": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": ["%(app_label)s.view_%(model_name)s"],
    }
```

The same `perms_map` override closes the GET gap on `DjangoModelPermissions`
itself, for a project that uses that class with no object-permission backend.
Without it a safe method asks for authentication and nothing else.

With a map that requires a view permission, the response codes are deliberate
and frequently "corrected" by mistake:

- safe method, permission missing → **404**;
- unsafe method, permission missing but read permission held → **403**;
- unsafe method, read permission also missing → **404**.

The 404 exists so responses don't confirm that an object exists. Do not change
it to a 403 for consistency.

## Django admin: the permission surface

`has_view/add/change/delete_permission()` and `has_module_permission()` gate the
admin, and `get_queryset()` scopes the changelist. The changelist scoping is
what keeps one tenant's rows off another tenant's screen — the `has_*_permission`
hooks alone will not.

**Bulk `delete_selected`.** Current Django *does* check per object:
`get_deleted_objects()` calls `has_delete_permission(request, obj)` for each
collected object and `delete_selected` raises `PermissionDenied` when any is
denied. Trac ticket #11383 is still formally open. #23869 addressed the
behavior. Older guidance says that the action checks only the model-level
permission, and that guidance is out of date. Verify against the Django
version in front of you, and note the gaps that remain real:

- the action's availability gate (`allowed_permissions = ("delete",)`) is
  model-level, called with `obj=None`;
- per-object checks only cover models **registered with the admin site**;
  unregistered cascade targets get none;
- deletion runs through `delete_queryset()` → `QuerySet.delete()`, so an
  overridden `Model.delete()` never runs (see `a09-logging-and-alerting.md`);
- an overridden `get_deleted_objects()` or `delete_queryset()` can drop the
  check entirely.

Per-object delete logic can be security-relevant, and you cannot always verify
the whole path. Remove the action in that case, with `get_actions()` or
`admin.site.disable_action("delete_selected")`. Then permit a delete only
through the change form. On Django 6.1 that override takes a new
`action_location` parameter, and Django deprecates an override without it. The
values it returns are `Action` objects now, so read their attributes rather
than unpacking or indexing them.

Other admin surfaces:

- Custom actions gate on `@admin.action(permissions=[...])`, checked against the
  **model-level** `has_*_permission`. Any per-object rule must be enforced inside
  the action body against the `queryset` argument. Signal: `self.model.objects`,
  `Model.objects`, or `_selected_action` inside an action body. Each one reads
  the rows again from the table, and drops the scope that `get_queryset()`
  applied to the changelist. A staff user of one tenant then posts the primary
  keys of another tenant and the action acts on them. Consume the `queryset`
  argument, and read nothing else. An action that declares no
  `permissions` is filtered by nothing. `_filter_actions_by_permissions()`
  keeps it for any staff user who reaches the changelist, on the POST path as
  well as in the dropdown. From Django 6.1 the `location` argument of
  `@admin.action` widens where that reaches.
  `ActionLocation.CHANGE_FORM` puts the action on the change form, and the
  default stays `ActionLocation.CHANGE_LIST`. An action with no `permissions`
  therefore gains a second unguarded entry point the moment somebody sets
  `location`.
- `readonly_fields` prevents edits in the form. It is not an authorization
  control and does nothing for other write paths.
- `autocomplete_fields` and `ForeignKeyRawIdWidget` expose the related model
  twice, and the two exposures need different fixes. The **lookup** answers a
  search with matching rows, and `AutocompleteJsonView` reads it from the
  `get_queryset()` and `get_search_results()` of the **related** model's
  `ModelAdmin`, never from those of the one you are editing. Scope that other
  `ModelAdmin`, or the suggestions stay a cross-tenant search. The **write**
  accepts whatever primary key the form posts, because
  `formfield_for_foreignkey()` builds the field from the default manager of
  the related model. `get_search_results()` narrows the suggestions only, and
  never the accepted value. Bind the write with `limit_choices_to`, which
  Django applies at validation, or pass a scoped `queryset` from
  `formfield_for_foreignkey()`. Verified against Django 5.2.15 source on
  27 Aug 2026.
- `is_staff` grants admin login only; `is_superuser` short-circuits every check.

**Custom admin views.** A view that an overridden `get_urls()` returns runs
with no admin gate unless the code wraps it. On Django 6.0.7 an unwrapped
custom admin URL answered an anonymous request in full, verified by execution
on 20 Aug 2026.

`self.admin_site.admin_view(view)` adds the check that `has_permission()`
makes — `is_active` and `is_staff` — plus `never_cache` and `csrf_protect`.
`cacheable=True` drops the cache decorator only, and never the check. Inside
the wrapped view, enforce the named model permission with
`request.user.has_perm(...)`. Scope any object the URL names with the same
queryset filter the changelist uses.

Admin *exposure* (path, TLS, IP restriction, MFA) is in
`a01-broken-access-control.md`.

## Default-deny architecture

In order of leverage:

1. **`DEFAULT_PERMISSION_CLASSES`** set to `IsAuthenticated` or stricter, so a
   newly added viewset is protected unless deliberately opened with
   `AllowAny`. The single highest-value lever for APIs — and it covers DRF
   only, not plain Django views, admin, or non-DRF endpoints.
2. **A URLconf-enumerating audit test.** It is the only mechanism that makes
   "a new endpoint is unreachable until someone decides" enforceable in CI.
   `scripts/entrypoint_inventory.py` enumerates the same surface read-only.
   That is what an audit has before a test exists to run.
3. Middleware that asserts a view was authorized. Effective, but it fights
   third-party views. The marker it reads must sit on the view at import time.
   A marker that a request sets is a marker that any earlier code sets, and
   the assert then reports every request as authorized.
4. `django-decorator-include` to apply a decorator across an included URLconf.

```python
from django.test import SimpleTestCase
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.permissions import AllowAny

# Every entry is a deliberate decision, reviewed when it changes.
PUBLIC_ROUTE_PREFIXES = ("admin/", "health/", "static/")
REVIEWED_VIEWS = {"api.views.SignupView", "api.views.WebhookView"}


def iter_routes(resolver=None, prefix=""):
    resolver = resolver or get_resolver()
    for entry in resolver.url_patterns:
        route = prefix + str(entry.pattern)
        if isinstance(entry, URLResolver):
            yield from iter_routes(entry, route)
        elif isinstance(entry, URLPattern):
            yield route, entry.callback


def view_target(callback):
    return getattr(callback, "cls", None) or getattr(
        callback, "view_class", callback
    )


def identify(callback):
    target = view_target(callback)
    return f"{target.__module__}.{target.__qualname__}"


def declared_permissions(callback):
    # The router copies the @action keyword arguments into initkwargs, and DRF
    # applies them to the instance at dispatch. They beat the class attribute.
    initkwargs = getattr(callback, "initkwargs", {})
    if "permission_classes" in initkwargs:
        return initkwargs["permission_classes"]
    return getattr(view_target(callback), "permission_classes", None)


def opens_the_route(permission):
    # AllowAny itself, and every subclass of it.
    return isinstance(permission, type) and issubclass(permission, AllowAny)


class EveryEndpointHasAnAuthorizationDecision(SimpleTestCase):
    def test_no_undecided_endpoints(self):
        undecided = []
        for route, callback in iter_routes():
            if route.startswith(PUBLIC_ROUTE_PREFIXES):
                continue
            name = identify(callback)
            if name in REVIEWED_VIEWS:
                continue
            if getattr(view_target(callback), "authorization_reviewed", False):
                continue
            permissions = declared_permissions(callback)
            if not permissions or any(map(opens_the_route, permissions)):
                undecided.append((route, name))
        self.assertEqual(undecided, [], f"Undecided endpoints: {undecided}")
```

Three properties of that test carry it, and each one is easy to lose:

- **A per-action override beats the class attribute.**
  `@action(detail=True, permission_classes=[AllowAny])` opens one route while
  `permission_classes` on the viewset stays restrictive. The router merges the
  `@action` keyword arguments into `initkwargs`, and `ViewSetMixin.as_view()`
  passes them to the constructor, so the instance attribute wins at dispatch.
  A test that reads the class attribute alone therefore reports the whole
  viewset as decided, and the new route answers everyone. Read `initkwargs`
  first, and treat each per-action override as its own review entry rather
  than as a property of the viewset. Verified by execution against DRF 3.17.1
  on 27 Aug 2026.
- **`AllowAny` is a class, and so is every subclass of it.** Compare with
  `issubclass`, and not with `in`. A permission class that opens the route
  under a setting or a flag still opens it.
- **The set names a reviewed view, and not a public one.** A protected plain
  Django view has nothing for the test to read, so it is driven into the set
  to make the suite green. Where the set is named for public access, the name
  stops describing the contents. A later reader then removes the view's own
  guard, because the list says the view is public. Name the set for the
  review, and prefer the marker on the view itself.

Where it breaks: third-party URLs (admin, allauth, health checks),
static/media, Django's own auth views, and DRF's browsable-API and schema
endpoints all need explicit allow-listing. The cost is a maintained allow-list;
the benefit is that adding a public endpoint becomes a conscious, reviewable act
rather than an omission. Never put a first-party prefix in
`PUBLIC_ROUTE_PREFIXES`. A prefix also exempts each route that someone adds
below it later.

**Write-time.** When you generate a new route, write its authorization
decision in the same edit that adds it to the URLconf. Extend the allow-list
above only where the route is deliberately public.

The audit test is the mechanism that makes the decision compulsory. An entry
added only to keep the suite green makes the control a formality. A plain
Django view, a Ninja operation, and a tool path carry no `permission_classes`
for that test to read. Each one therefore needs its own marker or its own row.
Never assume that one of them inherits a DRF default that never applied to it.

## Field-level authorization (BOPLA)

API3:2023 combines two former entries. "Excessive Data Exposure" is a response
with properties that the caller must not read. "Mass Assignment" is a request
with properties that the caller must not write. A grant of object access is
not a grant of property access.

Read-side patterns: per-role serializers, dynamic fields via `get_fields()` or
`__init__`, and `to_representation` filtering. The **write side** is where this
actually fails:

- a field removed from the read representation but still writable can be set
  through mass assignment on create or partial update;
- `read_only_fields` in `Meta` does **not** apply to explicitly *declared*
  fields — a declared field stays writable even when listed there (also noted in
  `api-drf-specific.md`);
- `PATCH` must be tested separately from `PUT`; partial-update paths routinely
  accept what the full-update path rejects.

Prefer allow-listing writable fields per role over deny-listing them:

```python
class InvoiceSerializer(serializers.ModelSerializer):
    # `account` is the tenant, so no role writes it. See the rule below.
    WRITABLE_BY_ROLE = {
        "viewer": set(),
        "editor": {"title", "notes"},
        "admin": {"title", "notes", "status"},
    }

    class Meta:
        model = Invoice
        fields = ["id", "title", "notes", "status", "account", "total"]
        read_only_fields = ["id", "account", "total"]

    def get_fields(self):
        fields = super().get_fields()
        # No request in context, or an unknown role, means nothing is writable.
        user = getattr(self.context.get("request"), "user", None)
        role = getattr(user, "role", None)
        writable = self.WRITABLE_BY_ROLE.get(role, set())
        for name, field in fields.items():
            if name not in writable:
                field.read_only = True
        return fields
```

Setting `read_only` on the field instance covers declared and generated fields
alike, and applies to `PUT` and `PATCH` equally.

**A field that an authorization decision reads is never in a writable set.**
Signal: `account`, `tenant`, `owner`, `role`, `groups`, or an `is_*` flag
inside `fields`, with no matching `read_only_fields` entry. The unsafe pattern
gives the top role a write to the field that selects the tenant, or a write to
the field that selects its own role. A `PATCH` of `account` moves the row to
another tenant, where the scoped list of that tenant reads it, and a `PATCH`
of `role` promotes the caller for every request after it. The self-service
serializer matters most here, because signup, profile, and `/me` all write the
identity that the next decision reads. Put each of these fields in
`read_only_fields`, and change a grant or a tenant only through a separately
permissioned path.

**The allow-list must govern every serializer that the route can build.** It
lives on one class, and one route reaches several. Three signals: a
`get_serializer_class()` with a branch per action, format, or version; a
writable nested serializer declared on the parent; and a field set that the
caller names in the query string. The unsafe pattern puts the allow-list on
the default class alone, so a caller reaches the export, the bulk, or the
versioned class, writes the nested payload, or asks for the properties the
role must not read. Put the allow-list in one base class, and let every
serializer that the route can instantiate inherit it. Intersect a
caller-named field set with the set of the role, and never let the caller
replace that set.

The same failure appears in a GraphQL schema, as a type that publishes every
model field. The deny-list version there fails open as the model grows. See
`graphql-and-alternative-api-surfaces.md`, "Schema exposure and the all-fields
type (BOPLA)".

## Search indexes and denormalized copies

A search index, a materialized report table, an analytics export, and a
replica are the same shape of problem. Each is a second copy of the data with
**its own query path**. That path does not pass through the queryset scoping,
the permission classes, or the database policies that guard the source rows.
Authorization was implemented once, at the table, and the copy silently
reintroduces an unguarded door. Maps to CWE-639, CWE-284, and CWE-285;
A01:2025 and API1:2023.

The failure has two halves and a review has to test both:

- **Missing predicate.** The query against the copy does not apply the
  authorization filter that governs the source rows. Any match therefore
  reaches any caller who can reach the endpoint.
- **Drift.** The pipeline refreshes the copy on a *content* change, and not on
  a *permission* change. A document therefore stays available after the
  revocation of the grant that justified it.

The design that prevents it rather than patching it:

1. **Every indexed document carries its authorization metadata** as
   first-class fields. That metadata is the tenant, the owner, the visibility,
   and the ACL. The pipeline writes it at index time, from the same source of
   truth as the row.
2. **Every query applies a server-derived filter** as a mandatory clause,
   built in trusted backend code from the authenticated principal and never
   accepted from the caller. One search-service choke point is far easier to
   audit than per-view query construction, because a mandatory clause cannot
   be omitted by forgetting it. A matched record is not the only result the
   copy returns. A count, an aggregate, a facet, a suggestion, and a
   similarity search each read the copy on a path of their own, and each one
   needs the same clause. A clause that the engine applies *after* the
   aggregate stage does not scope the aggregate. A caller then asks for zero
   records and reads the other tenants out of the facet counts.
3. **Reindex on authorization change**, not only on content change. Treat an
   ACL or membership edit as an index-invalidating event and bound staleness
   with a periodic reconcile.
4. **Index-per-tenant** is stronger isolation, and it scales poorly. A shared
   index with a mandatory tenant filter is the usual acceptable middle. The
   engine enforces document-level security where it offers that, and the
   application enforces it where the engine does not. This middle holds only
   where nothing can bypass the filter.

Audit it in four steps. Enumerate every client that holds the engine
credential rather than only the query-building sites, because a second
service, a scheduled job, or a notebook with that credential reaches the copy
without the clause; confirm that trusted code adds the principal-derived
filter on each path. Authenticate as tenant A, search a term that exists only
in tenant B, and assert zero hits; repeat that probe for a count, a facet, and
a suggestion, because each one returns the data of tenant B with no matched
record at all. Revoke access to a document, re-run the search *before* any
content edit, and assert that the document disappears. Confirm that the
indexing pipeline writes the authorization metadata and fires on a permission
change.

The same reasoning covers a read that a decision depends on. An authorization
read covers role, membership, and revocation state. A route of that read to a
lagging replica authorizes what the primary has already denied. See
`data-layer-and-database.md`, "Read replicas and stale authorization".

Agent and tool surfaces reach retrieval through this same path.
`agent-and-llm-interfaces.md` owns the agent-specific slice, where a tool that
republishes retrieval must also intersect the tool's scope with the invoking
user's own permissions.

This section owns who may read the copy. A separate failure is whether the
copy still exists after a delete of the source row. In that failure the
deletion event never reached the index, the report table, or the cache. It
belongs to `data-lifecycle-and-privacy.md`, "Erasure as a fan-out with a
completion ledger". Both halves apply to the same object, and a review that
tests only the filter will pass a system that still serves erased records.

## Authorization test suites

A suite worth trusting asserts, for each protected resource, a **matrix** of
{role or tenant} × {action} × {expected allow or deny}, including:

- cross-tenant object ids (expect 404 or 403, and assert which);
- object state as an axis of its own, such as draft against published, active
  against archived, and soft-deleted against live. A rule that reads the state
  of the row is a different rule from one that reads only the principal. A
  matrix over roles alone never exercises it;
- unauthenticated access to every protected route;
- field-level read *and* write per role, with `PATCH` separate from `PUT`;
- state after a denied write, not just the status code;
- any path that republishes a view to an agent or tool surface, as its own
  row. Such a path may not run the same permission classes. See
  `agent-and-llm-interfaces.md`.

A suite that gives false confidence:

- **uses a superuser fixture everywhere** — the superuser short-circuit means
  nothing is exercised. This is the most common one.
- tests 403 on one endpoint and assumes the rest of the module behaves.
- mocks the permission class, testing the mock rather than the policy.
- asserts only happy paths.
- never enumerates the URLconf, so new endpoints are silently untested.

An enumeration of `urlpatterns` with a coverage assertion is what makes the
suite exhaustive rather than representative. `01-audit-workflow.md`, "Holding
the fix: the security regression harness" owns when the suite runs. That
section also owns what runs beside it after a finding closes.

## Permission-model decay and access review

Long-lived systems accumulate role explosion, **permission creep** (grants
added, never removed), and **orphaned grants** (permissions on deactivated users
or deleted objects). The code-level artifacts that make periodic access review
possible:

- permissions defined declaratively in one place, not scattered `if` checks;
- roles as data, each with an owner and a description;
- a script that lists any user's effective permissions;
- object-permission rows that can be enumerated and reconciled against current
  ownership;
- an audit test that fails when an undeclared permission or role appears.

Two Django 6.1 changes help here. A migration that renames a model now renames
the matching `Permission.name` and `Permission.codename`, where earlier
versions left the old rows behind. Check the grant tables after any model
rename on an older line. A stale codename denies silently, and a hand-made
replacement row can grant twice. The new `Permission.user_perm_str` property
returns the string `User.has_perm()` expects, so a script that lists effective
permissions no longer builds `"app_label.codename"` by hand.

The absence of all of these is a finding in its own right, for a system with
meaningful privilege tiers. Nobody can then answer who holds what.

## Identity lifecycle and provisioning desynchronization

Stack-neutral by necessity — Django ships no mechanism for any of it. Maps to
CWE-613 and CWE-672; A01:2025 and A07:2025.

### Principle layer

An identity has three events — **joiner, mover, leaver** — and a system that
models only the first two has no offboarding at all. The joiner is provisioned
and granted. The mover changes team, role, or tenant. That change must be a
*replacement* of the previous grants, and not an addition to them. A mover
whose grants only accumulate is how one person comes to hold the access of two
jobs. The leaver is disabled at the identity provider, and the divergence
starts there.

**A disable is not a revocation.** It stops the provider issuing new
assertions and does nothing to authority the application already handed out.
Between the disable and the last expiry, an offboarded person keeps whatever
of these the system issued and never re-checks:

| Survivor | Ends when |
|---|---|
| An active session | its server-side record is deleted, or an absolute lifetime runs out |
| A bearer or refresh token | it expires, unless the request path re-reads the account |
| An API key or personal access token | somebody revokes it by hand |
| A webhook or signing secret they hold a copy of | it is rotated |
| A service account they created or share | it is found and reassigned |
| A local group or role grant | it is removed locally |

The last row outlives all the others, because it is not a credential.
**Synchronization has a direction**, and that direction is usually one way.
The provider pushes group membership in. A grant made locally is therefore
unknown to the provider, and a provider-side removal cannot take it away. Such
a grant comes from the admin, a support tool, or a migration. A reconciliation
that walks only the identities the provider knows about reports itself clean
while the system holds grants the provider has no record of.

Machine identities decay the same way with nobody watching. Three cases are a
live principal that no lifecycle event reaches. They are a service account
made for a one-off integration, and a token minted by a person who has left. A
bot user with no named owner is the third. The lifecycle was attached to
people.

Two controls, and neither substitutes for the other:

1. **A revocation fan-out on the disable event.** Keep it as a durable record
   with per-target state. A partial failure is then visible and retryable, and
   a handler that already returned does not hide it. That record is the same
   shape as the erasure ledger in `data-lifecycle-and-privacy.md`, "Erasure as
   a fan-out with a completion ledger". Reuse that ledger, and do not build a
   second one. **A target is done when a read-back confirms the effect.** A
   handler that queues the work and returns proves nothing, and a lost message
   then reads as a clean offboarding. Signal: the ledger write sits beside the
   call that queues the work. Mark the target dispatched there, and mark it
   done only where the code reads the target again and finds the session
   record gone, the token revoked, or the grant row absent. Retry until that
   read succeeds.
2. **A periodic reconciliation job that produces a report.** It compares every
   local identity and grant against the provider. It compares every machine
   identity against a named owner. It writes the difference down. The fan-out
   handles the event; the job catches what the event missed and what never had
   an event to miss. A reconciliation that logs nothing when it finds nothing
   is indistinguishable from one that did not run.

### Django & DRF implementation layer

Django gives you `is_active`. `is_active` reaches only the paths that read the
user row. `a07-authentication-failures.md`, "The user model as an identity
contract" names those paths, and the credentials that skip them. Everything
above it is the project's to build, so the review is an inventory rather than
a settings check:

- **Sessions are not enumerable by user.** `django_session` holds an opaque
  key and an encoded blob, so finding one user's sessions means decoding rows.
  Where forced logout is a requirement, record the mapping at session
  creation. Do not rebuild it under pressure. You can instead increment a
  per-user credential version that the session-load path reads.
- **Every token model needs an owner, an expiry, and a revocation flag** that
  the authentication path actually reads. The DRF `authtoken` `Token` carries
  the owner and neither of the other two. Its whole model is `key`, a
  `OneToOneField` to the user, and `created`. It therefore never expires, and
  nothing can mark it revoked. It also holds one token per user, which makes
  deletion the only rotation. The discipline it fails is in
  `a07-authentication-failures.md`, "API keys".
- **Grants made off the sync path are the ones to enumerate**: rows in
  `auth_user_groups` and `auth_user_user_permissions`, object-permission rows
  from guardian, and any local role field. These are the orphaned grants of
  the section above, arriving from the other direction.
- **A user row the provider does not know about** is a finding wherever the
  provider is the source of truth. A social account, service account, or API
  key whose own owner is disabled is also a finding.

**Write-time.** When you generate a path that deactivates, suspends, or
offboards an account, revoke its other credentials in the same change as the
flag. Those credentials are sessions, tokens, and API keys.
`is_active = False` is the part that looks like the feature, and it stops the
least.

When you generate any new credential model, give it an owner, an expiry, and a
revoked-at column in its first migration. Read all three on the authentication
path. The offboarding job never revokes a credential that it cannot find.

## Review checklist

### Stack-neutral

- [ ] Privileges are enumerable without reading every view; roles have owners.
- [ ] Every decision reads server-side identity and relationship state. No
      decision reads a client-supplied role, tenant, or owner id.
- [ ] Unknown role, null tenant, new endpoint, and unmapped state all deny.
- [ ] Function-, object-, and field-level decisions each exist where relevant.
- [ ] Deactivation and revocation take effect promptly on every path.
- [ ] Joiner, mover, and leaver each have a path, and a mover's previous
      grants are replaced rather than added to.
- [ ] A disable at the identity provider fans out to sessions, tokens, keys,
      and locally made grants. Each target is marked done from a read-back,
      and not from a handler that returned. A periodic reconciliation reports
      what the fan-out missed.
- [ ] Every machine identity has a named owner whose own identity is still
      active. Those identities are the service account, the bot user, and the
      integration token.
- [ ] Every denormalized copy applies a server-derived authorization filter
      again at its own query path. Those copies are the search index, the
      report table, the export, and the replica. That filter reaches the
      count, the aggregate, and the suggestion, and not the matched record
      alone. Each copy refreshes on a permission change, and not only on a
      content change.

### Django & DRF

- [ ] No reliance on `user.has_perm(perm, obj)` with only `ModelBackend`
      installed; one object-authorization path is chosen and applied.
- [ ] Permission changes re-fetch the user; no long-lived cached user object
      in tasks, commands, or consumers.
- [ ] The `permission_required` decorator sets `raise_exception=True`; without
      it an authenticated-but-unauthorized user is redirected to login.
      `PermissionRequiredMixin` already 403s that user and needs it (or
      `LoginRequiredMiddleware`) only for anonymous requests; object scoping
      comes from the queryset.
- [ ] Custom DRF permissions implement both `has_permission` and
      `has_object_permission` explicitly; list and create paths are secured by
      queryset and `perform_create`.
- [ ] `DjangoObjectPermissions` 404 behavior is preserved, not "fixed" to 403.
- [ ] Admin `get_queryset()` scopes the changelist. Per-object delete logic is
      verified against the deployed Django version, or the bulk action is
      removed. Every custom admin action enforces its per-object rules in the
      action body.
- [ ] Every admin related field that names a scoped model binds its write
      with `limit_choices_to` or a scoped `formfield_for_foreignkey()`
      queryset; the related model's own `ModelAdmin` scopes the lookup.
- [ ] Every view an overridden `get_urls()` adds is wrapped in
      `admin_site.admin_view()` and re-checks the named model permission
      inside; every custom action declares `permissions=[...]`.
- [ ] `DEFAULT_PERMISSION_CLASSES` is restrictive and a URLconf audit test
      asserts every endpoint has an explicit decision. That test reads the
      `@action` override in `initkwargs`, and not the class attribute alone.
- [ ] Writable fields are allow-listed per role; declared fields use
      `read_only=True` rather than relying on `Meta.read_only_fields`. No
      serializer makes the tenant, the owner, the role, the group membership,
      or an `is_*` flag writable. The allow-list reaches every serializer class
      the route can build, nested classes included.
- [ ] Authorization tests use real non-superuser principals across a role ×
      action × object matrix, with `PATCH` covered separately.
