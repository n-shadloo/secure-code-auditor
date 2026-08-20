# Authorization Architecture and the Privilege Model

A01 covers individual access-control *failures*. This file covers the *model*
that produces them: how privileges are structured, what Django's permission
layer actually does, where DRF and the admin do and don't enforce object
access, how to make deny-by-default enforceable, and how to test an
authorization model so the suite is worth trusting. Read alongside
`a01-broken-access-control.md` (per-request enforcement),
`api-drf-specific.md` (serializer shape),
`privileged-access-and-impersonation.md` (operator privilege), and
`data-layer-and-database.md` (database-enforced isolation as a mechanism under
this model). Maps to OWASP
A01:2025 and API1/API3/API5:2023, ASVS 5.0 V8, and CWE-862, CWE-863,
CWE-639, CWE-269, and CWE-284.

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

A privilege model is the design; a permission check is the enforcement. Most
authorization bugs are not a missing `if` — they are a model that cannot express
the rule the business actually has, so each view improvises. Three properties
separate a model that holds up from one that decays:

1. **Declarative and enumerable.** You can list every privilege and who holds
   it without reading every view. If answering "who can delete an invoice?"
   requires grepping, periodic access review is impossible.
2. **Derived from server-side identity state.** The decision reads the
   authenticated principal and stored relationships, never a role, tenant, or
   owner id the client supplied.
3. **Fail closed.** An unknown role, a null tenant, a new endpoint, or an
   unmapped state denies. Anything that defaults to allow eventually gets
   reached by a path nobody reviewed.

ASVS 5.0 V8 splits authorization into three levels, and a model that answers
only the first is incomplete:

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

For most Django SaaS — tenant isolation, a handful of roles, and ownership —
RBAC plus queryset scoping is sufficient, cheaper, and far easier to audit.
Reach for a relationship engine only when authorization genuinely depends on
arbitrary graphs: nested folder/document inheritance, user-to-user resharing,
or cross-service authorization. See `security-hardening-libraries.md` for vetted
engine choices and their operational cost.

Each model has a characteristic decay:

- **RBAC** decays into **role explosion** (a new role per customer or
  permutation), **roles-as-permissions** (roles named after a single action,
  e.g. `can_export_csv`), and **boolean flags on the user model**
  (`is_manager`, `is_reviewer`) that no longer compose.
- **ABAC** decays into attribute sprawl and implicit precedence — conflicting
  allow/deny rules where nobody can say which wins — and, worse, attributes
  sourced from request input rather than server state.
- **ReBAC** decays into relationship drift and stale membership, usually
  because each feature reimplements its own recursive membership query.

Code smells to grep for during review, each a lead rather than a finding:

- `BooleanField` role flags on the user or profile model.
- `if user.role == "..."` or long `if/elif` role ladders inside views.
- permission codenames that are really feature flags.
- authorization decisions reading `request.data` / `request.GET` /
  client-controlled headers without validating against server-side state.
- hand-rolled recursive membership or ancestry queries duplicated per feature.

## Django's permission layer: what it actually does

### Object permissions are a no-op by default

`ModelBackend._get_permissions()` returns an **empty set** whenever `obj` is not
`None`. `has_perm()` consults `get_all_permissions()`, so passing an object
yields an empty permission set and the check returns `False` — for every
non-superuser, even one who holds the model-level permission.

```python
# Misleading: with only ModelBackend installed this is False for every
# non-superuser, including one who holds documents.change_document.
if user.has_perm("documents.change_document", document):
    ...
```

It does not "fall back" to the model permission — it does the opposite. The
dangerous shape is code that reads as an object check, denies everyone in
production, and appears to work in development because the developer is a
superuser (see below). Pick one enforcement path and apply it consistently:

- **queryset scoping** — the default recommendation (`a01-broken-access-control.md`);
- **django-guardian** — object ACL rows, when grants are per-object data;
- **django-rules** — predicate functions, when the rule is computable.

Only the second and third make `user.has_perm(perm, obj)` meaningful, and only
after their backend is added to `AUTHENTICATION_BACKENDS`. Their minimal
wiring, for the cases where queryset scoping genuinely does not fit:

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

Keep `ModelBackend` in the list either way: neither object backend answers a
model-level check, so they add object decisions rather than replacing the
model-level ones.

### Superuser short-circuits everything

`PermissionsMixin.has_perm()` returns `True` for any active superuser before
backends are consulted; `has_module_perms()` behaves the same way, and otherwise
returns `True` if the user holds *any* permission in the app label. Two
consequences matter in review: a superuser fixture exercises no authorization
logic at all (see [test suites](#authorization-test-suites)), and every
superuser account is an unbounded blast radius
(`privileged-access-and-impersonation.md`).

### The permission cache is per-instance and sticky

`ModelBackend` caches permissions on the user object (`_perm_cache`,
`_user_perm_cache`, `_group_perm_cache`) for the life of that instance.
Permission changes made mid-request are not reflected, and
**`User.refresh_from_db()` does not rebuild the cache** — only a fresh query or
a new instance does.

```python
# After changing group membership or permissions, re-fetch the user.
# refresh_from_db() will not rebuild the permission cache.
user = User.objects.get(pk=user.pk)
```

The security-relevant case is **revocation**: a request or worker that removes a
permission and then keeps acting on the same user object continues to see the
old answer. Long-lived user objects in Celery tasks, management commands, and
Channels consumers are where this bites; so are tests that assert a revocation
took effect without re-fetching.

### Async permission APIs

- Django 5.0: `HttpRequest.auser()`, `aauthenticate()`, `aget_user()`,
  `alogin()`, `alogout()`.
- Django 5.1: async `login_required`, `permission_required`,
  `user_passes_test`.
- Django 5.2: `ahas_perm()`, `ahas_perms()`, `ahas_module_perms()`,
  `aget_all_permissions()`, `aget_user_permissions()`,
  `aget_group_permissions()` on both `PermissionsMixin` and `ModelBackend`
  (confirmed in the 5.2 release notes).

Below 5.2 there is no async permission API, and calling the sync one from async
context is the usual source of `SynchronousOnlyOperation` — which developers
then "fix" by moving the check somewhere it no longer runs. Do not carry a
cached user object across awaits or connections; see `async-and-channels.md`.

## Django views: permission_required and PermissionRequiredMixin

Both check **model-level** permissions only. The mixin's `has_permission()` has
no object parameter, so there is no supported way to pass one.

Their failure behavior differs, and the difference is the more common bug.
`AccessMixin.handle_no_permission()` raises `PermissionDenied` when
`self.raise_exception or self.request.user.is_authenticated`, so the **mixin**
already returns 403 to an authenticated-but-unauthorized user; only anonymous
users get the login redirect. The **decorator** has no such clause — its
`check_perms()` returns `False` unless `raise_exception=True`, and
`user_passes_test()` then redirects unconditionally, sending an authenticated
user to a login page they are already past. That is the classic redirect loop,
and it breaks API clients.

```python
class InvoiceUpdateView(PermissionRequiredMixin, UpdateView):
    permission_required = "billing.change_invoice"
    raise_exception = True  # 403 for anonymous requests too, not a redirect

    def get_queryset(self):
        return Invoice.objects.filter(account=self.request.user.account)
```

Set `raise_exception=True` on both, for different reasons: on the decorator it
is what produces a 403 at all, and on the mixin it removes the remaining
redirect for anonymous requests.

The queryset supplies the object-level decision; the mixin never does. On
Django 5.1+, `LoginRequiredMiddleware` makes authentication a project-wide
default so a view's own declaration is purely about authorization.

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

So list endpoints must be secured by filtering the queryset, and creation must
be restricted in the serializer or `perform_create()` — a `has_object_permission`
that forbids writing someone else's record will not stop a client from creating
one against another owner.

Two defaults compound this:

- `BasePermission.has_object_permission` **returns `True`**. A custom permission
  class that implements only `has_permission` grants object access to everyone
  who clears the view-level check.
- With the exception of `DjangoObjectPermissions`, none of the provided classes
  implement object-permission methods at all. `IsAuthenticated` authorizes the
  view, never the object.

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

`DjangoModelPermissions` requires an authenticated user and maps HTTP methods to
the model add/change/delete permissions; it does not require `view` for GET, and
`authenticated_users_only` (default `True`) controls whether unauthenticated
users are rejected outright. It grants no object-level control.

`DjangoObjectPermissions` extends it per object and needs an object-permission
backend. Read its `perms_map` before you rely on it. The stock map holds an
empty permission list for `GET`, `HEAD`, and `OPTIONS`, so a safe request
checks no object permission at all. Read access is view-level only until you
subclass the map:

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
denied. Trac ticket #11383 is still formally open, but the behavior was
addressed via #23869 — older guidance that the action checks only the
model-level permission is out of date. Verify against the Django version in
front of you, and note the gaps that remain real:

- the action's availability gate (`allowed_permissions = ("delete",)`) is
  model-level, called with `obj=None`;
- per-object checks only cover models **registered with the admin site**;
  unregistered cascade targets get none;
- deletion runs through `delete_queryset()` → `QuerySet.delete()`, so an
  overridden `Model.delete()` never runs (see `a09-logging-and-alerting.md`);
- an overridden `get_deleted_objects()` or `delete_queryset()` can drop the
  check entirely.

If per-object delete logic is security-relevant and you cannot verify the whole
path, remove the action with `get_actions()` or
`admin.site.disable_action("delete_selected")` and allow deletes only through
the change form.

Other admin surfaces:

- Custom actions gate on `@admin.action(permissions=[...])`, checked against the
  **model-level** `has_*_permission`. Any per-object rule must be enforced inside
  the action body against the queryset.
- `readonly_fields` prevents edits in the form. It is not an authorization
  control and does nothing for other write paths.
- `autocomplete_fields` and `ForeignKeyRawIdWidget` lookups expose related-object
  querysets. Scope them with `get_search_results()` or `limit_choices_to` where
  the related data is sensitive.
- `is_staff` grants admin login only; `is_superuser` short-circuits every check.

Admin *exposure* (path, TLS, IP restriction, MFA) is in
`a01-broken-access-control.md`.

## Default-deny architecture

In order of leverage:

1. **`DEFAULT_PERMISSION_CLASSES`** set to `IsAuthenticated` or stricter, so a
   newly added viewset is protected unless deliberately opened with `AllowAny`.
   The single highest-value lever for APIs — and it covers DRF only, not plain
   Django views, admin, or non-DRF endpoints.
2. **A URLconf-enumerating audit test**, the only mechanism that makes "a new
   endpoint is unreachable until someone decides" enforceable in CI —
   `scripts/entrypoint_inventory.py` enumerates the same surface read-only,
   which is what an audit has before there is a test to run.
3. Middleware that asserts a view was authorized. Effective, but it fights
   third-party views.
4. `django-decorator-include` to apply a decorator across an included URLconf.

```python
from django.test import SimpleTestCase
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.permissions import AllowAny

# Every entry is a deliberate decision, reviewed when it changes.
PUBLIC_ROUTE_PREFIXES = ("admin/", "accounts/", "health/", "static/")
PUBLIC_VIEWS = {"api.views.SignupView", "api.views.WebhookView"}


def iter_routes(resolver=None, prefix=""):
    resolver = resolver or get_resolver()
    for entry in resolver.url_patterns:
        route = prefix + str(entry.pattern)
        if isinstance(entry, URLResolver):
            yield from iter_routes(entry, route)
        elif isinstance(entry, URLPattern):
            yield route, entry.callback


def identify(callback):
    target = getattr(callback, "cls", None) or getattr(
        callback, "view_class", callback
    )
    return f"{target.__module__}.{target.__qualname__}"


class EveryEndpointHasAnAuthorizationDecision(SimpleTestCase):
    def test_no_undecided_endpoints(self):
        undecided = []
        for route, callback in iter_routes():
            if route.startswith(PUBLIC_ROUTE_PREFIXES):
                continue
            name = identify(callback)
            if name in PUBLIC_VIEWS:
                continue
            permissions = getattr(
                getattr(callback, "cls", None), "permission_classes", None
            )
            if not permissions or AllowAny in permissions:
                undecided.append((route, name))
        self.assertEqual(undecided, [], f"Undecided endpoints: {undecided}")
```

Where it breaks: third-party URLs (admin, allauth, health checks),
static/media, Django's own auth views, and DRF's browsable-API and schema
endpoints all need explicit allow-listing. The cost is a maintained allow-list;
the benefit is that adding a public endpoint becomes a conscious, reviewable act
rather than an omission. A non-DRF view has no `permission_classes`, so either
allow-list it or give it a project-specific marker the test can read.

**Write-time.** When generating a new route, write its authorization decision
in the same edit that adds it to the URLconf, and extend the allow-list above
only where the route is deliberately public, because the audit test is the
mechanism that makes the decision compulsory and an entry added to keep the
suite green converts the control into a formality. A plain Django view, a
Ninja operation, and a tool path carry no `permission_classes` for that test
to read, so each needs its own marker or its own row rather than being assumed
to inherit a DRF default that never applied to it.

## Field-level authorization (BOPLA)

API3:2023 combines the former "Excessive Data Exposure" (returning properties
the caller shouldn't read) and "Mass Assignment" (accepting properties the
caller shouldn't write). Object access granted is not property access granted.

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
    WRITABLE_BY_ROLE = {
        "viewer": set(),
        "editor": {"title", "notes"},
        "admin": {"title", "notes", "status", "account"},
    }

    class Meta:
        model = Invoice
        fields = ["id", "title", "notes", "status", "account", "total"]
        read_only_fields = ["id", "total"]

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

The same failure appears in a GraphQL schema as a type that publishes every
model field, where the deny-list version fails open as the model grows; see
`graphql-and-alternative-api-surfaces.md`, "Schema exposure and the all-fields
type (BOPLA)".

## Search indexes and denormalized copies

A search index, a materialized report table, an analytics export, and a replica
are the same shape of problem: a second copy of the data with **its own query
path**, which does not pass through the queryset scoping, permission classes, or
database policies that guard the source rows. Authorization was implemented once,
at the table, and the copy silently reintroduces an unguarded door. Maps to
CWE-639, CWE-284, and CWE-285; A01:2025 and API1:2023.

The failure has two halves and a review has to test both:

- **Missing predicate.** The copy is queried without re-applying the
  authorization filter that governs the source rows, so any match is returned to
  any caller who can reach the endpoint.
- **Drift.** The copy is refreshed on *content* change but not on *permission*
  change, so a document keeps being served after the grant that justified it was
  revoked.

The design that prevents it rather than patching it:

1. **Every indexed document carries its authorization metadata** — tenant,
   owner, visibility, ACL — as first-class fields, written at index time from
   the same source of truth as the row.
2. **Every query applies a server-derived filter** as a mandatory clause, built
   in trusted backend code from the authenticated principal and never accepted
   from the caller. One search-service choke point is far easier to audit than
   per-view query construction, because a mandatory clause cannot be omitted by
   forgetting it.
3. **Reindex on authorization change**, not only on content change. Treat an ACL
   or membership edit as an index-invalidating event and bound staleness with a
   periodic reconcile.
4. **Index-per-tenant** is stronger isolation and scales poorly. A shared index
   with a mandatory tenant filter — engine-enforced document-level security
   where the engine offers it, application-enforced where it does not — is the
   usual acceptable middle, but only where the filter is genuinely
   unbypassable.

How to audit it: enumerate every site that builds a search query and confirm the
principal-derived filter is added in trusted code; authenticate as tenant A and
search a term that exists only in tenant B, asserting zero hits; revoke access to
a document and re-run the search *before* any content edit, asserting it
disappears; and confirm the indexing pipeline both writes the authorization
metadata and fires on permission changes.

The same reasoning covers a read that a decision depends on. Routing an
authorization read — role, membership, revocation state — to a lagging replica
authorizes what the primary has already denied; see
`data-layer-and-database.md`, "Read replicas and stale authorization".

Agent and tool surfaces reach retrieval through this same path.
`agent-and-llm-interfaces.md` owns the agent-specific slice, where a tool that
republishes retrieval must also intersect the tool's scope with the invoking
user's own permissions.

This section owns who may read the copy. Whether the copy still exists after
the source row was deleted is the orthogonal failure — the deletion event never
fanned out to the index, the report table, or the cache — and it belongs to
`data-lifecycle-and-privacy.md`, "Erasure as a fan-out with a completion
ledger". Both halves apply to the same object, and a review that tests only the
filter will pass a system that still serves erased records.

## Authorization test suites

A suite worth trusting asserts, for each protected resource, a **matrix** of
{role or tenant} × {action} × {expected allow or deny}, including:

- cross-tenant object ids (expect 404 or 403, and assert which);
- object state as an axis of its own — draft against published, active
  against archived, soft-deleted against live — because a rule that reads the
  row's state is a different rule from one that reads only the principal, and
  a matrix over roles alone never exercises it;
- unauthenticated access to every protected route;
- field-level read *and* write per role, with `PATCH` separate from `PUT`;
- state after a denied write, not just the status code;
- any path that republishes a view to an agent or tool surface as its own row,
  since it may not run the same permission classes
  (`agent-and-llm-interfaces.md`).

A suite that gives false confidence:

- **uses a superuser fixture everywhere** — the superuser short-circuit means
  nothing is exercised. This is the most common one.
- tests 403 on one endpoint and assumes the rest of the module behaves.
- mocks the permission class, testing the mock rather than the policy.
- asserts only happy paths.
- never enumerates the URLconf, so new endpoints are silently untested.

Enumerating `urlpatterns` and asserting coverage is what lets a reviewer believe
the suite is exhaustive rather than representative. When the suite runs, and
what else runs beside it once a finding is closed, is
`01-audit-workflow.md`, "Holding the fix: the security regression harness".

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

Absence of all of these is a finding in its own right for a system with
meaningful privilege tiers: it means no one can answer who holds what.

## Identity lifecycle and provisioning desynchronization

Stack-neutral by necessity — Django ships no mechanism for any of it. Maps to
CWE-613 and CWE-672; A01:2025 and A07:2025.

### Principle layer

An identity has three events — **joiner, mover, leaver** — and a system that
models only the first two has no offboarding at all. The joiner is
provisioned and granted. The mover changes team, role, or tenant, and that
has to be a *replacement* of the previous grants rather than an addition to
them, because a mover whose grants only ever accumulate is how one person
ends up holding two jobs' worth of access. The leaver is disabled at the
identity provider, and the divergence starts there.

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
**Synchronization has a direction**, and it is usually one way: the provider
pushes group membership in, so a grant made locally — in the admin, by a
support tool, by a migration — was never known to the provider and a
provider-side removal cannot take it away. A reconciliation that walks only
the identities the provider knows about reports itself clean while the system
holds grants the provider has no record of.

Machine identities decay the same way with nobody watching. A service account
made for a one-off integration, a token minted by someone who has since left,
a bot user with no named owner: each is a live principal that no lifecycle
event touches, because the lifecycle was attached to people.

Two controls, and neither substitutes for the other:

1. **A revocation fan-out on the disable event**, as a durable record with
   per-target state, so a partial failure is visible and retryable rather
   than swallowed by a handler that already returned. That is the same shape
   as the erasure ledger in `data-lifecycle-and-privacy.md`, "Erasure as a
   fan-out with a completion ledger" — reuse it rather than growing a second.
2. **A periodic reconciliation job that produces a report**: every local
   identity and grant compared against the provider, every machine identity
   compared against a named owner, and the difference written down. The
   fan-out handles the event; the job catches what the event missed and what
   never had an event to miss. A reconciliation that logs nothing when it
   finds nothing is indistinguishable from one that did not run.

### Django & DRF implementation layer

Django gives you `is_active`, and `is_active` reaches only the paths that
read the user row — `a07-authentication-failures.md`, "The user model as an
identity contract", has which those are and which credentials skip them.
Everything above it is the project's to build, so the review is an inventory
rather than a settings check:

- **Sessions are not enumerable by user.** `django_session` holds an opaque
  key and an encoded blob, so finding one user's sessions means decoding
  rows. Where forced logout is a requirement, record the mapping when the
  session is created rather than reconstructing it under pressure, or bump a
  per-user credential version that the session-load path reads.
- **Every token model needs an owner, an expiry, and a revocation flag** that
  the authentication path actually reads. DRF's `authtoken` `Token` carries
  the owner and neither of the other two — `key`, a `OneToOneField` to the
  user, and `created` are the whole model — so it never expires, cannot be
  marked revoked, and holds one token per user, which makes deletion the only
  rotation there is. The discipline it fails is in
  `a07-authentication-failures.md`, "API keys".
- **Grants made off the sync path are the ones to enumerate**: rows in
  `auth_user_groups` and `auth_user_user_permissions`, object-permission rows
  from guardian, and any local role field. These are the orphaned grants of
  the section above, arriving from the other direction.
- **A user row the provider does not know about** is a finding wherever the
  provider is the source of truth, and so is a social account, service
  account, or API key whose own owner is disabled.

**Write-time.** When generating a path that deactivates, suspends, or
offboards an account, write the revocation of its other credentials into the
same change as the flag — sessions, tokens, API keys — because setting
`is_active = False` is the part that looks like the feature and the part that
stops the least. When generating any new credential model, give it an owner,
an expiry, and a revoked-at column in its first migration and read all three
on the authentication path, since a credential the offboarding job cannot
find is one it will never revoke.

## Review checklist

### Stack-neutral

- [ ] Privileges are enumerable without reading every view; roles have owners.
- [ ] Decisions read server-side identity/relationship state, never a
      client-supplied role, tenant, or owner id.
- [ ] Unknown role, null tenant, new endpoint, and unmapped state all deny.
- [ ] Function-, object-, and field-level decisions each exist where relevant.
- [ ] Deactivation and revocation take effect promptly on every path.
- [ ] Joiner, mover, and leaver each have a path, and a mover's previous
      grants are replaced rather than added to.
- [ ] A disable at the identity provider fans out to sessions, tokens, keys,
      and locally made grants, and a periodic reconciliation reports what the
      fan-out missed.
- [ ] Every machine identity — service account, bot user, integration token —
      has a named owner whose own identity is still active.
- [ ] Every denormalized copy — search index, report table, export, replica —
      re-applies a server-derived authorization filter at its own query path and
      is refreshed on permission change, not only on content change.

### Django & DRF

- [ ] No reliance on `user.has_perm(perm, obj)` with only `ModelBackend`
      installed; one object-authorization path is chosen and applied.
- [ ] Permission changes re-fetch the user; no long-lived cached user object in
      tasks, commands, or consumers.
- [ ] The `permission_required` decorator sets `raise_exception=True`; without
      it an authenticated-but-unauthorized user is redirected to login.
      `PermissionRequiredMixin` already 403s that user and needs it (or
      `LoginRequiredMiddleware`) only for anonymous requests; object scoping
      comes from the queryset.
- [ ] Custom DRF permissions implement `has_object_permission` explicitly; list
      and create paths are secured by queryset and `perform_create`.
- [ ] `DjangoObjectPermissions` 404 behavior is preserved, not "fixed" to 403.
- [ ] Admin `get_queryset()` scopes the changelist; per-object delete logic is
      verified against the actual Django version or the bulk action is removed;
      custom admin actions enforce per-object rules in the action body.
- [ ] `DEFAULT_PERMISSION_CLASSES` is restrictive and a URLconf audit test
      asserts every endpoint has an explicit decision.
- [ ] Writable fields are allow-listed per role; declared fields use
      `read_only=True` rather than relying on `Meta.read_only_fields`.
- [ ] Authorization tests use real non-superuser principals across a
      role × action × object matrix, with `PATCH` covered separately.
