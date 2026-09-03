# A01:2025 — Broken Access Control

Covers object-level and function-level authorization, and IDOR/BOLA. Covers
the polymorphic reference that a client resolves when it names its own content
type. Covers URL resolution, which is the surface that every one of those
checks assumes.

Covers SSRF, which A01 absorbed in 2025. Covers open redirect and the locale
redirects that are one form of it. Covers multi-tenancy isolation, admin
exposure, and cache-mediated authorization leaks. Maps to OWASP API1:2023
(BOLA) and API5:2023 (BFLA).

This file owns the **per-request failure**. That failure is the request that
reached data it must not reach, and this file states how to recognize it in
code.

This file does not own the model behind that failure.
`authorization-architecture.md` owns the privilege model and field-level
authorization. `api-drf-specific.md` owns the DRF call sites where a correct
model still fails to run. `privileged-access-and-impersonation.md` owns
operator privilege.

This file owns three topics outright, and every other file defers to them. The
first is SSRF, which includes the cloud metadata endpoint that reaches a
leaked workload credential. The second is the cache-mediated leak, and a CDN
cache key that drops its signing parameters is one case of it. The third is
path traversal, which is the filesystem path that a request names on a read,
with no upload anywhere in the flow.

`file-uploads.md` keeps the other half of that split. That half is the
filename that an upload brings, and the storage key it lands under. That half
also covers the private download of a file that the application stored.

`deployment-and-runtime.md` owns the infrastructure side of caching. The rule
about who may read a cached response is here. Routing splits the same way.
`api-drf-specific.md` owns how a reviewer produces the route inventory. This
file owns which of two matching patterns a path reaches.

## Contents
- [Principle](#principle)
- [Django & DRF: object-level authorization](#django--drf-object-level-authorization)
- [IDOR / BOLA](#idor--bola)
- [Generic relations and the client-chosen content type](#generic-relations-and-the-client-chosen-content-type)
- [Function-level authorization](#function-level-authorization)
- [URL resolution as an access-control surface](#url-resolution-as-an-access-control-surface)
- [Multi-tenancy and data isolation](#multi-tenancy-and-data-isolation)
- [Caching and authorization](#caching-and-authorization)
- [SSRF](#ssrf)
- [Path traversal](#path-traversal)
- [Open redirect](#open-redirect)
- [Locale redirects and language negotiation](#locale-redirects-and-language-negotiation)
- [Admin exposure](#admin-exposure)
- [Review checklist](#review-checklist)

## Principle

Access control decides *who may do what to which resource*. It fails in three
recurring ways. The first is **object-level**: user A reaches the record of
user B when they change an identifier, which is IDOR/BOLA. The second is
**function-level**: a normal user reaches an admin-only action, which is BFLA.
The third is **context**: a request reaches an internal resource that it must
not reach, through SSRF, path traversal, or forced browsing.

The defense principle is the same everywhere. **Deny by default. Enforce on
the server for every request. Derive the allowed set from the authenticated
identity, and not from an identifier the client supplied.**

Authentication is who you are. Authorization is what you may touch.
Authentication is not authorization. A check of the first with no check of the
second is the most common serious backend bug. Enforce at the data-access
layer, so that a forgotten check fails closed.

## Django & DRF: object-level authorization

DRF splits permission checks in two. `has_permission(request, view)` runs for
the view. `has_object_permission(request, view, obj)` runs for a specific
object. Two facts cause most bugs:

- DRF calls `has_object_permission` **only** when you fetch through
  `get_object()`, which is the generic detail, update, and destroy path. DRF
  does **not** call it for a list endpoint. DRF also does **not** call it for
  an object that you fetch yourself with `Model.objects.get(...)`.
- A built-in permission class other than `DjangoObjectPermissions` does not
  implement `has_object_permission`. `IsAuthenticated` alone therefore
  authorizes the *view*, and never the *object*.
- The Django `user.has_perm(perm, obj)` call does not help. With the default
  `ModelBackend` it returns `False` for every non-superuser, whatever
  model-level permission that user holds. It does not fall back to the model
  permission. See `authorization-architecture.md`.

The robust default is to **scope the queryset to the requester**. Isolation
then holds for both the list route and the detail route, with no dependence on
the object hook:

```python
# Correct: isolation lives in the queryset
class DocumentViewSet(ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

```python
# Wrong: authentication without ownership -> IDOR on detail routes
class DocumentViewSet(ModelViewSet):
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]
```

If you must expose a shared queryset, add an object permission. The generic
detail, update, and destroy path then calls that permission:

```python
class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id
```

Note that `BasePermission.has_object_permission` returns `True` by default. A
custom class that implements only `has_permission` therefore grants object
access to everyone who clears the view check. `authorization-architecture.md`
covers the full enforcement surface. That surface is the DRF paths that call
the object hook, the admin permission hooks, and the permission model behind
them.

## IDOR / BOLA

Indicators to investigate (each is a lead, confirm reachability):

- `get_queryset` returns `.all()` while the route takes a `pk`/`slug` from the
  URL.
- `Model.objects.get(pk=request.data["id"])` or `get_object_or_404(Model, pk=...)`
  with no ownership term in the filter.
- Ownership taken from the request body (`account_id`, `user_id`) instead of
  `request.user`.
- Nested routes (`/orgs/<id>/projects/<id>/`) where only the leaf is checked.
- Sequential or guessable primary keys exposed in the API. Prefer UUIDs for
  externally referenced objects, but treat UUIDs as *defense in depth*, never as
  the authorization control.

## Generic relations and the client-chosen content type

### Principle layer

A polymorphic reference stores its target as data rather than as a relation.
It stores a type identifier, an object identifier, and application code that
joins the two. No foreign key constrains the pair. Nothing below the
application therefore decides which table the pair resolves to.

That makes the type an input. Where a request supplies both halves, one
endpoint reaches every model that the project installs. The author wrote the
object permission for one model, and it does not run for the model that the
caller names. The check and the target came apart when the class became a
parameter.

Two rules, and their order is the whole control:

- **Resolve first, then authorize the object resolution produced.** A check
  that runs before the code resolves the pair has a type name to judge and no
  record. Load the target on the server. Then run the object-level check
  against that target. `authorization-architecture.md`, "DRF: where the object
  check actually runs" says which paths invoke that hook for you, and which
  paths leave it to you.
- **Restrict the permitted types with a server-side allow list.** The set of
  models that a feature may point at is a design decision with a short answer.
  A route that accepts an arbitrary type from a request body publishes the
  whole model layer.

Two further properties come with the shape rather than with any framework. The
identifier column has one type, and the targets do not need one type. A target
with a different key type therefore breaks the join. The pointer also outlives
its target, because no database-level cascade reaches a row that the database
does not know is related.

The pattern arrives under many names, such as comments, attachments, tags,
reactions, audit records, and notifications. The review question is the same
for each one. Determine who chose the type.

### Django & DRF implementation layer

The `contenttypes` framework is the usual implementation. It uses a
`ForeignKey` to `ContentType`, an `object_id` field, and a `GenericForeignKey`
that joins them. These facts come from the Django 6.0.7 source on 14 Aug 2026,
and a run of each case confirmed them.

- **Resolution runs through `_base_manager`.** `GenericForeignKey.__get__`
  calls `ContentType.objects.get_for_id()` and then
  `get_object_for_this_type()`, which is `model_class()._base_manager.get()`.
  Django does not consult a default manager that scopes by tenant or hides
  soft-deleted rows. The traversal therefore returns rows that the model's own
  queryset excludes. `data-lifecycle-and-privacy.md`, "Soft delete and what it
  does not hide" owns the tombstone half of that.
- **A failed resolution is silent.** `__get__` catches `ObjectDoesNotExist`
  and returns `None`. A missing or mistyped target therefore reads as an
  absent relation, and not as an error. Code in the form
  `if comment.target.owner != request.user` raises `AttributeError` on that
  `None`, and returns a 500. Code in the form
  `if target and not allowed(target)` skips the check. Style decides which of
  the two an application does.
- **Two neighboring failures are not silent.** A `content_type` id with no row
  raises `ContentType.DoesNotExist`. A stale row whose model no longer exists
  returns `model_class() is None`, so resolution raises `AttributeError`. Both
  reach the client as a 500 unless the view catches them. A client-supplied
  content type is therefore an availability lever as well as an authorization
  one.
- **`object_id` is typed and its targets are not.** With the common
  `PositiveIntegerField`, a pointer to a model with a `UUID` primary key fails
  at the database layer rather than in validation. The field coerces with
  `int()`, and `int(UUID)` is a 128-bit integer that no integer column can
  hold. A `CharField` takes every primary key, which removes the error and
  none of the ambiguity.
- **The key is the pair, and half a key is not a key.** Nothing stops two
  models from owning the same `object_id` value. A query that filters on
  `object_id` alone therefore reaches rows that point at a different model.
  Examples are a query that deletes every comment on this object, and a query
  that counts the reactions for this id. Every hand-written query over a
  pointer table filters both columns, or it is a cross-model read.
- **The cascade is a `GenericRelation` on the target, not a constraint.** A
  delete of a target that declares none leaves the pointer row behind, and its
  `target` then reads `None`. A target that declares one makes the Django
  collector delete the pointers with the target. Where `object_id` cannot hold
  the primary key of the target, that same collector query raises, so nothing
  can delete the target. The erasure sweep those orphans defeat is
  `data-lifecycle-and-privacy.md`, "Erasure as a fan-out with a completion
  ledger".

```python
# Wrong: the permission class authorized the view, the pair is resolved
# afterwards, and nothing checks the row resolution produced. The type
# arrives in the body, so this one route reaches every installed model --
# auth.User and admin.LogEntry among them.
class CommentCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ct = ContentType.objects.get(model=request.data["target_type"])
        comment = Comment.objects.create(
            content_type=ct,
            object_id=request.data["target_id"],
            body=request.data["body"],
            author=request.user,
        )
        return Response(CommentSerializer(comment).data, status=201)
```

```python
# Correct: the type comes from a server-side allow list, the target is loaded
# through that model's own scoped queryset, and the object check runs against
# the row rather than against the name it arrived under. CanCommentOn
# implements has_object_permission, so check_object_permissions can deny --
# with IsAuthenticated alone that call authorizes nothing. An unknown type is
# a 404 so the response does not enumerate which types exist.
COMMENTABLE = {"article": Article, "ticket": Ticket}


class CommentCreateView(APIView):
    permission_classes = [IsAuthenticated, CanCommentOn]

    def post(self, request):
        model = COMMENTABLE.get(request.data.get("target_type"))
        if model is None:
            raise Http404
        target = get_object_or_404(
            model.objects.visible_to(request.user),
            pk=request.data.get("target_id"),
        )
        self.check_object_permissions(request, target)
        comment = Comment.objects.create(
            content_type=ContentType.objects.get_for_model(model),
            object_id=target.pk,
            body=request.data["body"],
            author=request.user,
        )
        return Response(CommentSerializer(comment).data, status=201)
```

**Write-time.** When you generate a model with a `GenericForeignKey`, write
the allow list of permitted targets in the same edit as the field. The set is
obvious during the design of the feature, and lost after it. A column that
accepts every model does not tell the next reader which models the author
intended.

Give `object_id` a type that fits every primary key on that list. Add a
`GenericRelation` on each target model in the same edit. Both are schema
decisions, and a later migration has to backfill around them. Where a
serializer exposes the pair, make the type field a `ChoiceField` over the
allow list, rather than a free string.

### Commonly mistaken for a finding

**A generic relation whose content type the server sets.** The field
declaration is the same whether the caller or the code chooses the type. Every
`GenericForeignKey` therefore reads like a client-chosen target.

Three examples take no type from a request. The first is an attachment model
whose type is always `ContentType.objects.get_for_model(...)` on a model that
the view already resolved. The second is an audit record stamped from the
instance that the code saves. The third is a notification that a signal
receiver writes. For each one, the object permission that matters is the one
on the route that produced the target.

The deciding question is whether a request value reaches the content-type
field, or the type is fixed at each write site. Where the type is fixed, the
lifecycle half remains. The pointer still outlives its target, unless a
`GenericRelation` says otherwise.

## Function-level authorization

- Set a restrictive project default and open up per view:
  `REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}`.
  A default of `AllowAny` means every view you forget to annotate is public.
- Admin/staff actions need `IsAdminUser` or a role check, not just
  `IsAuthenticated`.
- `@action` methods on viewsets get the viewset's permissions unless you pass
  `permission_classes=` — check custom actions explicitly.
- `DjangoModelPermissions` ties DRF to the model permission table; it requires an
  authenticated user and maps HTTP verbs to add/change/delete, but grants **no**
  object-level control.

## URL resolution as an access-control surface

### Principle layer

Every access-control decision assumes that the request reached the code that
makes the decision. Resolution is what that assumption rests on. Resolution is
a matching problem rather than a lookup. Django tries the patterns in order,
and the first pattern that matches wins. Where two patterns can match one
path, nothing reports the overlap. The router selects one silently, and
selects the same one on every request.

Three failures follow from that, and none of them looks like an authorization
bug in the file it lives in:

- **A pattern matches more than its author meant it to.** Paths that nobody
  designed then reach a view. A rule written elsewhere against the exact path
  also stops describing the same set of requests. That rule can be at a proxy,
  in a deny list, or in a cache key.
- **The second of two matching patterns is unreachable.** The first pattern
  can carry no permission check while the second does. The protected route
  then exists and passes its tests on a direct call, and never runs.
- **The name is not the route.** The code that generates a link or a redirect
  is a second resolver over the same table. It does not have to agree with the
  first resolver about which of two candidates is the real one.

The review action separates this from an ordinary route review: **enumerate
the resolved routes, not the route files.** Two patterns that resolve one path
are the finding. Neither file shows that finding, because the conflict exists
only in the merged table.

### Django & DRF implementation layer

These facts come from the Django 6.0.7 source on 14 Aug 2026, and a resolution
of the patterns confirmed them.

- **`path()` anchors both ends; `re_path()` anchors the end only if you write
  it.** `_route_to_regex` appends `\Z` for an endpoint route, and a
  converter-free endpoint compares the route string exactly. `RegexPattern`
  uses `fullmatch` only when the pattern is an endpoint *and* its text ends
  with `$`. Otherwise `RegexPattern` uses `re.search`. An endpoint `re_path`
  without its `$` therefore matches any longer path. `URLPattern.resolve` then
  discards the unmatched remainder rather than rejecting it.
- **No system check reports the missing anchor.** `urls.W001` fires for the
  opposite mistake, which is a `$` on a route passed to `include()`. Nothing
  reports a route that matches too much.
- **The converters decide what a captured value may contain.** `str` is
  `[^/]+`, `slug` is `[-a-zA-Z0-9_]+`, `int` is `[0-9]+`, and `path` is `.+`.
  Only `path` admits the separator, so only `path` can carry a traversal
  sequence into a view. `str` still admits `..` on its own. "Path traversal"
  below states what the view must do with such a value.
- **`reverse()` and `resolve()` disagree about a duplicated name.** Resolution
  walks the patterns in declaration order. Django builds the reverse table
  from `reversed(url_patterns)`. One name on two patterns therefore resolves
  to the first pattern and reverses to the last. Every link and redirect from
  that name goes to a route other than the one a top-down reader expects.
- **A duplicated namespace is reported, as a warning.** `urls.W005` says that
  the namespace is not unique. `reverse()` then resolves it against the
  first-declared mount. A generated redirect therefore never points at a
  second mount behind different middleware or a different permission
  decorator. `urls.W005` is a `Warning`, so it prints under `manage.py check`
  and does not fail the default gate. See `a02-security-misconfiguration.md`,
  "check --deploy" for the fail level that catches it.
- **An `include()` shadows a later route only when something inside it
  matches.** A prefix alone falls through. Where no pattern in the included
  module matches the remainder, resolution continues with the next top-level
  pattern. A catch-all inside the include is what makes the prefix absorb the
  path. Catch-alls live in legacy and fallback modules.
- **`APPEND_SLASH` answers a POST with a redirect.** `CommonMiddleware`
  rewrites only on a 404, and only when the slashed path resolves. Django
  raises the `RuntimeError` that names the lost data when `DEBUG` is `True`.
  With `DEBUG` off, the response is a 301, and the body does not survive it. A
  permanent redirect is also a cacheable answer to a state-changing request. A
  route that works only because of this rewrite is one deployment setting away
  from a silent loss of writes.
- **`reverse()` on a name taken from the request** makes the whole name table
  of the project a client-selectable index. It raises `NoReverseMatch` for
  every other value, which is an unhandled 500. Map an input to a name through
  a server-side dictionary. Never pass the input through.

```python
# Wrong: the first pattern is an endpoint with no terminating anchor, so
# Django matches it with re.search. /reports/7, /reports/7extra, and
# /reports/7/audit all resolve here with pk="7" and the rest discarded --
# which means the audit route below it can never run.
urlpatterns = [
    re_path(r"^reports/(?P<pk>\d+)", ReportView.as_view()),
    re_path(r"^reports/(?P<pk>\d+)/audit$", ReportAuditView.as_view()),
]
```

```python
# Correct: path() anchors both ends, so each route matches one shape and the
# more specific one is reachable.
urlpatterns = [
    path("reports/<int:pk>/", ReportView.as_view()),
    path("reports/<int:pk>/audit/", ReportAuditView.as_view()),
]
```

Keep the resolved-route table as an artifact. Do not read it one time.
`api-drf-specific.md`, "Endpoint inventory (API9)" owns how to produce it.
`scripts/entrypoint_inventory.py` resolves the same chain from source, and
does not start the project. This section adds the duplicate-detection pass to
that inventory. Group the rows by resolved path, and read every group with
more than one member.

The table has one precondition, and a project can remove it. A source
inventory starts at `ROOT_URLCONF`. Django reads `request.urlconf` first where
a middleware sets that attribute, and resolves the request against that module
instead. `set_urlconf` moves the same table for the thread or the task, and
`reverse()` follows it. Grep for both names before you trust the artifact.
Where either is present, the artifact describes one branch, and every other
branch needs its own inventory and its own duplicate pass.

**Write-time.** When you generate a route, use `path()` and a converter rather
than `re_path()`. The anchor and the character class are then properties of
the form, and not items the author must remember.

Where a regular expression is genuinely necessary, write the `$` in the same
keystroke as the `^`. You can add a route to a module that already has one for
a neighboring shape. Place the more specific pattern above the more general
one. Then check the resolved path rather than the file, because the pattern
that you shadow is usually in another module.

### Commonly mistaken for a finding

**A second route that resolves the same path.** A duplicate is the pattern
this section is about, so every duplicate reads as an unreachable permission
check. It is only that where the two differ in what guards them.

Three duplicates end at the same code behind the same permission class. The
first is one viewset registered twice on the same router prefix. The second is
a module included at one path from two places. The third is a legacy alias
kept beside its replacement. The unreachable route changes nothing about who
gets in.

The deciding question is what guards each candidate. Compare the permission
class, the decorator, the enclosing middleware, the queryset scope, and the
serializer. Where all five agree, the finding is duplicated routing to remove,
and not a broken control. Where one of the five differs, the duplicate is the
finding. Two candidates that share a permission class can still differ in the
queryset. One sets `queryset = Model.objects.all()` while the other scopes
`get_queryset`, and this file puts the isolation there.

## Multi-tenancy and data isolation

- Every tenant-scoped query must filter by the tenant derived from the request
  identity. Centralize that filter in a manager, a base queryset, or
  middleware that sets the tenant. An individual view then cannot forget it.
- Never accept the tenant id from the body or a header the client can set.
- Watch aggregates, `values()`, exports, and admin. An isolation defect hides
  in a reporting or CSV endpoint as often as in CRUD.

Tenant identity arrives from a subdomain, a URL path segment, a JWT claim, a
session, or a header, and these are not equally trustworthy. A session-stored
tenant is trustworthy; a JWT claim is trustworthy **only** if the token is
verified server-side and the claim was bound at issuance. Subdomains, path
segments, and client-supplied headers are attacker-controllable and must be
validated against the authenticated user's tenant memberships before use, never
trusted alone.

Trust here answers one question only. It says that the client did not author
the value, and not that the value is still true. A session and a token both
hold a tenant that somebody bound at an earlier moment, and a membership can
end after that moment. Re-read the membership from the database on the
request. Where you cache that read, give the cache a short maximum age that
you state at the site. A removed collaborator otherwise keeps the tenant for
the life of the session or the token.

The core failure mode is **tenant resolution and object authorization running
as separate code paths**. The code fetches the object by id, and resolves the
tenant separately. Nothing then asserts that the object belongs to the
resolved tenant. That is cross-tenant IDOR, and both halves still look
correct. Bind the two by a scope on the query, as in
`Model.objects.filter(tenant=request.tenant, pk=pk)`. Do not fetch the object
and then compare.

A "current tenant" held in a thread-local or a `contextvars` global is an
anti-pattern for the same reason. Under async, and with thread-pool reuse, a
thread-local can leak a tenant across requests or tasks. `contextvars` is
safer for async. It still couples authorization to ambient state, and a
background job, a signal receiver, or a consumer can inherit or lose that
state silently. An explicit scope is the deeper fix.

Application-side scoping is opt-in. Its failure mode is therefore the one
query that nobody scoped.

Where that residual risk is unacceptable, move the tenant predicate into the
database itself. Row-level security or a schema per tenant enforces the
predicate on paths that the ORM never sees. Four such paths are raw SQL, a
management command, a Celery task, and the psql session of an operator. This
is a backstop behind scoped querysets, and not a replacement for them. It
carries its own failure modes around pooled connections. See
`data-layer-and-database.md`.

### Commonly mistaken for a finding

**A `get_queryset` that reads unscoped in the file you have open.** An
unscoped queryset under a `pk` route is the highest-yield pattern in this
file. It is therefore also the pattern most often reported where the scope is
real and sits in another file.

Two places carry the scope invisibly. The first is a viewset registered on a
nested router under a tenant-scoped parent. The second is a model whose
default manager already filters, so `Model.objects` is not the whole table.

Read the nested case precisely. The registration alone adds no predicate. What
constrains the child is a parent-filter mixin in the class's bases, the
`NestedViewSetMixin` shape. Look for that mixin. Check that the parent object
itself is authorized for the caller. A parent filter scopes the child to a
parent that the caller may still not own.

The class bases, the router registration, and the model's `Meta` and manager
decide the question. Read them before you conclude. Where they do scope, the
finding that remains is the legibility of the scope rather than a broken
control.

**Write-time.** Some generated views depend on a scope that they do not apply
themselves. Two examples are the parent lookup of a nested router, and a
default manager that filters. Name that dependency in one line at the site.
The only alternative for the next reader is to derive it again from two other
files. A review that does not derive it files the view as a cross-tenant read.

## Caching and authorization

Cache leaks map primarily to CWE-524 (Use of Cache Containing Sensitive
Information), CWE-488 (Exposure of Data Element to Wrong Session), and CWE-862
(Missing Authorization).

### Principle layer

A cache is a second data-serving path. A key can omit an attribute that
changes what a principal may see. One principal then receives the result of
another, and the authorization code below does not run. The invariant is this:
**a cached representation may be reused only when every requester represented
by that key is authorized to receive the same bytes. That authorization is
under the same current policy.**

For sensitive or personalized output, the safest shared-cache policy is not to
cache it. Where caching is justified:

- authorize before reading or populating the cache;
- include every visibility dimension in the key: tenant, principal or audience,
  object, locale/format where relevant, and an authorization-policy/version
  component;
- invalidate or version entries when ownership, role, membership, visibility,
  or revocation state changes;
- keep public, tenant-wide, role-wide, and user-private namespaces separate; and
- apply the same rules to framework caches, reverse proxies, CDNs, browser
  caches, fragments, computed objects, and background-generated exports.

`Vary` is key metadata, not an authorization decision. It is useful only where
the named request headers fully capture the response audience, and every
caching layer honors it.

A signed URL served through a CDN is this failure in its least obvious form.
Where the cache key omits the signing parameters, the CDN stores one
authorized response under a key that another request also produces.
`file-uploads.md`, "Private downloads" holds the storage-specific form of that
rule.

### Django & DRF implementation layer

Do not put `cache_page` or Django's site cache around an authenticated or
personalized view by default:

```python
# Wrong: the URL is shared while the response varies by request.user.
@login_required
@cache_page(300)
def dashboard(request):
    return render(request, "dashboard.html", build_dashboard(request.user))
```

Prefer no caching for sensitive pages and state that policy explicitly:

```python
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache


@never_cache
@login_required
def dashboard(request):
    return render(request, "dashboard.html", build_dashboard(request.user))
```

If a measured hot path genuinely needs application caching, authorize and scope
the data first, then use a low-level key whose audience is explicit:

```python
from django.core.cache import cache
from django.shortcuts import get_object_or_404


def account_summary(request, account_id):
    account = get_object_or_404(
        Account.objects.visible_to(request.user),
        pk=account_id,
    )
    key = (
        f"account-summary:v3:tenant:{account.tenant_id}:"
        f"viewer:{request.user.pk}:account:{account.pk}:"
        f"policy:{account.authorization_version}"
    )
    summary = cache.get(key)
    if summary is None:
        summary = build_account_summary(account, request.user)
        cache.set(key, summary, timeout=60)
    return summary
```

`authorization_version` is an application-owned counter or immutable policy
version updated whenever access to that audience changes; it is not a Django
built-in. Other tenants or operators can sometimes observe a cache key, and
they must not see identifiers. Derive an opaque keyed digest for that case. Do
not put an email, a token, or another sensitive value in the key.

When a response really is safe for a defined audience:

- use `vary_on_cookie` for session-cookie variation and
  `vary_on_headers("Authorization")` for authorization-header variation;
- preserve, append, and test `Vary` through Django, DRF, Nginx, and any CDN
  rather than overwriting it in later middleware;
- set `Cache-Control: private` or `no-store` for private responses and verify
  every intermediary honors it; and
- never assume DRF authentication or permission classes are re-run on a cache
  hit outside the view.

A reviewer can reach two of the 2026 cache advisories from application code
alone, and not only from the installed patch level. Both are cheaper to check
than the version is.

**A hand-written `Cache-Control` whose directive is not lowercase.**
`UpdateCacheMiddleware` compared directives case-sensitively below 6.0.6 and
5.2.15. A response that set `Cache-Control: Private` by hand was therefore
cached as though it had asked for nothing. That is CVE-2026-8404, disclosed 3
June 2026 and rated low under the Django security policy.

The defect affected only a manually set header, which is what makes it a code
finding. Look for a `response["Cache-Control"] = ...` assignment. Look also
for a DRF renderer or middleware that composes the header itself. Then read
the case of the directive. Do not trust that the directive says `private`.

The patch closes the Django half, and leaves the portability half open. A
directive is case-insensitive by specification. An intermediary that reads it
the way Django used to read it is not visible from this repository.

**Write-time.** When you generate a view or middleware that must mark a
response uncacheable, use `never_cache` or `cache_control()`. Do not assign
the header string yourself.

The decorator settles the spelling of the directive in one place. The
hand-written header was also the only form that reached this advisory.
Sometimes a renderer or a proxy-facing shim must compose the header by hand.
Write the directive in lowercase in that first version, because nothing
downstream reports that an intermediary ignored it.

**`SESSION_SAVE_EVERY_REQUEST = True` in front of a cached public page.** The
setting makes Django write a session, and therefore a `Set-Cookie`, on every
response. That includes a response from a view with no authentication in it.

Where the site cache or `cache_page` sits on such a view, the cache stores
that `Set-Cookie` with the page. The cache then replays it to the next
anonymous caller. That caller receives a session identifier that somebody else
already holds. That is CVE-2026-35192, fixed in 6.0.5 and 5.2.14 on 5 May
2026, and rated low under the Django security policy. It is session fixation
reached through a cache rather than through a URL.

A grep finds both halves. The first half is the setting in the settings
module. The second half is `UpdateCacheMiddleware` with
`FetchFromCacheMiddleware` in `MIDDLEWARE`, or a `cache_page` on a view that
requires no login. Neither half is a finding on its own.

**Write-time.** A generated settings module can turn on
`SESSION_SAVE_EVERY_REQUEST`, usually to slide the session expiry on activity.
Check in that same edit whether the site cache middleware is installed. Where
it is installed, keep the cached views off the session path with
`never_cache`. Do not depend on the patch level of the deployed Django. The
setting and the cache are written by different people on different days, and
each is defensible alone.

Keep Django at the current patch level in the supported line — 6.1, 6.0.8, or
5.2.17 as of 9 Aug 2026. The 2026 cache security fixes are spread across the
releases of the whole year, and not concentrated in one release. 6.0.5 and
5.2.14 carry `Vary: *` handling and the `SESSION_SAVE_EVERY_REQUEST` session
fixation above, which is CVE-2026-35192. 6.0.6 and 5.2.15 carry
`Authorization` variation, `Vary` whitespace parsing, and the mixed-case
directives above. 6.0.7 and 5.2.16 carry a further, separate fix for cached
responses that set cookies. Patching is necessary, but it cannot repair an
application key that omits tenant, user, or permission state.

See `deployment-and-runtime.md` for proxy/CDN/cache exposure and infrastructure
configuration.

### Cache review checklist

#### Stack-neutral

- [ ] Every cached sensitive result has an explicit audience. The key captures
      every authorization and representation dimension for that audience.
- [ ] Authorization occurs before a cache read and before cache population. A
      change of role, tenant, ownership, or revocation state invalidates or
      versions the affected entries.
- [ ] Public, tenant, role, and user namespaces cannot collide; keys contain
      no raw secrets or unnecessary personal data.
- [ ] Application, proxy, CDN, fragment, browser, export, and object caches
      obey the same privacy policy.

#### Django & DRF

- [ ] `cache_page`, cache middleware, and DRF response caching are absent from
      authenticated views unless audience-safe behavior is demonstrated.
- [ ] `Vary: Cookie` / `Vary: Authorization`, `private` / `no-store`, decorator
      order, and all intermediary behavior are tested with two different users
      and tenants.
- [ ] Every hand-written `Cache-Control` header spells its directive in
      lowercase, and no cached public view sits behind
      `SESSION_SAVE_EVERY_REQUEST = True`.
- [ ] Django is on a supported patch containing the 2026 cache fixes; patching
      is not treated as a substitute for scoped keys and invalidation.

## SSRF

Any server-side fetch of a client-influenced URL (webhooks, link previews,
image/PDF fetchers, "import from URL") is SSRF-prone; Django has no built-in
guard for developer-initiated requests.

- Allowlist destination hosts/schemes; reject everything else. State how a
  host matches. The naive tests accept a host the list does not hold: a suffix
  test accepts `partner.example.evil.test`, and a substring test accepts
  `evil-partner.example`. Compare the parsed host to an entry for equality.
  Convert the host to lower case and to its IDNA form before that comparison.
  Pin the scheme and the port on each entry. Reject a URL that carries a
  userinfo part, because `https://partner.example@evil.test/` has the host
  `evil.test`. Parse with the library the HTTP client uses, so that the matcher
  and the connection read one host.
- Block link-local and metadata addresses (`169.254.169.254`,
  `metadata.google.internal`), loopback, and private ranges — after DNS
  resolution, and re-check on redirects. Connect to the address that you
  checked. Never let the HTTP client resolve the host a second time. DNS
  rebinding moves the target between the check and the connection.
  The standard library classifies those ranges, so no list is written by hand.
  `not ip.is_global or ip.is_multicast` refuses loopback, every private range,
  the link-local range that holds `169.254.169.254`, the shared address space,
  and each IPv4-mapped IPv6 form of them. `is_global` returns `True` for a
  multicast address, so the predicate reads both properties. Python 3.12.4 is
  the floor, because it added the 6to4 range. On 3.12.3 the 6to4 form of the
  metadata address is still global. The same fix is in 3.9.20, 3.10.15, and
  3.11.10. The predicate refuses only what CPython classifies. `64:ff9b::/96`
  stays global, and behind a NAT64 gateway `64:ff9b::a00:1` reaches `10.0.0.1`,
  so the allowlist above still leads.
- The cloud metadata endpoint is the highest-value entry on that list, because
  what it returns is a live credential for the workload. Deny it in the
  application *and* require the hardened, token-based metadata service of the
  instance, with a minimal hop limit. A single SSRF then does not become
  credential theft. What such a credential then unlocks is in
  `service-identity-and-secrets.md`.
- Disable or bound redirects; set timeouts; never reflect the raw response
  back to the user.
- A URL that a model assembles is client-influenced for this purpose. So is a
  URL taken from content that a model retrieved. See
  `agent-and-llm-interfaces.md`, "Model output as an injection source".

**Write-time.** When you generate an outbound call whose URL derives from
input, write four controls as part of the call. Write the host and scheme
allowlist, and the post-resolution address check. Write the bounded or
disabled redirects, and the timeout. Do not add them around the call
afterwards. A fetch helper that works gets reused, and the second caller
inherits what the first caller settled for.

Write the allowlist as the set of destinations that the feature needs. Do not
write it as a list of ranges to refuse. The refusal list is the list that must
be complete, and it never is complete. Where the destination does not need to
be dynamic, take it from configuration instead. The class of defect then
disappears, and needs no defense.

### Commonly mistaken for a finding

**An outbound request whose URL is built from a settings value or a stored
service record.** The shape is the same as the finding. A URL is assembled at
run time and handed to an HTTP client, with no allowlist near it.
`requests.get(url)` looks the same whichever side of the boundary `url` came
from. What makes SSRF a finding is that a caller influences the destination.

The deciding question is who last wrote the value. A settings entry, an
environment variable, or a service record that only an operator can create is
a deploy-time input. It is not an attacker-controlled one.

A principal below an operator can sometimes write that stored record. Examples
are a tenant admin who registers a callback, and a user who sets a profile
URL. The value is then attacker-controlled again, and the finding is live.

### Egress control

The controls above stop one call from reaching somewhere it should not. Egress
control asks the next question. An attacker can compromise a process through
deserialization, a dependency, a template sink, or a prompt-injected agent.
Egress control decides what that process can still reach. A service that may
open a connection to any host on the internet makes every foothold an
exfiltration channel and a command-and-control path. The fetch helper does not
change that.

**Allowlist by destination; do not enumerate what to refuse.** A denylist of
private ranges is a list that must be complete.

Four things defeat it. A DNS name can resolve into the range after the check.
A redirect can reach the range. An IPv6-mapped or alternative-notation form of
the address can pass the check. Every internal service and cloud metadata
endpoint added after the list was written also passes it. An allowlist of the
few hosts a feature legitimately calls fails closed against all of them at
once, and it is short enough to review.

**Default to deny for the processes with the narrowest needs.** Four processes
each talk to a small, enumerable set of destinations. They are a webhook
delivery worker, a link-preview or import-from-URL worker, a media fetcher,
and an agent tool runner. That set is known before the code ships.
Deny-by-default egress costs least and gives most on those processes. They are
also the most exposed processes, because their whole job is to fetch what
somebody else named.

**The platform and the application enforce different halves and neither
substitutes for the other.** The platform half is an egress gateway, a network
policy, or a forward proxy that the process must use. That half survives code
that never went through the fetch helper, such as the HTTP client of a
library, a subprocess, or a debug shell.

The application-side check sees what the platform cannot see. It sees which
user asked, and which redirect the response carried. It also sees whether the
resolved address changed between the check and the connection. Report the
platform half as a cross-team recommendation and the application half as a
repository finding, in the same split `deployment-and-runtime.md` uses for
orchestrator enforcement.

An outbound webhook sender is the worked example.
`a08-integrity-and-deserialization.md`, "Sending webhooks of your own" holds
its delivery-side controls. Those controls are registered destinations
validated again at send time, bounded redirects, and capped retries. An
agent's tool egress is in `agent-and-llm-interfaces.md`, "Retrieved content
and indirect prompt injection", which reaches the same conclusion from the
exfiltration side.

## Path traversal

SSRF is a request that reaches a network resource it must not reach. Path
traversal is the same failure against the filesystem, and it belongs here for
the same reason. Nothing in the code looks like an authorization decision. The
effect is still that a caller reads a file the application never meant to
expose. Maps to CWE-22 (Path Traversal) and CWE-23 (Relative Path Traversal).
The upload case is elsewhere: `file-uploads.md` owns the name an upload brings
and the key it is stored under.

This section owns the read whose path the request named. That is usually a
flow with no upload in it. Examples are a report download, a generated export,
a documentation tree, and a log or artifact viewer.

The sink is any request-derived value reaching `open()`, `os.path.join()`, a
`pathlib` join, or a template or file path resolved outside the storage API.

The reason this keeps shipping is that `os.path.join` reads like a containment
function and is not one. It does not normalize `..`, so a value walks upward
without resistance. Where the value is absolute, it discards the base
completely. That is a documented property rather than an edge case:
`os.path.join("/srv/exports", "/etc/passwd")` is `"/etc/passwd"`. A base
directory in the expression is therefore not evidence that anything is
confined to it.

### What Django actually protects, and what it does not

Three answers, because they are routinely assumed to be one:

- **`safe_join` is the real control, and it rejects rather than repairs.** It
  resolves `abspath(join(base, *paths))` against `abspath(base)`. It raises
  `SuspiciousFileOperation` unless one of three conditions holds. The result
  begins with the base plus a separator, the result equals the base exactly,
  or the base is a filesystem root. The trailing separator is what defeats a
  sibling directory sharing the base's prefix, and the comparison runs through
  `normcase`, so it holds on case-insensitive filesystems.
  `SuspiciousFileOperation` is a `SuspiciousOperation` subclass, which Django
  renders as a 400. Note where it lives: `django.utils._os`, an
  underscore-prefixed private module that no public documentation covers. Use
  of it is reasonable. A direct dependence on it is a dependence on something
  Django has not promised to keep. That is a further argument to reach it
  through the storage API, which calls it for you. The containment is lexical.
  A storage tree that an untrusted process can write links into defeats it
  between the check and the open. Prefer object storage for untrusted content.
  Reject link members at ingestion, as the upload rules already require.
- **`FileSystemStorage` inherits that protection, so the storage API is the
  supported route.** `path()` returns `safe_join(self.location, name)`, and
  `open()`, `exists()`, and `size()` all resolve through `path()`. On the
  write side `get_available_name()` and `generate_filename()` additionally
  raise on `..` in the directory parts and run `validate_file_name`, which
  requires `name == os.path.basename(name)` unless `allow_relative_path=True`.
  None of this reaches a bare `open()` — the protection is a property of the
  API, not of the framework being present.
- **`FileResponse` validates nothing, and `django.views.static.serve` is not a
  production answer.** `FileResponse` streams a file object that the caller
  already opened. It sets `Content-Length`, `Content-Type`, and
  `Content-Disposition`. It makes no decision about the origin of the bytes.
  Traversal safety is therefore settled before the call to it. `serve()` does
  use `safe_join`, and it is traversal-safe. Django states in the module
  itself that `serve()` is for development, and that a project should not use
  it in production. Safety against this defect is not an endorsement to serve
  files with it.

```python
# Wrong: the base directory in the expression is decorative. os.path.join does
# not normalize "..", and an absolute value discards EXPORT_ROOT outright, so
# ?name=../../etc/passwd and ?name=/etc/passwd both resolve off the base.
import os

from django.http import FileResponse

EXPORT_ROOT = "/srv/exports"


def download_export(request):
    path = os.path.join(EXPORT_ROOT, request.GET["name"])
    return FileResponse(open(path, "rb"), as_attachment=True)
```

```python
# Correct: the client names a key the server published rather than a path, so
# no part of the filename is attacker-authored. The storage instance is the
# backstop for the next caller who is handed a name from somewhere else -- its
# path() runs safe_join, which raises SuspiciousFileOperation rather than
# quietly normalizing an escape into a valid path.
from django.core.exceptions import SuspiciousFileOperation
from django.core.files.storage import FileSystemStorage
from django.http import FileResponse, Http404

EXPORTS = FileSystemStorage(location="/srv/exports")
AVAILABLE = {
    "monthly": "monthly-summary.csv",
    "annual": "annual-summary.csv",
}


def download_export(request):
    name = AVAILABLE.get(request.GET.get("report"))
    if name is None:
        raise Http404
    try:
        stream = EXPORTS.open(name, "rb")
    except (SuspiciousFileOperation, FileNotFoundError):
        raise Http404
    return FileResponse(stream, as_attachment=True, filename=name)
```

The pattern generalizes in one line: **let the client choose an identifier,
not a path.** Three forms let the server decide every character of the
filename. They are a key in a server-side mapping, a primary key resolved
through a scoped queryset, and an enumerated slug. Each one removes the class
of defect, rather than defending against it. Where a join is unavoidable,
resolve through the storage API, and let `SuspiciousFileOperation` reject the
escape. Catch it as a 404 rather than a 400, so that the response does not
confirm which paths exist.

Two things this does not settle. Confinement is not authorization. A path
correctly confined to the base must still be a file that *this* requester may
read. That is the object-level check that the rest of this file is about.

In production the web server usually serves the bytes better, after Django
performs the check. Use `X-Accel-Redirect` or `X-Sendfile`, and keep the files
outside the public root. `file-uploads.md`, "Private downloads" holds that
arrangement and its trade-offs.

**Write-time.** When you generate a view that reads a file whose name derives
from a request, write the identifier-to-name mapping first. Write the file
access second. The mapping removes the traversal question, rather than
answering it.

Where a name must pass through, open it with a `FileSystemStorage` pinned to
the base directory. Do not use `open()` and `os.path.join()`. Handle
`SuspiciousFileOperation` in the same edit, because an uncaught one is a 500
on a path that had to fail closed. Add the ownership check beside the path
resolution, and not after it. A confined path is still the file of some
principal.

### Commonly mistaken for a finding

**`os.path.join` against a base where the joined component is a server-chosen
identifier.** This section says that `os.path.join` is not a containment
function. Every hit therefore reads as traversal, and the call looks the same
whatever sits on its right-hand side. A primary key, a UUID, a hash digest, or
a slug from a fixed set contains no separator and no `..`. The server produced
every character of it.

The deciding question is who authored the component, and not what the function
does with it. Where the value is a request parameter that the code only
believes is an integer, that belief is the finding. Where the value is the
`str(obj.pk)` of a row already fetched through a scoped queryset, nothing can
traverse with it. The ownership question is separate and stays live either
way: a confined path is still someone's file.

## Open redirect

For any user-supplied redirect target (`next`, `return_to`), validate before
redirecting:

```python
from django.utils.http import url_has_allowed_host_and_scheme

if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
    return redirect(nxt)
return redirect("home")
```

Never call `redirect(request.GET["next"])` without a check. It enables
phishing, and it can start OAuth token theft.

A redirect can also carry the request method and the body forward.
`preserve_request=True` makes `HttpResponseRedirect` and `redirect()` answer
with 307 or 308 rather than 302 or 301. Django added that argument in 5.2.
Django 6.1 adds the same control to the class-based view as
`RedirectView.preserve_request`, which defaults to `False`. Rate an enabled one
above a plain open redirect, because the POST body reaches the target host as
well as the visit. Validate the target with `url_has_allowed_host_and_scheme`
before the response is built, exactly as above.

Django also bounds the redirect URL at 16384 characters and raises
`DisallowedRedirect` above it. Django 6.0 hard-codes that bound. Django 6.1
adds a `max_length` argument that overrides it, and `max_length=None` removes
the check. Read `max_length=None` on a caller-supplied target as a finding,
because it deletes a bound the framework enforced for every project. Verified
against the 6.1 and 6.0 source on 20 Aug 2026.

**Write-time.** Do not generate `preserve_request=True` or `max_length=None`
for a redirect whose target comes from the request. Validate the target first,
then choose the status code the flow needs.

## Locale redirects and language negotiation

### Principle layer

Language selection is an input that changes the response, and it arrives from
places the client controls: a path prefix, a cookie, a request header. Three
consequences, and each is a familiar failure wearing an unfamiliar name.

- **A language switch is a redirect endpoint.** It takes a target from the
  request and sends the browser there, which is the shape in "Open redirect"
  above with a language parameter attached.
- **A framework that redirects to add a language prefix multiplies the URLs
  for one resource.** It also inserts a hop into a flow that the author
  treated as a single request. Three such flows are an unauthenticated entry,
  a login return, and a POST.
- **A header that changes the response is a cache dimension.** A cache that
  does not separate on it serves one visitor's rendering to the next.

### Django & DRF implementation layer

These facts come from the Django 6.0.7 source on 14 Aug 2026, and a run of
each case confirmed them.

- **The built-in switch validates; a replacement usually does not.**
  `django.views.i18n.set_language` reads `next` from the POST body or the
  query string and passes it through `url_has_allowed_host_and_scheme` against
  `request.get_host()`, with `require_https` taken from `request.is_secure()`.
  On failure it falls back to the `Referer` header, validated the same way,
  and then to `/`. It writes the language cookie only on a POST and only for a
  code `check_for_language` accepts. Treat a hand-written language switcher as
  an open-redirect candidate immediately. The validation is three lines that
  read as routine, and nobody reviews the view around them.
- **Four sources, in order.** `get_language_from_request` takes the path
  prefix first when `i18n_patterns` is in use, then the `LANGUAGE_COOKIE_NAME`
  cookie, then `Accept-Language`, then `LANGUAGE_CODE`. Every source but the
  last comes from the request. The cookie among them has weaker defaults than
  the session cookie. `a02-security-misconfiguration.md`, "Cookie prefixes and
  the subdomain boundary" states those defaults and what to change.
- **The prefix redirect fires on a narrow condition, and the setting moves
  it.** `LocaleMiddleware` redirects only under five conditions. The response
  is a 404, the path carries no language, and `i18n_patterns` is in use. Also,
  `prefix_default_language` is `True`, and the prefixed path resolves.
  `LocaleMiddleware` patches `Vary: Accept-Language, Cookie` onto that
  redirect. A `prefix_default_language` of `False` removes the prefix from the
  default language completely. Which paths redirect therefore changes with the
  setting. A chain walked under one value must be walked again under the
  other. Walk it with a non-default `Accept-Language`, and follow every hop. A
  loop and an unauthenticated detour are both cheaper to observe than to
  reason about.
- **The language can drop out of the cache key while `Vary` still names it.**
  With `USE_I18N` on, `learn_cache_key` strips `Accept-Language` from the
  header list that it stores. `_i18n_cache_key_suffix` appends the active
  language to the key instead. That language is `request.LANGUAGE_CODE` where
  a middleware set it, and otherwise the active language. That suffix is
  computed by `FetchFromCacheMiddleware` in the request phase, so it is right
  only if `LocaleMiddleware` has already run. A run in the other order
  reproduces the defect. A request with `Accept-Language: fr` filled the
  cache. The next request, with `Accept-Language: en`, received the French
  body. That response carried `Vary: Accept-Language`, which was accurate and
  irrelevant. Some projects resolve the language themselves, through a custom
  middleware, a stored profile preference, or content negotiation in DRF. Such
  a project gets the suffix only where it activates the language before the
  cache read. It also gets no `Vary` from any component.

```python
# Wrong: the cache key is computed before the request's language is known, so
# every entry is stored under whatever language was already active.
MIDDLEWARE = [
    "django.middleware.cache.UpdateCacheMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.cache.FetchFromCacheMiddleware",
    "django.middleware.locale.LocaleMiddleware",
]
```

```python
# Correct: the locale middleware resolves the language before the cache is
# read, and adds its Vary header before the response is stored.
MIDDLEWARE = [
    "django.middleware.cache.UpdateCacheMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.cache.FetchFromCacheMiddleware",
]
```

Rate the cache case on what the language actually changes. Where the two
renderings differ only in wording, the case is a defect and not a disclosure.
Where the language stands for a market, it discloses. Three such cases are a
price, a jurisdiction-specific notice, and a catalog that varies by region.

Where the same key defect sits in front of authenticated output, it is not a
locale question. It is the failure in "Caching and authorization" above. This
case demonstrates the rule of that section: `Vary` is key metadata, not an
authorization decision.

**Write-time.** When you generate a language switch, mount `set_language`. Do
not write a view that redirects to a `next` value. The built-in already
carries the host and scheme check, and a replacement starts without that
check.

When you add `LocaleMiddleware` to a project that caches, place it relative to
the cache middleware in that same edit. Put it above
`FetchFromCacheMiddleware` and below `UpdateCacheMiddleware`. The two are
usually added months apart, and the resulting order is silent in both
directions.

## Admin exposure

- Move the admin off the default path in `urls.py`. Serve it only over HTTPS.
  Restrict it at the proxy with an IP allowlist or a VPN where that is
  possible.
- Separate staff from superuser; grant the minimum. Audit who has `is_staff` /
  `is_superuser`.
- Add MFA for admin (`django-otp`); see the auth and libraries files.

This section covers *exposure*. `authorization-architecture.md` owns the admin
permission hooks. Those hooks are `get_queryset()` scoping, bulk actions, and
custom `@admin.action` permissions. That file also states what
`readonly_fields` does and does not enforce. Impersonation ("log in as user")
and break-glass elevation are in `privileged-access-and-impersonation.md`.

## Review checklist

- [ ] Every detail, update, and destroy route scopes by the requester, through
      a queryset or an object permission.
- [ ] Every list endpoint filters by identity. No list or export leaks across
      tenants.
- [ ] The default permission class is restrictive. Every public view is a
      deliberate choice.
- [ ] Ownership/tenant comes from `request.user`, never the request body.
- [ ] A generic relation whose content type a request can influence accepts
      only an allow-listed model. The object check runs against the row that
      resolution produced, and not ahead of it.
- [ ] No two patterns resolve one path. The resolved-route table is what the
      reviewer read. Every endpoint `re_path` without a terminating anchor is
      treated as a match for more than its shape.
- [ ] Tenant resolution and object lookup are one scoped query, and not two
      independent steps. No ambient thread-local or `contextvars` tenant is in
      use. A session-stored or claim-stored tenant is re-checked against
      current membership.
- [ ] Any database-enforced isolation is a backstop behind scoped querysets.
      Its context cannot leak between pooled connections.
- [ ] Admin/staff actions use a role check, not bare `IsAuthenticated`.
- [ ] No shared cache holds an authenticated or personalized response. Every
      private cache key and its invalidation cover every authorization
      dimension.
- [ ] A language switch validates its redirect target. `LocaleMiddleware` sits
      above the cache fetch, so the key carries the language of the request
      and not the language that was active.
- [ ] Every server-side URL fetch is allowlisted, and blocks internal ranges.
      The application denies the cloud metadata endpoint, and the instance
      hardens it.
- [ ] Some processes have enumerable destinations, such as webhook senders,
      fetch and preview workers, and agent tool runners. The platform denies
      egress by default for each one. The application-side allowlist stays as
      the half that sees the redirect and the caller.
- [ ] No request-derived value reaches `open()`, `os.path.join()`, or a
      `pathlib` join for a read. Each file name comes from a server-side
      identifier, and resolves through the storage API. The code handles the
      rejection of that API, and does not let it become a 500.
- [ ] `url_has_allowed_host_and_scheme` validates every redirect target. A
      307/308 `preserve_request` redirect is a finding on a caller-supplied
      target, and so is a `max_length=None` override.
