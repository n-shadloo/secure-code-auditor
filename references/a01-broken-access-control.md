# A01:2025 — Broken Access Control

Covers object-level and function-level authorization, IDOR/BOLA, the
polymorphic reference a client resolves by naming its own content type, URL
resolution as the surface every one of those checks assumes, SSRF (folded into
A01 in 2025), open redirect and the locale redirects that are one,
multi-tenancy isolation, admin exposure, and cache-mediated authorization
leaks. Maps to OWASP API1:2023 (BOLA) and API5:2023 (BFLA).

This file owns the **per-request failure** — the request that reached data it
should not have, and how to recognize it in code. It does not own the model
behind that failure: `authorization-architecture.md` owns the privilege model
and field-level authorization, `api-drf-specific.md` owns the DRF call sites
where a correct model still fails to run, and
`privileged-access-and-impersonation.md` owns operator privilege. Three topics
are owned here outright and every other file defers to them: SSRF, including
the cloud metadata endpoint a leaked workload credential is reached through;
the cache-mediated leak of which a CDN cache key dropping its signing
parameters is one case; and path traversal — the filesystem path a request
names on a read, with no upload anywhere in the flow. `file-uploads.md` keeps
the other half of that split, the filename an upload brings and the storage key
it lands under, along with the private download of a file the application
stored. `deployment-and-runtime.md` owns the infrastructure side of caching;
the rule about who may read a cached response is here. Routing splits the same
way: `api-drf-specific.md` owns how the route inventory is produced, and which
of two matching patterns a path actually reaches is owned here.

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
recurring ways: **object-level** (user A reaches user B's record by changing an
identifier — IDOR/BOLA), **function-level** (a normal user reaches an
admin-only action — BFLA), and **context** (a request reaches an internal
resource it shouldn't — SSRF, path traversal, forced browsing). The defense
principle is the same everywhere: **deny by default, enforce on the server for
every request, and derive the allowed set from the authenticated identity — not
from an identifier the client supplied.** Authentication (who you are) is not
authorization (what you may touch); checking the first and skipping the second
is the single most common serious backend bug. Enforce at the data-access layer
so a forgotten check fails closed.

## Django & DRF: object-level authorization

DRF splits permission checks in two: `has_permission(request, view)` runs for the
view; `has_object_permission(request, view, obj)` runs for a specific object.
Two facts cause most bugs:

- `has_object_permission` is **only** called when you fetch through
  `get_object()` (the generic detail/update/destroy path). It is **not** called
  for list endpoints, and **not** for objects you fetch yourself with
  `Model.objects.get(...)`.
- Built-in permission classes other than `DjangoObjectPermissions` don't
  implement `has_object_permission`, so `IsAuthenticated` alone authorizes the
  *view*, never the *object*.
- Django's own `user.has_perm(perm, obj)` does not help: with the default
  `ModelBackend` it returns `False` for every non-superuser, whatever
  model-level permission they hold. It does not fall back to the model
  permission — see `authorization-architecture.md`.

The robust default is to **scope the queryset to the requester**, so isolation
holds for both list and detail without depending on the object hook:

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

If you must expose a shared queryset, add an object permission and rely on the
generic path calling it:

```python
class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id
```

Note that `BasePermission.has_object_permission` returns `True` by default, so a
custom class implementing only `has_permission` grants object access to everyone
who clears the view check. `authorization-architecture.md` covers the full
enforcement surface — which DRF paths call the object hook, the admin permission
hooks, and the permission model behind them.

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

A polymorphic reference stores its target as data rather than as a relation: a
type identifier, an object identifier, and application code that joins the two.
No foreign key constrains the pair, so nothing beneath the application decides
which table it resolves to.

That makes the type an input. Where a request supplies both halves, one
endpoint reaches every model the project has installed, and the object
permission its author wrote for the model they had in mind does not run for the
model the caller named. The check and the target came apart the moment the
class became a parameter.

Two rules, and their order is the whole control:

- **Resolve first, then authorize the object resolution produced.** A check
  that runs before the pair is resolved has a type name to judge and no record.
  Load the target on the server, then run the object-level check against it.
  `authorization-architecture.md`, "DRF: where the object check actually runs"
  says which paths invoke that hook for you and which leave it to you.
- **Restrict the permitted types with a server-side allow list.** The set of
  models a feature may point at is a design decision with a short, enumerable
  answer. Accepting an arbitrary type from a request body publishes the whole
  model layer through one route.

Two further properties come with the shape rather than with any framework. The
identifier column has one type while the targets need not, so a target keyed
differently from that column breaks the join. And the pointer outlives its
target, because no database-level cascade reaches a row the database does not
know is related.

The pattern arrives under many names — comments, attachments, tags, reactions,
audit records, notifications — and the review question is the same for each:
who chose the type?

### Django & DRF implementation layer

The `contenttypes` framework is the usual implementation: a `ForeignKey` to
`ContentType`, an `object_id` field, and a `GenericForeignKey` joining them.
Read off the Django 6.0.7 source on 14 Aug 2026 and confirmed by running each
case.

- **Resolution runs through `_base_manager`.** `GenericForeignKey.__get__`
  calls `ContentType.objects.get_for_id()` and then
  `get_object_for_this_type()`, which is `model_class()._base_manager.get()`. A
  default manager that scopes by tenant or hides soft-deleted rows is not
  consulted, so the traversal returns rows the model's own queryset would not.
  `data-lifecycle-and-privacy.md`, "Soft delete and what it does not hide" owns
  the tombstone half of that.
- **A failed resolution is silent.** `__get__` catches `ObjectDoesNotExist` and
  returns `None`, so a missing or mistyped target reads as an absent relation
  rather than as an error. Code shaped as
  `if comment.target.owner != request.user` raises `AttributeError` on that
  `None` and returns a 500; code shaped as `if target and not allowed(target)`
  skips the check entirely. Which of the two an application does is an accident
  of style rather than a decision.
- **Two neighboring failures are not silent.** A `content_type` id with no row
  raises `ContentType.DoesNotExist`, and a stale row whose model has since been
  removed returns `model_class() is None`, so resolution raises
  `AttributeError`. Both reach the client as a 500 unless the view catches
  them, which makes a client-supplied content type an availability lever as
  well as an authorization one.
- **`object_id` is typed and its targets are not.** With the common
  `PositiveIntegerField`, pointing at a model with a `UUID` primary key fails
  at the database layer rather than in validation: the field coerces with
  `int()`, and `int(UUID)` is a 128-bit integer no integer column can hold. A
  `CharField` takes every primary key there is, which removes the error and
  none of the ambiguity.
- **The key is the pair, and half a key is not a key.** Nothing stops two
  models from owning the same `object_id` value, so a query filtering on
  `object_id` alone — delete every comment on this object, count the reactions
  for this id — reaches rows that point at a different model entirely. Every
  hand-written query over a pointer table filters both columns or it is a
  cross-model read.
- **The cascade is a `GenericRelation` on the target, not a constraint.**
  Deleting a target that declares none leaves the pointer row behind, and its
  `target` reads `None` from then on. Declaring one makes Django's collector
  delete the pointers with the target — and where `object_id` cannot hold the
  target's primary key, that same collector query raises, so the target cannot
  be deleted at all. The erasure sweep those orphans defeat is
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
# the row rather than against the name it arrived under. An unknown type is a
# 404 so the response does not enumerate which types exist.
COMMENTABLE = {"article": Article, "ticket": Ticket}


class CommentCreateView(APIView):
    permission_classes = [IsAuthenticated]

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

**Write-time.** When generating a model with a `GenericForeignKey`, write the
allow list of permitted targets in the same edit as the field, because the set
is obvious while the feature is being designed and unrecoverable afterwards —
the next reader cannot tell which models were intended from a column that
accepts them all. Give `object_id` a type that fits every primary key on that
list, and add a `GenericRelation` on each target model in the same edit, since
both are schema decisions that a later migration has to backfill around. Where
a serializer exposes the pair, make the type field a `ChoiceField` over the
allow list rather than a free string.

### Commonly mistaken for a finding

**A generic relation whose content type the server sets.** The field
declaration is identical whether the type is chosen by the caller or by the
code, so every `GenericForeignKey` reads like a client-chosen target. An
attachment model whose type is always `ContentType.objects.get_for_model(...)`
on a model the view already resolved, an audit record stamped from the instance
being saved, a notification written by a signal receiver — none of these take a
type from a request, and the object permission that matters is the one on the
route that produced the target. The deciding question is whether any request
value reaches the content-type field or the type is fixed at each write site.
Where it is fixed, what remains is the lifecycle half: the pointer still
outlives its target unless a `GenericRelation` says otherwise.

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

Every access-control decision assumes the request reached the code that makes
it. Resolution is what that assumption rests on, and it is a matching problem
rather than a lookup: patterns are tried in order and the first one that
matches wins. Where two patterns can match one path, nothing reports the
overlap — the router picks, silently, and picks the same way on every
request.

Three failures follow from that, and none of them looks like an authorization
bug in the file it lives in:

- **A pattern matches more than its author meant it to**, so paths nobody
  designed reach a view, and a rule written elsewhere against the exact path —
  at a proxy, in a deny list, in a cache key — no longer describes the same
  set of requests.
- **The second of two matching patterns is unreachable.** When the first
  carries no permission check and the second does, the protected route exists,
  passes its tests when called directly, and never runs.
- **The name is not the route.** Link and redirect generation is a second
  resolver over the same table, and it does not have to agree with the first
  about which of two candidates is the real one.

The review action is what separates this from ordinary route review:
**enumerate the resolved routes, not the route files.** Two patterns that
resolve one path are the finding, and neither file shows it — the conflict
exists only in the merged table.

### Django & DRF implementation layer

Read off the Django 6.0.7 source on 14 Aug 2026 and confirmed by resolving the
patterns.

- **`path()` anchors both ends; `re_path()` anchors the end only if you write
  it.** `_route_to_regex` appends `\Z` for an endpoint route, and a
  converter-free endpoint compares the route string exactly. `RegexPattern`
  uses `fullmatch` only when the pattern is an endpoint *and* its text ends
  with `$`; otherwise it uses `re.search`. So an endpoint `re_path` missing its
  `$` matches any longer path, and `URLPattern.resolve` discards the unmatched
  remainder rather than rejecting it.
- **No system check reports the missing anchor.** `urls.W001` fires for the
  opposite mistake — a `$` on a route passed to `include()`. A route that
  matches too much is reported by nothing.
- **The converters decide what a captured value may contain.** `str` is
  `[^/]+`, `slug` is `[-a-zA-Z0-9_]+`, `int` is `[0-9]+`, and `path` is `.+`.
  Only `path` admits the separator, so it is the one that can carry a traversal
  sequence into a view; `str` still admits `..` on its own. What the view must
  then do with such a value is "Path traversal" below.
- **`reverse()` and `resolve()` disagree about a duplicated name.** Resolution
  walks the patterns in declaration order, while the reverse table is built
  from `reversed(url_patterns)`, so one name on two patterns resolves to the
  first and reverses to the last. Every link and redirect built from that name
  goes somewhere other than the route a reviewer reading top-down would expect.
- **A duplicated namespace is reported, as a warning.** `urls.W005` says the
  namespace is not unique; `reverse()` then resolves it against the
  first-declared mount, so a second mount behind different middleware or a
  different permission decorator is never the one a generated redirect points
  at. Being a `Warning`, it prints under `manage.py check` and does not fail
  the default gate — see `a02-security-misconfiguration.md`, "check --deploy"
  for the fail level that catches it.
- **An `include()` shadows a later route only when something inside it
  matches.** A prefix alone falls through: if no pattern in the included module
  matches the remainder, resolution continues with the next top-level pattern.
  A catch-all inside the include is what turns the prefix into a swallow, and
  legacy or fallback modules are where catch-alls live.
- **`APPEND_SLASH` answers a POST with a redirect.** `CommonMiddleware`
  rewrites only on a 404, and only when the slashed path resolves. The
  `RuntimeError` naming the lost data is raised when `DEBUG` is `True`; with
  `DEBUG` off the response is a 301, the body does not survive it, and a
  permanent redirect is a cacheable answer to a state-changing request. A route
  that only works because of this rewrite is one deployment setting away from
  silently dropping writes.
- **`reverse()` on a name taken from the request** turns the project's whole
  name table into a client-selectable index, and raises `NoReverseMatch` — an
  unhandled 500 — for everything else. Map an input to a name through a
  server-side dictionary rather than passing it through.

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

Run the resolved-route table as an artifact rather than reading it once:
`api-drf-specific.md`, "Endpoint inventory (API9)" owns how to produce it, and
`scripts/entrypoint_inventory.py` resolves the same chain from source without
starting the project. What this section adds to that inventory is the
duplicate-detection pass — group the rows by resolved path and read every group
with more than one member.

**Write-time.** When generating a route, reach for `path()` and a converter
rather than `re_path()`, because the anchor and the character class are then
properties of the form instead of things the author has to remember. Where a
regular expression genuinely is required, write the `$` in the same keystroke
as the `^`. When adding a route to a module that already has one for a
neighboring shape, place the more specific pattern above the more general one
and check the resolved path rather than the file — the pattern you are
shadowing is usually in another module.

### Commonly mistaken for a finding

**A second route that resolves the same path.** A duplicate is the pattern
this section is about, so every duplicate reads as an unreachable permission
check. It is only that where the two differ in what guards them. One viewset
registered twice on the same router prefix, a module included at one path from
two places, and a legacy alias kept beside its replacement all end at the same
code behind the same permission class, and the unreachable one changes nothing
about who gets in. The deciding question is what each candidate's permission
class, decorator, and enclosing middleware are — where all three agree, the
finding is duplicated routing to clean up rather than a broken control.

## Multi-tenancy and data isolation

- Every tenant-scoped query must filter by the tenant derived from the request
  identity, ideally centralized (a manager, a base queryset, or middleware that
  sets the tenant), so an individual view can't forget it.
- Never accept the tenant id from the body or a header the client can set.
- Watch aggregates, `values()`, exports, and admin: isolation bugs hide in
  reporting and CSV endpoints as often as in CRUD.

Tenant identity arrives from a subdomain, a URL path segment, a JWT claim, a
session, or a header, and these are not equally trustworthy. A session-stored
tenant is trustworthy; a JWT claim is trustworthy **only** if the token is
verified server-side and the claim was bound at issuance. Subdomains, path
segments, and client-supplied headers are attacker-controllable and must be
validated against the authenticated user's tenant memberships before use, never
trusted alone.

The core failure mode is **tenant resolution and object authorization running as
separate code paths**: the object is fetched by id, the tenant is resolved
independently, and nothing asserts that the object belongs to the resolved
tenant. That is cross-tenant IDOR even though both halves look correct. Bind
them by scoping the query — `Model.objects.filter(tenant=request.tenant, pk=pk)`
— rather than fetching and then comparing.

Storing the "current tenant" in a thread-local or `contextvars` global is an
anti-pattern for the same reason. Under async and with thread-pool reuse, a
thread-local can leak a tenant across requests or tasks; `contextvars` is safer
for async but still couples authorization to ambient state that background jobs,
signal receivers, and consumers may inherit or lose silently. Explicit scoping
is the deeper fix.

Application-side scoping is opt-in, so its failure mode is the one query nobody
remembered to scope. Where that residual risk is unacceptable, the tenant
predicate can be pushed into the database itself — row-level security or a
schema per tenant — which enforces it on paths the ORM never sees: raw SQL, a
management command, a Celery task, an operator's psql session. It is a backstop
behind scoped querysets rather than a replacement for them, and it carries its
own failure modes around pooled connections. See `data-layer-and-database.md`.

### Commonly mistaken for a finding

**A `get_queryset` that reads unscoped in the file you have open.** An
unscoped queryset under a `pk` route is the highest-yield pattern in this
file, which is why it is also the one most often reported where the scoping is
real but sits somewhere else. Two places carry it invisibly: a viewset
registered on a nested router under a tenant-scoped parent, and a model whose
default manager already filters, so `Model.objects` is not the whole table.
Read the nested case precisely. The registration alone adds no predicate. What
constrains the child is a parent-filter mixin in the class's bases, the
`NestedViewSetMixin` shape. Look for that mixin. Check that the parent object
itself is authorized for the caller. A parent filter scopes the child to a
parent that the caller may still not own. The class bases, the router
registration, and the model's `Meta` and manager decide the question. Read them
before you conclude. Where they do scope, the finding that remains is the
legibility of the scope rather than a broken control.

**Write-time.** When generating a view that leans on scoping it does not
perform — a nested router's parent lookup, a filtering default manager — name
that dependency in one line at the site, because the next reader's only
alternative is to re-derive it from two other files and a review that does not
will file the view as a cross-tenant read.

## Caching and authorization

Cache leaks map primarily to CWE-524 (Use of Cache Containing Sensitive
Information), CWE-488 (Exposure of Data Element to Wrong Session), and CWE-862
(Missing Authorization).

### Principle layer

A cache is a second data-serving path. If its key omits any attribute that
changes what a principal may see, one principal can receive another's result
without the underlying authorization code running. The invariant is: **a cached
representation may be reused only when every requester represented by that key
is authorized to receive the same bytes under the same current policy.**

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

`Vary` is key metadata, not an authorization decision. It is useful only if the
named request headers fully capture the response audience and every caching
layer honors it.

A signed URL served through a CDN is this failure in its least obvious form: if
the cache key omits the signing parameters, one authorized response is stored
under a key that another request also produces. The storage-specific form of
that rule is in `file-uploads.md`, "Private downloads".

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
built-in. If a cache key can be observed by other tenants or operators who
should not see identifiers, derive an opaque keyed digest rather than placing
emails, tokens, or other sensitive values in the key.

When a response really is safe for a defined audience:

- use `vary_on_cookie` for session-cookie variation and
  `vary_on_headers("Authorization")` for authorization-header variation;
- preserve, append, and test `Vary` through Django, DRF, Nginx, and any CDN
  rather than overwriting it in later middleware;
- set `Cache-Control: private` or `no-store` for private responses and verify
  every intermediary honors it; and
- never assume DRF authentication or permission classes are re-run on a cache
  hit outside the view.

Two of the 2026 cache advisories are reachable from something a reviewer can
read in application code, rather than only from the installed patch level, and
both are cheaper to check than the version is.

**A hand-written `Cache-Control` whose directive is not lowercase.**
`UpdateCacheMiddleware` compared directives case-sensitively below 6.0.6 and
5.2.15, so a response setting `Cache-Control: Private` by hand was cached as
though it had asked for nothing — CVE-2026-8404, disclosed 3 June 2026 and
rated low under Django's security policy. Only manually set headers were
affected, which is what makes it a code finding: look for a
`response["Cache-Control"] = ...` assignment, or a DRF renderer or middleware
that composes the header itself, and read the case of the directive rather
than trusting that `private` is what it says. The patch closes Django's half
and leaves the portability half open, because a directive is case-insensitive
by specification and an intermediary that reads it the way Django used to is
not visible from this repository at all.

**Write-time.** When generating a view or middleware that has to mark a
response uncacheable, reach for `never_cache` or `cache_control()` rather than
assigning the header string yourself, because the decorator settles the
directive's spelling in one place and the hand-written header was the only form
this advisory could be reached through. Where the header genuinely must be
composed
by hand — a renderer, a proxy-facing shim — write the directive lowercase in
that first version, since nothing downstream will tell you it was ignored.

**`SESSION_SAVE_EVERY_REQUEST = True` in front of a cached public page.** The
setting makes Django write a session, and therefore a `Set-Cookie`, on every
response — including responses from views with no authentication in them. Where
the site cache or `cache_page` sits on such a view, that `Set-Cookie` is stored
with the page and replayed to the next anonymous caller, who is handed a session
identifier somebody else already holds. That is CVE-2026-35192, fixed in 6.0.5
and 5.2.14 on 5 May 2026 and rated low under Django's security policy; it is
session fixation reached through a cache rather than through a URL. Both halves
are a grep — the setting in the settings module, and `UpdateCacheMiddleware`
with `FetchFromCacheMiddleware` in `MIDDLEWARE` or a `cache_page` on a view
that requires no login. Neither half is a finding on its own.

**Write-time.** When generating a settings module that turns on
`SESSION_SAVE_EVERY_REQUEST` — usually to slide the session expiry on activity
— check in the same edit whether the site cache middleware is installed, and if
it is, keep the cached views off the session path with `never_cache` rather than
relying on the patch level of whatever Django is deployed. The setting and the
cache are written by different people on different days, and each is defensible
alone.

Keep Django at the current patch level in the supported line — 6.1, 6.0.8, or
5.2.17 as of 9 Aug 2026. The 2026 cache security fixes are spread across the
whole year's releases rather than concentrated in one: `Vary: *` handling and
the `SESSION_SAVE_EVERY_REQUEST` session fixation above (CVE-2026-35192) in
6.0.5 and 5.2.14, `Authorization` variation, `Vary` whitespace parsing, and the
mixed-case directives above in 6.0.6 and 5.2.15, and a further, separate fix
for cached responses that set cookies in 6.0.7 and 5.2.16. Patching is
necessary, but it cannot repair an application key that omits tenant, user, or
permission state.

See `deployment-and-runtime.md` for proxy/CDN/cache exposure and infrastructure
configuration.

### Cache review checklist

#### Stack-neutral

- [ ] Every cached sensitive result has an explicit audience, and the key
      captures all authorization and representation dimensions for that audience.
- [ ] Authorization occurs before cache read/population; role, tenant,
      ownership, and revocation changes invalidate or version affected entries.
- [ ] Public, tenant, role, and user namespaces cannot collide; keys contain no
      raw secrets or unnecessary personal data.
- [ ] Application, proxy, CDN, fragment, browser, export, and object caches obey
      the same privacy policy.

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

- Allowlist destination hosts/schemes; reject everything else.
- Block link-local and metadata addresses (`169.254.169.254`, `metadata.google.internal`),
  loopback, and private ranges — after DNS resolution, and re-check on redirects.
  Connect to the address that you checked. Never let the HTTP client resolve
  the host a second time. DNS rebinding moves the target between the check and
  the connection.
- The cloud metadata endpoint is the highest-value entry on that list, because
  what it returns is a live credential for the workload. Deny it in the
  application *and* require the instance's hardened, token-based metadata
  service with a minimal hop limit, so a single SSRF does not become credential
  theft. What such a credential then unlocks is in
  `service-identity-and-secrets.md`.
- Disable or bound redirects; set timeouts; never reflect the raw response back
  to the user.
- A URL assembled by a model, or lifted from content a model retrieved, is
  client-influenced for this purpose; see `agent-and-llm-interfaces.md`,
  "Model output as an injection source".

**Write-time.** When generating an outbound call whose URL derives from input,
write the host and scheme allowlist, the post-resolution address check, the
bounded or disabled redirects, and the timeout as part of the call rather than
around it afterwards, because a fetch helper that works is a fetch helper that
gets reused and the second caller inherits whatever the first one settled for.
Write the allowlist as the set of destinations the feature actually needs
rather than as a list of ranges to refuse, because the refusal list is the one
that has to be complete and it never is. Where the destination does not
genuinely need to be dynamic, take it from configuration instead and the class
of bug disappears rather than being defended against.

### Commonly mistaken for a finding

**An outbound request whose URL is built from a settings value or a stored
service record.** The shape is identical to the finding — a URL assembled at
run time, handed to an HTTP client, with no allowlist anywhere near it — and
`requests.get(url)` looks the same whichever side of the boundary `url` came
from. What makes SSRF a finding is that a caller influences the destination.
The deciding question is who last wrote the value: a settings entry, an
environment variable, or a service record only an operator can create is a
deploy-time input rather than an attacker-controlled one. Where a principal
short of an operator can write that stored record — a tenant admin registering
a callback, a user setting a profile URL — the value is attacker-controlled
again and the finding is live.

### Egress control

The controls above stop one call from reaching somewhere it should not. Egress
control asks the next question: once a process is compromised — through
deserialization, a dependency, a template sink, or a prompt-injected agent —
what can it still reach? A service that may open a connection to any host on
the internet turns every foothold into an exfiltration channel and a
command-and-control path, whatever the fetch helper does.

**Allowlist by destination; do not enumerate what to refuse.** A denylist of
private ranges is a list that must be complete, and it is defeated by a DNS
name that resolves into the range after the check, a redirect to it, an
IPv6-mapped or alternative-notation form of the address, and by every internal
service and cloud metadata endpoint added after the list was written. An
allowlist of the few hosts a feature legitimately calls fails closed against
all of them at once, and it is short enough to review.

**Default to deny for the processes with the narrowest needs.** A webhook
delivery worker, a link-preview or import-from-URL worker, a media fetcher,
and an agent tool runner each talk to a small, enumerable set of destinations
that is known before the code ships. Those are the processes where
deny-by-default egress costs least and buys most, and they are also the ones
most exposed, because their whole job is to fetch what someone else named.

**The platform and the application enforce different halves and neither
substitutes for the other.** The platform — an egress gateway, a network
policy, a forward proxy the process must use — is the half that survives code
that never went through the fetch helper: a library's own HTTP client, a
subprocess, a debug shell. The application-side check is the half that sees
what the platform cannot: which user asked, which redirect the response
carried, and whether the resolved address changed between the check and the
connection. Report the platform half as a cross-team recommendation and the
application half as a repository finding, in the same split
`deployment-and-runtime.md` uses for orchestrator enforcement.

An outbound webhook sender is the worked example, and its delivery-side
controls — registered destinations re-validated at send time, bounded
redirects, capped retries — are in `a08-integrity-and-deserialization.md`,
"Sending webhooks of your own". An agent's tool egress is in
`agent-and-llm-interfaces.md`, "Retrieved content and indirect prompt
injection", which reaches the same conclusion from the exfiltration side.

## Path traversal

SSRF is a request reaching a network resource it should not; this is the same
failure against the filesystem, and it belongs here for the same reason —
nothing about the code looks like an authorization decision, yet the effect is
that a caller reads a file the application never meant to expose. Maps to
CWE-22 (Path Traversal) and CWE-23 (Relative Path Traversal). The upload case
is elsewhere: `file-uploads.md` owns the name an upload brings and the key it
is stored under. This section owns the read whose path the request named, which
is usually a flow with no upload in it at all — a report download, a generated
export, a documentation tree, a log or artifact viewer.

The sink is any request-derived value reaching `open()`, `os.path.join()`, a
`pathlib` join, or a template or file path resolved outside the storage API.
The reason this keeps shipping is that `os.path.join` reads like a
containment function and is not one. It does not normalize `..`, so a value
walks upward unimpeded; and if the value is absolute it discards the base
entirely, which is a documented property rather than an edge case —
`os.path.join("/srv/exports", "/etc/passwd")` is `"/etc/passwd"`. A base
directory in the expression is therefore not evidence that anything is
confined to it.

### What Django actually protects, and what it does not

Three answers, because they are routinely assumed to be one:

- **`safe_join` is the real control, and it rejects rather than repairs.** It
  resolves `abspath(join(base, *paths))` against `abspath(base)` and raises
  `SuspiciousFileOperation` unless the result begins with the base plus a
  separator, equals the base exactly, or the base is a filesystem root. The
  trailing separator is what defeats a sibling directory sharing the base's
  prefix, and the comparison runs through `normcase`, so it holds on
  case-insensitive filesystems. `SuspiciousFileOperation` is a
  `SuspiciousOperation` subclass, which Django renders as a 400. Note where it
  lives: `django.utils._os`, an underscore-prefixed private module that no
  public documentation covers. Using it is reasonable; depending on it directly
  is depending on something Django has not promised to keep, which is a further
  argument for reaching it through the storage API that calls it for you. The
  containment is lexical. A storage tree that an untrusted process can write
  links into defeats it between the check and the open. Prefer object storage
  for untrusted content. Reject link members at ingestion, as the upload rules
  already require.
- **`FileSystemStorage` inherits that protection, so the storage API is the
  supported route.** `path()` returns `safe_join(self.location, name)`, and
  `open()`, `exists()`, and `size()` all resolve through `path()`. On the write
  side `get_available_name()` and `generate_filename()` additionally raise on
  `..` in the directory parts and run `validate_file_name`, which requires
  `name == os.path.basename(name)` unless `allow_relative_path=True`. None of
  this reaches a bare `open()` — the protection is a property of the API, not
  of the framework being present.
- **`FileResponse` validates nothing, and `django.views.static.serve` is not a
  production answer.** `FileResponse` streams a file object the caller already
  opened; it sets `Content-Length`, `Content-Type`, and `Content-Disposition`
  and has no opinion on where the bytes came from, so traversal safety is
  decided entirely before it is called. `serve()` does use `safe_join` and is
  traversal-safe, but Django states in the module itself that it is for
  development and should not be used in production — being safe against this
  bug is not an endorsement to serve files with it.

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

The pattern generalizes in one line: **let the client choose an identifier, not
a path.** A key in a server-side mapping, a primary key resolved through a
scoped queryset, or an enumerated slug all end with the server deciding every
character of the filename, which removes the class rather than defending
against it. Where a join genuinely cannot be avoided, resolve through the
storage API and let `SuspiciousFileOperation` reject the escape; catching it as
a 404 rather than surfacing a 400 avoids confirming which paths exist.

Two things this does not settle. Confinement is not authorization — a path
correctly confined to the base still has to be a file *this* requester may
read, which is the object-level check the rest of this file is about. And in
production the bytes are usually better served by the web server after Django
performs the check, through `X-Accel-Redirect` or `X-Sendfile` with the files
kept outside the public root; that arrangement and its trade-offs are in
`file-uploads.md`, "Private downloads".

**Write-time.** When generating a view that reads a file whose name derives
from a request, write the identifier-to-name mapping first and the file access
second, because the mapping is what makes the traversal question moot rather
than answered. Where a name has to be passed through, open it with a
`FileSystemStorage` pinned to the base directory instead of `open()` and
`os.path.join()`, and handle `SuspiciousFileOperation` in the same edit, since
an uncaught one is a 500 on a path that was supposed to fail closed. Add the
ownership check alongside the path resolution rather than after it: a confined
path is still someone's file.

### Commonly mistaken for a finding

**`os.path.join` against a base where the joined component is a server-chosen
identifier.** This section says `os.path.join` is not a containment function,
so every hit reads as traversal, and the call looks the same whatever is on
its right-hand side. A primary key, a UUID, a hash digest, or a slug drawn
from a fixed set contains no separator and no `..` because the server produced
every character of it. The deciding question is who authored the component,
not what the function does with it — where the value is a request parameter
that the code merely believes is an integer, the belief is the finding, and
where it is the `str(obj.pk)` of a row already fetched through a scoped
queryset, there is nothing to traverse with. The ownership question is
separate and stays live either way: a confined path is still someone's file.

## Open redirect

For any user-supplied redirect target (`next`, `return_to`), validate before
redirecting:

```python
from django.utils.http import url_has_allowed_host_and_scheme

if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
    return redirect(nxt)
return redirect("home")
```

Never `redirect(request.GET["next"])` unchecked — it enables phishing and can
bootstrap OAuth token theft.

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
  for one resource** and inserts a hop into flows that were reasoned about as
  single requests — an unauthenticated entry, a login return, a POST.
- **A header that changes the response is a cache dimension.** A cache that
  does not separate on it serves one visitor's rendering to the next.

### Django & DRF implementation layer

Read off the Django 6.0.7 source on 14 Aug 2026 and confirmed by running each
case.

- **The built-in switch validates; a replacement usually does not.**
  `django.views.i18n.set_language` reads `next` from the POST body or the query
  string and passes it through `url_has_allowed_host_and_scheme` against
  `request.get_host()`, with `require_https` taken from `request.is_secure()`.
  On failure it falls back to the `Referer` header, validated the same way, and
  then to `/`. It writes the language cookie only on a POST and only for a code
  `check_for_language` accepts. Treat a hand-written language switcher as an
  open-redirect candidate on sight: the validation is three lines that read
  like plumbing, and the view around them is the one nobody reviews.
- **Four sources, in order.** `get_language_from_request` takes the path prefix
  first when `i18n_patterns` is in use, then the `LANGUAGE_COOKIE_NAME` cookie,
  then `Accept-Language`, then `LANGUAGE_CODE`. Everything but the last comes
  from the request, and the cookie among them has defaults weaker than the
  session's — `a02-security-misconfiguration.md`, "Cookie prefixes and the
  subdomain boundary" states them and what to change.
- **The prefix redirect fires on a narrow condition, and the setting moves
  it.** `LocaleMiddleware` redirects only when the response is a 404, the path
  carries no language, `i18n_patterns` is in use, `prefix_default_language` is
  `True`, and the prefixed path resolves; it patches
  `Vary: Accept-Language, Cookie` onto that redirect. Turning
  `prefix_default_language` off removes the prefix from the default language
  entirely, so which paths redirect changes with the setting and a chain walked
  under one value has to be walked again under the other. Walk it with a
  non-default `Accept-Language` and follow every hop: a loop and an
  unauthenticated detour are both cheaper to observe than to reason about.
- **The language can drop out of the cache key while `Vary` still names it.**
  With `USE_I18N` on, `learn_cache_key` strips `Accept-Language` from the
  header list it stores, because `_i18n_cache_key_suffix` appends the active
  language to the key instead — `request.LANGUAGE_CODE` where a middleware set
  it, otherwise whatever language is active. That suffix is computed by
  `FetchFromCacheMiddleware` in the request phase, so it is right only if
  `LocaleMiddleware` has already run. Reproduced in the other order: a request
  carrying `Accept-Language: fr` populated the cache and the next request
  carrying `Accept-Language: en` was served the French body, with
  `Vary: Accept-Language` on it, accurate and irrelevant. A project that
  resolves the language itself — a custom middleware, a stored profile
  preference, content negotiation in DRF — gets the suffix only if it activates
  the language before the cache is read, and gets no `Vary` from anyone.

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
renderings differ only in wording, it is a defect and not a disclosure; where
the language stands in for a market — a price, a jurisdiction-specific notice,
a catalog that varies by region — it discloses. Where the same key defect sits
in front of authenticated output it is not a locale question at all, but the
failure in "Caching and authorization" above, whose rule this case
demonstrates: `Vary` is key metadata, not an authorization decision.

**Write-time.** When generating a language switch, mount `set_language` rather
than writing a view that redirects to a `next` value, because the built-in
already carries the host and scheme check and a replacement starts without it.
When adding `LocaleMiddleware` to a project that caches, place it in the same
edit relative to the cache middleware — above `FetchFromCacheMiddleware` and
below `UpdateCacheMiddleware` — since the two are usually added months apart
and the resulting order is silent in both directions.

## Admin exposure

- Move the admin off the default path (`urls.py`), serve it only over HTTPS, and
  restrict it at the proxy (IP allowlist / VPN) where feasible.
- Separate staff from superuser; grant the minimum. Audit who has `is_staff` /
  `is_superuser`.
- Add MFA for admin (`django-otp`); see the auth and libraries files.

This section covers *exposure*. The admin's permission hooks — `get_queryset()`
scoping, bulk actions, custom `@admin.action` permissions, and what
`readonly_fields` does and doesn't enforce — are in
`authorization-architecture.md`. Impersonation ("log in as user") and
break-glass elevation are in `privileged-access-and-impersonation.md`.

## Review checklist

- [ ] Detail/update/destroy routes scope by requester (queryset or object perm).
- [ ] List endpoints filter by identity; no cross-tenant leakage in lists/exports.
- [ ] Default permission class is restrictive; every public view is deliberate.
- [ ] Ownership/tenant comes from `request.user`, never the request body.
- [ ] A generic relation whose content type a request can influence accepts
      only an allow-listed model, and the object check runs against the row
      resolution produced rather than ahead of it.
- [ ] No two patterns resolve one path; the resolved-route table is what was
      read, and every endpoint `re_path` without a terminating anchor is
      treated as matching more than its shape.
- [ ] Tenant resolution and object lookup are one scoped query, not two
      independent steps; no ambient thread-local/`contextvars` tenant.
- [ ] Any database-enforced isolation is a backstop behind scoped querysets and
      its context cannot leak between pooled connections.
- [ ] Admin/staff actions use a role check, not bare `IsAuthenticated`.
- [ ] Authenticated/personalized responses are not shared-cached; any private
      cache key and invalidation cover every authorization dimension.
- [ ] A language switch validates its redirect target, and `LocaleMiddleware`
      sits above the cache fetch so the key carries the request's language
      rather than the one that happened to be active.
- [ ] Every server-side URL fetch is allowlisted and blocks internal ranges;
      the cloud metadata endpoint is both denied in the application and
      hardened at the instance.
- [ ] Processes whose destinations are enumerable — webhook senders, fetch and
      preview workers, agent tool runners — are denied egress by default at
      the platform, with the application-side allowlist kept as the half that
      sees the redirect and the caller.
- [ ] No request-derived value reaches `open()`, `os.path.join()`, or a
      `pathlib` join for a read; file names come from a server-side identifier
      and resolve through the storage API, whose rejection is handled rather
      than left to become a 500.
- [ ] Redirect targets validated with `url_has_allowed_host_and_scheme`; a
      307/308 `preserve_request` redirect and a `max_length=None` override are
      each read as findings on a caller-supplied target.
