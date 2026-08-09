# A01:2025 — Broken Access Control

Covers object-level and function-level authorization, IDOR/BOLA, SSRF (folded
into A01 in 2025), open redirect, multi-tenancy isolation, admin exposure, and
cache-mediated authorization leaks. Maps to OWASP API1:2023 (BOLA) and
API5:2023 (BFLA).

This file owns the **per-request failure** — the request that reached data it
should not have, and how to recognise it in code. It does not own the model
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
the rule about who may read a cached response is here.

## Contents
- [Principle](#principle)
- [Django & DRF: object-level authorization](#django--drf-object-level-authorization)
- [IDOR / BOLA](#idor--bola)
- [Function-level authorization](#function-level-authorization)
- [Multi-tenancy and data isolation](#multi-tenancy-and-data-isolation)
- [Caching and authorization](#caching-and-authorization)
- [SSRF](#ssrf)
- [Path traversal](#path-traversal)
- [Open redirect](#open-redirect)
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

Keep Django at the current patch level in the supported line — 6.1, 6.0.8, or
5.2.17 as of 9 Aug 2026. The 2026 cache security fixes landed in 6.0.7 and
5.2.16 and covered `Authorization` variation, malformed or mixed-case cache
directives, `Vary` parsing, and responses that set cookies. Patching is
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
- [ ] Django is on a supported patch containing the 2026 cache fixes; patching
      is not treated as a substitute for scoped keys and invalidation.

## SSRF

Any server-side fetch of a client-influenced URL (webhooks, link previews,
image/PDF fetchers, "import from URL") is SSRF-prone; Django has no built-in
guard for developer-initiated requests.

- Allowlist destination hosts/schemes; reject everything else.
- Block link-local and metadata addresses (`169.254.169.254`, `metadata.google.internal`),
  loopback, and private ranges — after DNS resolution, and re-check on redirects.
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
  argument for reaching it through the storage API that calls it for you.
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

The pattern generalises in one line: **let the client choose an identifier, not
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
- [ ] Tenant resolution and object lookup are one scoped query, not two
      independent steps; no ambient thread-local/`contextvars` tenant.
- [ ] Any database-enforced isolation is a backstop behind scoped querysets and
      its context cannot leak between pooled connections.
- [ ] Admin/staff actions use a role check, not bare `IsAuthenticated`.
- [ ] Authenticated/personalized responses are not shared-cached; any private
      cache key and invalidation cover every authorization dimension.
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
- [ ] Redirect targets validated with `url_has_allowed_host_and_scheme`.
