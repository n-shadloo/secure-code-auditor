# A01:2025 — Broken Access Control

Covers object-level and function-level authorization, IDOR/BOLA, SSRF (folded
into A01 in 2025), open redirect, multi-tenancy isolation, admin exposure, and
cache-mediated authorization leaks. Maps to OWASP API1:2023 (BOLA) and
API5:2023 (BFLA).

## Contents
- [Principle](#principle)
- [Django & DRF: object-level authorization](#django--drf-object-level-authorization)
- [IDOR / BOLA](#idor--bola)
- [Function-level authorization](#function-level-authorization)
- [Multi-tenancy and data isolation](#multi-tenancy-and-data-isolation)
- [Caching and authorization](#caching-and-authorization)
- [SSRF](#ssrf)
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

Keep Django at 6.0.7 or 5.2.16 or later in the supported line. The 2026 cache
security fixes covered `Authorization` variation, malformed or mixed-case cache
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
- Disable or bound redirects; set timeouts; never reflect the raw response back
  to the user.

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

## Review checklist

- [ ] Detail/update/destroy routes scope by requester (queryset or object perm).
- [ ] List endpoints filter by identity; no cross-tenant leakage in lists/exports.
- [ ] Default permission class is restrictive; every public view is deliberate.
- [ ] Ownership/tenant comes from `request.user`, never the request body.
- [ ] Admin/staff actions use a role check, not bare `IsAuthenticated`.
- [ ] Authenticated/personalized responses are not shared-cached; any private
      cache key and invalidation cover every authorization dimension.
- [ ] Every server-side URL fetch is allowlisted and blocks internal ranges.
- [ ] Redirect targets validated with `url_has_allowed_host_and_scheme`.
