# API and DRF-Specific Concerns

Cross-cutting DRF material that spans several OWASP categories: where the
framework runs an object check and every route that skips it, function-level
authorization on viewset actions, serializer exposure and mass assignment,
pagination/filter leakage, throttling, schema and browsable-API exposure,
endpoint inventory, version deprecation, bulk routes, and CSRF interaction.
Read alongside A01 (authz), A02 (config/CORS), A06/A07 (rate limiting/auth),
`file-uploads.md`, and `async-and-channels.md` when those surfaces apply. Maps
to OWASP API Security Top 10:2023 broadly (API1 BOLA, API3 BOPLA, API4 resource
consumption, API5 BFLA, API8 misconfiguration, API9 inventory) and to A01:2025
and A02:2025.

Three files share the authorization material and the split is deliberate: A01
owns the per-request access-control failure and how to recognise it,
`authorization-architecture.md` owns the permission *model* and the table of
which DRF paths invoke the object hook, and this file owns the **call sites** —
the DRF routes, actions, and defaults where a correct model still fails to run.
Read the other two for the model; read this one for where DRF lets it leak.

This file is about DRF specifically. For a GraphQL schema, or a non-DRF
framework such as Django Ninja whose defaults differ from DRF's, read
`graphql-and-alternative-api-surfaces.md` — several patterns below generalise
there with the unit of measurement changed, and the framework defaults do
not carry over at all.

## Contents
- [Principle](#principle)
- [Where the object check runs, and the routes that skip it](#where-the-object-check-runs-and-the-routes-that-skip-it)
- [Function-level authorization on actions (API5)](#function-level-authorization-on-actions-api5)
- [Serializer exposure and mass assignment (API3)](#serializer-exposure-and-mass-assignment-api3)
- [Pagination and filter leakage](#pagination-and-filter-leakage)
- [Default auth and permission classes](#default-auth-and-permission-classes)
- [CSRF and SessionAuthentication](#csrf-and-sessionauthentication)
- [Throttling as quota, not security (API4)](#throttling-as-quota-not-security-api4)
- [Schema and browsable-API exposure](#schema-and-browsable-api-exposure)
- [Endpoint inventory (API9)](#endpoint-inventory-api9)
- [Versioning and deprecation lifecycle](#versioning-and-deprecation-lifecycle)
- [Bulk endpoints](#bulk-endpoints)
- [Unsafe DRF defaults, enumerated](#unsafe-drf-defaults-enumerated)
- [Payments and webhook bodies](#payments-and-webhook-bodies)
- [Review checklist](#review-checklist)

## Principle

An API framework decides two things a reviewer cannot see from the routing
table: *where* an authorization decision is invoked, and *what* the shape of a
response reveals. Both fail quietly. A hook that defaults to "allow" turns every
route that forgets to call it into an access-control hole, and a serializer,
filter, or paginator that was never asked to hide anything will answer questions
the caller was not entitled to ask. The portable rule is that authorization must
be enforced at the point a specific object is loaded for a specific action —
not at the view door — and that the response must carry only what this caller
may see, in a shape that does not let them infer the rest.

The same reasoning applies to the surface as a whole. Endpoints you cannot
enumerate cannot be reviewed, so the authoritative inventory is the live URL
map rather than the documentation; and a deprecated version left running is not
a legacy concern but a second, less-maintained copy of every control.

In DRF the object decision is invoked in exactly one place the framework
controls, the response shape is decided by serializers, filter backends, and
pagination classes, and several of the relevant defaults are permissive. Those
three facts organise everything below.

## Where the object check runs, and the routes that skip it

`GenericAPIView.get_object()` ends by calling
`self.check_object_permissions(self.request, obj)` before returning the
instance. That call is the **only** place DRF invokes `has_object_permission()`
for you. `authorization-architecture.md`, "DRF: where the object check actually
runs", holds the table of which paths reach it and the permission-class defaults
behind it — including that `BasePermission.has_object_permission` returns `True`,
so a class implementing only `has_permission` is permissive at the object level.
This section covers the route shapes where that table is easiest to violate.

**A detail action does not fetch the object.** `@action(detail=True)` shapes the
URL — it adds the `pk` keyword argument — and nothing more. It does not call
`get_object()`. A developer who queries the model directly inside the action
gets no object check at all, and the code looks like every other detail route.

```python
# Wrong: detail=True adds `pk` to the URL; it does not authorize anything
class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()          # every tenant's invoices
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated]    # door check only

    @action(detail=True, methods=["post"])
    def send(self, request, pk=None):
        invoice = Invoice.objects.get(pk=pk)  # get_object() never runs
        invoice.send()
        return Response({"status": "sent"})
```

```python
# Correct: scope the queryset, and load through get_object() so the hook fires
class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated, IsTenantMember]

    def get_queryset(self):
        # scopes the list route and every lookup, including the action below
        return Invoice.objects.filter(tenant=self.request.user.tenant)

    @action(detail=True, methods=["post"])
    def send(self, request, pk=None):
        invoice = self.get_object()           # runs check_object_permissions
        invoice.send()
        return Response({"status": "sent"})
```

The other route shapes that skip the hook:

- **Plain `APIView`** has no `get_object()` at all, so nothing is called
  automatically. Any object it loads must be authorized by hand with
  `self.check_object_permissions(request, obj)`, or by loading from a
  requester-scoped queryset.
- **List routes** reach `filter_queryset(get_queryset())` and never touch
  `get_object()`. Isolation on a list is the queryset's job — a correct
  `has_object_permission` contributes nothing there. Note the ordering:
  `filter_queryset` applies the *client's* filters on top of whatever
  `get_queryset()` returned, so a `get_queryset()` that is not already scoped
  cannot be rescued by a filter backend.
- **Create** has no object yet, so the hook cannot run. Owner and tenant must be
  set in `perform_create()` from `request.user`, never accepted from the body.
- **`@action(detail=False)`** has no object identity at all; it is a
  function-level surface, below.
- **An overridden `get_object()`** that omits `self.check_object_permissions(...)`
  silently removes the one automatic check.
- **Bulk routes** — see "Bulk endpoints".

CWE-285 (Improper Authorization), CWE-639 (Authorization Bypass Through
User-Controlled Key); OWASP API1:2023, A01:2025. Severity: high to critical.

## Function-level authorization on actions (API5)

Object-level checks answer "may this caller touch *this* record?". Function-level
checks answer "may this caller invoke *this operation* at all?". A system can
pass the first and fail the second, and the two failures live in different
places in the code: BOLA is a missing queryset scope or object hook on a
per-record path, BFLA is a missing or too-weak `has_permission` on the operation.

In DRF, BFLA is almost always a custom `@action` that inherited the viewset's
permissions when it needed stricter ones. `permission_classes` on the decorator
**replaces** the viewset's list for that action rather than adding to it, so
restate the base requirement alongside the stricter one.

```python
# Wrong: any authenticated user can promote themselves
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=["post"])     # inherits IsAuthenticated only
    def promote_to_staff(self, request, pk=None):
        user = self.get_object()
        user.is_staff = True
        user.save()
        return Response({"ok": True})
```

```python
# Correct: the action states its own requirement, base check restated
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=["post"],
            permission_classes=[IsAuthenticated, IsAdminUser])
    def promote_to_staff(self, request, pk=None):
        ...
```

Also review: destructive methods left on a `ModelViewSet` because it was quicker
than `ReadOnlyModelViewSet` plus explicit writes; staff-only routes gated on
`IsAuthenticated`; and `get_permissions()` overrides that branch on
`self.action`, where a new action added later falls through to the permissive
default branch. Prefer an explicit mapping with a deny fallback over an
`if/elif` chain that ends in the base return.

`authorization-architecture.md` owns the privilege model these classes express;
A01 owns the finding as a per-request failure. CWE-862 (Missing Authorization);
OWASP API5:2023, A01:2025. Severity: high to critical where the operation
escalates privilege.

## Serializer exposure and mass assignment (API3)

Serializers are where APIs over-share and where clients over-write. Both are
Broken Object Property Level Authorization.

```python
# Wrong: exposes and accepts every field, including server-controlled ones
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
```

```python
# Correct: explicit allowlist; server-controlled fields read-only; secrets write-only
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "display_name", "is_staff", "date_joined"]
        read_only_fields = ["id", "is_staff", "date_joined"]
        extra_kwargs = {"password": {"write_only": True}}
```

- Prefer an explicit `fields` allowlist over `exclude` (with `exclude`, a new
  sensitive model field silently joins the API).
- Mark server-controlled attributes (`is_staff`, `is_active`, `owner`, `balance`,
  `role`) `read_only` so a client can't set them via mass assignment. Note:
  `read_only_fields` in `Meta` does **not** apply to *explicitly declared*
  fields — those need `read_only=True` on the field itself.
- `write_only` for passwords/secrets so they're accepted but never serialized
  back. Be careful with `depth` and nested serializers exposing related data.
- Never trust the client to omit dangerous fields; the serializer must exclude
  them.
- Object permissions are **not** applied on create — `get_object()` never runs,
  so `has_object_permission` cannot stop a client from creating a record against
  another owner or tenant. Set those fields in `perform_create()` from
  `request.user`, or validate them in the serializer.

The declared-field rule above is the one most often read and then violated,
because the `Meta` entry looks authoritative. A declared field silently wins:

```python
# Wrong: `role` is writable despite read_only_fields, and get_balance
# reaches through a relation the caller was never authorized against
class AccountSerializer(serializers.ModelSerializer):
    role = serializers.CharField()
    balance = serializers.SerializerMethodField()

    class Meta:
        model = Account
        fields = ["id", "email", "role", "balance"]
        read_only_fields = ["role"]        # ignored for the declared `role`

    def get_balance(self, obj):
        return obj.owner.private_balance
```

```python
# Correct: read-only stated on the field; no unauthorized relation traversal
class AccountSerializer(serializers.ModelSerializer):
    role = serializers.CharField(read_only=True)

    class Meta:
        model = Account
        fields = ["id", "email", "role"]
```

A `SerializerMethodField` is ordinary Python and is subject to no field-level
check whatsoever, so treat every relation it walks as a separate read that needs
its own justification. The same applies to nested serializers and `depth`.

**Write-time.** When generating a `ModelSerializer`, enumerate `fields`
explicitly and mark the server-controlled attributes read-only in the same
edit, because `"__all__"` and `exclude` both admit whatever the model gains
next and the field added six months from now is the one nobody re-reviews.
Where the field is declared on the serializer rather than only named in `Meta`,
put `read_only=True` on the field, since `read_only_fields` does not reach it.

Where the writable set differs *by role*, allow-list writable fields per role
rather than deny-listing them, and test `PATCH` separately from `PUT`; see
`authorization-architecture.md` for the pattern and the full BOPLA surface.
CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object
Attributes); OWASP API3:2023, A01:2025. Severity: high.

## Pagination and filter leakage

Filters and pagination are read paths with no object hook, so every control has
to be in the queryset and in the field allowlist.

- **Scope first, filter second.** `filter_queryset()` runs over whatever
  `get_queryset()` returned. If that is `Model.objects.all()`, filter backends
  and search become a cross-tenant read rather than a convenience (A01).
- **Allow-list the filterable fields.** `django-filter` generates a filter per
  field when pointed at a model, so declare an explicit `FilterSet` or a narrow
  `filterset_fields`. A filter over a sensitive column is an oracle even when
  the column is not serialized: the caller learns which rows match by counting
  results.

```python
# Wrong: filterable and orderable over every field, on an unscoped queryset
class PatientViewSet(viewsets.ModelViewSet):
    queryset = Patient.objects.all()
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = "__all__"
    ordering_fields = "__all__"
```

```python
# Correct: scoped queryset, explicit filter and ordering allowlists
class PatientViewSet(viewsets.ModelViewSet):
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ["status", "admitted_on"]
    ordering_fields = ["admitted_on"]        # not `diagnosis`, not `risk_score`

    def get_queryset(self):
        return Patient.objects.filter(clinic=self.request.user.clinic)
```

- **Ordering is an oracle too.** Sorting on a field the caller may not read
  leaks its relative values across the result set; allow-list `ordering_fields`
  as deliberately as `filterset_fields`, and never leave either as `"__all__"`.
- **`search_fields` traversals** follow relations with `__`, so a search
  configured across a foreign key can match on a related record the caller has
  no access to. Review each traversal as a read.
- **Pagination should not reveal what it excluded.** `PageNumberPagination` and
  `LimitOffsetPagination` return a total `count`, which discloses the size of
  the matching set — including under a filter the caller controls, which turns
  the count into a binary search over data they cannot read. Where the
  collection is sensitive, `CursorPagination` exposes neither offsets nor a
  total, at the cost of ordering on a stable field and no random access.
- Ids in a paginated response are still a disclosure: a listing that includes
  identifiers of records the caller cannot open tells them those records exist.
- A page size the client raises without a ceiling, and the `count()` scan a
  paginator issues per request, are the cost half of the same controls. The
  design rule behind them and the surfaces it spans are in
  `a06-insecure-design.md`, "Algorithmic resource exhaustion"; the DRF
  attributes that enforce it are `max_page_size` and `PAGE_SIZE`.

OWASP API1:2023 and API3:2023, A01:2025. Severity: medium to high depending on
what the ordering or count discloses.

## Default auth and permission classes

Set safe project defaults and override up, never down:

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        # or a token/JWT class for API clients
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}
```

A default of `AllowAny` makes every un-annotated view public — a common
misconfiguration.

**Write-time.** When generating a viewset or an `APIView`, set
`permission_classes` on the class itself rather than inheriting whatever the
project default happens to be, and reserve `AllowAny` for an endpoint you were
told is public — DRF's own default is `AllowAny`, so an omission is a decision
to publish. Write `get_queryset()` scoped to the requester in the same edit,
before the serializer or the actions, because the unscoped queryset is what
turns an authenticated route into a cross-tenant read and no object hook runs
on the list path to catch it. Setting the project default as well is belt and
braces, not an alternative: the per-class declaration is what survives a
settings file being replaced.

This setting covers DRF only, not plain Django views, the admin, or third-party
URLs. To make deny-by-default enforceable across the whole project, pair it with
a URLconf-enumerating audit test — see `authorization-architecture.md`.

## CSRF and SessionAuthentication

- DRF `APIView`s are CSRF-exempt **except** inside `SessionAuthentication`, which
  enforces CSRF for authenticated (cookie) requests. Token/JWT auth via the
  `Authorization` header needs no CSRF (the credential isn't auto-sent by the
  browser).
- Known gotcha: a login/token-obtain view built on plain `APIView` +
  `SessionAuthentication` does **not** get CSRF enforced for *unauthenticated*
  users. Login views should always apply CSRF.
- Don't paper over CSRF errors with `@csrf_exempt` on cookie-authenticated,
  state-changing endpoints; confirm the auth model first.

This section owns the DRF interaction only. The settings behind it —
`CSRF_TRUSTED_ORIGINS`, the cookie matrix, and CORS — are declared in
`a02-security-misconfiguration.md`.

## Throttling as quota, not security (API4)

This section is the authoritative treatment of DRF throttling mechanics;
`a06-insecure-design.md` owns rate limiting as a design decision — which flows
need anti-automation at all — and defers here for how the classes behave.

DRF throttles provide basic fair-use quotas and are **not** a brute-force or DoS
defense. The DRF documentation states plainly that the throttling it provides
should not be considered a security measure against brute forcing or
denial-of-service, because a deliberate attacker can spoof the IP origin the
default classes key on. Use throttles for quotas; use `django-axes` plus edge
limits for abuse protection. Configure real limits where resource consumption
matters (expensive queries, exports, file processing). Upload endpoints also
need hard edge, per-file, aggregate, parser, and storage-quota controls from
`file-uploads.md`.

Four mechanics decide whether a configured limit is the limit you actually get:

- **The default client-IP identity is the whole forwarded chain.** The throttle
  base class keys on `NUM_PROXIES`, which defaults to `None`; on that default it
  identifies the caller by the entire `X-Forwarded-For` value with whitespace
  stripped, which DRF's own documentation describes as less strict IP matching.
  A caller who varies the header therefore gets a fresh bucket per value and the
  limit becomes opt-out. Set `NUM_PROXIES` to the number of proxies you actually
  operate and the class takes the address that many hops in from the right —
  the entry your own infrastructure appended. The rule and the topology it
  depends on are in `deployment-and-runtime.md`, "Reading the client IP".
- **The counter is not atomic.** `SimpleRateThrottle` reads the request history
  from the cache, trims it in local memory, appends the current timestamp, and
  writes the list back. There is no lock and no compare-and-set, so concurrent
  requests read the same history and each write their own version over it. Under
  load the effective rate is higher than configured — the DRF documentation
  describes this as fuzziness in the measured rate.
- **`LocMemCache` is per process.** With N Gunicorn workers you get N
  independent counters and roughly N times the configured limit. This is the
  single most common throttling misconfiguration and it is invisible in
  development, where there is one worker. Throttles need a shared Redis or
  Memcached cache, and the throttle cache should be one whose eviction policy
  will not silently discard counters under memory pressure.
- **Throttles run after authentication.** `APIView.initial()` performs
  authentication, then permission checks, then throttle checks. A throttle
  therefore cannot protect the authentication step itself; login and token
  endpoints need lockout and edge limits, not a throttle class.

Where a limit must actually hold — login, password reset, payment, invitation —
supplement the throttle with an atomic counter (a Redis `INCR` with an expiry,
or a database constraint) and a limit at the edge. Fail closed on those flows,
but define the degraded behavior so a cache outage does not silently remove the
protection instead of denying the request.

A throttle caps requests, not what a request costs. Where a call spends money,
model tokens, or heavy database work, add a per-identity cost and concurrency
cap alongside it. `AnonRateThrottle` and any `SimpleRateThrottle` subclass that
falls back to the client address also share one key across every caller behind
a single egress address, which makes IP keying ineffective against a machine
client; return an identity-derived cache key instead. See
`agent-and-llm-interfaces.md`, "Cost and concurrency limits, not only request
rate".

CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-799
(Improper Control of Interaction Frequency); OWASP API4:2023. Severity: high on
authentication-adjacent flows, medium elsewhere.

## Schema and browsable-API exposure

**The browsable API is a production exposure, not a cosmetic one.**
`BrowsableAPIRenderer` renders the API root as a navigable index, generates a
writable HTML form disclosing every writable field on every endpoint, and can
surface exception detail. It is selected by content negotiation, so listing JSON
first does not retire it: a request with `Accept: text/html`, or `?format=api`
where format suffixes are enabled, still reaches it. Reordering
`DEFAULT_RENDERER_CLASSES` is therefore not a fix — remove the renderer in
production configuration, or gate its inclusion on `DEBUG`.

```python
# Correct: the browsable renderer exists only where DEBUG is on
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}
if DEBUG:
    REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"].append(
        "rest_framework.renderers.BrowsableAPIRenderer"
    )
```

**Whether the OpenAPI schema should be public is a real decision, not a
default.** A schema is a complete reconnaissance map: every route, parameter,
and serializer field, including the ones nobody remembered were there. Publish
it when third-party integrators genuinely need it, and keep it private
otherwise. The tradeoff is worth stating honestly — a public schema is not
itself a vulnerability, and obscurity is not a control, but publishing removes
the attacker's enumeration cost and advertises exactly the properties that BOPLA
and BFLA target. Where it is private, gate the schema and any Swagger or Redoc
UI behind authentication or `DEBUG`, and disable the schema endpoint's
self-inclusion so it does not document itself to an anonymous caller. Where it
is public, the schema must not be the only place the access requirements of an
endpoint are written down.

OWASP API9:2023 and API8:2023, A02:2025. Severity: medium, higher where the
schema covers an internal or admin surface.

## Endpoint inventory (API9)

You cannot secure endpoints you cannot see, and the authoritative inventory is
the live URL map — not the documentation, and not the schema, which only
describes what it was pointed at. Three read-only techniques, in order of what
they prove:

- **Walk the URLconf.** On the supported Django lines there is no built-in
  command, so resolve the root URLconf and recurse: `django.urls.get_resolver()`
  yields `url_patterns`, where each entry is either a `URLResolver` (from an
  `include()`, recurse into it, carrying the namespace) or a `URLPattern` (a
  real route, record it with its callback). This expands router-generated routes
  for free, because routers register ordinary patterns. `django-extensions`'
  `show_urls` does the same thing and is a reasonable development-only
  convenience on an existing install. Django 6.2 adds a built-in `listurls`
  command, which will become the first choice once a project is on it.
- **Expand the routers.** Enumerate `router.urls` to see every generated viewset
  route including custom actions. Note that `DefaultRouter` additionally mounts
  an API root view and format-suffixed variants of every route, where
  `SimpleRouter` does not — so the router choice alone changes the size of the
  surface.
- **Generate the schema.** An OpenAPI document is the most complete
  machine-readable inventory of operations, parameters, and serializer fields.
  Its value in an audit is the diff: **anything in the URL map that is not in
  the schema is a candidate shadow endpoint.**

Shadow, zombie, and orphan routes arise in recognisable Django ways: an
`include()` left behind for an app whose views still resolve; a debug or
browsable route behind `if settings.DEBUG` on a deployment where `DEBUG` is
accidentally on; an app in `INSTALLED_APPS` mounting URLs nobody chose
(`django.contrib.admin`, `rest_framework.urls`, a schema or Swagger route); an
old versioned URL module kept alive after its successor shipped; and
`format_suffix_patterns` doubling every route it touches.

Treat the inventory as a recurring artifact rather than a one-time exercise:
generate it in CI, diff it against the previous run, and require that a new
public route is an intentional reviewed change. OWASP API9:2023. Severity:
medium on its own, but it multiplies every other finding — an endpoint missing
from the inventory was never reviewed at all.

## Versioning and deprecation lifecycle

Deprecation without a switch-off date is not deprecation; it is a permanent
second attack surface. The controls on an old version decay while the traffic
does not, so v1 is where the unpatched BOLA lives.

Run the lifecycle in three stages, each with a header the client can act on:

1. **Announce.** Serve `Deprecation` on every response from the old version.
   RFC 9745 defines it as a structured-field date carrying the moment the
   version became deprecated, and pairs it with a `Link` relation pointing at
   the migration documentation.
2. **Sunset.** Add `Sunset` (RFC 8594), an HTTP-date naming the exact instant
   the version stops being served. The old version still works until then.
3. **Switch off.** The old version returns `410 Gone`. This is the stage that
   is skipped, and skipping it is the finding.

In DRF, emit both headers from a small mixin or renderer keyed on
`request.version` so no view has to remember.

While both versions run, the security requirements are:

- **Identical authorization on both.** The same `permission_classes` and the
  same `get_queryset()` scoping. A shared serializer with a v1-only field is the
  usual leak.
- **`DEFAULT_VERSION` must be a real version**, and `ALLOWED_VERSIONS` must be
  set. Without an allowlist, `request.version` is unvalidated client input that
  code may branch on. Note the DRF behavior rather than fighting it: the default
  version is always treated as allowed, and every versioning class falls back to
  it when the client sends nothing — so with stock classes you cannot require a
  client to state a version, only constrain which ones you accept.
- **Evidence before switch-off.** Monitor traffic per version so the
  decommission date is a decision rather than a guess, and so a client still
  calling v1 the day before is discovered before it breaks.

OWASP API9:2023. Severity: medium to high, depending on the gap between the
versions' controls.

## Bulk endpoints

A bulk route is a per-object authorization problem wearing a list's clothing.
The framework offers no bulk path of its own, so a bulk endpoint is either
hand-written or comes from a package, and both fail the same way: the object
hook runs zero times for N objects.

- **Package bulk mixins skip the hook.** `djangorestframework-bulk` returns no
  object on its bulk update path, so `check_object_permissions` never fires;
  `drf-extensions` implements bulk operations as a queryset-level `update()` or
  `delete()`, which by design bypasses serializer `save`/`delete` and every
  per-object check. Both are unmaintained — see the library index.
- **A hand-written bulk route must authorize each object explicitly**, either by
  loading the whole set from a requester-scoped queryset and confirming the
  returned count matches the requested ids, or by calling
  `self.check_object_permissions(request, obj)` per object.
- **Define the partial-failure semantics.** If object 7 of 10 is denied, does
  the whole request fail, or do nine succeed? Either is defensible; silence is
  not. Wrap the accepted set in a transaction so a partial write cannot leave
  the caller unable to tell what happened.
- **A queryset-level `update()` or `delete()` writes without signals, without
  `save()`, and without per-row checks.** That is a legitimate performance tool
  and a dangerous authorization primitive; if the queryset it runs on was not
  scoped to the requester, it is a mass-assignment and mass-deletion path in one.

CWE-862 (Missing Authorization); OWASP API1:2023 and API5:2023. Severity: high
to critical — the blast radius is the size of the request body.

## Unsafe DRF defaults, enumerated

Each of these is safe to leave alone only when someone decided to. Use the list
at write-time as a checklist and at review-time as a sweep:

- `DEFAULT_PERMISSION_CLASSES` unset behaves as `AllowAny`: every un-annotated
  view is public.
- `BasePermission.has_object_permission` returns `True`, so an incomplete custom
  permission class is permissive exactly where it looks strictest.
- `queryset = Model.objects.all()` on a viewset leaves the list route unscoped;
  the object hook never runs there to catch it.
- `fields = "__all__"` or `exclude` on a serializer means a new sensitive model
  field joins the API the day it is added.
- `BrowsableAPIRenderer` in `DEFAULT_RENDERER_CLASSES` is reachable in production
  by content negotiation regardless of ordering.
- `DEFAULT_VERSION = None` with no `ALLOWED_VERSIONS` leaves `request.version`
  as unvalidated client input.
- `filterset_fields`, `ordering_fields`, or `search_fields` set to `"__all__"`
  or generated across a model exposes every column as a filter or sort oracle.
- Offset and page-number pagination return a total `count` over whatever the
  filter matched.
- `SessionAuthentication` on a login or token-obtain view built on plain
  `APIView` does not enforce CSRF for unauthenticated users.
- The throttle cache defaulting to `LocMemCache` gives one counter per worker.
- `NUM_PROXIES = None` keys the IP throttles on the whole `X-Forwarded-For`
  value, so varying the header is enough to earn a fresh bucket.
- `@action(detail=True)` adds a `pk` to the URL and authorizes nothing.

## Payments and webhook bodies

Payment integrity lives in A06 (resolve money server-side, idempotency, business
invariants), A08 (webhook signature verification, replay tolerance,
reconciliation), and A10 (the idempotency-key design itself, and the race
conditions a double-submitted payment exploits). Read those; they are not
restated here. Two rules are worth
repeating because they are absolute: never trust a client-supplied amount,
price, or currency, and never store raw card data.

The complete receiver — raw-body capture, timestamp tolerance, constant-time
comparison, the per-provider signing schemes, and the de-duplication store — is
in `a08-integrity-and-deserialization.md`, "Webhook and callback integrity".

The DRF-specific mechanic is the raw body. A signature must be verified against
the exact bytes the provider signed, but DRF's parsers consume the request
stream — once `request.data` has been accessed, reading `request.body` raises
`RawPostDataException`, because the stream is gone. A verifier that parses first
and reads the raw body second will therefore fail at runtime, and the tempting
fix — re-serializing the parsed data — silently breaks the HMAC, because key
order and separators will not match what was signed.

```python
# Correct: read and verify the raw body before anything parses the stream
@api_view(["POST"])
@authentication_classes([])          # the signature is the authentication
@permission_classes([AllowAny])
def payment_webhook(request):
    payload = request.body           # must come before request.data
    verify_signature(payload, request.headers.get("Stripe-Signature", ""))
    event = json.loads(payload)
    ...
```

## Review checklist

- [ ] Every `@action(detail=True)` that touches a record loads it with
      `self.get_object()`, not a direct model query.
- [ ] Every viewset scopes `get_queryset()` to the requester; no bare
      `Model.objects.all()` behind a list or detail route.
- [ ] Any overridden `get_object()` still calls
      `self.check_object_permissions(self.request, obj)`; plain `APIView`s that
      load objects call it by hand.
- [ ] Actions needing stricter access declare their own `permission_classes`,
      restating the base requirement; `get_permissions()` overrides deny by
      default rather than falling through.
- [ ] No `fields = "__all__"`; explicit fields; server-controlled fields
      read-only, with `read_only=True` on *declared* fields rather than only in
      `read_only_fields`; passwords write-only.
- [ ] `SerializerMethodField` and nested serializers do not traverse to related
      records the caller was never authorized against.
- [ ] Owner/tenant set server-side on create, since object permissions don't run
      there; role-dependent writable fields allow-listed and `PATCH` tested.
- [ ] Filters, ordering, and search run on requester-scoped querysets and are
      allow-listed by field; nothing is `"__all__"`; sensitive collections use
      cursor pagination rather than exposing a total count.
- [ ] `DEFAULT_PERMISSION_CLASSES` restrictive; no accidental `AllowAny`.
- [ ] CSRF correct for the auth model; login views not CSRF-exempt by accident.
- [ ] Throttles used as quotas only; real abuse defense elsewhere; the throttle
      cache is shared rather than `LocMemCache`; `NUM_PROXIES` matches the
      deployed proxy count so the key is not a caller-supplied forwarded chain;
      machine callers are keyed on identity, not IP; costly calls are capped by
      cost and concurrency as well as rate.
- [ ] `BrowsableAPIRenderer` is absent from production renderers, not merely
      ordered last; schema and Swagger/Redoc routes are authenticated or
      `DEBUG`-gated unless the API is deliberately public.
- [ ] The live URL map has been enumerated and diffed against the served schema;
      shadow, zombie, and orphan routes are retired or protected.
- [ ] Deprecated versions emit `Deprecation` and `Sunset` with a dated
      switch-off, carry the same authorization as the current version, and
      `DEFAULT_VERSION`/`ALLOWED_VERSIONS` are both set.
- [ ] Bulk routes authorize every object and define partial-failure semantics;
      no queryset-level bulk update or delete on an unscoped queryset.
- [ ] Payments resolve amounts server-side; webhook verifiers read
      `request.body` before `request.data`; no raw card storage.
- [ ] Any GraphQL schema or non-DRF framework in the same project was reviewed
      against `graphql-and-alternative-api-surfaces.md`; DRF defaults such as
      `DEFAULT_PERMISSION_CLASSES` do not apply to those surfaces.
