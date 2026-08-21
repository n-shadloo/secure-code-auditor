# API and DRF-Specific Concerns

Covers cross-cutting DRF material that spans several OWASP categories. Covers
where the framework runs an object check, and every route that skips it.
Covers function-level authorization on viewset actions, and serializer
exposure and mass assignment. Covers pagination and filter leakage,
throttling, and schema and browsable-API exposure. Covers the endpoint
inventory, version deprecation, bulk routes, and CSRF interaction.

Read this file with A01 for authorization, and A02 for configuration and CORS.
Read it with A06 and A07 for rate limiting and authentication. Read
`file-uploads.md` and `async-and-channels.md` where those surfaces apply.

Maps broadly to the OWASP API Security Top 10:2023. The entries are API1 BOLA,
API3 BOPLA, API4 resource consumption, API5 BFLA, API8 misconfiguration, and
API9 inventory. Maps also to A01:2025 and A02:2025.

Three files share the authorization material, and the split is deliberate. A01
owns the per-request access-control failure, and how to recognize it.
`authorization-architecture.md` owns the permission *model*, and the table of
which DRF paths invoke the object hook. This file owns the **call sites**,
which are the DRF routes, actions, and defaults where a correct model still
fails to run. Read the other two for the model; read this one for where DRF
lets it leak.

This file is about DRF specifically. Read
`graphql-and-alternative-api-surfaces.md` for a GraphQL schema. Read it also
for a non-DRF framework such as Django Ninja, whose defaults differ from the
DRF defaults. Several patterns below generalize there with a different unit of
measurement. The framework defaults do not carry over.

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

An API framework decides two things that a reviewer cannot see from the
routing table. It decides *where* the code invokes an authorization decision.
It decides *what* the shape of a response reveals. Both fail quietly. A hook
that defaults to "allow" makes every route that does not call it an
access-control hole. A serializer, filter, or paginator that nobody asked to
hide anything answers questions that the caller had no right to ask.

The portable rule has two halves. Enforce authorization at the point where the
code loads a specific object for a specific action, and not at the view door.
Make the response carry only what this caller may see, in a shape that does
not let them infer the rest.

The same reasoning applies to the surface as a whole. Nobody can review an
endpoint that nobody can enumerate. The authoritative inventory is therefore
the live URL map, and not the documentation. A deprecated version that still
runs is not a legacy concern. It is a second, less-maintained copy of every
control.

In DRF the framework invokes the object decision in exactly one place that it
controls. Serializers, filter backends, and pagination classes decide the
response shape. Several of the relevant defaults are permissive. Those three
facts organize everything below.

## Where the object check runs, and the routes that skip it

`GenericAPIView.get_object()` ends by calling
`self.check_object_permissions(self.request, obj)` before returning the
instance. That call is the **only** place DRF invokes
`has_object_permission()` for you.

`authorization-architecture.md`, "DRF: where the object check actually runs"
holds the table of which paths reach it. It also holds the permission-class
defaults behind that table. Those defaults include
`BasePermission.has_object_permission`, which returns `True`. A class that
implements only `has_permission` is therefore permissive at the object level.
This section covers the route shapes where that table is easiest to violate.

**A detail action does not fetch the object.** `@action(detail=True)` shapes
the URL, and adds the `pk` keyword argument. It does nothing more. It does not
call `get_object()`. A developer who queries the model directly inside the
action gets no object check. That code also looks like every other detail
route.

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

- **Plain `APIView`** has no `get_object()`, so DRF calls nothing
  automatically. Authorize any object it loads by hand, with
  `self.check_object_permissions(request, obj)`. You can instead load the
  object from a requester-scoped queryset.
- **List routes** reach `filter_queryset(get_queryset())`, and never touch
  `get_object()`. Isolation on a list is the job of the queryset. A correct
  `has_object_permission` contributes nothing there. Note the order.
  `filter_queryset` applies the filters of the *client* on top of the result
  of `get_queryset()`. A filter backend therefore cannot rescue a
  `get_queryset()` that is not already scoped.
- **Create** has no object yet, so the hook cannot run. Set the owner and the
  tenant in `perform_create()` from `request.user`. Never accept either one
  from the body.
- **`@action(detail=False)`** has no object identity at all; it is a
  function-level surface, below.
- **An overridden `get_object()`** that omits
  `self.check_object_permissions(...)` silently removes the one automatic
  check.
- **Bulk routes** — see "Bulk endpoints".

CWE-285 (Improper Authorization), CWE-639 (Authorization Bypass Through
User-Controlled Key); OWASP API1:2023, A01:2025. Severity: high to critical.

## Function-level authorization on actions (API5)

An object-level check answers whether this caller may touch *this* record. A
function-level check answers whether this caller may invoke *this operation*
at all. A system can pass the first check and fail the second. The two
failures live in different places in the code. BOLA is a missing queryset
scope, or a missing object hook, on a per-record path. BFLA is a missing or
weak `has_permission` on the operation.

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

Review three more shapes. The first is a destructive method left on a
`ModelViewSet`, because that was quicker than `ReadOnlyModelViewSet` plus
explicit writes. The second is a staff-only route gated on `IsAuthenticated`.
The third is a `get_permissions()` override that branches on `self.action`,
where a new action falls through to the permissive default branch. Prefer an
explicit mapping with a deny fallback over an `if/elif` chain that ends in the
base return.

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
# Correct: explicit allowlist; server-controlled fields read-only; the secret
# accepted write-only and validated before it is hashed
from django.contrib.auth.password_validation import validate_password


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    class Meta:
        model = User
        fields = [
            "id", "email", "display_name", "is_staff",
            "date_joined", "password",
        ]
        read_only_fields = ["id", "is_staff", "date_joined"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        validate_password(password, user=user)
        user.set_password(password)
        user.save()
        return user
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

A `SerializerMethodField` is ordinary Python, and no field-level check applies
to it. Treat every relation it walks as a separate read that needs its own
justification. The same applies to nested serializers and `depth`.

**Write-time.** When you generate a `ModelSerializer`, enumerate `fields`
explicitly. Mark the server-controlled attributes read-only in that same edit.
`"__all__"` and `exclude` both admit whatever the model gains next. Nobody
re-reviews the field added six months later. Where the field is declared on
the serializer rather than only named in `Meta`, put `read_only=True` on the
field, since `read_only_fields` does not reach it.

A writable relation is a second mass-assignment surface. `ModelSerializer`
builds each writable `PrimaryKeyRelatedField` with the related model's default
queryset. The client can then name any row in that table, and another tenant's
row is one of them.

Declare the relation with a scoped queryset, or scope it per request in
`get_fields()` or in `validate_<field>()` from `self.context["request"]`. The
same rule reaches `SlugRelatedField` and nested writes. `UniqueValidator` and
`UniqueTogetherValidator` run their own querysets too. An unscoped validator
queryset answers whether a value exists in another tenant, which is an
existence oracle.

**Write-time.** When a serializer gains a writable relation, write the scoped
queryset in the same edit. State in one line which principal scope that
queryset encodes.

The same rule with the same spelling exists outside DRF, and a Django codebase
usually has both. `ModelForm` with `Meta.fields = "__all__"` is the same
serializer failure in a Django form. Every model field becomes writable from
POST data, including the `is_staff`, `owner`, or `balance` column added two
migrations later. `exclude = [...]` fails open the same way an excluded
serializer field does: the next added field is writable by default. Require an
explicit `fields` allowlist on every `ModelForm` bound to request data.

Treat a server-owned field rendered as a form input as the same finding. The
shape is a missing `disabled=True`, or a value round-tripped through a hidden
input and trusted on POST. A hidden field is client input and not server
state. The bundled scanner's `CFG001` fires on the `Meta` line in either
container.

Formsets add one multiplier: the management form's counts (`TOTAL_FORMS`) are
client input. Django bounds instantiation at `absolute_max`, which defaults to
`max_num + 1000`, and `DATA_UPLOAD_MAX_NUMBER_FIELDS` bounds the request
itself. So the review question is not whether a bound exists. It is whether
the project raised one or removed one. Three shapes are a caller-controlled
work multiplier. The first is a formset factory that takes a large
`absolute_max`. The second is a `validate_max=False` on data that feeds bulk
model writes. The third is a raised `DATA_UPLOAD_MAX_NUMBER_FIELDS`. Each
belongs in the table in `a06-insecure-design.md`, "Algorithmic resource
exhaustion".

**Write-time.** When generating a `ModelForm`, write the explicit `fields`
list in the same edit that creates the class. Mark a server-owned rendered
field `disabled=True` rather than re-validating it by hand. Leave the formset
bounds at their defaults unless the request names a number, and then say what
the raised bound multiplies.

Where the writable set differs *by role*, allow-list the writable fields per
role. Do not deny-list them. Test `PATCH` separately from `PUT`. See
`authorization-architecture.md` for the pattern and the full BOPLA surface.
CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object
Attributes); OWASP API3:2023, A01:2025. Severity: high.

### Commonly mistaken for a finding

**`fields = "__all__"` on a serializer used only for output, over a model
whose every field is already public.** The `"__all__"` literal is the wrong
example at the head of this section, so it is reported at the section's
severity wherever it appears.

Both halves of this class need the write path to exist. Mass assignment needs
a client that can send fields. Over-exposure needs a field worth exposing. A
read-only serializer over a model of already-public columns has neither today.

Two questions decide the case. Ask whether a write route reaches the
serializer, either directly or through a viewset that uses it as
`serializer_class` for every action. Ask whether the model carries anything
that the API has not already published. Keep the recommendation to enumerate
`fields`. The defect class is an unreviewed field set, and the model gains its
next field with nobody re-reading this line. Drop the severity, which belongs
to a write exposure that is absent here.

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

- **Ordering is an oracle too.** A sort on a field the caller may not read
  leaks its relative values across the result set. Allow-list
  `ordering_fields` as deliberately as `filterset_fields`. Never leave either
  one as `"__all__"`.
- **`search_fields` traversals** follow relations with `__`, so a search
  configured across a foreign key can match on a related record the caller has
  no access to. Review each traversal as a read.
- **Pagination should not reveal what it excluded.** `PageNumberPagination`
  and `LimitOffsetPagination` return a total `count`. That count discloses the
  size of the matching set, including under a filter the caller controls. The
  count then becomes a binary search over data the caller cannot read. Where
  the collection is sensitive, `CursorPagination` exposes neither offsets nor
  a total, at the cost of ordering on a stable field and no random access.
- Ids in a paginated response are still a disclosure: a listing that includes
  identifiers of records the caller cannot open tells them those records
  exist.
- A page size that the client raises with no ceiling is the cost half of the
  same controls. So is the `count()` scan that a paginator issues on each
  request. `a06-insecure-design.md`, "Algorithmic resource exhaustion" holds
  the design rule behind them, and the surfaces it spans. `max_page_size` and
  `PAGE_SIZE` are the DRF attributes that enforce it.

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

**Write-time.** When you generate a viewset or an `APIView`, set
`permission_classes` on the class itself. Do not inherit the project default.
Reserve `AllowAny` for an endpoint that somebody told you is public. The DRF
default is `AllowAny`, so an omission is a decision to publish.

Write `get_queryset()` scoped to the requester in that same edit, before the
serializer or the actions. An unscoped queryset makes an authenticated route a
cross-tenant read. No object hook runs on the list path to catch that. A
project default as well is a second layer, and not an alternative. The
per-class declaration is what survives a replacement of the settings file.

This setting covers DRF only. It does not cover a plain Django view, the
admin, or a third-party URL. Pair it with a URLconf-enumerating audit test to
make deny-by-default enforceable across the whole project. See
`authorization-architecture.md`.

### Commonly mistaken for a finding

**A viewset with no `permission_classes` where `DEFAULT_PERMISSION_CLASSES` is
restrictive.** The missing attribute is the most visible authorization defect
in a DRF codebase and the easiest to report from the view file alone. Where
the project default is `IsAuthenticated` or narrower, that default *is* the
policy, and the view is authenticated. What remains is the durability point of
the write-time rule above. It is not an open endpoint. The deciding question
is what `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]` holds in the settings
module the deployment runs.

The converse is the reason that question comes first rather than second. The
DRF default is `AllowAny`, and an un-annotated project therefore has it. Where
that default holds, the missing attribute *is* the finding, at the severity of
what the view returns. It is a finding on every view that omitted the
attribute, and not on one view. One file that is not open decides whether the
same line of code is a non-finding or a High. Read the settings module before
you judge any view.

## CSRF and SessionAuthentication

- A DRF `APIView` is CSRF-exempt **except** inside `SessionAuthentication`.
  That class enforces CSRF for an authenticated cookie request. Token and JWT
  authentication through the `Authorization` header needs no CSRF, because the
  browser does not send that credential automatically.
- Note one known trap. A login or token-obtain view built on plain `APIView`
  with `SessionAuthentication` does **not** enforce CSRF for an
  *unauthenticated* user. Always apply CSRF to a login view.
- Do not hide a CSRF error with `@csrf_exempt` on a cookie-authenticated,
  state-changing endpoint. Confirm the authentication model first.

This section owns the DRF interaction only. `a02-security-misconfiguration.md`
declares the settings behind it. Those settings are `CSRF_TRUSTED_ORIGINS`,
the cookie matrix, and CORS.

### Commonly mistaken for a finding

**`@csrf_exempt` on a DRF view whose authentication classes do not include
`SessionAuthentication`.** The decorator reads as protection being removed,
and on a Django view it would be. DRF enforces CSRF inside
`SessionAuthentication`, and not through the middleware. The first bullet
above says so. On a token-authenticated or JWT-authenticated view there is
therefore no middleware check for the decorator to remove. The decorator is
redundant, and not a downgrade.

The deciding question is what `authentication_classes` resolves to for that
view, including the project default it may be inheriting. Where
`SessionAuthentication` is in that list and the endpoint changes state, the
decorator is the finding the bullet above describes.

The webhook receiver is the other case that reaches this heading legitimately.
`@csrf_exempt` is correct there, because a MAC over the raw body replaces what
CSRF protected. `a08-integrity-and-deserialization.md`, "Webhook and callback
integrity" owns that receiver completely. It states what makes the exemption
safe. It also states what makes the endpoint an unauthenticated write instead.

## Throttling as quota, not security (API4)

This section is the authoritative treatment of DRF throttling mechanics.
`a06-insecure-design.md` owns rate limiting as a design decision, which is
which flows need anti-automation. That file defers to this section for the
behavior of the classes.

DRF throttles provide basic fair-use quotas and are **not** a brute-force or
DoS defense.

The DRF documentation states this plainly. Do not treat its throttling as a
security measure against brute forcing or denial of service. A deliberate
attacker can spoof the IP origin that the default classes key on. Use
throttles for quotas; use `django-axes` plus edge limits for abuse protection.
Configure real limits where resource consumption matters (expensive queries,
exports, file processing). Upload endpoints also need hard edge, per-file,
aggregate, parser, and storage-quota controls from `file-uploads.md`.

Four mechanics decide whether a configured limit is the limit you actually get:

- **The default client-IP identity is the whole forwarded chain.** The
  throttle base class keys on `NUM_PROXIES`, which defaults to `None`. On that
  default it identifies the caller by the whole `X-Forwarded-For` value, with
  the whitespace stripped. The DRF documentation describes that as less strict
  IP matching. A caller who varies the header therefore gets a fresh bucket
  per value and the limit becomes opt-out.

Set `NUM_PROXIES` to the number of proxies that you operate. The class then
takes the address that many hops in from the right. That entry is the one your
own infrastructure appended. The rule and the topology it depends on are in
`deployment-and-runtime.md`, "Reading the client IP".
- **The counter is not atomic.** `SimpleRateThrottle` reads the request
  history from the cache, trims it in local memory, appends the current
  timestamp, and writes the list back. There is no lock and no
  compare-and-set, so concurrent requests read the same history and each write
  their own version over it. Under load the effective rate is higher than
  configured — the DRF documentation describes this as fuzziness in the
  measured rate.
- **`LocMemCache` is per process.** With N Gunicorn workers you get N
  independent counters and roughly N times the configured limit. This is the
  single most common throttling misconfiguration and it is invisible in
  development, where there is one worker. A throttle needs a shared Redis or
  Memcached cache. Give the throttle a cache whose eviction policy does not
  discard a counter silently under memory pressure.
- **Throttles run after authentication.** `APIView.initial()` performs
  authentication, then permission checks, then throttle checks. A throttle
  therefore cannot protect the authentication step itself; login and token
  endpoints need lockout and edge limits, not a throttle class.

Where a limit must actually hold — login, password reset, payment, invitation
— supplement the throttle with an atomic counter and a limit at the edge. No
maintained general-purpose limiter currently clears the package gate to supply
one. This is therefore a pattern to own, and not a dependency to add.
`security-hardening-libraries.md`, "Existing-install audit only or rejected
candidates" records that category ruling and the date behind it. Django's own
cache API carries the pattern: `cache.incr()` is a single atomic operation on
the Memcached and Redis backends.

```python
# Wrong: a read, a decision, and a write across two round trips. Two requests
# that read the same count both write count + 1, so the effective limit is
# whatever concurrency allows -- the same non-atomic shape SimpleRateThrottle
# has, rebuilt by hand on the flow that most needed it not to.
from django.core.cache import cache
from rest_framework.exceptions import Throttled


def register_attempt(identity):
    key = f"login-attempts:{identity}"
    attempts = cache.get(key, 0)
    if attempts >= 5:
        raise Throttled()
    cache.set(key, attempts + 1, 300)
```

```python
# Correct: one atomic increment per attempt. add() creates the key and starts
# the window only when it is absent, so the expiry is established once and the
# window does not slide forward under sustained load. incr() raises ValueError
# when the key expires between the two calls -- that is the real race, and it
# is handled rather than left to chance.
from django.conf import settings
from django.core.cache import caches
from rest_framework.exceptions import Throttled


def register_attempt(identity):
    cache = caches["throttle"]
    key = f"login-attempts:{identity}"
    window = settings.LOGIN_ATTEMPT_WINDOW_SECONDS
    cache.add(key, 0, window)
    try:
        attempts = cache.incr(key)
    except ValueError:
        cache.set(key, 1, window)
        attempts = 1
    if attempts > settings.LOGIN_ATTEMPT_LIMIT:
        raise Throttled(wait=window)
```

Three constraints travel with it, and none is optional.

- **The backend decides whether it is atomic at all.** `incr()` is atomic only
  on Memcached and Redis. On `LocMemCache` the increment holds the lock of the
  backend, so it is consistent inside one process. The counter is still per
  process. N Gunicorn workers therefore give N independent counters, and
  approximately N times the limit. That is the same per-worker failure
  described above for throttles. It is worse here, because this counter is the
  control that had to hold.

The database cache backend's `incr` is a non-atomic get-then-set and races
even inside one process.
- **Name the cache alias explicitly.** Read `caches["throttle"]` rather than
  the default. That keeps the counter off a cache that somebody later repoints
  at LocMemCache for a test suite. It also keeps the counter off a cache whose
  eviction policy discards keys under memory pressure. An evicted counter is a
  reset counter.
- **Choose the outage behavior.** `incr()` raises when the cache is
  unreachable. The flow then denies or allows. A denial fails closed, which is
  correct for a credential or payment flow. An allow fails open, which makes a
  cache outage an open door. Letting the exception reach a 500 is a third
  behavior nobody chose.

**Write-time.** When you generate a login, password-reset, payment, or
invitation endpoint, write the atomic counter in the same change as the view.
Point it at a named Redis or Memcached alias. A reviewer sees the throttle
class, and the non-atomic counter is what runs.

Put the window and the ceiling in settings, and not inline. An operator can
then tune them with no code change. Select the cache-outage branch in that
same edit, and fail closed on a credential or payment flow. An unhandled cache
error is a 500, which reads as a defect rather than as the denial it had to
be.

A throttle caps requests, not what a request costs. Where a call spends money,
model tokens, or heavy database work, add a per-identity cost and concurrency
cap alongside it.

`AnonRateThrottle` shares one key across every caller behind a single egress
address. So does any `SimpleRateThrottle` subclass that falls back to the
client address. IP keying is therefore ineffective against a machine client.
Return an identity-derived cache key instead. See
`agent-and-llm-interfaces.md`, "Cost and concurrency limits, not only request
rate".

CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-799
(Improper Control of Interaction Frequency); OWASP API4:2023. Severity: high on
authentication-adjacent flows, medium elsewhere.

## Schema and browsable-API exposure

**The browsable API is a production exposure, not a cosmetic one.**
`BrowsableAPIRenderer` renders the API root as a navigable index. It generates
a writable HTML form that discloses every writable field on every endpoint. It
can also surface exception detail.

Content negotiation selects it, so a JSON entry first does not retire it. A
request with `Accept: text/html` still reaches it. So does `?format=api`,
where format suffixes are enabled. Reordering `DEFAULT_RENDERER_CLASSES` is
therefore not a fix — remove the renderer in production configuration, or gate
its inclusion on `DEBUG`.

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
otherwise.

State the tradeoff honestly. A public schema is not itself a vulnerability,
and obscurity is not a control.

Publication still removes the enumeration cost for the attacker. It also
advertises exactly the properties that BOPLA and BFLA target. Where the schema
is private, gate it behind authentication or `DEBUG`. Gate any Swagger or
Redoc UI the same way. Disable the self-inclusion of the schema endpoint, so
that it does not document itself to an anonymous caller. Where it is public,
the schema must not be the only place the access requirements of an endpoint
are written down.

**Serve the caller the document they are entitled to, and redact per
operation.** In `drf-spectacular`, `SERVE_PUBLIC` defaults to `True`. On that
default it generates the whole document for whoever reaches the endpoint. Set
to `False`, it drops the operations whose views the requesting caller fails.

`SERVE_PERMISSIONS` decides who reaches the endpoint at all. It defaults to
`AllowAny`, independently of `DEFAULT_PERMISSION_CLASSES`. A project with a
restrictive project-wide default therefore still serves its schema to an
anonymous caller until somebody sets this.

Read the filtering for what it is. It runs the `check_permissions` of each
view. It therefore reflects view-level access only, and knows nothing about
object permissions or queryset scoping. A tailored document is a smaller
reconnaissance map, not an authorization boundary.

Per-operation redaction has the same limit. `extend_schema(exclude=True)`
removes an operation from the document and
`extend_schema_serializer(exclude_fields=[...])` removes fields from a
component; both change the document only. The route still resolves, and the
serializer still returns the field. A caller who guesses the name gets exactly
the earlier response.

Use them to keep an internal operation out of a partner-facing contract. Never
use them as the reason an operation is safe. The permission class and the
field set are the control. The decoration only brings the document up to date.

```python
# Correct: the permission class does the gating; the decorations only keep
# the published document to the contract integrators are meant to code
# against. Neither decoration authorizes anything.
from drf_spectacular.utils import extend_schema, extend_schema_serializer
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from .models import Account


@extend_schema_serializer(exclude_fields=["internal_risk_score"])
class StaffAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["id", "name", "internal_risk_score"]


class AccountViewSet(viewsets.ReadOnlyModelViewSet):
    # The gate. Without it the two decorations merely hide a field and an
    # operation that any caller could still read and invoke.
    permission_classes = [IsAdminUser]
    serializer_class = StaffAccountSerializer

    def get_queryset(self):
        return Account.objects.filter(tenant=self.request.user.tenant)

    @extend_schema(exclude=True)
    @action(detail=False)
    def reindex(self, request):
        return Response({"queued": True})
```

**What a deliberately public schema should omit**, once it is a published
contract rather than an internal artifact:

- **Internal and admin operations.** Omit anything an integrator has no route
  to call. That includes staff-only actions and impersonation entry points. It
  includes reindex and other operational routes. It also includes the health
  and metrics surfaces that `deployment-and-runtime.md`, "Operational and
  development endpoints" owns.
- **Error internals.** Response schemas and examples carrying exception class
  names, stack frames, database constraint names, or upstream service
  identifiers. The rule is `a10-exceptional-conditions.md`, "Don't leak on
  error"; the schema is one more place it escapes, and the place nobody
  re-reads.
- **Fields the serializer returns only to an elevated role.** A component
  enumerating every field any caller might receive tells an unprivileged
  caller precisely which fields exist and which are worth escalating for.

**The schema is the inventory artifact, so diff it.** Its audit value is in
the change between two generations rather than in any single one.

Generate it in CI, keep the generated document as a build artifact, and diff
it on every dependency upgrade and every release. An upgrade is where
operations appear that nobody wrote. Three causes exist. They are a router
that began to mount a route, and a package that stopped honoring an exclusion.
The third is a serializer that gained a field from a model change. A release
diff makes "a new field reached the API" a reviewable line, instead of a later
discovery.

**Write-time.** When you generate a schema route, set `SERVE_PERMISSIONS` and
`SERVE_PUBLIC` in the same edit that adds the URL. Do not accept the defaults.
Together those defaults give the complete document to an anonymous caller. A
restrictive `DEFAULT_PERMISSION_CLASSES` implies neither of them.

Sometimes the published contract must not carry an operation. Give that
operation its own `permission_classes` first. Add
`extend_schema(exclude=True)` second, in that order. The permission is the
control, and the exclusion is documentation. An operation that only the
exclusion protects is a public operation with a delay in front of it.

OWASP API9:2023 and API8:2023, A02:2025. Severity: medium, higher where the
schema covers an internal or admin surface.

## Endpoint inventory (API9)

You cannot secure an endpoint that you cannot see. The authoritative inventory
is the live URL map. It is not the documentation, and not the schema. The
schema describes only what somebody pointed it at. Three read-only techniques,
in order of what they prove:

- **Walk the URLconf.** The supported Django lines have no built-in command
  for this. Resolve the root URLconf and recurse instead.
  `django.urls.get_resolver()` yields `url_patterns`. Each entry there is a
  `URLResolver` or a `URLPattern`. A `URLResolver` comes from an `include()`,
  so recurse into it and carry the namespace. A `URLPattern` is a real route,
  so record it with its callback.

This expands router-generated routes for free, because routers register
ordinary patterns. `django-extensions`' `show_urls` does the same thing and is
a reasonable development-only convenience on an existing install. Django 6.2
adds a built-in `listurls` command, which will become the first choice once a
project is on it. `scripts/entrypoint_inventory.py` resolves the same chain
from the source without starting Django, which is the form available when the
project cannot be run.
- **Expand the routers.** Enumerate `router.urls` to see every generated
  viewset route including custom actions. Note that `DefaultRouter` also
  mounts an API root view, and format-suffixed variants of every route.
  `SimpleRouter` mounts neither. The choice of router alone therefore changes
  the size of the surface.
- **Generate the schema.** An OpenAPI document is the most complete
  machine-readable inventory of operations, parameters, and serializer fields.
  Its value in an audit is the diff: **anything in the URL map that is not in
  the schema is a candidate shadow endpoint.**

Shadow, zombie, and orphan routes arise in recognizable Django ways. An
`include()` stays behind for an app whose views still resolve. A debug or
browsable route sits behind `if settings.DEBUG`, on a deployment where `DEBUG`
is on by accident. An app in `INSTALLED_APPS` mounts URLs that nobody chose,
such as `django.contrib.admin`, `rest_framework.urls`, or a schema or Swagger
route. An old versioned URL module stays alive after its successor ships.
`format_suffix_patterns` also doubles every route it touches.

The same table answers a second question that this file does not own. That
question is which of two matching patterns a path reaches.
`a01-broken-access-control.md`, "URL resolution as an access-control surface"
owns it.

Treat the inventory as a recurring artifact, and not as a single exercise.
Generate it in CI. Diff it against the previous run. Require that a new public
route is an intentional, reviewed change. OWASP API9:2023. Severity: medium on
its own, but it multiplies every other finding — an endpoint missing from the
inventory was never reviewed at all.

## Versioning and deprecation lifecycle

Deprecation without a switch-off date is not deprecation; it is a permanent
second attack surface. The controls on an old version decay while the traffic
does not, so v1 is where the unpatched BOLA lives.

Run the lifecycle in three stages, each with a header the client can act on:

1. **Announce.** Serve `Deprecation` on every response from the old version.
   RFC 9745 defines it as a structured-field date. That date carries the
   moment of deprecation of the version. RFC 9745 pairs it with a `Link`
   relation that points at the migration documentation.
2. **Sunset.** Add `Sunset` (RFC 8594), an HTTP-date naming the exact instant
   the version stops being served. The old version still works until then.
3. **Switch off.** The old version returns `410 Gone`. This is the stage that
   is skipped, and skipping it is the finding.

In DRF, emit both headers from a small mixin or renderer keyed on
`request.version` so no view has to remember.

While both versions run, the security requirements are:

- **Identical authorization on both.** The same `permission_classes` and the
  same `get_queryset()` scoping. A shared serializer with a v1-only field is
  the usual leak.
- **`DEFAULT_VERSION` must be a real version**, and `ALLOWED_VERSIONS` must be
  set. Without an allowlist, `request.version` is unvalidated client input
  that code may branch on.

Note the DRF behavior, and do not fight it. DRF always treats the default
version as allowed. Every versioning class falls back to that version when the
client sends nothing. With the stock classes you therefore cannot require a
client to state a version. You can only constrain which versions you accept.
- **Evidence before switch-off.** Monitor the traffic for each version. The
  decommission date is then a decision rather than a guess. You also find a
  client that still calls v1 the day before, and before it breaks.

That behavior is common to every versioning class. Two of them additionally
make the version a decision about something outside the request body, and
each changes what a reviewer has to check.

- **`HostNameVersioning` puts DNS inside the trust boundary.** The version is
  the first label of `request.get_host()`, so it is the `Host` header.
  `ALLOWED_HOSTS` is the only constraint on it. A wildcard DNS record can
  point at the application, beside a wildcard `ALLOWED_HOSTS` entry such as
  `.example.com`. Any hostname that an attacker can resolve is then version
  input.

Two mechanics matter in review. The class matches a hostname against a regex
of exactly three dot-separated labels. `v1.internal.example.com` and
`v1.example.co.uk` therefore do not match. They fall back to `default_version`
silently, and DRF does not reject them. A deployment that moves behind a
longer hostname stops versioning, and raises no error.

Where `USE_X_FORWARDED_HOST` is enabled, the version comes from a header. The
client sends that header, and the proxy forwards it. The proxy rules in
`deployment-and-runtime.md`, "Reverse proxy and forwarded headers" therefore
decide whether it is trustworthy.
- **`NamespaceVersioning` binds the version to URLconf include scope.** It
  reads `request.resolver_match.namespace`. A version therefore exists for
  exactly as long as an `include(..., namespace="v1")` is reachable from the
  root URLconf. A stale include is a live old version. A removal of the routes
  switches it off, and an edit to a setting does not.

Two consequences. A route reachable outside any namespaced include resolves
with an empty namespace. It therefore runs at `default_version`. A viewset
mounted at the root, while its versioned copies exist under the includes, is
silently served as the default version. Any authorization that branches on
`request.version` branches on that value.

The class also splits nested namespaces, and returns the first allowed
component. An outer namespace therefore wins over the inner one. A module
re-mounted under a namespace that matches another version serves its code
under the name of the outer version.

OWASP API9:2023. Severity: medium to high, depending on the gap between the
versions' controls.

## Bulk endpoints

A bulk route is a per-object authorization problem wearing a list's clothing.
The framework offers no bulk path of its own. A bulk endpoint is therefore
hand-written, or it comes from a package. Both fail the same way. The object
hook runs zero times for N objects.

- **Package bulk mixins skip the hook.** `djangorestframework-bulk` returns no
  object on its bulk update path, so `check_object_permissions` never fires.
  `drf-extensions` implements a bulk operation as a queryset-level `update()`
  or `delete()`. That call bypasses serializer `save` and `delete` by design,
  and every per-object check with them. Both are unmaintained — see the
  library index.
- **A hand-written bulk route must authorize each object explicitly.** Load
  the whole set from a requester-scoped queryset, and confirm that the
  returned count matches the requested ids. You can instead call
  `self.check_object_permissions(request, obj)` for each object.
- **Define the partial-failure semantics.** If object 7 of 10 is denied, does
  the whole request fail, or do nine succeed? Either is defensible; silence is
  not. Wrap the accepted set in a transaction so a partial write cannot leave
  the caller unable to tell what happened.
- **A queryset-level `update()` or `delete()` writes without signals, without
  `save()`, and without per-row checks.** That is a legitimate performance
  tool, and a dangerous authorization primitive. Where the queryset it runs on
  is not scoped to the requester, it is a mass-assignment and mass-deletion
  path in one.

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

Payment integrity lives in three other files. A06 owns the server-side
resolution of money, idempotency, and business invariants. A08 owns webhook
signature verification, replay tolerance, and reconciliation. A10 owns the
idempotency-key design itself, and the races that a double-submitted payment
exploits. Read those; they are not restated here. Two rules are worth
repeating because they are absolute: never trust a client-supplied amount,
price, or currency, and never store raw card data.

The complete receiver — raw-body capture, timestamp tolerance, constant-time
comparison, the per-provider signing schemes, and the de-duplication store — is
in `a08-integrity-and-deserialization.md`, "Webhook and callback integrity".

The DRF-specific mechanic is the raw body. A verifier must check a signature
against the exact bytes that the provider signed. The DRF parsers consume the
request stream. After anything accesses `request.data`, a read of
`request.body` raises `RawPostDataException`, because the stream is gone.

A verifier that parses first and reads the raw body second therefore fails at
runtime. The attractive fix is to serialize the parsed data again. That fix
breaks the HMAC silently, because the key order and the separators do not
match the signed bytes. `DATA_UPLOAD_MAX_MEMORY_SIZE` bounds `request.body` at
2.5 MB by default. Never raise that bound for a webhook receiver.

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
      `self.check_object_permissions(self.request, obj)`; plain `APIView`s
      that load objects call it by hand.
- [ ] Actions needing stricter access declare their own `permission_classes`,
      restating the base requirement; `get_permissions()` overrides deny by
      default rather than falling through.
- [ ] No `fields = "__all__"`; explicit fields; server-controlled fields
      read-only, with `read_only=True` on *declared* fields rather than only
      in `read_only_fields`; passwords write-only.
- [ ] `SerializerMethodField` and nested serializers do not traverse to
      related records the caller was never authorized against.
- [ ] The server sets the owner and the tenant on create, because an object
      permission does not run there. Role-dependent writable fields are
      allow-listed, and `PATCH` is tested.
- [ ] Filters, ordering, and search run on requester-scoped querysets, and
      each one is allow-listed by field. Nothing is `"__all__"`. A sensitive
      collection uses cursor pagination, and does not expose a total count.
- [ ] `DEFAULT_PERMISSION_CLASSES` is restrictive. No view carries an
      accidental `AllowAny`.
- [ ] CSRF is correct for the authentication model. No login view is
      CSRF-exempt by accident.
- [ ] Throttles serve as quotas only, and the real abuse defense sits
      elsewhere. The throttle cache is shared, and is not `LocMemCache`.
      `NUM_PROXIES` matches the deployed proxy count, so the key is not a
      caller-supplied forwarded chain. A machine caller is keyed on identity,
      and not on IP. A costly call is capped by cost and concurrency as well
      as by rate. Any limit that must hold is an atomic `incr` on a Redis or
      Memcached alias, with a selected cache-outage branch, and not a
      read-modify-write.
- [ ] `BrowsableAPIRenderer` is absent from the production renderers, and not
      only ordered last. The schema, Swagger, and Redoc routes are
      authenticated or `DEBUG`-gated, unless the API is deliberately public.
- [ ] The schema view sets `SERVE_PERMISSIONS` and `SERVE_PUBLIC`, rather than
      taking the defaults. A public schema omits internal and admin
      operations, error internals, and the fields that only an elevated role
      receives. No operation depends on `extend_schema(exclude=True)` for its
      access control. The generated document is a CI artifact, diffed on
      upgrade and on release.
- [ ] The live URL map is enumerated, and diffed against the served schema.
      Every shadow, zombie, and orphan route is retired or protected.
- [ ] Every deprecated version emits `Deprecation` and `Sunset`, with a dated
      switch-off. It carries the same authorization as the current version.
      `DEFAULT_VERSION` and `ALLOWED_VERSIONS` are both set.
- [ ] Under `HostNameVersioning`, a wildcard DNS entry and a wildcard
      `ALLOWED_HOSTS` entry are each checked as version inputs. Under
      `NamespaceVersioning`, no stale `include()` keeps a retired version
      live. No route there resolves outside a namespace into
      `default_version`.
- [ ] Every bulk route authorizes every object, and defines its
      partial-failure semantics. No queryset-level bulk update or delete runs
      on an unscoped queryset.
- [ ] Payments resolve amounts server-side; webhook verifiers read
      `request.body` before `request.data`; no raw card storage.
- [ ] Any GraphQL schema or non-DRF framework in the same project was reviewed
      against `graphql-and-alternative-api-surfaces.md`; DRF defaults such as
      `DEFAULT_PERMISSION_CLASSES` do not apply to those surfaces.
