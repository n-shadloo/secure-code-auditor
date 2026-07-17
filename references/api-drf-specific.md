# API and DRF-Specific Concerns

Cross-cutting DRF material that spans several OWASP categories: serializer
exposure/mass assignment, pagination/filter leakage, throttling, default
auth/permission classes, CSRF interaction, and payment endpoints. Read alongside
A01 (authz), A02 (config/CORS), A06/A07 (rate limiting/auth),
`file-uploads.md`, and `async-and-channels.md` when those surfaces apply. Maps
to OWASP API Security Top 10:2023 broadly (API1 BOLA, API3 BOPLA, API4 resource
consumption, API8 misconfiguration).

## Contents
- [Serializer exposure and mass assignment (API3)](#serializer-exposure-and-mass-assignment-api3)
- [Pagination and filter leakage](#pagination-and-filter-leakage)
- [Default auth and permission classes](#default-auth-and-permission-classes)
- [CSRF and SessionAuthentication](#csrf-and-sessionauthentication)
- [Throttling as quota, not security (API4)](#throttling-as-quota-not-security-api4)
- [Inventory and versioning (API9)](#inventory-and-versioning-api9)
- [Payment endpoints](#payment-endpoints)
- [Review checklist](#review-checklist)

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

## Pagination and filter leakage

- `django-filter`: only expose intended fields (`filterset_fields`/an explicit
  `FilterSet`). Auto-generating filters over all fields can leak existence or
  allow enumeration by filtering on sensitive columns.
- Filtering/search must run on a queryset already scoped to the requester (A01),
  or filters become a cross-tenant read.
- Pagination shouldn't reveal counts or ids of objects the user can't access.

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

## Throttling as quota, not security (API4)

DRF throttles provide basic fair-use quotas and are **not** a brute-force or DoS
defense (see A06). Use them for quotas; use `django-axes` + edge limits for abuse
protection. Configure real limits where resource consumption matters (expensive
queries, exports, file processing). Upload endpoints also need hard edge,
per-file, aggregate, parser, and storage-quota controls from `file-uploads.md`.

## Inventory and versioning (API9)

- Retire or protect old API versions and debug/undocumented endpoints; "shadow"
  endpoints are attacked precisely because they're forgotten.
- Keep a clear map of exposed endpoints and their auth requirements.

## Payment endpoints

- **Never trust client-supplied amounts, prices, or currency.** Resolve the
  price/product server-side from your catalog (e.g. by product/price id), compute
  the charge on the server, and ignore any amount in the request body.
- Webhooks/callbacks: verify the signature on the raw body, enforce timestamp
  tolerance and idempotency, and reconcile against server records (full detail in
  A08).
- Never store raw card data; use the gateway's tokenization/hosted checkout to
  keep card data out of scope.

## Review checklist

- [ ] No `fields = "__all__"`; explicit fields; server-controlled fields
      read-only; passwords write-only.
- [ ] Filters/pagination run on requester-scoped querysets; no filter/enumeration
      leakage.
- [ ] `DEFAULT_PERMISSION_CLASSES` restrictive; no accidental `AllowAny`.
- [ ] CSRF correct for the auth model; login views not CSRF-exempt by accident.
- [ ] Throttles used as quotas only; real abuse defense elsewhere.
- [ ] Payments resolve amounts server-side; webhooks verified/idempotent; no raw
      card storage.
