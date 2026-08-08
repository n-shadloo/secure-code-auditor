# GraphQL and Alternative API Surfaces

Backend API surfaces where the client, not the route, decides the shape and the
cost of a request: GraphQL schemas served from Django, and non-DRF HTTP
frameworks such as Django Ninja whose defaults differ from DRF's. Covers
resolver-level authorization, schema and type over-exposure, document cost
limits, introspection and error leakage, mutation inputs and nested writes,
batching, persisted operations, and the framework defaults a DRF engineer will
assume are present and are not. Maps primarily to CWE-285, CWE-639, CWE-213,
CWE-770, CWE-915, CWE-799, CWE-306, and CWE-200; relevant OWASP categories
include A01:2025, A05:2025, A06:2025, and API1, API2, API3, and API4:2023.

The spine is unchanged. GraphQL is a transport and a query language, not a new
vulnerability class: every finding here is an existing category expressed
through a schema.

This file owns **the surface where the client composes the request** —
authorization at every resolved edge rather than at the route, document depth,
alias, token, and cost limits, schema and type over-exposure, and the defaults
of the non-DRF frameworks a DRF engineer will assume are present.
`a01-broken-access-control.md` owns the access-control failure itself,
`authorization-architecture.md` owns the field-level model,
`api-drf-specific.md` owns the serializer and throttling patterns generalised
here with the unit of measurement changed, `file-uploads.md` and
`async-and-channels.md` own uploads and subscriptions, and
`a03-software-supply-chain.md` owns the stale-library finding a
graphene-django install raises on its own weight.

## Contents
- [Principle](#principle)
- [Django implementation: choosing a stack](#django-implementation-choosing-a-stack)
- [Resolver authorization: a check at the root is not a check](#resolver-authorization-a-check-at-the-root-is-not-a-check)
- [Schema exposure and the all-fields type (BOPLA)](#schema-exposure-and-the-all-fields-type-bopla)
- [Bounding the document: depth, aliases, tokens, and cost](#bounding-the-document-depth-aliases-tokens-and-cost)
- [Introspection, field suggestions, and error masking](#introspection-field-suggestions-and-error-masking)
- [Mutations: allow-listed inputs and nested writes](#mutations-allow-listed-inputs-and-nested-writes)
- [Batching and throttling: the unit of measurement changes](#batching-and-throttling-the-unit-of-measurement-changes)
- [N+1 as a resource-exhaustion surface](#n1-as-a-resource-exhaustion-surface)
- [Persisted queries and operation allowlists](#persisted-queries-and-operation-allowlists)
- [CSRF and file uploads on a GraphQL endpoint](#csrf-and-file-uploads-on-a-graphql-endpoint)
- [Django Ninja: nothing is authenticated by default](#django-ninja-nothing-is-authenticated-by-default)
- [Out of backend scope](#out-of-backend-scope)
- [Review checklist](#review-checklist)

## Principle

In a REST API the server defines each response and the route is the unit of
authorization: one URL, one shape, one predictable cost. In GraphQL the client
composes the query against a schema, so a single endpoint answers an unbounded
set of documents, and neither the shape nor the cost of a request can be read
off the route.

Two consequences follow, and almost every GraphQL finding is one of them:

1. **Authorization belongs to every edge the client can traverse**, not to the
   entry point. A check at the query root is bypassed by nesting, because the
   client chooses what to walk to next.
2. **Cost must be bounded before execution.** The work a document will do is a
   property of the document, so it has to be computed and rejected during
   validation — before the first resolver runs and before a database
   connection is taken.

The invariant is: **authorization is a property of each resolved edge, cost is
a property of the document and is bounded before any resolver executes, and
the schema is public regardless of whether introspection is enabled.**

General defenses:

- Default-deny per resolver. The entry point authorizes reaching itself and
  nothing beyond it; every nested field re-derives its own scope from the
  authenticated principal.
- Order the pipeline so the cheap rejections come first: parse, then validate
  (depth, aliases, tokens, cost), then authenticate and authorize, then
  resolve. A request that reaches a database connection has already passed
  several cheap checks.
- Expose fields by allow-list. A schema type is a representation of a record,
  so representation over-exposure and mass assignment apply to it exactly as
  they apply to a serializer.
- Treat the schema as public. Disabling introspection is attack-surface
  reduction, not a control; never rely on schema secrecy to protect a field or
  an operation.
- Mask internal errors in production. Resolver errors are a leak channel that
  the equivalent REST error handler already closed.
- Meter by cost consumed per identity, not by request count, because one
  request is no longer one unit of work.
- For a first-party API, allow-list the operations you actually ship instead
  of accepting arbitrary documents.

## Django implementation: choosing a stack

**Package decision (4 Aug 2026):** the dispositions are recorded in
`security-hardening-libraries.md`, "GraphQL and alternative API surfaces".
Neither Django GraphQL library enforces any of the controls above by default;
both require them to be added explicitly.

- **Strawberry** (`strawberry-graphql` with `strawberry-graphql-django`) is the
  defensible choice for new work, at tier *conditional* and pinned to an exact
  version. It declares Django 5.2 and 6.0, ships the limiter extensions and
  field-level permission extensions this file uses, and its recent releases
  moved defaults toward secure ones.
- **graphene-django** is *existing-install audit only*. Its latest release is
  3.2.3 (13 Mar 2025) and its classifiers stop at Django 4.2 — it declares no
  support for Django 5.2 LTS or Django 6.0. Finding a graphene-django install
  on a supported Django line is a supply-chain finding in its own right, not
  merely a compatibility note; report it under
  `a03-software-supply-chain.md`, "Third-party dependency vetting".

Auditing an existing graphene-django deployment is a legitimate and common
task, so the graphene patterns below are given in full. Do not read their
presence as a recommendation to adopt it.

## Resolver authorization: a check at the root is not a check

### Principle layer

This is the highest-severity finding on the surface and the most
pattern-matchable. It is Broken Object Level Authorization reached through a
resolver graph rather than through a URL, so it maps to the same place as any
IDOR — `a01-broken-access-control.md`, "IDOR / BOLA" — and to API1:2023.

The failure: authentication or authorization is checked once, in the resolver
for the root field, and the nested resolvers below it return objects by
following relations. The client authenticates as anyone, enters at a field it
is allowed to reach, and walks to data it is not.

The fix is structural, not a matter of adding more checks in more places:
every type scopes its own queryset from the authenticated principal, so the
check runs again on each edge regardless of the path the client took to get
there. Maps to CWE-285 and CWE-639.

### Django & DRF implementation layer

```python
# Wrong: the only check is at the entry point, and the type exposes every
# field, so each reverse relation becomes a walkable edge with no check of
# its own.
class OrganizationType(DjangoObjectType):
    class Meta:
        model = Organization
        fields = "__all__"


class Query(graphene.ObjectType):
    organization = graphene.Field(OrganizationType, id=graphene.ID(required=True))

    def resolve_organization(self, info, id):
        if not info.context.user.is_authenticated:
            raise GraphQLError("authentication required")
        return Organization.objects.get(pk=id)
```

Any authenticated user submits `organization(id: <any id>) { members {
invoices { amount } } }`. The root check passes once, then `members` and
`invoices` resolve through unscoped relations to records belonging to another
organization entirely.

```python
# Correct: each type scopes its own queryset, so the authorization decision is
# re-derived at every edge instead of being inherited from the entry point.
class OrganizationType(DjangoObjectType):
    class Meta:
        model = Organization
        fields = ("id", "name", "members")

    @classmethod
    def get_queryset(cls, queryset, info):
        return queryset.filter(members=info.context.user)


class InvoiceType(DjangoObjectType):
    class Meta:
        model = Invoice
        fields = ("id", "amount", "issued_on")

    @classmethod
    def get_queryset(cls, queryset, info):
        # The nested edge needs its own scope. The parent type's scope does
        # not carry down to it.
        return queryset.filter(account__members=info.context.user)
```

Three graphene-django specifics decide whether this actually holds:

- `DjangoObjectType.get_queryset` is a no-op by default; it returns the
  queryset unchanged. Scoping exists only where a type overrides it.
- In 3.2.3, `get_queryset` **is** invoked on foreign-key and one-to-one
  traversal as well as on list fields, so overriding it does close the nested
  path — but only for types that override it.
- `graphene_django.utils.bypass_get_queryset` is a public decorator that sets
  `_bypass_get_queryset` on a resolver and makes the traversal skip
  `get_queryset` entirely. A resolver carrying it has silently opted out of
  every scope the type declares. Grep for it by name; each occurrence needs a
  written justification or it is a finding.

Under Strawberry the equivalent is a permission extension attached to the
field, so it applies wherever that field appears in the graph:

```python
# Correct (Strawberry): the permission travels with the field definition, so a
# nested selection is checked on the same terms as a root selection.
@strawberry_django.type(Organization, fields=["id", "name"])
class OrganizationType:
    invoices: list["InvoiceType"] = strawberry_django.field(
        extensions=[HasSourcePerm("billing.view_invoice")],
    )
```

The three object-level variants differ in what they check and when, and the
difference is auditable: `HasPerm` checks before the object is resolved,
`HasSourcePerm` checks against the object the field is defined on, and
`HasRetvalPerm` checks against the resolved return value. A field guarded only
by `IsAuthenticated` has a root-style check, not an object-level one.

Whichever library is in use, the permission model behind these checks is the
one in `authorization-architecture.md` — in particular "Object permissions are
a no-op by default", which applies unchanged, because `user.has_perm(perm,
obj)` behaves identically whether it is called from a resolver or a viewset.

## Schema exposure and the all-fields type (BOPLA)

The GraphQL analogue of serializer over-exposure is a type that publishes every
model field. It is the same finding as `api-drf-specific.md`, "Serializer
exposure and mass assignment (API3)", and the full read/write surface is in
`authorization-architecture.md`, "Field-level authorization (BOPLA)". Maps to
CWE-213 and API3:2023.

Detection is at the type, not the view:

- `fields = "__all__"` on a `DjangoObjectType`, or `fields="__all__"` on a
  `strawberry_django.type` — every column, including the ones added next
  quarter.
- A `DjangoObjectType` with `Meta.model` set and **neither** `fields` nor
  `exclude`. graphene-django 3.2.3 emits a `DeprecationWarning` and then
  exposes every field anyway. A warning in a log is not a control, and in
  production nobody reads it.
- Any `exclude` list. A deny-list fails open: the next migration adds a field
  and the schema publishes it.

The correct pattern is an explicit `fields` allow-list, and server-controlled
attributes must be absent from input types rather than merely absent from
output types.

## Bounding the document: depth, aliases, tokens, and cost

### Principle layer

Four limits, each defeating a different amplification, all applied as
validation rules that run before execution:

- **Depth** — rejects deeply nested documents, including cycles through
  mutually referencing types. Blunt: a shallow document can still be enormous.
- **Max aliases** — the same field requested many times under different
  aliases multiplies work without adding depth.
- **Max tokens** — bounds the size of the document itself, which bounds parse
  cost before anything else runs.
- **Cost budget** — the only one that measures the actual work. Assign a
  static cost per field, multiply list fields by their pagination argument,
  sum the tree, and reject over budget.

Depth limiting alone is not a cost control; it is the cheapest of the four and
the easiest to route around. A complexity limit that can be bypassed is not an
enforced one, so the limit needs a test that submits a document over budget
and asserts rejection, not merely a setting that exists. Maps to CWE-770 and
API4:2023.

An execution timeout is the backstop underneath all four, and it is the one
control that holds when a cost model is wrong.

### Django & DRF implementation layer

Neither library applies any of these by default, and neither ships true cost
analysis; both provide the hook.

- **Strawberry**: add `QueryDepthLimiter`, `MaxAliasesLimiter`, and
  `MaxTokensLimiter` to the schema's extensions, and supply a cost rule
  through `AddValidationRules`. Pass the extension **class or a factory, not a
  shared instance** — a single instance shared across concurrent requests
  carries execution context between them.
- **graphene**: `graphene.validation.depth_limit_validator` exists in the core
  package and is not wired into `GraphQLView`; pass it, and any cost rule you
  write, through the view's validation rules.

Confirm the limits in the code that constructs the schema and the view. A
limit named in documentation but absent from the schema definition is not
applied, and this is one of the few places where reading the settings file is
not enough.

The database-side backstop — statement timeouts and pool limits, so an
expensive document cannot hold connections indefinitely — is in
`data-layer-and-database.md`, "Connection exhaustion and query timeouts".

## Introspection, field suggestions, and error masking

Disable introspection and the GraphiQL or Playground interface in production:
graphene has `DisableIntrospection` in `graphene.validation`, Strawberry has a
`DisableIntrospection` extension, and the graphene view takes `graphiql=False`.

Then assume it did not work. GraphQL implementations return "did you mean"
field suggestions on a misspelled field, which lets a schema be reconstructed
from error messages alone, and a first-party front end ships the schema in its
own traffic regardless. **Never rely on schema secrecy** — an operation that is
safe only because it is hard to discover is an unauthorized operation with a
delay in front of it.

Production error masking is the related and more valuable control. An
unmasked resolver exception returns the exception string to the client, which
routinely carries model and column names, file paths, and SQL fragments.
Strawberry provides a `MaskErrors` extension; graphene requires a formatter
that replaces messages for non-allowlisted exception types. The underlying
rules are unchanged: `a10-exceptional-conditions.md`, "Don't leak on error",
and `a09-logging-and-alerting.md`, "Scrub error reports" — log the detail
server-side, return an opaque reference to the client. Maps to CWE-200 and
A05:2025.

## Mutations: allow-listed inputs and nested writes

A mutation input type mapped one-to-one onto a model and splatted into
`objects.create()` is mass assignment with a schema in front of it. Maps to
CWE-915 and API3:2023.

```python
# Wrong: every model field is writable through the input type, including the
# ones that decide privilege and ownership.
def mutate(self, info, input):
    return Project.objects.create(**input)
```

```python
# Correct: writable fields are an allow-list, ownership is set from the
# authenticated principal rather than accepted from the client, and the
# nested write is authorized on its own terms rather than inheriting the
# parent's decision.
def mutate(self, info, input):
    user = info.context.user
    project = Project.objects.create(
        name=input.name,
        description=input.description,
        owner=user,
    )
    for member_id in input.member_ids:
        # Adding a member to a project is a second authorization decision,
        # not a side effect of being allowed to create the project.
        membership = get_membership_or_deny(user, member_id)
        project.members.add(membership.user)
    return project
```

Two rules, both surface-independent: an input type is an allow-list of
writable fields, and every nested write inside a mutation is authorized
individually. A mutation that creates a parent and attaches children performs
one authorization decision per object, not one for the operation.

## Batching and throttling: the unit of measurement changes

The principle from `api-drf-specific.md`, "Throttling as quota, not security
(API4)", is unchanged: a throttle is a quota, not an abuse defense. What
changes is the unit. A request-count throttle sees one request where the
document contained hundreds of aliased operations, and an edge proxy or WAF
counting HTTP requests sees the same one. This is how batching is used to
brute-force credentials through a login mutation that is "rate limited" — maps
to CWE-799.

- Bound or disable array batching if the client does not use it. An
  unbounded batch endpoint multiplies every other limit by the batch size.
- Count aliases and operations toward the same budget as the rest of the
  document, before execution.
- Meter cost consumed per identity per window, not requests. The cost and
  concurrency pattern is in `agent-and-llm-interfaces.md`, "Cost and
  concurrency limits, not only request rate"; the abuse-design side is in
  `a06-insecure-design.md`, "Rate limiting and anti-automation".
- Authentication-bearing mutations need the same lockout and anti-automation
  controls as a REST login route, keyed on the account, and they need them
  applied per operation inside the document rather than per HTTP request.

## N+1 as a resource-exhaustion surface

In REST, an N+1 query pattern is a performance defect. In GraphQL it is also
an availability control, because the client chooses N: a nested list selection
turns one document into thousands of queries, exhausting the connection pool
for every other caller.

Prefer the built-in optimizer over adding a dependency. Strawberry ships
`DjangoOptimizerExtension`, which resolves the common cases into
`select_related`/`prefetch_related`; graphene-django has no equivalent
built in and needs a dataloader or an optimizer package. Either way, verify
against query counts under a realistic nested document rather than trusting
that the optimizer engaged. The pool-side consequence and its limits are in
`data-layer-and-database.md`, "Connection exhaustion and query timeouts".

## Persisted queries and operation allowlists

Where the API serves only first-party clients — which is most Django GraphQL
deployments — the strongest available control is to stop accepting arbitrary
documents. Register the operations the application actually ships, key them by
hash, and have clients send the hash. Every unregistered document is then
rejected before parsing, which collapses depth, alias, cost, and introspection
into a single decision made at build time.

Two cautions. An automatic-persisted-query implementation that registers
whatever a client sends on first use is a cache, not an allowlist, and
provides none of this. And an allowlisted operation is still an operation:
authorization and input validation run exactly as before, and an allowlisted
upload mutation still needs full upload validation.

Django has no first-party library for this; it is normally implemented at the
gateway or with a small server-side registry. Treat its absence on a
first-party-only API as a hardening finding, not a defect.

## CSRF and file uploads on a GraphQL endpoint

**CSRF.** If the endpoint authenticates with cookies, it must not be
CSRF-exempt. graphene-django's documented setup wraps `GraphQLView` in
`csrf_exempt`, which removes CSRF protection from every cookie-authenticated
mutation on that endpoint — the most common way this fails is that the exempt
wrapper was copied from documentation written for token auth. Strawberry's
Django view is CSRF-protected as of release 0.243.0, which fixed
CVE-2024-47082 (GHSA-79gp-q4wv-33fr); on that library the audit question is
whether the secure default has been re-disabled. The underlying rules are in
`api-drf-specific.md`, "CSRF and SessionAuthentication".

**Uploads.** File uploads over the GraphQL multipart request specification
carry every risk in `file-uploads.md` unchanged — content-type validation,
storage keys, inert serving, SVG and other active content, and size and count
limits. Strawberry disables multipart uploads by default
(`multipart_uploads_enabled = False`); if a view enables them, the endpoint
needs the whole of `file-uploads.md`, "Type and content validation", applied
to it.

**Subscriptions** run over a WebSocket and are owned by
`async-and-channels.md`: origin checks, per-connection authentication, per-
message authorization, and backpressure apply to a subscription exactly as to
any other socket.

## Django Ninja: nothing is authenticated by default

Django Ninja is the most likely non-DRF surface in a Django codebase, and its
defaults differ from DRF's in the direction that matters. Maps to CWE-306 and
API2:2023.

**An operation is public unless `auth=` is set.** There is no equivalent of
`DEFAULT_PERMISSION_CLASSES` — no project-wide default that a route inherits.
A DRF engineer who has internalized "the default is `IsAuthenticated` and I
override it upward" will read an un-annotated route as protected. It is not.

```python
# Wrong: no auth argument anywhere, so every operation on this router is
# public regardless of what the project's DRF settings say.
api = NinjaAPI()

@api.get("/invoices/{invoice_id}")
def get_invoice(request, invoice_id: int):
    return Invoice.objects.get(pk=invoice_id)
```

```python
# Correct: authentication set once at the API object so it applies to every
# operation, and the queryset scoped to the caller rather than looked up by
# raw id.
api = NinjaAPI(auth=JWTAuth())

@api.get("/invoices/{invoice_id}")
def get_invoice(request, invoice_id: int):
    return get_object_or_404(
        Invoice.objects.filter(account=request.auth.account), pk=invoice_id
    )
```

Set `auth=` on the `NinjaAPI` object so it is inherited, and treat a route
that overrides it to `None` as a deliberate, reviewed exception. Route-level
`auth=` scattered across a codebase is a deny-list.

Three more Ninja-specific checks:

- Authentication is not authorization. A resolved `request.auth` says who is
  calling, and nothing about which object they may reach; scope the queryset
  as in `a01-broken-access-control.md`.
- CSRF is off by default, which is correct for token and bearer auth and wrong
  the moment `django_auth` (session cookies) is used. Enable it explicitly on
  cookie-authenticated operations.
- `django-ninja-jwt` defaults its `SIGNING_KEY` to Django's `SECRET_KEY`,
  which couples token forgery to every other use of that key and makes
  rotation an all-or-nothing event. Set an independent signing key; see
  `service-identity-and-secrets.md`, "Rotating Django's SECRET_KEY".

Ninja's input validation is a genuine strength — Pydantic models validate
request bodies by type — and it is easy to mistake that for a security posture
it does not provide. Validated input is still unauthorized input.

Ninja routes must appear as their own rows in the URLconf audit test in
`authorization-architecture.md`, "Default-deny architecture". They are not
DRF views and will not be caught by a DRF-shaped audit.

## Out of backend scope

Mirroring `00-methodology-and-severity.md`, "What to exclude" — do not search
backend code for these, and do not report their absence as a backend finding:

- client-side query construction, front-end caching, and whether the browser
  over-fetches;
- federation and gateway topology, except where this Django application is
  itself one subgraph, in which case it is ordinary API security and
  everything above applies;
- schema design quality, naming, and deprecation hygiene, which are API-design
  concerns rather than security ones;
- gRPC transport and service-mesh configuration. Where a Django application
  serves gRPC, the authorization, input-validation, and limit rules in this
  file apply unchanged to its handlers; the transport and mesh belong to
  `deployment-and-runtime.md` and `service-identity-and-secrets.md`.

## Review checklist

### Stack-neutral

- [ ] Authorization is enforced on every resolved edge, not once at the query
      root; a nested selection reaching another tenant's records is tested for
      explicitly.
- [ ] Types expose an explicit field allow-list; no all-fields type and no
      deny-list `exclude`.
- [ ] Depth, alias, token, and cost limits are all applied as validation rules
      that run before execution, and a document over budget is tested and
      rejected.
- [ ] An execution or wall-clock timeout exists underneath the limits.
- [ ] Array batching is bounded or disabled, and aliases and operations count
      toward the document budget.
- [ ] Rate limiting meters cost per identity, not HTTP requests; mutations
      that authenticate carry the same anti-automation controls as a login
      route, applied per operation.
- [ ] Introspection and the in-browser query interface are disabled in
      production, and nothing depends on the schema being secret.
- [ ] Production errors are masked; no exception strings, SQL, model names, or
      file paths reach the client.
- [ ] Mutation inputs are allow-lists, ownership is set server-side, and each
      nested write is authorized on its own terms.
- [ ] N+1 is mitigated and verified by query count under a nested document.
- [ ] For a first-party-only API, operations are allowlisted or persisted, and
      the mechanism is not a register-on-first-use cache.
- [ ] Cookie-authenticated endpoints are not CSRF-exempt.

### Django & DRF

- [ ] Every `DjangoObjectType` that is reachable overrides `get_queryset` and
      scopes from `info.context.user`; the default implementation returns the
      queryset unchanged.
- [ ] No resolver carries `graphene_django.utils.bypass_get_queryset` without
      a written justification — it disables type-level scoping on foreign-key
      and one-to-one traversal.
- [ ] No `DjangoObjectType` has `Meta.model` set with neither `fields` nor
      `exclude`; graphene-django only warns and then exposes every field.
- [ ] Strawberry limiter extensions are passed as classes or factories, never
      as shared instances.
- [ ] Strawberry field permissions distinguish object-level checks
      (`HasSourcePerm`, `HasRetvalPerm`) from the root-style `IsAuthenticated`.
- [ ] Strawberry's `multipart_uploads_enabled` and CSRF protection have not
      been re-disabled; uploads that are enabled meet `file-uploads.md` in full.
- [ ] graphene's `GraphQLView` is not blanket-wrapped in `csrf_exempt` on a
      cookie-authenticated deployment, and `graphiql=False` in production.
- [ ] graphene-django's Django compatibility is checked against the deployed
      Django: 3.2.3 declares support only through Django 4.2, so an install on
      5.2 or 6.0 is a supply-chain finding.
- [ ] Every Django Ninja `NinjaAPI`, router, and route has an explicit `auth=`,
      and any `auth=None` override is a reviewed exception.
- [ ] Ninja routes appear as their own rows in the URLconf audit test.
- [ ] `django-ninja-jwt`'s `SIGNING_KEY` is independent of `SECRET_KEY`.
- [ ] Subscriptions meet the origin, authentication, authorization, and
      backpressure requirements in `async-and-channels.md`.
