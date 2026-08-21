# GraphQL and Alternative API Surfaces

Covers the backend API surfaces that are not DRF routes. Covers a GraphQL
schema served from Django, where the client rather than the route decides the
shape and the cost of a request. Covers a non-DRF HTTP framework such as
Django Ninja, whose defaults differ from the DRF defaults. Covers a gRPC
servicer, which answers on a second server that the Django request cycle never
enters.

Covers resolver-level authorization, and schema and type over-exposure. Covers
document cost limits, and introspection and error leakage. Covers mutation
inputs and nested writes, batching, and persisted operations. Covers protobuf
message and recursion limits. Covers the framework defaults that a DRF
engineer assumes are present and that are absent.

Maps primarily to CWE-285, CWE-639, CWE-213, CWE-770, CWE-915, CWE-799, and
CWE-306. The relevant OWASP categories include A01:2025, A05:2025, and
A06:2025. They also include API1, API2, API3, and API4:2023.

The spine is unchanged. GraphQL is a transport and a query language, and not a
new vulnerability class. Every finding here is an existing category expressed
through a schema.

This file owns **the surface where the client composes the request**. That
means authorization at every resolved edge rather than at the route. It also
means document depth, alias, token, and cost limits, and schema and type
over-exposure.

This file also owns **the API surface that is not a DRF route at all**. That
surface is the defaults of the non-DRF frameworks and transports that a DRF
engineer assumes are present. It reaches from a Django Ninja route to a gRPC
servicer on a second server.

`a01-broken-access-control.md` owns the access-control failure itself.
`authorization-architecture.md` owns the field-level model.
`api-drf-specific.md` owns the serializer and throttling patterns, which this
file generalizes with a different unit of measurement. `file-uploads.md` and
`async-and-channels.md` own uploads and subscriptions.
`a03-software-supply-chain.md` owns the stale-library finding that a
graphene-django install raises on its own.

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
- [gRPC: nothing from the DRF request cycle applies](#grpc-nothing-from-the-drf-request-cycle-applies)
- [Out of backend scope](#out-of-backend-scope)
- [Review checklist](#review-checklist)

## Principle

In a REST API the server defines each response, and the route is the unit of
authorization. One URL gives one shape and one predictable cost. In GraphQL
the client composes the query against a schema. A single endpoint therefore
answers an unbounded set of documents. Neither the shape nor the cost of a
request is visible from the route.

Two consequences follow, and almost every GraphQL finding is one of them:

1. **Authorization belongs to every edge the client can traverse**, not to the
   entry point. A check at the query root is bypassed by nesting, because the
   client chooses what to walk to next.
2. **Cost must be bounded before execution.** The work of a document is a
   property of that document. Compute it during validation, and reject the
   document there. Do that before the first resolver runs, and before the code
   takes a database connection.

One invariant applies. **Authorization is a property of each resolved edge.
Cost is a property of the document, and a bound applies before any resolver
executes. The schema is public, whether or not introspection is enabled.**

General defenses:

- Default-deny per resolver. The entry point authorizes access to itself, and
  to nothing beyond it. Every nested field derives its own scope again from
  the authenticated principal.
- Order the pipeline so that the cheap rejections come first. Parse first.
  Then validate the depth, the aliases, the tokens, and the cost. Then
  authenticate and authorize. Then resolve. A request that reaches a database
  connection has already passed several cheap checks.
- Expose fields by allow-list. A schema type is a representation of a record.
  Representation over-exposure and mass assignment therefore apply to it
  exactly as they apply to a serializer.
- Treat the schema as public. A disabled introspection reduces the attack
  surface, and is not a control. Never depend on schema secrecy to protect a
  field or an operation.
- Mask internal errors in production. Resolver errors are a leak channel that
  the equivalent REST error handler already closed.
- Meter by cost consumed per identity, not by request count, because one
  request is no longer one unit of work.
- For a first-party API, allow-list the operations that you ship. Do not
  accept an arbitrary document.

## Django implementation: choosing a stack

**Package decision (4 Aug 2026):** the dispositions are recorded in
`security-hardening-libraries.md`, "GraphQL and alternative API surfaces".
Neither Django GraphQL library enforces any of the controls above by default.
Both need you to add those controls explicitly.

- **Strawberry** is the defensible choice for new work. Use
  `strawberry-graphql` with `strawberry-graphql-django`, at tier
  *conditional*, and pin it to an exact version. It declares Django 5.2 and
  6.0. It ships the limiter extensions and the field-level permission
  extensions that this file uses. Its recent releases also moved the defaults
  toward secure ones.
- **graphene-django** is *existing-install audit only*. Its latest release is
  3.2.3, of 13 Mar 2025. Its classifiers stop at Django 4.2. It declares no
  support for Django 5.2 LTS or Django 6.0. A graphene-django install on a
  supported Django line is a supply-chain finding in its own right. It is not
  only a compatibility note. Report it under `a03-software-supply-chain.md`,
  "Third-party dependency vetting".

Auditing an existing graphene-django deployment is a legitimate and common
task, so the graphene patterns below are given in full. Do not read their
presence as a recommendation to adopt it.

## Resolver authorization: a check at the root is not a check

### Principle layer

This is the highest-severity finding on the surface and the most
pattern-matchable. It is Broken Object Level Authorization reached through a
resolver graph, and not through a URL. It therefore maps to the same place as
any IDOR, which is `a01-broken-access-control.md`, "IDOR / BOLA". It also maps
to API1:2023.

The failure has one shape. The code checks authentication or authorization one
time, in the resolver for the root field. The nested resolvers below it then
return objects when they follow relations. The client authenticates as anyone,
enters at a field it is allowed to reach, and walks to data it is not.

The fix is structural. It is not more checks in more places. Every type scopes
its own queryset from the authenticated principal. The check therefore runs
again on each edge, whatever path the client took to reach it. Maps to CWE-285
and CWE-639.

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
- In 3.2.3, graphene **does** invoke `get_queryset` on a foreign-key traversal
  and a one-to-one traversal, as well as on a list field. An override
  therefore closes the nested path. It closes that path only for a type that
  overrides it.
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

The three object-level variants differ in what they check and when they check
it, and a reviewer can audit the difference. `HasPerm` checks before
resolution of the object. `HasSourcePerm` checks against the object that
carries the field definition. `HasRetvalPerm` checks against the resolved
return value. A field guarded only by `IsAuthenticated` has a root-style
check, not an object-level one.

The permission model behind these checks is the one in
`authorization-architecture.md`, for either library. "Object permissions are a
no-op by default" applies unchanged there. `user.has_perm(perm, obj)` behaves
identically from a resolver and from a viewset.

**Write-time.** When you generate a type or a resolver, override
`get_queryset` on every type that reaches an object. Scope it to
`info.context.user`. Do not authorize the entry point and then trust the edges
below it. The default implementation returns the queryset unchanged, and the
client chooses the nested selection.

Enumerate `fields` on the type in that same edit. Use an allow-list. Never use
`exclude`, and never use `"__all__"`. A deny-list publishes whatever the next
migration adds.

Wire the depth, alias, token, and cost rules onto the schema and the view as
you construct them. Neither library applies one by default. A limit that
exists only in the documentation is not applied.

## Schema exposure and the all-fields type (BOPLA)

The GraphQL analog of serializer over-exposure is a type that publishes every
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
the easiest to route around. A complexity limit that something can bypass is
not an enforced limit. The limit therefore needs a test. That test submits a
document over budget and asserts a rejection. A setting that exists is not
enough. Maps to CWE-770 and API4:2023.

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
  package, and nothing wires it into `GraphQLView`. Pass it through the
  validation rules of the view. Pass any cost rule that you write the same
  way.

The cost rule is the one you have to write, and it is the same object in both
stacks because both execute on graphql-core. Give each field a static cost.
Multiply by the pagination argument at the level where it appears. Sum over
the tree. Run the rule as a validation rule, so that the rejection happens
before any resolver runs.

```python
# Correct: a static per-field cost multiplied by the pagination argument at
# each level, summed over the tree, and rejected before execution.
from graphql import GraphQLError
from graphql.language import FieldNode, FragmentSpreadNode, IntValueNode
from graphql.validation import ASTValidationRule

MAX_COST = 1000
FIELD_COST = {"search": 50}      # anything unlisted costs 1
PAGE_ARGUMENTS = ("first", "last", "limit")
ASSUMED_PAGE_SIZE = 100          # when the size arrives in a variable


def page_multiplier(field):
    for argument in field.arguments:
        if argument.name.value in PAGE_ARGUMENTS:
            if isinstance(argument.value, IntValueNode):
                return int(argument.value.value)
            return ASSUMED_PAGE_SIZE
    return 1


class CostLimitRule(ASTValidationRule):
    def enter_operation_definition(self, node, *_args):
        cost = self.cost_of(node.selection_set, 1)
        if cost > MAX_COST:
            self.report_error(GraphQLError(
                f"Operation cost {cost} exceeds the limit {MAX_COST}.", node
            ))

    def cost_of(self, selection_set, multiplier):
        total = 0
        for selection in selection_set.selections:
            if isinstance(selection, FragmentSpreadNode):
                # An unfollowed spread is a free bypass of the budget.
                fragment = self.context.get_fragment(selection.name.value)
                if fragment is not None:
                    total += self.cost_of(fragment.selection_set, multiplier)
                continue
            factor = multiplier
            if isinstance(selection, FieldNode):
                factor *= page_multiplier(selection)
                total += FIELD_COST.get(selection.name.value, 1) * factor
            if selection.selection_set is not None:
                total += self.cost_of(selection.selection_set, factor)
        return total
```

Three details decide whether a rule of this shape is worth anything. The
multiplier must **compound down the tree**, and must not apply per field.
`authors(first: 100) { books(first: 100) { ... } }` is ten thousand objects,
and not two hundred.

A **fragment spread that is not followed is a complete bypass**. A caller
moves the expensive selection into a fragment, and the budget then reads as
zero. The rule therefore resolves a spread through the validation context, and
does not skip a non-field selection.

A page size that arrives **in a variable is not in the AST**. The rule must
therefore assume a ceiling, and must not fall through to a multiplier of one.
Validation runs before the coercion of the variables. The assumed value should
therefore be the maximum that the paginator serves.

Strawberry takes such a rule through `AddValidationRules`. Supply it as a
factory rather than a shared instance, for the reason above. graphene takes it
in the `validation_rules` argument to `GraphQLView`. That is the same argument
that its `depth_limit_validator` uses.

Confirm the limits in the code that constructs the schema and the view. A
limit named in documentation and absent from the schema definition is not
applied. This is one of the few places where the settings file alone is not
enough.

`data-layer-and-database.md`, "Connection exhaustion and query timeouts" holds
the database-side backstop. That is statement timeouts and pool limits, so an
expensive document cannot hold connections indefinitely. The four limits here
are the instance of a wider rule on this surface. That rule is that every
caller-controlled value which multiplies work carries a server-enforced
ceiling. `a06-insecure-design.md`, "Algorithmic resource exhaustion" states it.

## Introspection, field suggestions, and error masking

Disable introspection in production. Disable the GraphiQL or Playground
interface there too. graphene has `DisableIntrospection` in
`graphene.validation`. Strawberry has a `DisableIntrospection` extension. The
graphene view also takes `graphiql=False`.

Then assume it did not work. A GraphQL implementation returns a "did you mean"
field suggestion on a misspelled field. A caller can rebuild a schema from
those error messages alone. A first-party front end also ships the schema in
its own traffic. **Never rely on schema secrecy.** An operation that is safe
only because it is hard to discover is an unauthorized operation with a delay
in front of it.

Production error masking is the related and more valuable control. An unmasked
resolver exception returns the exception string to the client, which routinely
carries model and column names, file paths, and SQL fragments.

Strawberry provides a `MaskErrors` extension; graphene requires a formatter
that replaces messages for non-allowlisted exception types. The rules
underneath are unchanged. `a10-exceptional-conditions.md`, "Don't leak on
error" and `a09-logging-and-alerting.md`, "Scrub error reports" own them. Log
the detail server-side. Return an opaque reference to the client. Maps to
CWE-209 and A05:2025.

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
document held hundreds of aliased operations. An edge proxy or WAF that counts
HTTP requests sees the same one request. This is how batching is used to
brute-force credentials through a login mutation that is "rate limited" — maps
to CWE-799.

- Bound or disable array batching if the client does not use it. An unbounded
  batch endpoint multiplies every other limit by the batch size.
- Count aliases and operations toward the same budget as the rest of the
  document, before execution.
- Meter cost consumed per identity per window, not requests.
  `agent-and-llm-interfaces.md`, "Cost and concurrency limits, not only
  request rate" holds the cost and concurrency pattern.
  `a06-insecure-design.md`, "Rate limiting and anti-automation" holds the
  abuse-design side.
- An authentication-bearing mutation needs the same lockout and
  anti-automation controls as a REST login route. Key those controls on the
  account. Apply them per operation inside the document, and not per HTTP
  request.

## N+1 as a resource-exhaustion surface

In REST, an N+1 query pattern is a performance defect. In GraphQL it is also
an availability control, because the client chooses N. A nested list selection
makes one document into thousands of queries. That exhausts the connection
pool for every other caller.

Prefer the built-in optimizer over adding a dependency. Strawberry ships
`DjangoOptimizerExtension`, which resolves the common cases into
`select_related`/`prefetch_related`; graphene-django has no equivalent
built in and needs a dataloader or an optimizer package. Either way, verify
against query counts under a realistic nested document rather than trusting
that the optimizer engaged. The pool-side consequence and its limits are in
`data-layer-and-database.md`, "Connection exhaustion and query timeouts".

This file owns the finding when an unbounded query becomes a
denial-of-service surface or a scope bypass. Query count, batching, and plan
work are outside its scope.

## Persisted queries and operation allowlists

Where the API serves only first-party clients — which is most Django GraphQL
deployments — the strongest available control is to stop accepting arbitrary
documents. Register the operations the application actually ships, key them by
hash, and have clients send the hash. Every unregistered document is then
rejected before parsing, which collapses depth, alias, cost, and introspection
into a single decision made at build time.

Two cautions. An automatic-persisted-query implementation that registers
whatever a client sends on first use is a cache, not an allowlist, and
provides none of this. An allowlisted operation is still an operation.
Authorization and input validation run exactly as before. An allowlisted
upload mutation also still needs full upload validation.

Django has no first-party library for this; it is normally implemented at the
gateway or with a small server-side registry. Treat its absence on a
first-party-only API as a hardening finding, not a defect.

The registry is the whole control, and it is small enough that the shape is
worth stating exactly.

```python
# Correct: the client sends an id, and the server answers only from the
# registry the build produced, so an unregistered document is refused
# before anything parses it.
import hashlib
import json
from pathlib import Path

from django.core.exceptions import PermissionDenied

REGISTRY_PATH = Path("/srv/app/build/persisted-operations.json")


def load_registry(path):
    """Registration is out of band: the client build emits the operations it
    ships and this process only ever reads that artifact."""
    return {
        hashlib.sha256(document.encode("utf-8")).hexdigest(): document
        for document in json.loads(path.read_text())
    }


REGISTRY = load_registry(REGISTRY_PATH)


def resolve_document(body):
    """`body` is the decoded JSON request body. Nothing here writes to
    REGISTRY: an implementation that registers whatever a client sends on
    first use is a cache, not an allowlist, and gates nothing."""
    if "query" in body:
        raise PermissionDenied("This endpoint accepts operation ids only.")
    document = REGISTRY.get(body.get("operationId"))
    if document is None:
        raise PermissionDenied("Unregistered operation.")
    return document
```

Two properties are what make it a gate rather than a cache. The registry is
**loaded, never written**. A request path that can add an entry makes the
allowlist accept every document a client sends. That is the
automatic-persisted-query behavior above, and it is the most frequent way to
build this control wrong.

A request that carries a `query` key is **refused rather than executed**. An
endpoint that falls back to the arbitrary document when the id is absent has
an allowlist that any client can leave. Hook it where the view decodes the
body, and before the view hands a document to the schema. That place is
`GraphQLView.parse_body` in graphene, or the Django view in Strawberry. It is
the gateway where one sits in front.

Everything downstream is unchanged. An allowlisted operation still runs its
own resolver authorization, and still validates its inputs. Where it takes an
upload, it still needs the full upload validation below.

## CSRF and file uploads on a GraphQL endpoint

**CSRF.** Where the endpoint authenticates with a cookie, it must not be
CSRF-exempt. The documented graphene-django setup wraps `GraphQLView` in
`csrf_exempt`. That removes CSRF protection from every cookie-authenticated
mutation on that endpoint. This most often fails because somebody copied the
exempt wrapper from documentation written for token authentication.

The Strawberry Django view is CSRF-protected as of release 0.243.0. That
release fixed CVE-2024-47082, which is GHSA-79gp-q4wv-33fr. On that library
the audit question is whether somebody disabled the secure default again. The
underlying rules are in `api-drf-specific.md`, "CSRF and
SessionAuthentication".

**Uploads.** A file upload over the GraphQL multipart request specification
carries every risk in `file-uploads.md` unchanged. Those risks are
content-type validation, storage keys, and inert serving. They also are SVG
and other active content, and size and count limits. Strawberry disables
multipart uploads by default, with `multipart_uploads_enabled = False`. Where
a view enables them, apply the whole of `file-uploads.md`, "Type and content
validation" to that endpoint.

**Subscriptions** run over a WebSocket. `async-and-channels.md`,
"Subscriptions as long-lived queries" owns them. That section maps origin
checks, per-connection authentication, and per-message authorization onto the
subscribe and publish paths. It maps revocation and limits onto them as well.
This file keeps the schema, the resolver, and the document limits.

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

The input validation of Ninja is a genuine strength, because a Pydantic model
validates a request body by type. A reader easily mistakes that for a security
posture that Ninja does not provide. Validated input is still unauthorized
input.

Ninja routes must appear as their own rows in the URLconf audit test in
`authorization-architecture.md`, "Default-deny architecture". They are not
DRF views and will not be caught by a DRF-shaped audit.

**Write-time.** When you generate a Django Ninja route, set `auth=` on the
`NinjaAPI` object in the edit that creates it. Treat an operation that
overrides it to `None` as an exception that you must justify. There is no
project-wide default to inherit. An un-annotated operation is public from the
moment of its routing.

Scope the queryset to `request.auth` at the same time. Authentication resolves
who is calling, and decides nothing about which object they may reach. Enable
CSRF explicitly on any operation that authenticates from a session cookie.
CSRF is off by default there, and that default is correct only for a bearer
credential.

## gRPC: nothing from the DRF request cycle applies

A Django project that serves gRPC runs a second server on a second port. That
server speaks HTTP/2 with protobuf message bodies. The Django request cycle is
not in the path.

No middleware runs, no `DEFAULT_AUTHENTICATION_CLASSES` or
`DEFAULT_PERMISSION_CLASSES` are consulted, no throttle class applies, no CSRF
check happens, and `ALLOWED_HOSTS` decides nothing. The servicer imports the
same models, and often reuses the same serializers. That is exactly why the
surface reads as covered. The business logic is shared, and every control
around it is not. Each control is re-earned here or it does not exist. Maps to
CWE-306 and API2:2023.

Like a Django Ninja route, a gRPC method is not a URLconf entry and will not
appear in the audit test in `authorization-architecture.md`, "Default-deny
architecture". Inventory the surface from the `.proto` service definitions and
the servicers registered on the server, and carry each method as its own row.

**A server with no interceptor serves everyone.** `grpc.server(...)` applies
no authentication of its own. Every method on every registered servicer
answers any caller that can open a connection. `add_insecure_port` also gives
out a connection with no transport identity.

There is no project-wide default-deny to inherit. The library has nothing
analogous to `DEFAULT_PERMISSION_CLASSES`. The interceptor list is therefore
the whole of the enforcement. That list is empty until somebody fills it.

```python
# Wrong: no interceptor and an insecure port, so every method on every
# registered servicer answers any caller that can reach the port.
from concurrent import futures

import grpc

import billing_pb2_grpc

server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
billing_pb2_grpc.add_BillingServicer_to_server(Billing(), server)
server.add_insecure_port("[::]:50051")
server.start()
```

```python
# Correct: an authenticating interceptor runs before any handler and refuses
# rather than annotating, the port carries server and client certificates,
# and the three limits that are unbounded or generous by default are set.
from concurrent import futures

import grpc
from django.conf import settings

import billing_pb2_grpc


class ServiceTokenInterceptor(grpc.ServerInterceptor):
    def __init__(self):
        self._deny = grpc.unary_unary_rpc_method_handler(
            lambda request, context: context.abort(
                grpc.StatusCode.UNAUTHENTICATED, "Invalid credentials"
            )
        )

    def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata)
        if verify_service_token(metadata.get("authorization", "")) is None:
            return self._deny
        return continuation(handler_call_details)


credentials = grpc.ssl_server_credentials(
    [(settings.GRPC_PRIVATE_KEY, settings.GRPC_CERTIFICATE_CHAIN)],
    root_certificates=settings.GRPC_CLIENT_CA,
    require_client_auth=True,
)

server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=[ServiceTokenInterceptor()],
    options=[
        ("grpc.max_receive_message_length", 1 * 1024 * 1024),
        ("grpc.max_send_message_length", 4 * 1024 * 1024),
    ],
    maximum_concurrent_rpcs=100,
)
billing_pb2_grpc.add_BillingServicer_to_server(Billing(), server)
server.add_secure_port("[::]:50051", credentials)
server.start()
```

Three things about that shape are the review rather than the example.

- **Interceptors are given control in the order they are specified**, per
  `grpc.server`'s own documentation, so the first in the list is outermost. An
  authenticating interceptor placed after one that logs, unpacks, or meters
  the request has already let unauthenticated work happen.
- **Establishing who is calling is not deciding what they may call.** An
  interceptor that admits every caller with a valid token is the gRPC form of
  a check at the query root. That is why `PERMISSION_DENIED`, which is code 7,
  is a different answer from `UNAUTHENTICATED`, which is code 16. Decide per
  method and inside the handler which methods this principal may invoke.
  Decide there also which objects it may reach through them. Use the
  scoped-queryset terms in `a01-broken-access-control.md`, "IDOR / BOLA". An
  interceptor that authorizes by service name lets every method on that
  service through.
- **Transport identity is not application authorization either.** Mutual TLS
  through `ssl_server_credentials(..., require_client_auth=True)` and a
  metadata bearer token are two mechanisms. They match a proxy-verified client
  certificate and an `Authorization` header on an HTTP service.
  `service-identity-and-secrets.md`, "Validating an inbound machine token"
  holds the rules for both, and what to validate in the token.

**django-socio-grpc inherits the open default and adds to it.** These facts
come from the 0.25.0 distribution on 9 Aug 2026. Its `GRPC_FRAMEWORK` settings
ship `DEFAULT_AUTHENTICATION_CLASSES` and `DEFAULT_PERMISSION_CLASSES` as
empty lists. They ship `SERVER_INTERCEPTORS` and `SERVER_OPTIONS` as `None`.
They ship `REQUIRE_CLIENT_AUTH` as `False`.

An empty permission list is not a deny. The permission check of the service
iterates that list and falls through. A service written against the DRF-shaped
base classes is therefore public, in the way an `AllowAny` viewset is. It
lacks the visual signal, because no permission class is written down for a
reviewer to read as wrong. `SERVER_OPTIONS` at `None` means the package sets
no message-size limits either, so the grpcio defaults below are what the
deployment gets. Its disposition is in `security-hardening-libraries.md`,
"GraphQL and alternative API surfaces".

**Two of the three size and concurrency limits are unbounded by default.** The
values below were read from grpcio 1.83.0 and protobuf 7.35.1 on 9 Aug 2026.

- `grpc.max_receive_message_length` defaults to 4 MB, written in the source as
  `4 * 1024 * 1024` bytes, with `-1` meaning unlimited. This is the one bound
  that the stack supplies. A change to `-1`, to let one large message through,
  removes that bound for every caller.
- `grpc.max_send_message_length` has no default limit.
- `maximum_concurrent_rpcs` on `grpc.server(...)` defaults to `None`, which
  the signature documents as no limit. Set it. The server then answers
  `RESOURCE_EXHAUSTED` past the ceiling. Otherwise it accepts unbounded
  concurrent work against a fixed thread pool and a fixed connection pool.
- protobuf's pure-Python decoder carries `DEFAULT_RECURSION_LIMIT = 100`,
  changeable process-wide through `SetRecursionLimit`.
- `json_format.Parse` and `ParseDict` both default `max_recursion_depth=100`.

Those recursion guards have been bypassed twice in the pure-Python path. The
advisories and the version floors they set belong to the protobuf entry in
`a08-integrity-and-deserialization.md`, "Insecure deserialization". The
general rule the limits above instance — every caller-controlled value that
multiplies work carries a server-enforced ceiling — is in
`a06-insecure-design.md`, "Algorithmic resource exhaustion".

**`Any` lets the sender choose the type, and unknown fields survive a
forward.** Two protobuf behaviors become concrete review checks the moment a
servicer accepts messages from anything but a first-party caller.

- A `google.protobuf.Any` field carries a type URL and a serialized payload,
  so unpacking one instantiates and parses whichever message type the sender
  named. Allow-list the type URLs a field may carry and reject the rest before
  unpacking. An `Any` accepted on the terms of the sender is a sender-chosen
  constructor. The nesting it permits is what defeated the JSON recursion
  guard in the second advisory above.
- Proto3 preserves an unknown field through a binary parse and re-serialize. A
  servicer that relays a received message onward therefore passes
  attacker-supplied fields to a downstream service. That service may
  understand them. Copy the fields you validated into a fresh message before
  forwarding rather than passing on the object you parsed. Serializing through
  JSON drops them, which is a side effect of that path and not a control you
  can rely on.

**Reflection is this surface's introspection.** The server reflection service
in `grpcio-reflection` lets a client enumerate services, methods, and message
types. It also lets that client fetch the schemas needed to call them. That is
the gRPC equivalent of a served OpenAPI document. It is also what lets
`grpcurl` and `grpcui` work against an unknown endpoint.

GraphQL introspection is on by default, and this service is not. It exists
only where something called `enable_server_reflection`. The check is therefore
that no production server calls it.

Then assume that did not work, on the same terms as the GraphQL case above.
The schema leaks through error messages, and ships inside every compiled
first-party client. **Never rely on schema secrecy.** A method that is safe
only because nobody discovered it is an unauthorized method with a delay in
front of it.

Two other opt-in services belong in the same sweep. `grpcio-health-checking`
serves per-service SERVING and NOT_SERVING status, which is low sensitivity
and still an enumeration of service names.

`grpcio-channelz` serves live per-channel and per-socket internals. Those
internals are the connection state, the peer sockets, and the message and
failure counts. That is operational intelligence about the inside of the
deployment. Give it whatever access control any other debug endpoint gets. See
`deployment-and-runtime.md`, "Operational and development endpoints".

**Write-time.** When you generate a gRPC server, pass `interceptors=` with an
authenticating interceptor first in the list. Do that in the same edit that
calls `grpc.server(...)`. There is no project-wide default to inherit. Every
registered method is public from the moment the port opens.

Set `grpc.max_receive_message_length`, `grpc.max_send_message_length`, and
`maximum_concurrent_rpcs` in that same call. The send length and the
concurrency ceiling have no default. Prefer `add_secure_port` with credentials
over `add_insecure_port`. Then authorize per method inside the handler. Scope
the queryset from the authenticated principal. An interceptor that established
who is calling has decided nothing about which objects they may reach.

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
- service-mesh topology, sidecar configuration, and the gRPC transport itself.
  The servicer is in scope, and has its own section above. Where the mesh
  terminates TLS, or issues the workload identity behind it, that belongs to
  `deployment-and-runtime.md` and `service-identity-and-secrets.md`.

## Review checklist

### Stack-neutral

- [ ] Authorization is enforced on every resolved edge, not once at the query
      root. A test covers a nested selection that reaches another tenant's
      records.
- [ ] Types expose an explicit field allow-list; no all-fields type and no
      deny-list `exclude`.
- [ ] Depth, alias, token, and cost limits are all applied as validation rules
      that run before execution. A document over budget is tested and rejected.
- [ ] The cost rule compounds its multiplier down the tree. It follows a
      fragment spread, and does not skip one. It assumes a ceiling for a page
      size supplied in a variable.
- [ ] An execution or wall-clock timeout exists underneath the limits.
- [ ] Array batching is bounded or disabled, and aliases and operations count
      toward the document budget.
- [ ] Rate limiting meters cost per identity, not HTTP requests. Mutations that
      authenticate carry the same anti-automation controls as a login route,
      applied per operation.
- [ ] Introspection and the in-browser query interface are disabled in
      production, and nothing depends on the schema being secret.
- [ ] Production errors are masked; no exception strings, SQL, model names, or
      file paths reach the client.
- [ ] Mutation inputs are allow-lists, ownership is set server-side, and each
      nested write is authorized on its own terms.
- [ ] N+1 is mitigated and verified by query count under a nested document.
- [ ] For a first-party-only API, the operations are allowlisted or persisted.
      The mechanism is not a register-on-first-use cache. No request path
      writes to the registry. A body that carries a raw document is refused,
      and not executed.
- [ ] Cookie-authenticated endpoints are not CSRF-exempt.
- [ ] A gRPC server installs an authenticating interceptor, and that
      interceptor is first in the list. A call that arrives without a valid
      credential is refused with `UNAUTHENTICATED`, and does not reach a
      handler.
- [ ] Authorization is decided per method and per object inside the handler.
      It is not decided one time by the interceptor that established who is
      calling. An interceptor keyed on the service name is tested against a
      second method on the same service.
- [ ] `grpc.max_receive_message_length`, `grpc.max_send_message_length`, and
      `maximum_concurrent_rpcs` are all set explicitly. The send length and
      the concurrency ceiling have no default. Nothing has raised the receive
      default of 4 MB to `-1`.
- [ ] No `Any` field from an untrusted peer is unpacked without an allow-list
      of acceptable type URLs. A servicer that forwards a message copies the
      validated fields into a fresh message. It does not relay the parsed
      object with its unknown fields intact.
- [ ] Server reflection is not registered on a production server, and the
      health and channelz services are either absent or access-controlled.
- [ ] gRPC methods are inventoried from the `.proto` service definitions and
      the registered servicers, each as its own row. They are not URLconf
      entries. No URLconf-shaped audit finds them.

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
      (`HasSourcePerm`, `HasRetvalPerm`) from the root-style
      `IsAuthenticated`.
- [ ] Strawberry's `multipart_uploads_enabled` and CSRF protection have not
      been re-disabled; uploads that are enabled meet `file-uploads.md` in
      full.
- [ ] graphene's `GraphQLView` is not blanket-wrapped in `csrf_exempt` on a
      cookie-authenticated deployment, and `graphiql=False` in production.
- [ ] The Django compatibility of graphene-django is checked against the
      deployed Django. 3.2.3 declares support only through Django 4.2. An
      install on 5.2 or 6.0 is therefore a supply-chain finding.
- [ ] Every Django Ninja `NinjaAPI`, router, and route has an explicit
      `auth=`, and any `auth=None` override is a reviewed exception.
- [ ] Ninja routes appear as their own rows in the URLconf audit test.
- [ ] `django-ninja-jwt`'s `SIGNING_KEY` is independent of `SECRET_KEY`.
- [ ] A gRPC servicer that reuses a DRF serializer gets no credit for the DRF
      settings. `DEFAULT_AUTHENTICATION_CLASSES`,
      `DEFAULT_PERMISSION_CLASSES`, and the throttle classes in
      `REST_FRAMEWORK` are never consulted on this surface.
- [ ] On django-socio-grpc, `GRPC_FRAMEWORK` sets non-empty
      `DEFAULT_AUTHENTICATION_CLASSES` and `DEFAULT_PERMISSION_CLASSES`, and
      `SERVER_OPTIONS` carries the message-size limits the package leaves at
      `None`.
- [ ] Subscriptions meet the origin, authentication, authorization, and
      backpressure requirements in `async-and-channels.md`.
