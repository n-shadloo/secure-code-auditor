# Agent and LLM-Facing Backend Interfaces

This file covers backend surfaces that autonomous agents and LLM-driven callers
reach. The first surface is an endpoint republished as a tool over MCP or a
similar protocol. The second is an endpoint that an agent drives on behalf of a
user. The third is any path where model-generated or model-retrieved text
reaches server-side code.

The controls in scope are tool-boundary authorization, inbound token audience
validation, output-as-injection, and indirect prompt injection. They also
include cost and concurrency limits, server-enforced confirmation,
runtime-discovered components, and tool-call audit. Maps primarily to CWE-862,
CWE-863, CWE-441, CWE-770, CWE-306, and CWE-1357. Relevant OWASP categories
include A01:2025, A03:2025, A05:2025, A06:2025, and API1, API2, API4, and
API5:2023.

The spine is unchanged. This file uses the agent-specific taxonomies as
secondary mappings only. These taxonomies are OWASP's Top 10 for Agentic
Applications (ASI), the Top 10 for LLM Applications, and the MCP Top 10.
"Mapping to the LLM and Agentic Top 10s" below states them section by section.
The MCP Top 10 is a beta document at the time of writing. Cite it as such
rather than as a settled standard.

This file owns the **tool-call threat model**: what changes when the caller is
a program that drives the backend on behalf of someone. It also owns the
MCP-specific controls and the prohibition on a passthrough of an inbound token
to a downstream service. It owns the per-agent cost and concurrency limits that
no other file carries.

This file restates none of the machinery that it reuses.
`a01-broken-access-control.md` and `authorization-architecture.md` own the
authorization a tool boundary has to re-run. `service-identity-and-secrets.md`
owns inbound machine-token validation and audience binding. `a05-injection.md`
owns the sink that model output or retrieved text finally reaches.
`a06-insecure-design.md` owns which flows need a limit at all.
`a09-logging-and-alerting.md` owns the audit record a tool call has to leave.

`agent-operator-security.md` owns the opposite side of this boundary. That
side is the access the agent itself holds, rather than the backend it calls.

## Contents
- [Principle](#principle)
- [Mapping to the LLM and Agentic Top 10s](#mapping-to-the-llm-and-agentic-top-10s)
- [Django & DRF implementation](#django--drf-implementation)
- [What survives when a DRF view is republished as a tool](#what-survives-when-a-drf-view-is-republished-as-a-tool)
- [Inbound token validation and the passthrough prohibition](#inbound-token-validation-and-the-passthrough-prohibition)
- [Effective authority: tool scope intersected with user permissions](#effective-authority-tool-scope-intersected-with-user-permissions)
- [Model output as an injection source](#model-output-as-an-injection-source)
- [Retrieved content and indirect prompt injection](#retrieved-content-and-indirect-prompt-injection)
- [Cost and concurrency limits, not only request rate](#cost-and-concurrency-limits-not-only-request-rate)
- [Server-enforced confirmation for irreversible actions](#server-enforced-confirmation-for-irreversible-actions)
- [Runtime-discovered tools and servers](#runtime-discovered-tools-and-servers)
- [Tool-call audit records](#tool-call-audit-records)
- [Out of backend scope](#out-of-backend-scope)
- [Review checklist](#review-checklist)

## Principle

An agent that calls a backend is a client with four properties that no ordinary
API consumer has at once. It **holds a credential**, usually granted more
broadly than the person it acts for. It **acts on someone else's behalf**, so
the accountable identity is not the identity that authenticated. It **retries
at machine speed**, and a slow or expensive response never discourages it. And
content it reads can **rewrite its instructions**. A document, a ticket, or a
web page it retrieved can then decide what it asks the backend to do next.

The invariant is: **the effective authority of a tool call is the intersection
of the tool's granted scope and the invoking user's own permissions. Every
control that protected the equivalent HTTP endpoint is re-applied explicitly on
the tool path. Everything a model produces or retrieves is untrusted input at
every sink it reaches.**

General defenses:

- Resolve the human principal from a validated token on every invocation and
  narrow the work to that principal. Delegation can subtract authority; it
  cannot manufacture it.
- Re-validate the token on every call rather than once per session: signature,
  issuer, expiry, audience, and scope. Accept only tokens whose audience names
  this server, and never forward an inbound token to a downstream service.
- Enumerate what a republishing layer drops. When you move an endpoint onto a
  non-HTTP transport, that move silently discards every control attached to the
  HTTP request/response cycle. The discard holds unless the republisher re-runs
  each control.
- Treat model output as untrusted input wherever it reaches a sink — query
  language, shell, template, path, URL fetcher, deserializer. The rules do not
  change; only the source does.
- Bound cost, not only request rate. Cap the resource actually consumed —
  spend, tokens, database work, concurrency — per agent identity per window.
- Make confirmation a server-side state machine. A client-supplied "the user
  approved this" flag is not a control.
- Move the dependency trust decision from build time to call time wherever the
  system discovers components at runtime.
- Record each invocation, so that you can reconstruct the episode afterwards.
  Record the acting identity, the principal, the tool, the argument shape, the
  granted scope, the decision, and the outcome.

## Mapping to the LLM and Agentic Top 10s

Two OWASP lists cover this surface, and they answer different questions. The
**Top 10 for LLM Applications 2026**, published 3 August 2026, ranks what goes
wrong when a model is a *component* of an application. That list covers what
the application feeds the model, what the model emits, and what it costs to
run. The **Top 10 for Agentic Applications 2026**, published 9 December 2025,
ranks what goes wrong when a model is an *actor*. That list covers what the
model may invoke, under whose identity, and how far the damage travels.

A backend that publishes tools to an agent is in scope of both. Where both
apply, cite both.

Neither list displaces the spine. The OWASP Top 10:2025 and API Security Top 10
2023 identifiers that each section already carries decide severity and routing.
These two lists name which agent-specific failure a finding is an instance of.
A reader of an agent design wants that name, and the 2025 spine has no token
for it.

Carry one of these tokens only where the project is genuinely held to that
framing. Such a framing is an AI-specific security review, a customer
questionnaire built on one of these lists, or an internal standard that names
them. The rule that `00-methodology-and-severity.md` states for ASVS applies
here unchanged: CWE and the OWASP mapping are not optional, and this one is.

**Cite the entry token, and pin the edition on the LLM one** — `LLM03:2026`,
`ASI03`. Below the entry token these documents are prose. They hold prevention
checklists and example scenarios that each edition rewrites, with no stable
identifier to cite. The token itself is not stable either. The 2026 LLM edition
renumbered against 2025. It moved Excessive Agency from LLM06 to LLM03, and
Improper Output Handling from LLM05 to LLM10. An unpinned `LLM06` therefore now
names a different entry than it did at the time of writing.

The Agentic list publishes no year inside its tokens. Cite `ASI01` through
`ASI10` bare, and date them by the edition named above.

| Section in this file | LLM Top 10 2026 | Agentic Top 10 2026 |
|---|---|---|
| What survives when a DRF view is republished as a tool | LLM03:2026 Excessive Agency | ASI02 Tool Misuse and Exploitation |
| Inbound token validation and the passthrough prohibition | — | ASI03 Identity and Privilege Abuse |
| Effective authority: tool scope intersected with user permissions | LLM03:2026 | ASI03 |
| Model output as an injection source | LLM10:2026 Improper Output Handling | ASI05 Unexpected Code Execution |
| Retrieved content and indirect prompt injection | LLM01:2026 Prompt Injection | ASI06 Memory and Context Poisoning |
| Cost and concurrency limits, not only request rate | LLM06:2026 Unbounded Consumption | ASI08 Cascading Failures |
| Server-enforced confirmation for irreversible actions | LLM03:2026 | ASI09 Human-Agent Trust Exploitation |
| Runtime-discovered tools and servers | LLM04:2026 Supply Chain | ASI04 Agentic Supply Chain Vulnerabilities |
| Tool-call audit records | — | ASI10 Rogue Agents, in the one part a backend owns |

**The overlaps are corroboration, not conflict.** LLM03:2026 is the LLM entry
for three of the rows. That list treats every failure to bound an agent's
authority as one entry. The Agentic list separates the same failure into tool
misuse, identity abuse, and trust exploitation. That difference is where a
citation of both earns its place. The LLM token names the class, and the ASI
token names which half of it failed.

ASI03 covers both the token check and the intersection rule, and it has no
counterpart at all on the LLM list. That list carries no identity entry, which
is the largest single gap between the two for a backend. Cost and concurrency
is the one clean pair, LLM06:2026 against ASI08.

**Three entries hold on this surface without owning a section here.**
LLM02:2026 Sensitive Information Disclosure is the impact behind several rows
above rather than a defect of its own. Its controls are the queryset scoping
and serializer field sets in `api-drf-specific.md`, "Serializer exposure and
mass assignment (API3)", and the personal-data rules in
`data-lifecycle-and-privacy.md`.

LLM08:2026 Hidden Context Exposure is the 2026 rename and rescope of what 2025
called System Prompt Leakage. It is a design principle rather than a control.
Treat everything placed in a model's context as discoverable by anyone who can
prompt the model, and include the system prompt and the tool schemas. No
credential therefore belongs in any of it (`service-identity-and-secrets.md`,
"Where secrets live and how they reach the process").

ASI01 Agent Goal Hijack is the outcome the retrieved-content section defends
against, rather than a control of its own. The hijack happens at the model
layer, and every backend instrument against it is already a row above. The
intersection rule bounds what a hijacked agent reaches, and egress allowlisting
bounds what leaves.

**Named and excluded rather than mapped.** The list below extends "Out of
backend scope" to both lists:

- **LLM05:2026 Data and Model Poisoning** — training, fine-tuning, and
  embedding integrity.
- **LLM07:2026 Misinformation** — output correctness is a model property. A
  backend can require verification before it acts on model output, but it
  cannot make the output true.
- **LLM09:2026 Vector and Embedding Weaknesses** — the authorization boundary
  around retrieval is in scope and mapped above; embedding behavior and
  retrieval quality are not.
- **ASI07 Insecure Inter-Agent Communication** — multi-agent transport. Where
  the Django application is itself one endpoint, it is ordinary API security.
- **ASI10 Rogue Agents** — behavioral monitoring and fleet governance are
  operational, which is why the audit record is the only row it appears on.

Some sections below also carry MCP Top 10 tokens. Those tokens are a third list
and a beta document. They stay secondary, as the opening says, and they are not
part of this mapping.

## Django & DRF implementation

No secure-by-default way exists to publish a Django or DRF application as an
agent tool surface. **Package decision (1 Aug 2026): no MCP integration package
clears the recommendation gate**. `security-hardening-libraries.md`, "Agent and
MCP interfaces" records the dispositions. The preferred construction is DRF's
own authentication, permission, filter, pagination, and throttle classes, with
a hand-written authentication class that validates the audience. Put that
construction in front of a thin tool layer that adds no authority of its own.

Two properties decide most of the review:

1. **Which identity the tool surface runs as.** A tool that you mount under a
   service account or a superuser token has already lost the intersection rule
   before any view code runs. `request.user` is no longer the invoking human.
2. **Whether the tool path re-enters DRF's pipeline.** When you publish a
   viewset as a tool, that step does not guarantee that its
   `authentication_classes`, `permission_classes`, `filter_backends`,
   `pagination_class`, or throttles execute on that path. Confirm this in the
   source of the integration, not in its documentation.

## What survives when a DRF view is republished as a tool

Enumerate the controls one at a time for every viewset that you expose as a
tool. Assume none of them.

`django-mcp-server` (0.5.7, 10 Oct 2025) publishes DRF viewsets as MCP tools.
It leaves `authentication_classes`, `permission_classes`, `filter_backends`,
and `pagination_class` **disabled by default**. Its stated reasoning is that
MCP-level authentication replaces them. Each consequence is a separate finding:

- object-level checks that ran through `check_object_permissions()` no longer
  run, because the view-level permission list is empty;
- filter backends that scoped the queryset to a tenant or an owner are gone, so
  a filtered "my documents" view becomes an unfiltered one;
- pagination is gone and `self.paginator` becomes `None`, so a list tool
  returns the whole table instead of a page of it;
- view-level throttling does not reach the tool path; and
- serializer field allowlists survive only where the tool reuses the same
  serializer. A tool-specific serializer is a new BOPLA surface
  (`api-drf-specific.md`, "Serializer exposure and mass assignment (API3)").

`django-rest-framework-mcp` (0.1.0a4) defaults the other way: authentication
and permissions apply unless `BYPASS_VIEWSET_AUTHENTICATION` or
`BYPASS_VIEWSET_PERMISSIONS` is set. Its `RETURN_200_FOR_ERRORS` flag, also off
by default, returns HTTP 200 on an authentication or permission failure. That
flag does not create the failure. But it hides the failure from any alert that
keys on 4xx rates (`a09-logging-and-alerting.md`, "Log the right security
events").

**Warning: the error path is a control that the HTTP cycle carried.** DRF
renders an exception through `EXCEPTION_HANDLER`, and that handler decides what
detail a caller sees. A tool layer that calls the view outside
`APIView.handle_exception` renders the exception itself. The database message,
the file path, and the internal identifier inside that exception then reach the
model's context. Confirm which handler runs on the tool path
(`a10-exceptional-conditions.md`, "Don't leak on error").

**Warning: an error message that quotes the submitted value carries that value
back into the model's context.** A caller who puts an instruction in a
parameter reads that instruction again in the refusal. Return the field name
and the reason. Never return the value the caller sent. The refusal is
retrieved content by the time the model reads it, so "Retrieved content and
indirect prompt injection" below applies to it as well.

```python
# Wrong: the tool layer inherits nothing and the queryset is unscoped, so the
# tool hands every tenant's rows to whoever prompted the agent.
class OrderViewSet(ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
```

```python
# Correct: state every control on the tool path, and scope by the resolved end
# user rather than by the process that holds the credential.
class OrderToolViewSet(ModelViewSet):
    authentication_classes = [AudienceBoundTokenAuthentication]
    permission_classes = [IsAuthenticated, IsOrderOwner]
    filter_backends = [DjangoFilterBackend]
    pagination_class = CappedPageNumberPagination  # a list tool must not dump a table
    throttle_classes = [AgentIdentityThrottle]
    serializer_class = OrderSerializer

    def get_queryset(self):
        return Order.objects.filter(owner=self.request.user)
```

**Write-time.** When you generate an MCP tool over a Django application, state
`authentication_classes`, `permission_classes`, `filter_backends`,
`pagination_class`, and `throttle_classes` on the tool path itself. Do not rely
on the viewset that declared them. The integration decides whether that
pipeline runs at all, and the integration in widest use disables four of them
by default.

Authenticate with a class that validates `aud` against this server's own
identifier on every invocation. Resolve `request.user` to the invoking human
rather than to the process credential. `get_queryset()` can then scope to the
intersection of the scope granted to the tool and the permissions of that user.
Where the tool does anything irreversible, issue and consume a server-side
confirmation token in the same change. Bind that token to the action and its
parameters, over a canonical encoding that separates the fields. Write the
consume as one statement that lets a single caller win. A `confirmed` flag in
the request body is only the client's assertion of its own approval.

Write the error path of the tool as well. Return the field name and the reason
for a refusal. Never return the exception detail, and never return the value
the caller sent.

Severity is Critical where the tool spans tenants. The failure is BOLA at the
scale of the whole table rather than one object
(`a01-broken-access-control.md`, "IDOR / BOLA"). Maps to CWE-862, CWE-1220;
API1, API3, and API4:2023; LLM03:2026 Excessive Agency; ASI02 Tool Misuse and
Exploitation.

## Inbound token validation and the passthrough prohibition

A bearer token that an agent presents is not a session. Validate it on every
invocation — signature, algorithm, `iss`, `exp`, and `aud` — and reject any
token whose audience does not name this server. The MCP authorization
specification (revision 2026-07-28, which superseded 2025-11-25 on 28 July
2026) requires both, unchanged across the two revisions. A server accepts only
tokens issued for itself, and it must not pass through the token it received
from the client. Audience binding follows RFC 8707.

The current revision adds one duty the previous one did not place on the
resource server. RFC 9728 protected-resource metadata is now mandatory rather
than optional. That metadata is the document a client reads to discover the
authorization server and the audience to ask for. Refuse a token that is
insufficient rather than invalid with a 403. Name the required scope and the
location of that metadata in the refusal. Scope hierarchies count when you
decide whether a token is sufficient.

**Warning: a valid token is not evidence that a human is behind the call.** A
token whose `sub` names a service identity has no human principal to intersect
against. RFC 8693 keeps the acting party visible in an `act` claim, so a
delegated token names the human in `sub` and the agent in `act`. Reject a token
that names a service identity in `sub` and carries no actor chain back to a
person. Never run the permission check against the agent's own identity. The
signal in code is a lookup of `claims["sub"]` as a user, with no test of which
kind of subject that claim names.

Passthrough is a confused-deputy vulnerability (CWE-441). The downstream
service sees a valid token and cannot detect that the caller is an
intermediary. It applies the token's full authority to a request the
intermediary shaped. Replace the passthrough with a separately issued
downstream credential, scoped to the downstream resource and to the acting
principal. That credential comes from RFC 8693 token exchange, a stored service
credential, or a platform-managed identity.

Read the failure path of that exchange. A fallback to the subject token when
the exchange is unavailable is the passthrough this section prohibits. The call
fails closed instead.

```python
# Wrong: audience unchecked, the principal cached for the session, and the
# caller's own token reused for the next hop.
claims = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
request.session["agent_user_id"] = claims["sub"]
billing.get("/invoices", headers={"Authorization": f"Bearer {token}"})
```

```python
# Correct: revalidate on every call against this server's own resource URI,
# then obtain a distinct token for the downstream hop.
claims = jwt.decode(
    token,
    key,
    algorithms=["RS256"],
    audience=settings.MCP_RESOURCE_URI,   # this server, per RFC 8707
    issuer=settings.OIDC_ISSUER,          # iss and exp are verified as well
)
downstream = exchange_token(
    subject_token=token, resource=settings.BILLING_RESOURCE_URI
)
billing.get("/invoices", headers={"Authorization": f"Bearer {downstream}"})
```

`a07-authentication-failures.md`, "JWT" owns algorithm pinning, key rotation,
lifetimes, claim staleness, and revocation. `service-identity-and-secrets.md`
owns the ordered claim-by-claim verification, JWKS caching and rotation, and
the RFC 8693 exchange mechanics. Both apply unchanged. What is specific here is
the audience check on every call and the passthrough prohibition. Maps to
CWE-287, CWE-345, CWE-441; API2:2023; ASI03 Identity and Privilege Abuse; MCP01
Token Mismanagement and Secret Exposure, MCP07 Insufficient Authentication and
Authorization.

## Effective authority: tool scope intersected with user permissions

The authority of a tool call is the intersection of the scope granted to the
agent and the permissions of the user it acts for. It is never the union, and
never the larger of the two. Every invocation requires two checks, and neither
one substitutes for the other:

1. whether the tool holds the scope for this operation, and
2. whether this user may perform it on this object.

If you drop the first check, a narrowly-scoped integration becomes a
general-purpose one. If you drop the second check, the result is BOLA with an
agent in front of it.

```python
# Correct: both halves, in order, before any object is touched.
def get_queryset(self):
    if "orders:read" not in self.request.auth.scopes:
        raise PermissionDenied("tool is not granted orders:read")
    # request.user is the human principal resolved from the validated token,
    # not the service account the tool process runs as.
    return Order.objects.filter(owner=self.request.user)
```

**A scope check that matches a prefix grants more than the scope it names.** A
check that accepts a granted `orders` as sufficient for `orders:read` accepts
it for `orders:write` too. Require exact membership in the granted set, as the
example above does. Where a hierarchy exists, expand it into that set once, in
one tested function rather than at each call site.

Queryset scoping covers list and detail alike. The object hook does not run on
list or create paths at all (`authorization-architecture.md`, "DRF: where the
object check actually runs"). Default-deny for the tool surface belongs where
the rest of it lives. That place is a URLconf audit test that treats a tool
route with no explicit decision as a failure. It is also an authorization
matrix that carries the tool path as its own row. Do not assume that the tool
path inherits the HTTP route's coverage (`authorization-architecture.md`,
"Default-deny architecture" and "Authorization test suites").

This is the impersonation invariant with a machine delegate. The human remains
the accountable identity, the delegated capability is narrower than that
human's own account, and the episode is reconstructable afterwards.
`privileged-access-and-impersonation.md`, "Impersonation: design requirements"
owns the machinery for scope embedding, time-boxing, and audit identity. This
file does not restate it. Maps to CWE-862, CWE-863; API1 and API5:2023; ASI03
Identity and Privilege Abuse; LLM03:2026 Excessive Agency.

## Model output as an injection source

Model-generated text is untrusted input. Every rule in `a05-injection.md`
applies unchanged when the string came from a model rather than a request body.
The only new thing is the source, and the only new risk is a reviewer who
treats "our own model wrote it" as provenance.

`a05-injection.md`, "Tracing input to a sink" keeps the sink inventory: every
interpreter a request can reach, and which reference owns each one. An agent
design is the case that most needs that inventory whole. A model can emit input
for any row in it from a single tool call.

These rules apply unchanged from `a05-injection.md`:

- parameterized queries only — never `.raw()`, `.extra()`, `RawSQL`, or
  `cursor.execute()` with model output interpolated in ("SQL and the ORM");
- no `shell=True` and no string-built commands ("OS command injection");
- autoescaping intact, and never `mark_safe()` or a template constructed from
  model output, which is server-side template injection and reaches RCE
  ("Template injection and server-side output");
- allowlisted identifiers wherever a model supplies a column, alias, or sort
  key — the dictionary-expansion class applies directly ("The
  dictionary-expansion column-alias class").

Three sinks are worth restating because agent designs reach them more often
than ordinary request handlers do:

- **generated file paths** — a model-supplied filename or storage key is path
  traversal input; generate the storage identity server-side
  (`file-uploads.md`, "Filenames and storage keys");
- **generated URLs** — a model-assembled URL handed to a fetcher is SSRF;
  allowlist scheme and destination and re-check after redirects
  (`a01-broken-access-control.md`, "SSRF");
- **generated serialized data** — never `pickle.loads()` or `yaml.load()` on
  model output (`a08-integrity-and-deserialization.md`, "Insecure
  deserialization").

Maps to CWE-89, CWE-78, CWE-94, CWE-1336, CWE-22, CWE-918, CWE-502; A05:2025;
LLM10:2026 Improper Output Handling; ASI05 Unexpected Code Execution.

## Retrieved content and indirect prompt injection

When a backend pulls a document, ticket, email, or web page into a model's
context, that content can carry instructions. This is indirect prompt
injection, and a backend cannot fix it at the model layer. "Separate
instructions from data" is a model-layer aspiration, not a server-side control.
Do not report it as one.

A backend can actually enforce four controls, in order of leverage:

1. **The intersection rule above.** Injected instructions reach only what the
   invoking user could already reach, which turns a context-exfiltration attack
   into a caller who reads their own data.
2. **Egress allowlisting.** An exfiltration URL assembled from context still
   has to resolve and connect. Allowlist outbound destinations from the
   tool-executing process and treat every model-influenced fetch as SSRF
   (`a01-broken-access-control.md`, "SSRF"). Read each entry for who may
   publish under it. An entry that names a host where anybody can host content
   is an open egress path with an allowlist in front of it. A wildcard over a
   shared provider domain, an object-storage host, and a snippet service are
   three such entries.
3. **Provenance labeling.** Record the trust level of retrieved content, and
   refuse to let low-trust content trigger a high-privilege tool. A ticket body
   that an anonymous reporter submitted is not the same input class as a record
   that the tenant's own administrator wrote.
4. **Sink controls.** Everything in "Model output as an injection source" above
   applies to retrieved content as well as generated content.

EchoLeak (CVE-2025-32711) is the reference incident. Instructions hidden in a
retrieved email caused zero-click exfiltration of the user's context through an
outbound link. The user took no action other than receipt of the message. The
vendor fixed it server-side. The exfiltration path, not the injection, is where
a backend has leverage.

RAG and vector-store internals are out of scope. Only the authorization
boundary around retrieval is in scope. `authorization-architecture.md`, "Search
indexes and denormalized copies" holds the general form of that boundary. That
form is authorization metadata on each indexed document, a mandatory
server-derived filter at query time, and a reindex when permissions change.
What is agent-specific here is that a tool that republishes retrieval must also
intersect the tool's scope with the invoking user's own permissions.

Maps to CWE-77; A01:2025; LLM01:2026 Prompt Injection; ASI06 Memory and Context
Poisoning. Assign severity by what the injected instruction can reach —
Critical when it can reach a privileged tool or an unrestricted egress path.

## Cost and concurrency limits, not only request rate

A request-per-minute cap and a cost cap are different controls, and an agent
defeats the first without a breach of it. A retry loop runs for hours under any
per-user rate limit. A denial-of-wallet attack stays comfortably inside one
limit while it exhausts an inference budget or an export budget. Bound the
resource that the caller actually consumes:

- **cost or spend** per agent identity per window — model tokens, inference
  spend, exported rows, database work;
- **concurrency** — a hard cap on simultaneous in-flight tool calls per
  identity, enforced before the expensive work starts; and
- **request rate**, which remains necessary and is not sufficient.

Key all three on the resolved agent identity or principal identity. **A
throttle keyed on IP is ineffective here.** An agent fleet behind one egress
address shares a single key. One caller then consumes the whole allowance, or
the limit is high enough to protect nothing. A `SimpleRateThrottle` subclass on
a tool path should return an identity-derived cache key. The general position
on DRF throttling is unchanged: a quota tool, not a security control. See
`api-drf-specific.md`, "Throttling as quota, not security (API4)" and
`a06-insecure-design.md`, "Rate limiting and anti-automation".

Return HTTP 429 with `Retry-After` when a caller hits a limit. Fail closed on
the cost check specifically: a cache outage must not silently remove a spend
cap. Maps to CWE-770, CWE-400; API4:2023; LLM06:2026 Unbounded Consumption;
ASI08 Cascading Failures.

## Server-enforced confirmation for irreversible actions

"Ask the user before doing this" is a server-side state machine, not a prompt
instruction and not a client courtesy. A tool that performs an irreversible or
high-impact action returns a pending state. Such an action is a refund, a
dataset deletion, a message on behalf of a customer, or a permission change.
The tool runs only against a second, separately authorized step.

```python
# Wrong: the client asserts that a human approved, and the server believes it.
if request.data.get("confirmed"):
    issue_refund(order)
```

```python
# Correct: the server issues the confirmation token, binds it to this exact
# action and these exact parameters, and consumes it once.
token = ConfirmationToken.objects.consume(
    raw=request.data["confirmation_token"],
    actor=request.user,
    action="refund.issue",
    parameters_digest=digest_of(order_id, amount),  # a changed amount invalidates it
)
if token is None:
    raise PermissionDenied("confirmation required")
issue_refund(order)
```

**Warning: a digest over concatenated parameters is ambiguous.** An encoding
that joins `order_id` and `amount` end to end gives one digest to `1` with `23`
and to `12` with `3`. Build the digest over a canonical encoding that separates
the fields and sorts them. Cover every parameter that changes what the action
does, and not only the two this example names. Keep the action name fully
qualified, as `refund.issue` is here. A token for one tool then never matches
the same verb on another.

**Warning: single-use is a property of the consume, not of the token.** The
agent retries at machine speed, so two calls can present one token at the same
moment. `consume` must let exactly one caller win. That is one conditional
statement that marks the token used and reports how many rows it changed. A
locked read inside a transaction is the other form
(`a10-exceptional-conditions.md`, "Races, TOCTOU, and adversarial
sequencing"). A check that reads the token and then
deletes it runs the irreversible action twice.

The token is short-lived, single-use, bound to the action and its parameters,
and stored as a digest like any other credential
(`a07-authentication-failures.md`, "API keys"). Absence of a valid token fails
closed. Maps to CWE-306, CWE-841; A06:2025; LLM03:2026 Excessive Agency; ASI09
Human-Agent Trust Exploitation.

## Runtime-discovered tools and servers

The gate in `a03-software-supply-chain.md`, "Third-party dependency vetting"
assumes that the dependency set is fixed when the build produces the artifact.
An agent can discover and load a tool or a server at call time. That moves the
trust decision to a point none of the build-time machinery reaches.

- Pin the servers and tools a backend connects to. A discovery mechanism that
  connects to every server it finds has no gate at all.
- Require signed provenance or an explicit allowlist entry before you use a
  runtime-discovered server. Treat an unknown server the way the gate treats an
  unvetted package: refuse it, rather than warn and proceed.
- **Treat tool descriptions as untrusted input.** The name, the description,
  and the parameter documentation of a tool are attacker-influenced text that
  reaches a model's context. They are content, not configuration. The
  project's own tool definitions carry the same weight. A change to a
  description string changes what every later session is told, and it reads in
  review as a documentation change. Review such a change as a change to a
  control. Flag a description that instructs the model rather than describes
  the tool.
- An outward connection is itself a code-execution surface. CVE-2025-6514
  (CWE-78, fixed in `mcp-remote` 0.1.16) was OS command execution. A crafted
  response from the server at the far end triggered it, and not anything the
  client sent.

Maps to CWE-1357; A03:2025; LLM04:2026 Supply Chain; ASI04 Agentic Supply
Chain Vulnerabilities; MCP04 Software Supply Chain Attacks, MCP09 Shadow MCP
Servers.

## Tool-call audit records

A tool invocation must be reconstructable afterwards. Record the agent
identity, the acting human, and which tool ran. Record also the shape of the
arguments, the scope granted, the decision, a result summary, and the start and
stop timestamps. Write that record where the caller cannot rewrite it. This is
the audit guarantee in `privileged-access-and-impersonation.md`,
"Impersonation: design requirements", applied to a machine delegate. The
durability requirements are identical.

One tension is specific to this surface. Reconstructability asks for verbatim
arguments and results, and arguments and results routinely carry credentials
and personal data. Resolve that tension in favor of
`a09-logging-and-alerting.md`, "Don't log secrets". Record the argument shape,
the field names, and digests rather than values. Redact known-sensitive fields,
and neutralize control characters in any model-supplied string before it
reaches a log line ("Log injection and integrity"). Denials are the more
valuable half of the record, so log the refused call and not only the executed
one.

One class of argument is an exception to the digest rule. Where a call pulls
external content into the model's context, record which content it pulled.
Record the URL, the document identifier, or the record key as a value rather
than as a digest. The source is not the secret, and it is where an
investigation into an injection starts. A digest of it answers nothing.

Maps to CWE-778, CWE-532; A09:2025; ASI10 Rogue Agents; MCP08 Lack of Audit and
Telemetry.

## Out of backend scope

This list mirrors `00-methodology-and-severity.md`, "What to exclude". Do not
search backend code for these items, and do not report their absence as a
backend finding:

- rogue-agent behavioral monitoring, kill switches, and agent-fleet governance,
  which are operational controls rather than server-side code;
- inter-agent transport and multi-agent coordination, except where the Django
  application is itself one endpoint, in which case it is ordinary API security;
- model selection, prompt engineering, system-prompt content, and alignment;
- RAG pipeline and vector-store internals — the authorization boundary around
  retrieval is in scope, retrieval quality and embedding behavior are not;
- AI bills of material and AI-governance process.

## Review checklist

### Stack-neutral

- [ ] Every tool call resolves the human principal from a validated token. It
      applies the tool's scope *and* that principal's own permissions, and
      infers neither from the other. A token whose subject names a service
      identity, with no actor chain back to a person, is refused.
- [ ] The scope check requires exact membership in the granted set. No prefix
      match, and no wildcard, stands in for it.
- [ ] The server validates inbound tokens on every invocation for signature,
      issuer, expiry, audience, and scope. The audience check names this
      server's own resource identifier. No inbound token reaches a downstream
      service.
- [ ] The server publishes RFC 9728 protected-resource metadata. A 403 refuses
      a token that is insufficient rather than invalid, and names the required
      scope and that metadata location.
- [ ] The tool path explicitly re-applies every control the equivalent HTTP
      endpoint carried. The enumeration ran against the republishing layer's
      source rather than its documentation.
- [ ] Model-generated and retrieved text passes the same sink controls as any
      other untrusted input, and that covers generated paths, URLs, and
      serialized data.
- [ ] Low-trust retrieved content cannot trigger a privileged tool, and
      outbound destinations are allowlisted from the tool-executing process.
      No entry on that list names a host where a third party can publish.
- [ ] Cost, spend, and concurrency caps exist per agent identity alongside
      request-rate limits, and the cost check fails closed.
- [ ] Irreversible actions require a server-issued, single-use confirmation
      token bound to the action and its parameters. The server trusts no
      client-supplied confirmation flag.
- [ ] The parameter digest reads a canonical encoding with separated fields,
      and it covers every parameter that changes the outcome. One caller wins
      the consume when two calls present one token together.
- [ ] Runtime-discovered servers and tools require signed provenance or an
      allowlist entry, and the review treats tool descriptions as untrusted
      input. That treatment covers the project's own tool definitions, and a
      change to one is reviewed as a change to a control.
- [ ] The server records invocations and denials reconstructably in a store the
      caller cannot rewrite, with values reduced to shapes and digests. The
      source of any external content the call pulled is recorded as a value.

### Django & DRF

- [ ] The tool surface does not run under a service account or superuser token
      that makes `request.user` something other than the invoking human.
- [ ] For every viewset exposed as a tool, the tool path sets six items
      explicitly. These are `authentication_classes`, `permission_classes`,
      `filter_backends`, `pagination_class`, `throttle_classes`, and the
      serializer field sets.
- [ ] If `django-mcp-server` is installed, all four of its default-disabled
      controls are re-enabled and `self.paginator` is not `None` on a list tool.
- [ ] If `django-rest-framework-mcp` is installed,
      `BYPASS_VIEWSET_AUTHENTICATION`, `BYPASS_VIEWSET_PERMISSIONS`, and
      `RETURN_200_FOR_ERRORS` are all off.
- [ ] No admin-exposing or shell-exposing MCP package is installed in
      production.
- [ ] Tool routes appear in the URLconf audit test and in the authorization
      test matrix as their own rows. The matrix does not assume that they
      inherit from the HTTP route.
- [ ] Throttles on tool paths key on the resolved identity, never on IP.
- [ ] The tool path renders an exception through a handler the review has
      identified. No exception detail and no submitted value returns to the
      caller inside an error message.
