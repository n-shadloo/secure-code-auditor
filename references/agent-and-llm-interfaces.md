# Agent and LLM-Facing Backend Interfaces

Backend surfaces exposed to autonomous agents and LLM-driven callers: endpoints
republished as tools over MCP or a similar protocol, endpoints an agent drives
on a user's behalf, and any path where model-generated or model-retrieved text
reaches server-side code. Covers tool-boundary authorization, inbound token
audience validation, output-as-injection, indirect prompt injection, cost and
concurrency limits, server-enforced confirmation, runtime-discovered
components, and tool-call audit. Maps primarily to CWE-862, CWE-863, CWE-441,
CWE-770, CWE-306, and CWE-1357; relevant OWASP categories include A01:2025,
A03:2025, A05:2025, A06:2025, and API1, API2, API4, and API5:2023.

The spine is unchanged. The agent-specific taxonomies — OWASP's Top 10 for
Agentic Applications (ASI), Top 10 for LLM Applications, and MCP Top 10 — are
used here as secondary mappings only, and the MCP Top 10 is a beta document at
the time of writing; cite it as such rather than as a settled standard.

## Contents
- [Principle](#principle)
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

An agent calling a backend is a client with four properties that no ordinary
API consumer has at once. It **holds a credential**, usually granted more
broadly than the person it acts for. It **acts on someone else's behalf**, so
the accountable identity is not the identity that authenticated. It **retries
at machine speed** and is never discouraged by a slow or expensive response.
And its instructions can be **rewritten by content it reads**, so a document, a
ticket, or a web page it retrieved can decide what it asks the backend to do
next.

The invariant is: **the effective authority of a tool call is the intersection
of the tool's granted scope and the invoking user's own permissions; every
control that protected the equivalent HTTP endpoint is re-applied explicitly on
the tool path; and everything a model produces or retrieves is untrusted input
at every sink it reaches.**

General defenses:

- Resolve the human principal from a validated token on every invocation and
  narrow the work to that principal. Delegation can subtract authority; it
  cannot manufacture it.
- Re-validate the token on every call rather than once per session: signature,
  issuer, expiry, audience, and scope. Accept only tokens whose audience names
  this server, and never forward an inbound token to a downstream service.
- Enumerate what a republishing layer drops. Moving an endpoint onto a
  non-HTTP transport silently discards every control attached to the HTTP
  request/response cycle unless the republisher re-runs it.
- Treat model output as untrusted input wherever it reaches a sink — query
  language, shell, template, path, URL fetcher, deserializer. The rules do not
  change; only the source does.
- Bound cost, not only request rate. Cap the resource actually consumed —
  spend, tokens, database work, concurrency — per agent identity per window.
- Make confirmation a server-side state machine. A client-supplied "the user
  approved this" flag is not a control.
- Move the dependency trust decision from build time to call time wherever
  components are discovered at runtime.
- Record each invocation so the episode can be reconstructed afterwards:
  acting identity, principal, tool, argument shape, granted scope, decision,
  and outcome.

## Django & DRF implementation

There is no secure-by-default way to publish a Django or DRF application as an
agent tool surface. **Package decision (1 Aug 2026): no MCP integration package
clears the recommendation gate**; the dispositions are recorded in
`security-hardening-libraries.md`, "Agent and MCP interfaces". The preferred
construction is DRF's own authentication, permission, filter, pagination, and
throttle classes plus a hand-written audience-validating authentication class,
in front of a thin tool layer that adds no authority of its own.

Two properties decide most of the review:

1. **Which identity the tool surface runs as.** A tool mounted under a service
   account or a superuser token has already lost the intersection rule before
   any view code runs, because `request.user` is no longer the invoking human.
2. **Whether the tool path re-enters DRF's pipeline.** Publishing a viewset as
   a tool does not guarantee that its `authentication_classes`,
   `permission_classes`, `filter_backends`, `pagination_class`, or throttles
   execute on that path. Confirm it in the integration's source, not its
   documentation.

## What survives when a DRF view is republished as a tool

Enumerate the controls one at a time for every viewset exposed as a tool. None
of them can be assumed.

`django-mcp-server` (0.5.7, 10 Mar 2026) publishes DRF viewsets as MCP tools
with `authentication_classes`, `permission_classes`, `filter_backends`, and
`pagination_class` **disabled by default**, on the stated reasoning that
MCP-level authentication replaces them. Each consequence is a separate finding:

- object-level checks that ran through `check_object_permissions()` no longer
  run, because the view-level permission list is empty;
- filter backends that scoped the queryset to a tenant or an owner are gone, so
  a filtered "my documents" view becomes an unfiltered one;
- pagination is gone and `self.paginator` becomes `None`, so a list tool
  returns the whole table instead of a page of it;
- view-level throttling does not carry over; and
- serializer field allowlists survive only where the same serializer is reused
  — a tool-specific serializer is a new BOPLA surface
  (`api-drf-specific.md`, "Serializer exposure and mass assignment (API3)").

`django-rest-framework-mcp` (0.1.0a4) defaults the other way: authentication
and permissions apply unless `BYPASS_VIEWSET_AUTHENTICATION` or
`BYPASS_VIEWSET_PERMISSIONS` is set. Its `RETURN_200_FOR_ERRORS` flag, also off
by default, returns HTTP 200 on an authentication or permission failure. That
does not create the failure, but it hides it from any alerting keyed on 4xx
rates (`a09-logging-and-alerting.md`, "Log the right security events").

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

Severity is Critical where the tool spans tenants: the failure is BOLA at the
scale of the whole table rather than one object
(`a01-broken-access-control.md`, "IDOR / BOLA"). Maps to CWE-862, CWE-1220;
API1, API3, and API4:2023; ASI02 Tool Misuse and Exploitation.

## Inbound token validation and the passthrough prohibition

A bearer token presented by an agent is not a session. Validate it on every
invocation — signature, algorithm, `iss`, `exp`, and `aud` — and reject any
token whose audience does not name this server. The MCP authorization
specification (revision 2025-11-25) requires both: a server accepts only tokens
issued for itself, and it must not pass through the token it received from the
client. Audience binding follows RFC 8707; the protected-resource metadata a
client uses to discover the correct audience follows RFC 9728.

Passthrough is a confused-deputy vulnerability (CWE-441). The downstream
service sees a valid token, cannot tell that the caller is an intermediary, and
applies the token's full authority to a request the intermediary shaped.
Replace it with a separately issued downstream credential — RFC 8693 token
exchange, a stored service credential, or a platform-managed identity — scoped
to the downstream resource and to the acting principal.

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
downstream = exchange_token(claims, resource=settings.BILLING_RESOURCE_URI)
billing.get("/invoices", headers={"Authorization": f"Bearer {downstream}"})
```

Algorithm pinning, key rotation, lifetimes, claim staleness, and revocation are
in `a07-authentication-failures.md`, "JWT"; the ordered claim-by-claim
verification, JWKS caching and rotation, and the RFC 8693 exchange mechanics
are in `service-identity-and-secrets.md`. Both apply unchanged. What is
specific here is the audience check on every call and the passthrough
prohibition. Maps to CWE-287, CWE-345, CWE-441; API2:2023; MCP01 Token
Mismanagement and Secret Exposure, MCP07 Insufficient Authentication and
Authorization.

## Effective authority: tool scope intersected with user permissions

The authority of a tool call is the intersection of the scope granted to the
agent and the permissions of the user it acts for — never the union, and never
whichever is larger. Two checks are required on every invocation, and neither
substitutes for the other:

1. does the tool hold the scope for this operation, and
2. may this user perform it on this object?

Dropping the first turns a narrowly-scoped integration into a general-purpose
one. Dropping the second is BOLA with an agent in front of it.

```python
# Correct: both halves, in order, before any object is touched.
def get_queryset(self):
    if "orders:read" not in self.request.auth.scopes:
        raise PermissionDenied("tool is not granted orders:read")
    # request.user is the human principal resolved from the validated token,
    # not the service account the tool process runs as.
    return Order.objects.filter(owner=self.request.user)
```

Queryset scoping covers list and detail alike, and the object hook does not run
on list or create paths at all (`authorization-architecture.md`, "DRF: where
the object check actually runs"). Default-deny for the tool surface belongs
where the rest of it lives: a URLconf audit test that treats a tool route with
no explicit decision as a failure, and an authorization matrix that carries the
tool path as its own row rather than assuming it inherits the HTTP route's
coverage (`authorization-architecture.md`, "Default-deny architecture" and
"Authorization test suites").

This is the impersonation invariant with a machine delegate: the human remains
the accountable identity, the delegated capability is narrower than that
human's own account, and the episode is reconstructable afterwards. The
machinery for scope embedding, time-boxing, and audit identity is in
`privileged-access-and-impersonation.md`, "Impersonation: design requirements"
and is not restated here. Maps to CWE-862, CWE-863; API1 and API5:2023; ASI03
Identity and Privilege Abuse; LLM06 Excessive Agency.

## Model output as an injection source

Model-generated text is untrusted input. Every rule in `a05-injection.md`
applies unchanged when the string came from a model rather than a request body.
The only new thing is the source, and the only new risk is a reviewer treating
"our own model wrote it" as provenance.

The sink inventory that file keeps — every interpreter a request can reach, and
which reference owns each one — is in `a05-injection.md`, "Tracing input to a
sink". An agent design is the case that most needs it whole, because a model
can emit input for any row in it from a single tool call.

Applying unchanged from `a05-injection.md`:

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
LLM05 Improper Output Handling; ASI05 Unexpected Code Execution.

## Retrieved content and indirect prompt injection

When a backend pulls a document, ticket, email, or web page into a model's
context, that content can carry instructions. This is indirect prompt
injection, and a backend cannot fix it at the model layer: "separate
instructions from data" is a model-layer aspiration, not a server-side control,
and should not be written up as one.

What a backend can actually enforce, in order of leverage:

1. **The intersection rule above.** Injected instructions reach only what the
   invoking user could already reach, which turns a context-exfiltration attack
   into a caller reading their own data.
2. **Egress allowlisting.** An exfiltration URL assembled from context still
   has to resolve and connect. Allowlist outbound destinations from the
   tool-executing process and treat every model-influenced fetch as SSRF
   (`a01-broken-access-control.md`, "SSRF").
3. **Provenance labelling.** Record the trust level of retrieved content and
   refuse to let low-trust content trigger a high-privilege tool. A ticket body
   submitted by an anonymous reporter is not the same input class as a record
   written by the tenant's own administrator.
4. **Sink controls.** Everything in "Model output as an injection source" above
   applies to retrieved content as well as generated content.

EchoLeak (CVE-2025-32711) is the reference incident: instructions hidden in a
retrieved email caused zero-click exfiltration of the user's context through an
outbound link, with no user action beyond receiving the message. It was fixed
by the vendor server-side. The exfiltration path, not the injection, is where a
backend has leverage.

RAG and vector-store internals are out of scope; only the authorization
boundary around retrieval is in scope. The general form of that boundary —
authorization metadata written onto each indexed document, a mandatory
server-derived filter at query time, and reindexing when permissions change —
is in `authorization-architecture.md`, "Search indexes and denormalised
copies". What is agent-specific here is that a tool republishing retrieval must
also intersect the tool's scope with the invoking user's own permissions.
Maps to CWE-77; A01:2025; LLM01 Prompt
Injection; ASI06 Memory and Context Poisoning. Assign severity by what the
injected instruction can reach — Critical when it can reach a privileged tool
or an unrestricted egress path.

## Cost and concurrency limits, not only request rate

A request-per-minute cap and a cost cap are different controls, and an agent
defeats the first without ever breaching it. A retry loop runs for hours under
any per-user rate limit; a denial-of-wallet attack stays comfortably inside one
while exhausting an inference or export budget. Bound the resource actually
consumed:

- **cost or spend** per agent identity per window — model tokens, inference
  spend, exported rows, database work;
- **concurrency** — a hard cap on simultaneous in-flight tool calls per
  identity, enforced before the expensive work starts; and
- **request rate**, which remains necessary and is not sufficient.

Key all three on the resolved agent or principal identity. **A throttle keyed
on IP is ineffective here**: an agent fleet behind one egress address shares a
single key, so either one caller consumes the whole allowance or the limit is
set high enough to protect nothing. A `SimpleRateThrottle` subclass on a tool
path should return an identity-derived cache key. The general position on DRF
throttling — a quota tool, not a security control — is unchanged
(`api-drf-specific.md`, "Throttling as quota, not security (API4)" and
`a06-insecure-design.md`, "Rate limiting and anti-automation").

Return HTTP 429 with `Retry-After` when a limit is hit, and fail closed on the
cost check specifically: a cache outage must not silently remove a spend cap.
Maps to CWE-770, CWE-400; API4:2023; LLM10 Unbounded Consumption.

## Server-enforced confirmation for irreversible actions

"Ask the user before doing this" is a server-side state machine, not a prompt
instruction and not a client courtesy. A tool that performs an irreversible or
high-impact action — issuing a refund, deleting a dataset, messaging on a
customer's behalf, changing a permission — returns a pending state and runs
only against a second, separately authorized step.

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

The token is short-lived, single-use, bound to the action and its parameters,
and stored as a digest like any other credential
(`a07-authentication-failures.md`, "API keys"). Absence of a valid token fails
closed. Maps to CWE-306, CWE-841; A06:2025; LLM06 Excessive Agency; ASI09
Human-Agent Trust Exploitation.

## Runtime-discovered tools and servers

The gate in `a03-software-supply-chain.md`, "Third-party dependency vetting"
assumes the dependency set is fixed when the artifact is built. An agent can
discover and load a tool or a server at call time, which moves the trust
decision to a point none of the build-time machinery reaches.

- Pin the servers and tools a backend will connect to. A discovery mechanism
  that connects to whatever it finds has no gate at all.
- Require signed provenance or an explicit allowlist entry before a
  runtime-discovered server is used. Treat an unknown server the way the gate
  treats an unvetted package: refuse, rather than warn and proceed.
- **Treat tool descriptions as untrusted input.** A tool's name, description,
  and parameter documentation are attacker-influenced text that reaches a
  model's context. They are content, not configuration.
- Connecting outward is itself a code-execution surface. CVE-2025-6514
  (CWE-78, fixed in `mcp-remote` 0.1.16) was OS command execution triggered by
  a crafted response from the server being connected to, not by anything the
  connecting client sent.

Maps to CWE-1357; A03:2025; LLM03 Supply Chain; ASI04 Agentic Supply Chain
Vulnerabilities; MCP04 Software Supply Chain Attacks, MCP09 Shadow MCP Servers.

## Tool-call audit records

A tool invocation must be reconstructable afterwards: agent identity and acting
human, which tool, the shape of the arguments, the scope granted, the decision,
a result summary, and start and stop timestamps — written where the caller
cannot rewrite it. This is the audit guarantee in
`privileged-access-and-impersonation.md`, "Impersonation: design requirements",
applied to a machine delegate; the durability requirements are identical.

The tension specific to this surface is that reconstructability pulls toward
logging arguments and results verbatim, and arguments and results routinely
carry credentials and personal data. Resolve it in favour of
`a09-logging-and-alerting.md`, "Don't log secrets": record argument shape,
field names, and digests rather than values, redact known-sensitive fields, and
neutralize control characters in any model-supplied string before it reaches a
log line ("Log injection and integrity"). Denials are the more valuable half of
the record — log the refused call, not only the executed one. Maps to CWE-778,
CWE-532; A09:2025; MCP08 Lack of Audit and Telemetry.

## Out of backend scope

Mirroring `00-methodology-and-severity.md`, "What to exclude" — do not search
backend code for these, and do not report their absence as a backend finding:

- rogue-agent behavioural monitoring, kill switches, and agent-fleet governance,
  which are operational controls rather than server-side code;
- inter-agent transport and multi-agent coordination, except where the Django
  application is itself one endpoint, in which case it is ordinary API security;
- model selection, prompt engineering, system-prompt content, and alignment;
- RAG pipeline and vector-store internals — the authorization boundary around
  retrieval is in scope, retrieval quality and embedding behaviour are not;
- AI bills of material and AI-governance process.

## Review checklist

### Stack-neutral

- [ ] Every tool call resolves the human principal from a validated token and
      applies the tool's scope *and* that principal's own permissions; neither
      is inferred from the other.
- [ ] Inbound tokens are validated on every invocation for signature, issuer,
      expiry, audience against this server's own resource identifier, and
      scope; no inbound token is forwarded to a downstream service.
- [ ] Every control the equivalent HTTP endpoint carried is explicitly
      re-applied on the tool path, and the enumeration was done against the
      republishing layer's source rather than its documentation.
- [ ] Model-generated and retrieved text passes the same sink controls as any
      other untrusted input, including generated paths, URLs, and serialized
      data.
- [ ] Low-trust retrieved content cannot trigger a privileged tool, and
      outbound destinations are allowlisted from the tool-executing process.
- [ ] Cost, spend, and concurrency caps exist per agent identity alongside
      request-rate limits, and the cost check fails closed.
- [ ] Irreversible actions require a server-issued, single-use confirmation
      token bound to the action and its parameters; no client-supplied
      confirmation flag is trusted.
- [ ] Runtime-discovered servers and tools require signed provenance or an
      allowlist entry, and tool descriptions are treated as untrusted input.
- [ ] Invocations and denials are recorded reconstructably in a store the
      caller cannot rewrite, with values reduced to shapes and digests.

### Django & DRF

- [ ] The tool surface does not run under a service account or superuser token
      that makes `request.user` something other than the invoking human.
- [ ] For every viewset exposed as a tool, `authentication_classes`,
      `permission_classes`, `filter_backends`, `pagination_class`,
      `throttle_classes`, and the serializer field sets are each set
      explicitly on the tool path.
- [ ] If `django-mcp-server` is installed, all four of its default-disabled
      controls are re-enabled and `self.paginator` is not `None` on a list tool.
- [ ] If `django-rest-framework-mcp` is installed,
      `BYPASS_VIEWSET_AUTHENTICATION`, `BYPASS_VIEWSET_PERMISSIONS`, and
      `RETURN_200_FOR_ERRORS` are all off.
- [ ] No admin-exposing or shell-exposing MCP package is installed in
      production.
- [ ] Tool routes appear in the URLconf audit test and in the authorization
      test matrix as their own rows, not as assumed inheritance from the HTTP
      route.
- [ ] Throttles on tool paths key on the resolved identity, never on IP.
