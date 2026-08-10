# The Audit Workflow

This file owns **how a codebase is swept**: the phase order, what each phase
hands the next and the coverage property that closes it, the entry-point
inventory, the principal and trust-boundary model, hypothesis generation and
the order the work runs in, the budget rule for a tree too large to read
closely, the coverage ledger, and the attack-chain reasoning that turns several
confirmed links into one finding. It owns no vulnerability and no control —
every phase names the reference that owns the rules for whatever it turns up.

`00-methodology-and-severity.md` owns the other half: how a finding is scored
and written, which is the severity rubric, the confidence scale, the finding
schema, the ASVS mapping, the report structure, and the standing write-time
contract. The split is procedural against evaluative. This file decides what
gets opened and in what order; that one decides what an opened file is worth
once something turns up in it. Neither works alone — a sweep with no scoring
model produces a list nobody can prioritize, and a scoring model with no sweep
scores only what someone happened to look at. `SKILL.md` owns the router that
sends you to the topic files both of them point at.

## Contents
- [Principle](#principle)
- [Phase 0 — scope, mode, and what the repository cannot tell you](#phase-0--scope-mode-and-what-the-repository-cannot-tell-you)
- [Phase 1 — entry-point inventory](#phase-1--entry-point-inventory)
- [Phase 2 — principals and trust boundaries](#phase-2--principals-and-trust-boundaries)
- [Phase 3 — sources to sinks](#phase-3--sources-to-sinks)
- [Phase 4 — hypothesis generation and ordering](#phase-4--hypothesis-generation-and-ordering)
- [Phase 5 — verification](#phase-5--verification)
- [Phase 6 — the coverage ledger](#phase-6--the-coverage-ledger)
- [Attack-chain reasoning](#attack-chain-reasoning)
- [Mapping to the OWASP Testing Guide](#mapping-to-the-owasp-testing-guide)
- [Write-time: the inventory run forward](#write-time-the-inventory-run-forward)
- [Review checklist](#review-checklist)

## Principle

A review is bounded by what the reviewer thought to open. Depth of analysis,
quality of fix, and accuracy of severity are all properties of code that was
read, and none of them says anything about the route nobody enumerated. So the
sweep is built inventory-first: establish the complete set of places where
execution begins on input the application did not author, and derive the work
from that set rather than from the files that looked interesting.

Three consequences make this a procedure rather than advice.

- **Coverage has to be recorded, not felt.** An unexamined surface and a clean
  one read identically in a report that does not separate them, and the reader
  will assume the second. The ledger in phase 6 exists to keep the difference
  visible.
- **Order is a decision with a cost.** Time spent on a low-yield class is time
  not spent on the authorization surface. The default order in phase 4 is the
  one that finds the most per file read in a Django codebase, and departing
  from it should follow from something specific that was seen rather than from
  a keyword that matched.
- **A phase ends on a property of its coverage, not on a quantity of reading.**
  Each phase below hands the next one a written artifact — the scope statement
  and the environment questions, the inventory, the principals and boundaries,
  the source-to-sink pairs, the ordered hypotheses, the dispositions — and is
  finished when that artifact is complete over the surface the previous phase
  named, rather than when some number of files have been read. A phase that
  hands forward an impression instead of an artifact makes the next one
  re-derive it by re-reading, and re-derivation is how a sweep narrows onto
  whatever was re-read.

## Phase 0 — scope, mode, and what the repository cannot tell you

Settle three things before reading application code: which mode is running,
what the tree contains, and where the tree stops.

Mode decides the output rather than the sweep. Review-time runs the phases
below over code that exists and ends in a findings report; write-time runs the
same inventory questions forward over code that does not exist yet. Both are
defined in `00-methodology-and-severity.md`, "Choosing the mode", and the
forward form is at the end of this file.

Scope is the set of directories, apps, and services in front of you, stated
before the sweep rather than inferred from it afterwards. Where a service the
application depends on is outside it, that is a scope decision and belongs in
the ledger — not a gap discovered at write-up time.

The phase hands forward the scope statement and the list of
confirm-with-operator questions below, and it is finished when every dependency
a finding might rest on has been placed on one side of the repository boundary
or the other. Not when the settings module has been read: the settings module
is where this phase looks, and the question is about what is not in it.

### Principle layer

The third question is the one that produces wrong findings, and it fails in
both directions:

- **Absence in the repository is not evidence of absence in production.** No
  rate limit in the code does not mean no rate limit runs; the gateway in
  front of the application may enforce one. Reporting the absence as a finding
  asserts something about a system that was never read.
- **An assertion in the repository is not evidence of presence.** A comment
  saying the proxy strips the header, a README describing a WAF rule, a
  setting named `ENFORCE_TENANT_ISOLATION` — none of these is the control.
  Each is a claim about a control, made by someone who may have been right on
  the day they wrote it.

Both errors have one fix. Name the thing, say which side of the boundary it
sits on, and record it as a question addressed to whoever operates that side,
written together with the answer that would settle it. A question is an honest
output. A finding resting on an assumption is not, and neither is silence,
because silence is read as a pass.

### Django & DRF implementation layer

`a03-software-supply-chain.md`, "The artifact boundary" already draws this
line for the build pipeline and states the form the output takes. The rows
below extend the same rule to the rest of the environment rather than
restating it. Each row that matters to a finding is carried as
confirm-with-operator; none of them is assumed in either direction.

| Not in the tree | The question that settles it |
|---|---|
| Reverse-proxy and ingress configuration, where it is not committed | How many proxies sit in front of the application, and which forwarded headers does the edge strip and re-set? `deployment-and-runtime.md`, "Reverse proxy and forwarded headers" states what the answer has to be for a client IP to mean anything |
| WAF and API-gateway rules | Which authentication, filtering, and rate limits apply before a request reaches Django, and does any of it fail open when the edge is bypassed? `a06-insecure-design.md`, "Rate limiting and anti-automation" |
| Object-store bucket policy and public-access settings | Is the bucket reachable anonymously, and does a policy or ACL grant more than the application's own credential does? `file-uploads.md`, "Object storage configuration" |
| Orchestrator and deployment-platform state | Does anything at deploy time enforce the posture the image only declares — the non-root user, the read-only filesystem, the dropped capabilities? `deployment-and-runtime.md`, "Container images" |
| Secret-manager contents and the values actually injected | Does the running process receive the values the settings module reads, and was any of them ever committed to this history? `service-identity-and-secrets.md`, "Where secrets live and how they reach the process" |
| Registry and CI runner state | Is the signature or attestation present beside the image, and does anything block a rollout without one? `a03-software-supply-chain.md`, "The artifact boundary" |

**Write-time.** When generating code whose correctness depends on something
outside the repository — a header the proxy is trusted to set, a bucket the
policy is trusted to keep private, an environment variable that has to exist —
write the dependency as a startup check or a comment at the site in the same
edit, and carry it into the security-decisions note as caller-owned, because
an assumption held only in the author's head is indistinguishable at review
time from an oversight.

## Phase 1 — entry-point inventory

This is the operational core of the sweep. Everything after it is derived from
it, and everything before it is preparation for it.

### Principle layer

An entry point is any place where execution begins on input the application
did not author: a request, a message, a schedule, a signal, a console
invocation. Enumerate by construct rather than by convention, because the
families that get missed are the ones that do not look like a view — a task
consuming a queue, a command an operator runs, a receiver firing on a save.

Three rules keep the inventory honest.

- **Enumerate from the declaration, not from the documentation.** A generated
  schema, an API reference, and a README each describe what someone pointed
  them at. The declaration is what runs.
- **Resolve to the full path, not the leaf pattern.** A route is the
  concatenation of every prefix an `include()` chain contributed, and the leaf
  module is the one file that does not contain that information.
- **A family with no members is a recorded result.** "No Channels routing in
  this project" belongs in the ledger. "Channels not mentioned" does not,
  because the next reader cannot tell it apart from an oversight.

### Django & DRF implementation layer

Each row is a family, where a Django project declares it, what finds it, and
the reference that owns its rules. The rules are not repeated here; the point
of the row is that the family was looked for at all.

| Family | Declared in | Find it with | Rules |
|---|---|---|---|
| URLconf routes | `ROOT_URLCONF` and every module an `include()` chain reaches | `path(`, `re_path(`, `include(`, `format_suffix_patterns` | `authorization-architecture.md`, "Default-deny architecture" |
| DRF routers, viewsets, and views | a `urls.py` that constructs a router; the view modules it names | `DefaultRouter`, `SimpleRouter`, `.register(`, `ViewSet`, `APIView`, `GenericAPIView` | `api-drf-specific.md`, "Where the object check runs, and the routes that skip it" |
| Viewset actions, including `detail=False` | the viewset body, not the router | `@action(` | `api-drf-specific.md`, "Function-level authorization on actions (API5)" |
| Django Ninja operations | the module that constructs `NinjaAPI()` or a `Router()` | `NinjaAPI(`, `Router(`, `@api.`, `@router.` | `graphql-and-alternative-api-surfaces.md`, "Django Ninja: nothing is authenticated by default" |
| GraphQL fields and resolvers | the schema module and every type it composes | `strawberry.type`, `ObjectType`, `Mutation`, `resolve_`, `DjangoObjectType` | `graphql-and-alternative-api-surfaces.md`, "Resolver authorization: a check at the root is not a check" |
| gRPC methods | the servicer class, and the `service` blocks in the `.proto` behind it | `grpc.server(`, `_Servicer_to_server`, `service ` in `*.proto` | `graphql-and-alternative-api-surfaces.md`, "gRPC: nothing from the DRF request cycle applies" |
| Channels consumers | `ASGI_APPLICATION` and the routing module it reaches | `ProtocolTypeRouter`, `URLRouter`, `Consumer`, `websocket_urlpatterns` | `async-and-channels.md`, "WebSocket authentication and origin validation" |
| Celery tasks and beat schedules | task modules, `beat_schedule`, and the `PeriodicTask` rows a database scheduler holds | `@shared_task`, `@app.task`, `.delay(`, `.apply_async(`, `beat_schedule` | `a08-integrity-and-deserialization.md`, "Celery and task queues" |
| Management commands | `<app>/management/commands/` | `BaseCommand`, `add_arguments`, `call_command(` | `a05-injection.md`, "OS command injection" |
| Signals and lifecycle hooks | `signals.py` and whatever `AppConfig.ready()` imports | `@receiver`, `post_save`, `pre_delete`, `m2m_changed`, `.connect(` | `a09-logging-and-alerting.md`, "Lifecycle hooks and audit guarantees" |
| Admin registrations, custom admin views, and admin actions | `admin.py`, plus any `get_urls()` override | `admin.register`, `ModelAdmin`, `get_urls`, `actions =`, `@admin.action` | `authorization-architecture.md`, "Django admin: the permission surface"; exposure of the surface itself in `a01-broken-access-control.md`, "Admin exposure" |
| Inbound webhook receivers | a URLconf route that authenticates nothing because the sender cannot log in | `csrf_exempt`, `AllowAny` on a POST route, `request.body` | `a08-integrity-and-deserialization.md`, "Webhook and callback integrity" |
| MCP tools published over the application | the tool-registration module, and any viewset it republishes | the integration package's registration decorator or `ModelAdmin`-style class, plus every viewset it names | `agent-and-llm-interfaces.md`, "What survives when a DRF view is republished as a tool" |
| Middleware | `MIDDLEWARE`, in order | `MIDDLEWARE`, `__call__`, `process_view`, `process_exception` | `authorization-architecture.md`, "Default-deny architecture" |

Middleware is the family most often left out of an inventory, and it is the
one that is an entry point for every request at once. Read it in declared
order: a component above the authentication middleware runs for anonymous
traffic, one that returns a response short-circuits everything below it, and
one that writes to `request` establishes a value every view underneath it
treats as trustworthy.

The include chain is the other recurring miss, because the grep that finds the
route is not the file that defines it:

```python
# The chain, in three files. Only the third holds a `path(` that a grep will
# land in, and it is the one file that cannot tell you what the route is.

# config/urls.py
urlpatterns = [path("internal/", include("ops.urls"))]

# ops/urls.py
urlpatterns = [path("v2/", include("ops.api.urls"))]

# ops/api/urls.py
urlpatterns = [path("reports/<int:pk>/", ReportView.as_view())]

# Wrong: the inventory records "reports/<int:pk>/", which is not a route and
# is indistinguishable from the public reports route three apps away.
# Correct: the inventory records "internal/v2/reports/<int:pk>/", which is
# what an attacker sends. Resolving the chain is also what catches a second
# mount -- an include() left under an older prefix serves the same view twice,
# and only the resolved form lists both entries.
```

`scripts/entrypoint_inventory.py` is the instrument for this phase. It parses
every module in the tree and reports the families above as declarations:
routes resolved through the include chain to their full prefix, router
registrations at the prefix they are actually mounted on, actions with whatever
the decorator declares, and, given `--settings`, `MIDDLEWARE` in declared
order. Every HTTP-reachable row says whether authorization is declared at the
site, inherited from a base class or a framework default and therefore not
visible there, or absent — the second and third are different facts and the run
keeps them apart. Its closing line names the families found and the families
looked for and not found, which is what phase 6 records. Confirm what it
surfaces by reading the code; the run is a starting set for the phase, not the
phase's output.

It finds declarations, and only declarations. A route registered at runtime — a
URLconf assembled in a loop, a viewset built by a factory, a tool registered
from a table when the app loads — is written nowhere a parser can see it, so it
appears in no run and in no diff of two runs. That is the residual gap this
phase closes by reading, and it is the reason the first rule above is to
enumerate from the declaration: a tool that reads declarations tells you what
was declared, and the question of what else runs is still yours.

The served OpenAPI schema is not the inventory. `api-drf-specific.md`,
"Endpoint inventory (API9)" owns that point together with the three techniques
behind it and the diff that makes a schema useful at all — anything in the URL
map that is not in the schema is a shadow-endpoint candidate. Take it from
there rather than re-deriving it here.

The phase hands every later phase its list, and it is finished when every
family in the table has a recorded result — members enumerated at their
resolved paths, or the family recorded absent. It is not finished when the
routes look complete. Routes are the family a reviewer finds without trying,
and a sweep that stops at them has enumerated the surface it was already going
to read.

**Write-time.** When adding a route, a task, a consumer, a command, a
receiver, or a tool, name which family it joins before writing the body, and
write that family's access rule in the same edit that makes it reachable,
because a family is chosen at the moment the decorator is typed and every
control that applies to the new code follows from which one it was.

## Phase 2 — principals and trust boundaries

An entry point is only half of the question. The other half is who arrives at
it, and the useful form of that question is not "is this authenticated" but
"what proves the caller is this principal, and what does being it reach".

### Principle layer

Enumerate the principals the application actually distinguishes, not the ones
its documentation names. A principal the code cannot tell apart from another
is not a principal; it is a comment. Then enumerate the boundaries, which are
the places where something crosses from one trust domain into another and the
crossing is where a check either exists or does not.

`authorization-architecture.md` owns the privilege model these principals are
expressed in, including which of RBAC, ABAC, and ReBAC fits, and
`privileged-access-and-impersonation.md` owns operator identity.

### Django & DRF implementation layer

| Principal | What proves it is this one | What being it reaches |
|---|---|---|
| Anonymous | nothing; it is the absence of a credential | every view that stated no rule, since DRF's own default is `AllowAny` — `api-drf-specific.md`, "Unsafe DRF defaults, enumerated" |
| Authenticated user | a session cookie or a token that resolved to a user row | the authenticated surface, and nothing about ownership — `a01-broken-access-control.md`, "IDOR / BOLA" |
| Tenant member | a stored relationship between the user row and the tenant, never a header, a body field, or a subdomain the client chose | the tenant's rows, if and only if every queryset says so — `a01-broken-access-control.md`, "Multi-tenancy and data isolation" |
| Staff | the `is_staff` boolean | admin login and every check written as `IsAdminUser`, which is a much larger set than most projects intend |
| Superuser | the `is_superuser` boolean | everything, because `has_perm` short-circuits before any backend runs — `authorization-architecture.md`, "Django's permission layer: what it actually does" |
| Service account | a machine token, a client certificate, or a platform workload identity | whatever its scope says, which is frequently the whole API — `service-identity-and-secrets.md`, "Choosing a machine-authentication mechanism" |
| Agent or tool caller | a token whose audience is this application, plus the end user it is acting for | the intersection of the tool's scope and that user's permissions, never the union — `agent-and-llm-interfaces.md`, "Effective authority: tool scope intersected with user permissions" |
| Worker consuming a queue | nothing at all; possession of broker access is the entire credential | whatever the task body does, under whatever database role the worker holds — `a08-integrity-and-deserialization.md`, "Celery and task queues" |
| Operator through impersonation | two identities at once, the operator who initiated and the subject being acted as | the subject's surface, with the operator's accountability — `privileged-access-and-impersonation.md`, "Impersonation: design requirements" |

| Boundary | What has to hold at the crossing |
|---|---|
| Client to view | authentication resolves a principal and authorization is decided from it, not from an identifier in the request — `a01-broken-access-control.md`, "Principle" |
| View to ORM | the queryset is scoped by the principal before a lookup runs, rather than filtered after one — `authorization-architecture.md`, "DRF: where the object check actually runs" |
| Model to serializer | the fields crossing outward are an allowlist and the writable ones exclude anything the server owns — `api-drf-specific.md`, "Serializer exposure and mass assignment (API3)" |
| Request to background task | the task re-derives tenant and permission from arguments it can verify, instead of inheriting the request's authority by assumption — `data-layer-and-database.md`, "Tenant context on a pooled connection" |
| Application to broker | a task message is input from anyone who can reach the broker, and the serializer decides whether that input can construct objects — `a08-integrity-and-deserialization.md`, "Celery and task queues" |
| Application to object store | the key is server-chosen, the bucket is not public, and a signed URL binds what it is supposed to bind — `file-uploads.md`, "Object storage configuration" |
| Application to a third party | the outbound destination is allowlisted after DNS resolution, and the response is untrusted input on the way back — `a01-broken-access-control.md`, "SSRF" |
| Proxy to application | the number of trusted hops is known, and the client IP is read from the position that survives a forged header — `deployment-and-runtime.md`, "Reading the client IP" |

The phase hands phase 4 a principal set and the boundaries each entry point
crosses, and it is finished when every entry point from phase 1 has at least
one principal named against it — including the ones whose answer is anonymous,
since that is both the answer nobody writes down and the one that most often
turns out to be wrong.

**Write-time.** When generating an endpoint, a task, or a tool, write down
which principals can reach it before writing its body, and derive tenant,
owner, and role from the authenticated identity in that same edit, because a
principal that is not distinguished at the moment the handler is written
cannot be distinguished by any check added later without changing the handler.

## Phase 3 — sources to sinks

`a05-injection.md`, "Tracing input to a sink" owns the method, and the
inventory in that section is the sink map for the whole sweep, not for the
injection topic alone. It is complete by design so that nothing needs a
partial copy; read it there and walk it once per entry point.

What belongs to the sweep rather than to that file is the pairing rule, which
decides how much of the result is worth carrying forward:

- **A sink with no source reaching it is not a finding.** A `subprocess` call
  with a constant argument vector is a grep hit, and reporting it teaches the
  reader to distrust the rest of the report.
- **A source with no sink is a validation question, not an injection one.** It
  belongs to the bound that the flow needs, not to this phase — see
  `a06-insecure-design.md`, "Algorithmic resource exhaustion".
- **The second-order path is found as two unrelated hits unless the stored
  field is tracked on purpose.** The writer contains no sink and the reader
  contains no request, so each half reviews clean. Carry the field name
  forward from phase 1 as a source in its own right; that is the only thing
  the two halves have in common.
- **The middle of the path is retrieved, not inferred from the two ends.** A
  view that calls a service that calls a helper is three files, and the
  construction that decides the question is in whichever of them nobody opened.
  Open each function between the entry point and the sink and read the call it
  makes, because the defect that survives a review is the one whose two ends
  each look correct in isolation — the parameter is validated where it arrives
  and the sink is called with a variable that looks local, and the layer that
  joined the two is where it stopped being data.

The phase hands phase 4 the source-to-sink pairs, and it is finished when every
entry point from phase 1 has been walked once against that inventory —
walked, and recorded as reaching no sink where it reaches none. An entry point
that paired with nothing and an entry point nobody walked are the same blank
line in any record that does not distinguish them.

**Write-time.** When generating code that writes a value to a model field
another process will later hand to an interpreter, constrain the field where
it is written and keep the value as data where it is read, in the same change,
because the writer and the reader are edited on different days and by then
neither side shows the other.

## Phase 4 — hypothesis generation and ordering

Generate candidates per entry point rather than per keyword. For each route,
task, consumer, or tool from phase 1, ask what it would take for this specific
one to fail: which principal from phase 2 is missing a check, which sink from
phase 3 it reaches, which of its parameters the server should own. A keyword
sweep produces leads that are already sorted by how common the keyword is; an
entry-point sweep produces leads sorted by nothing, which is why they then
need ordering.

Order by expected impact against effort to confirm. The default:

1. **Object- and function-level authorization.** First because it is the
   highest-yield class in Django codebases and among the cheapest to settle —
   the queryset and the permission list are usually two files, and the answer
   is either in them or absent from them.
2. **Authentication and session handling.** Second because a failure here
   invalidates the authorization work above it, but confirming it usually
   means reading a settings module and a backend rather than a data path.
3. **Injection at the sinks phase 3 paired.** Third because the pairing has
   already been done, so what remains is reading the construction at each
   site.
4. **Flows that move money, entitlements, or state.** Fourth because the
   impact is unambiguous but confirmation costs the most: it means reasoning
   about ordering, concurrency, and retries rather than reading a declaration.
5. **Configuration and deployment posture.** Last because much of it is
   confirm-with-operator from phase 0, and because a settings finding is worth
   less than an authorization finding on the same application.

The order is a default, not a gate. A surface carrying a known-weak pattern
jumps the queue on sight: a viewset with `queryset = Model.objects.all()` and
a `pk` in its route, a `@shared_task` that takes a tenant id as an argument,
a `.proto` served with no interceptor, a signed cookie read with no salt. Note
the jump in the ledger so the phases that were deferred are visibly deferred
rather than quietly skipped.

The phase hands phase 5 an ordered list of hypotheses, each attached to an
entry point rather than to a keyword, and it is finished when every entry point
from phase 1 has been triaged: a hypothesis was generated against it, or it was
recorded as generating none. Triaged is not investigated. Investigation is
phase 5, it is the expensive half, and on a large tree it is the half that runs
out.

### Budget on a large tree

A tree with more entry points than can be read closely forces a choice about
where the reading goes. The failure is not choosing badly, it is choosing
silently — a partial audit delivered in the shape of a complete one, with
nothing on the page that lets the reader tell. Two rules keep the choice
visible.

**Enumerate exhaustively, read selectively.** Phase 1 is cheap because it reads
declarations rather than logic, so it is completed over the whole tree whatever
the size, and it is the one thing never sampled: a family nobody enumerated
cannot be sampled from, only missed. What gets rationed is the close reading in
phases 3 and 5, and the ration is per area — a bounded pass over each area the
inventory named, before an unbounded one over any single area. The reason is in
this phase's own premise. An entry-point sweep produces leads sorted by
nothing, so the first interesting one is not the most valuable one, and a
budget spent confirming it is spent before anything else has been priced. Treat
that as a preference with a reason rather than as a gate — a lead already most
of the way to confirmed is worth finishing — but the default runs breadth
first, because depth first on the first lead is the shape a review takes when
nobody decided.

**A sample is recorded as a sample.** Where a family is large and repetitive —
forty viewsets over one base class, a hundred tasks in one module — read the
base class, the shared defaults, and a named subset of members, then write into
the ledger which members were read and on what basis they were chosen. The
ledger does not prevent a sample being substituted for a sweep and is not meant
to; what it does is make the substitution legible, so that the reader sees
twelve of eighty-three viewsets read as the ones carrying a `pk` in the route,
rather than a findings list that reads as though all eighty-three were opened.

## Phase 5 — verification

This phase is written as a gate rather than as advice, because pattern
matching is the cheap operation and restraint is the expensive one. A report
carrying four real findings and eleven confident wrong ones is worse than no
report: the reader cannot tell which four, so they stop trusting all fifteen
and the four that mattered are lost with the rest.

### The discharge gate

A hypothesis is promoted to a finding only after each of the six below has been
**discharged and recorded** — what was read and what it showed — rather than
assumed. The record is what a later reader needs in order to disagree with the
finding, and a discharge nobody wrote down is indistinguishable from one that
never happened.

Recorded means the retrieved text, not remembered behavior. Name the file the
discharge rests on and quote the line it turns on, because a claim about what a
decorator, a base class, or a library function does, made without opening it,
is how a report comes to describe code the project does not contain. That
failure costs more than the finding was worth. One citation a reader checks and
cannot find turns every other line in the report into something they now have
to confirm by hand, and the findings that were real go down with the one that
was not.

- **Attacker control.** Name the principal that supplies the value, the
  parameter it arrives in, and the route it arrives on. All three, by name. A
  value that only a deploy-time configuration sets is not attacker-controlled,
  and a hypothesis that cannot name the three is not yet describing an attack.
- **Reachability.** The route resolves through its `include()` chain, the
  permission classes in force admit the principal, and no earlier guard —
  a middleware, a `dispatch` override, a scoped `get_queryset` — returns
  first. A view that no URLconf reaches is dead code, and dead code is a
  hygiene note rather than a finding.
- **Protections examined.** Identify the framework behavior that should have
  stopped this, and show it absent, disabled, or insufficient. ORM
  parameterization, template autoescaping, `ALLOWED_HOSTS`, the CSRF
  middleware, `safe_join`, the storage API, DRF permission and throttle
  classes, and a serializer's declared field set all exist by default, so a
  finding that does not say why the default failed here is not finished.
- **Sanitization insufficiency.** Where validation or scoping is present, show
  the specific input it does not cover or the path that skips it. That the
  validation looks thin is an impression, not a discharge.
- **Concrete impact.** Which data, whose privilege, which money, which
  account. A sentence that could be pasted into any finding is not an impact
  statement.
- **Benign patterns ruled out.** The catalogue below, and the one carried by
  the topic reference that owns this control, were both consulted and the case
  in hand is not one of them.

Then dispose of the hypothesis, and the three outcomes are not
interchangeable:

- **Discharges all six — a finding.** Write it up against the schema in
  `00-methodology-and-severity.md`, "Finding schema".
- **Discharges everything but reachability — a "worth checking" item**, naming
  the exact thing that would settle it: the settings value, the URLconf, the
  permission default the deployment actually runs. Not a finding written with
  a hedge in it.
- **Fails attacker control, or matches a benign pattern — dropped**, and not
  mentioned anywhere. A dropped hypothesis is not a caveat: a list of things
  that turned out to be fine is padding, and it pushes the findings that
  survived down the page.

The phase hands the write-up those dispositions, and it is finished when every
hypothesis phase 4 ordered carries one of the three. One left in none of them
is the hypothesis that reaches the report as a hedge, which is the form this
gate exists to keep out.

Every finding carries the shortest source-to-sink path it was actually
confirmed on and the specific protection that failed. Two lines, not a
narrative — the path is the parameter, the call that carries it, and the sink;
the protection is the one named above together with the reason it did not
apply here. `00-methodology-and-severity.md`, "Finding schema" owns where that
goes in the write-up, and the baseline table beside it owns what the confirmed
class is worth.

### Commonly mistaken for a finding

The general rule first, because it generates the cases rather than following
from them: **a pattern is judged by the property that makes it dangerous, not
by the identifier that names it.** `raw`, `pickle`, `mark_safe`, `shell=True`,
and `random` each name a mechanism. The danger is a specific property of the
use — a statement built by interpolation, bytes a second principal can write,
markup assembled from a request, an argument that varies, a value that has to
be unguessable. Where the property is absent, the identifier is just an
identifier.

Four cases are cross-cutting and belong to no single topic file:

- **Dead code.** A view, task, or handler nothing reaches looks exactly like a
  reachable one, and it is where an unreachable defect is easiest to write up
  with confidence. What decides it is whether a URLconf, a router
  registration, a beat schedule, or a caller reaches it; where nothing does,
  it is a hygiene note saying so.
- **A control enforced in a layer you did not open.** A view with no
  `permission_classes` under a restrictive project default, a queryset that
  reads unscoped over a manager that scopes, a header set at the proxy rather
  than in Django. What decides it is reading the settings module, the manager,
  and the middleware list before concluding the control is missing — the
  per-file catalogues named at the end of this section carry the specific
  pairs.
- **Test, fixture, and factory code.** A hardcoded credential, `AllowAny`,
  `DEBUG = True`, or a disabled certificate check inside `tests/`,
  `conftest.py`, or a factory. What decides it is whether the production
  import chain or a production route reaches that module, which is a question
  about imports rather than about the line.
- **A defense-in-depth gap written up as an exploit.** A missing header, a
  short-lived token that does not rotate, a permissive default no route
  actually inherits. What decides it is whether there is an attacker action
  the gap enables today. Where there is not, it is a Low that says so, and
  inventing the chain that would make it a High is the failure this phase
  exists to stop.

The rest sit beside the controls they qualify, under this same heading, in the
references that own them: `a05-injection.md` for the SQL, shell, template, and
dictionary-expansion cases, `a01-broken-access-control.md` for scoping, SSRF,
and path joins, `a02-security-misconfiguration.md` for the settings modules a
production entry point never imports, `a08-integrity-and-deserialization.md`
for who can write the bytes a deserializer reads, `api-drf-specific.md` for
permission defaults, CSRF, and serializer field sets, and
`a04-cryptographic-failures.md` for the uses of `random` that need no
unguessability at all.

## Phase 6 — the coverage ledger

The ledger is working state the sweep populates as it goes and reports at the
end. Its one job is to keep *examined and clean* distinguishable from *not
examined*, because a report that conflates them is a report that says nothing:
the reader takes silence for coverage, and the surface nobody opened is the
one the next incident comes from.

Write it down as the sweep goes and read it back at each phase boundary rather
than carrying it in your head. Attention over a long input is a budget rather
than a constant: material in the middle of a long context is used measurably
less reliably than the same material near either end, and reliability falls
further as the input grows whatever position the material holds — which is the
condition a sweep of a real codebase has produced by the time it reaches phase
5. So phase 4's ordering is re-derived from what the ledger records rather than
from whatever the last few files made salient, and a family it still lists as
unexamined stays on the list even when nothing has referred to it for a long
while. A review that narrows late narrows towards what it read most recently,
and the written ledger is the only thing still holding what it did not read.

Five dimensions, each recorded as a count or a list rather than as a
judgement:

- **Entry-point families** examined against families found, from phase 1,
  including the families found to be absent.
- **Authorization surfaces exercised** — object, function, field, and tenant,
  each separately, because a sweep that checked object-level scoping on every
  route has still said nothing about field-level exposure.
- **Data-lifecycle paths walked** — delete, erasure fan-out, retention,
  export — since these are the paths a route-driven sweep does not reach.
- **Reference files loaded**, which is the honest record of which rule sets
  were actually applied rather than recalled.
- **Explicit non-goals** for this pass, stated as decisions rather than as
  omissions.

```
Coverage ledger
- Entry-point families: 14 looked for, 9 present, 8 examined. Not examined:
  the Celery beat schedule, which is defined in a deployment chart this
  repository does not contain.
- Routes: 61 resolved from the URLconf, 58 in the generated schema, 3 shadow
  candidates carried into the findings.
- Authorization surfaces: object yes, function yes, field yes, tenant
  partially -- the reporting app was read, the export app was not.
- Data-lifecycle paths: delete yes, erasure fan-out no, retention no.
- References loaded: 01-audit-workflow, a01, a05, api-drf-specific,
  authorization-architecture, a08.
- Non-goals this pass: the frontend, the Terraform module, and the vendored
  SDKs under third_party/.
```

The ledger is working state, not report structure. At write-up it collapses
into the fourth section of the report, whose shape
`00-methodology-and-severity.md`, "Report structure" owns. Every line that
reads *not examined* becomes a line there; every line that reads *examined and
clean* stays out of it, because a limitations section that lists what was read
buries the two lines that matter.

**Write-time.** When generating a feature that adds an entry point, record the
family it joined and the principals that reach it in the security-decisions
note whose shape `00-methodology-and-severity.md`, "The security-decisions
note" owns, because the next review starts from an inventory and a surface
introduced without one is the surface that inventory will be missing.

## Attack-chain reasoning

When an issue is confirmed, the question before writing it up is what it
enables next. Most real compromises are three cheap defects in sequence, and
each of the three, rated alone, is a Medium nobody schedules.

Rate the chain, not the link. A chain is reported as **one finding at the
severity of its outcome**, with the links named in order inside it, rather
than as several low-severity findings that read as unrelated and get closed
one at a time. Where a link is confirmed and the next one is only plausible,
say so at that link rather than downgrading the whole chain — the reader needs
to know which hop is the assumption.

The chains worth searching for, with the file that owns each hop:

| Chain | The links, in order | Files that own the hops |
|---|---|---|
| Enumeration into takeover | a login, reset, or signup response that distinguishes a known account; credential stuffing at whatever rate the endpoint permits; a session | `a07-authentication-failures.md`, "Brute force and enumeration"; `a06-insecure-design.md`, "Rate limiting and anti-automation"; `a07-authentication-failures.md`, "Sessions" |
| IDOR into a credential | an object read the requester should not have reached, whose serialized form carries an API key, an invite token, or a tenant identifier that is itself an authorization input | `a01-broken-access-control.md`, "IDOR / BOLA"; `api-drf-specific.md`, "Serializer exposure and mass assignment (API3)"; `authorization-architecture.md`, "Field-level authorization (BOPLA)" |
| SSRF into the object store | a server-side fetch on a caller-influenced URL; the cloud metadata endpoint; a workload credential; the bucket that credential can read | `a01-broken-access-control.md`, "SSRF"; `service-identity-and-secrets.md`, "Choosing a machine-authentication mechanism"; `file-uploads.md`, "Object storage configuration" |
| Soft delete through a relation | a row flagged deleted but still present, reached through a serializer that traverses a related object rather than through the manager that filters | `data-lifecycle-and-privacy.md`, "Soft delete and what it does not hide"; `api-drf-specific.md`, "Serializer exposure and mass assignment (API3)" |
| A won race a later step trusts | concurrent requests past a limit, quota, or balance check; a downstream step that treats the resulting state as validated | `a10-exceptional-conditions.md`, "Races, TOCTOU, and adversarial sequencing"; `api-drf-specific.md`, "Throttling as quota, not security (API4)" |
| Webhook into an entitlement | an inbound callback that is unsigned, or signed but replayable; a state transition that grants a plan, a credit, or a role | `a08-integrity-and-deserialization.md`, "Webhook and callback integrity"; `a10-exceptional-conditions.md`, "Idempotency" |
| A job more privileged than its caller | a task queued by a request; a worker that runs as a service account and never re-derives the tenant or permission the request had | `a08-integrity-and-deserialization.md`, "Celery and task queues"; `data-layer-and-database.md`, "Tenant context on a pooled connection" |
| A version left behind | an old API version still routed; a permission class or queryset scoping that never received the fix the current version did | `api-drf-specific.md`, "Versioning and deprecation lifecycle"; `a01-broken-access-control.md`, "Function-level authorization" |
| Impersonation with half an audit trail | an operator acting as a user; a record naming the operator but not the subject, or the subject but not the operator | `privileged-access-and-impersonation.md`, "Impersonation: design requirements"; `a09-logging-and-alerting.md`, "Log the right security events" |

**Write-time.** When generating the second step of a flow — the handler that
consumes a token another endpoint issued, the worker that acts on a row a
request created, the callback that completes a purchase — state what that step
re-verifies rather than inherits, in the same edit, because a chain is built
out of steps each of which was correct on the assumption that the previous one
had already checked.

## Mapping to the OWASP Testing Guide

The Web Security Testing Guide answers a third question, and the three do not
substitute for one another. The Top 10 ranks what goes wrong most often, and is
the spine the topic references are arranged on. ASVS enumerates what has to be
demonstrably true before someone signs the application off, which
`00-methodology-and-severity.md` maps at chapter level because that is an
output-side question. The WSTG says **how to go and look**, which is the
input-side question this file owns, and that is why the mapping is here: the
guide is the closest published counterpart to the phases above, written for
someone exercising a running target rather than reading a repository. The
difference between those two positions is what most of this section is about.

**Map at section level, and cite nothing finer.** The guide's own referencing
guidance states that its test identifiers may change between versions, and
tells anyone citing one to carry the version inside the identifier — the
`WSTG-v42-INFO-02` form rather than a bare `WSTG-INFO-02`, because a bare
identifier is read as naming the current content, which is not the content it
named on the day it was written. That is the same defect the ASVS mapping
avoids by citing chapters instead of requirement numbers, and it has the same
answer: a section name stays correct for as long as the section exists. The
current stable release is v4.2 and v5.0 is in development as of 10 August 2026;
shipping v5.0 renumbers identifiers and is the event that requires this table to
be redone.

Chapter 4, "Web Application Security Testing", is the only chapter carrying
material a source reviewer can act on. Its twelve sections:

| WSTG v4.2 section | Where this skill covers it |
|---|---|
| 4.1 Information Gathering | Phase 1 above is the source-side form of identifying entry points; `a02-security-misconfiguration.md` for what a debug or verbose setting publishes, `deployment-and-runtime.md` for an operational endpoint left reachable. Partial — the fingerprinting tests need a running target |
| 4.2 Configuration and Deployment Management Testing | `a02-security-misconfiguration.md` for what a settings module or a DNS zone declares, including the dangling record behind a subdomain takeover; `deployment-and-runtime.md` for the proxy, the process, and the image; `file-uploads.md` for object-storage exposure. Partial — see below |
| 4.3 Identity Management Testing | `a07-authentication-failures.md` for registration, provisioning, and enumeration; `authorization-architecture.md` for the privileges a new account is given |
| 4.4 Authentication Testing | `a07-authentication-failures.md` for the human principal; `service-identity-and-secrets.md` for the machine one |
| 4.5 Authorization Testing | `a01-broken-access-control.md` for the per-request failure, `authorization-architecture.md` for the model behind it, `api-drf-specific.md` for the call sites where a correct model still fails to run |
| 4.6 Session Management Testing | `a07-authentication-failures.md` for sessions and fixation; the cookie and CSRF matrix in `a02-security-misconfiguration.md` |
| 4.7 Input Validation Testing | `a05-injection.md`, which owns the sink inventory the whole skill defers to; SSRF in `a01-broken-access-control.md` |
| 4.8 Testing for Error Handling | `a10-exceptional-conditions.md` for the error path itself; `a09-logging-and-alerting.md` for what the failure records |
| 4.9 Testing for Weak Cryptography | `a04-cryptographic-failures.md`; transport in `deployment-and-runtime.md`; encrypted columns in `data-layer-and-database.md` |
| 4.10 Business Logic Testing | `a06-insecure-design.md` for which flows are worth attacking, `a10-exceptional-conditions.md` for sequencing and concurrency, `file-uploads.md` for upload logic |
| 4.11 Client-side Testing | **Non-goal.** |
| 4.12 API Testing | `api-drf-specific.md`; `graphql-and-alternative-api-surfaces.md` where the client composes the request |

### Where the two do not line up

Say this rather than stretching a mapping to hide it. The non-goals below are
declared, not missing, and a reader who knows what this skill deliberately does
not do can trust what it says it does.

- **4.11 Client-side Testing is a permanent non-goal**, on the same reasoning
  as ASVS V3. DOM XSS, clickjacking, browser storage, web messaging, and
  cross-site script inclusion are properties of a document a browser executes,
  not of Django code. Only the half a server controls appears here, as headers
  and cookie flags in `a02-security-misconfiguration.md`.
- **Anything requiring a proxy, intercepted traffic, or a live deployment is a
  non-goal as a procedure**, because this skill reads source and does not
  exercise a deployment: padding-oracle testing in 4.9, request splitting and
  smuggling in 4.7, and the timing-dependent tests in 4.10. Where the
  underlying weakness is still worth naming, it is named as a recommendation to
  whoever operates that layer — `deployment-and-runtime.md`, "Request smuggling
  and the parser chain" is the worked case.
- **Within 4.1, the reconnaissance tests are non-goals.** Search-engine
  discovery, server fingerprinting, and mapping an application's architecture
  from the outside all need a running target. The two tests with a source
  analogue are covered elsewhere and by a different means: identifying entry
  points is phase 1 of this file, read from the declarations rather than from
  the traffic, and what the application publishes about itself is the settings
  and operational-endpoint material the table above names.
- **Within 4.2, the split is by where the configuration lives**, not by whether
  the topic is interesting. What a settings module or a DNS zone declares is
  read directly; what the network infrastructure does with a request, and how
  the server chain answers an unusual HTTP method, is a deployment property and
  belongs to whoever operates it. `SKILL.md`, "Ownership and boundaries" draws
  the same line for the whole skill.
- **This skill also sweeps surfaces the WSTG has no section for**, so a
  guide-complete test is not a complete review. The guide is written for a web
  application reached over HTTP; phase 1 enumerates Celery tasks and beat
  schedules, management commands, signal receivers, admin actions, and MCP
  tools, none of which a tester with a proxy ever sees.

Carry a WSTG identifier in a finding **only where the project is genuinely
being tested against the guide** — a penetration test scoped in WSTG terms, a
report that has to reconcile with one. Everywhere else it is a third identifier
for a reader with no use for it, and the optional position it would occupy is
already described in `00-methodology-and-severity.md`, "Mapping to ASVS 5.0".
CWE and the OWASP mapping are not optional. Where one is carried, name the
section rather than a test, and where a test identifier is unavoidable, write
it version-tagged for the reason given above.

## Write-time: the inventory run forward

The workflow has a forward grammar, and it is the same four questions asked
before the code exists instead of after. Before generating a feature: which
entry-point family is being added, which principals reach it, which sinks it
introduces, and — following from those three — which standing defaults apply
at this moment.

The defaults themselves are not restated here. The six standing rules and the
index of which reference carries the per-task rule for each generation moment
are in `00-methodology-and-severity.md`, "The write-time contract". What this
file adds is the trigger: the moment a new entry point is declared is the
moment to consult that index, because the family determines which row of it
applies, and a feature written without asking which family it joined gets the
defaults of whichever file the author happened to have open.

## Review checklist

### Stack-neutral

- [ ] Scope and mode were stated before the sweep, and anything outside scope
      was recorded as a decision rather than discovered as a gap at write-up.
- [ ] Every claim about a control outside the repository is carried as a
      question to its operator, with the answer that would settle it, rather
      than assumed present or assumed absent.
- [ ] Entry points were enumerated from declarations, resolved to full paths,
      and families with no members were recorded as examined rather than left
      unmentioned.
- [ ] Principals were enumerated by what proves each one, and every trust
      boundary the feature crosses was named.
- [ ] Sources were paired to sinks before anything was called a finding, and
      the stored-then-used path was tracked across requests rather than left
      as two unrelated hits.
- [ ] The functions between an entry point and its sink were opened and read,
      rather than the path inferred from its two ends.
- [ ] Work was ordered by impact against effort to confirm, and any surface
      that jumped the queue is recorded together with what was deferred.
- [ ] Where the tree was too large to read closely, the inventory was still
      completed over all of it, the close reading was budgeted per area rather
      than spent on the first lead, and every family read as a sample is
      recorded in the ledger as a sample together with the basis it was chosen
      on.
- [ ] Each finding discharges all six gate items — attacker control,
      reachability, the protections that should have stopped it, the
      insufficiency of whatever sanitization is present, concrete impact, and
      the benign-pattern catalogue — with each discharge recorded rather than
      assumed.
- [ ] Every discharge names the file and quotes the line it rests on, rather
      than resting on what a decorator, a base class, or a library function is
      remembered to do.
- [ ] Every finding carries the shortest source-to-sink path it was confirmed
      on and the protection that failed, and every hypothesis that failed
      attacker control or matched a benign pattern was dropped rather than
      carried into the report as a caveat.
- [ ] Confirmed issues were escalated one step — what does this enable next —
      before write-up, and a chain is one finding at the severity of its
      outcome with its links named.
- [ ] The ledger distinguishes examined-and-clean from not-examined on every
      dimension, and its not-examined lines are what the report's limitations
      section carries.
- [ ] Each phase closed on the coverage property that ends it rather than on
      an amount of reading, handed the next phase a written artifact, and the
      ledger was read back at each boundary rather than recalled.

### Django & DRF

- [ ] The URLconf was walked through every `include()` chain, and each route
      recorded at its resolved prefix rather than at its leaf pattern.
- [ ] Routers, viewsets, `@action` methods including `detail=False`, and
      plain `APIView` subclasses were each enumerated, not inferred from the
      served schema.
- [ ] The non-DRF surfaces were looked for by name — Django Ninja, GraphQL,
      gRPC, Channels — and their absence recorded where they are absent.
- [ ] The families that are not routes were enumerated: Celery tasks and beat
      entries, management commands, signal receivers, admin registrations and
      actions, webhook receivers, and MCP tools.
- [ ] `MIDDLEWARE` was read in declared order, including what runs above
      authentication and what writes to `request`.
- [ ] The worker, the service account, and the impersonating operator were
      treated as principals in their own right rather than folded into
      "authenticated user".
- [ ] Object, function, field, and tenant authorization were each exercised
      separately and recorded separately in the ledger.
