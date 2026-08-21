# The Audit Workflow

This file owns **how a codebase is swept**. It owns the phase order, what each
phase hands the next, and the coverage property that closes each phase. It
owns the entry-point inventory, the principal model, and the trust-boundary
model. It owns the hypotheses, their order, and the budget rule for a tree too
large to read closely. It owns the coverage ledger and the attack-chain
reasoning that turns several confirmed links into one finding. It also owns
the regression harness that holds a finding closed after the report.

This file owns no vulnerability and no control that belongs to one. Every
phase names the reference that owns the rules for what the phase finds.

`00-methodology-and-severity.md` owns the other half, which is how a finding
is scored and written. That half is the severity rubric, the confidence scale,
the finding schema, the ASVS mapping, the report structure, and the standing
write-time contract. The split is procedural against evaluative. This file
decides which code a reviewer opens and in which order. That file decides what
an opened file is worth.

Neither file works alone. A sweep with no scoring model produces a list that
nobody can put in order. A scoring model with no sweep scores only the code
that someone opened. `SKILL.md` owns the router that sends you to the topic
files that both of these files point at.

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
- [Holding the fix: the security regression harness](#holding-the-fix-the-security-regression-harness)
- [Write-time: the inventory run forward](#write-time-the-inventory-run-forward)
- [Review checklist](#review-checklist)

## Principle

The code that the reviewer opens bounds the review. Depth of analysis, quality
of fix, and accuracy of severity are properties of the code that the reviewer
read. None of them says anything about the route that nobody enumerated. The
sweep is therefore inventory-first. Establish the complete set of places where
execution begins on input that the application did not author. Then derive the
work from that set, and not from the files that look interesting.

Three consequences make this a procedure rather than advice.

- **Coverage has to be recorded, not felt.** An unexamined surface and a clean
  surface read the same in a report that does not separate them, and the
  reader assumes the second one. The ledger in phase 6 keeps the difference
  visible.
- **Order is a decision with a cost.** Time on a low-yield class is time that
  the authorization surface does not get. The default order in phase 4 finds
  the most defects per file read in a Django codebase. A departure from that
  order should follow from something specific that you saw, and not from a
  keyword that matched.
- **A phase ends on a property of its coverage, not on a quantity of
  reading.** Each phase below hands the next phase a written artifact. That
  artifact is the scope statement and the environment questions, the
  inventory, the principals and boundaries, the source-to-sink pairs, the
  ordered hypotheses, or the dispositions. A phase is finished when its
  artifact is complete over the surface that the previous phase named. It is
  not finished at some number of files read. A phase that hands forward an
  impression makes the next phase derive that artifact again by a second read.
  That second read is how a sweep narrows onto the same code.

## Phase 0 — scope, mode, and what the repository cannot tell you

Settle three things before you read application code. Settle which mode runs.
Settle what the tree contains. Settle where the tree stops.

Mode decides the output rather than the sweep. Review-time runs the phases
below over code that exists, and ends in a findings report. Write-time runs
the same inventory questions forward over code that does not exist yet.
`00-methodology-and-severity.md`, "Choosing the mode" defines both modes. The
forward form is at the end of this file.

Scope is the set of directories, apps, and services in front of you. State the
scope before the sweep. Do not infer it from the sweep afterwards. Where a
service that the application depends on sits outside the scope, that is a
scope decision, and it belongs in the ledger. It is not a gap to discover at
write-up time.

The phase hands forward the scope statement and the list of
confirm-with-operator questions below. The phase is finished when every
dependency that a finding might rest on sits on one declared side of the
repository boundary. The phase is not finished when you have read the settings
module. The settings module is where this phase looks, and the question is
about what is absent from it.

### Principle layer

The third question produces wrong findings, and it fails in both directions:

- **Absence in the repository is not evidence of absence in production.** No
  rate limit in the code does not mean that no rate limit runs. The gateway in
  front of the application can enforce one. A finding that reports the absence
  asserts something about a system that nobody read.
- **An assertion in the repository is not evidence of presence.** A comment
  can say that the proxy strips the header. A README can describe a WAF rule.
  A setting can carry the name `ENFORCE_TENANT_ISOLATION`. None of these is
  the control. Each one is a claim about a control, from a person who was
  possibly correct on the day they wrote it.

Both errors have one fix. Name the item. Say which side of the boundary it
sits on.

Record it as a question to the person who operates that side, and write the
answer that settles it beside the question. A question is an honest output. A
finding that rests on an assumption is not honest. Silence is not honest
either, because the reader interprets silence as a pass.

### Django & DRF implementation layer

`a03-software-supply-chain.md`, "The artifact boundary" already draws this
line for the build pipeline. That section also states the form of the output.
The rows below extend the same rule to the rest of the environment. They do
not restate it. Carry each row that matters to a finding as
confirm-with-operator. Assume no row in either direction.

| Not in the tree | The question that settles it |
|---|---|
| Reverse-proxy and ingress configuration, where it is not committed | How many proxies sit in front of the application, and which forwarded headers does the edge strip and re-set? `deployment-and-runtime.md`, "Reverse proxy and forwarded headers" states what the answer has to be for a client IP to mean anything |
| WAF and API-gateway rules | Which authentication, filtering, and rate limits apply before a request reaches Django, and does any of it fail open when the edge is bypassed? `a06-insecure-design.md`, "Rate limiting and anti-automation" |
| Object-store bucket policy and public-access settings | Is the bucket reachable anonymously, and does a policy or ACL grant more than the application's own credential does? `file-uploads.md`, "Object storage configuration" |
| Orchestrator and deployment-platform state | Does anything at deploy time enforce the posture the image only declares — the non-root user, the read-only filesystem, the dropped capabilities? `deployment-and-runtime.md`, "Container images" |
| Secret-manager contents and the values actually injected | Does the running process receive the values the settings module reads, and was any of them ever committed to this history? `service-identity-and-secrets.md`, "Where secrets live and how they reach the process" |
| Registry and CI runner state | Is the signature or attestation present beside the image, and does anything block a rollout without one? `a03-software-supply-chain.md`, "The artifact boundary" |

**Write-time.** Some generated code is correct only because of something
outside the repository. Examples are a header that the proxy sets, a bucket
that the policy keeps private, and an environment variable that must exist.
Write that dependency as a startup check or as a comment at the site, in the
same edit. Then carry it into the security-decisions note as caller-owned. A
reviewer cannot tell an unwritten assumption from an oversight.

## Phase 1 — entry-point inventory

This is the operational core of the sweep. Everything after it is derived from
it, and everything before it is preparation for it.

### Principle layer

An entry point is any place where execution begins on input that the
application did not author. An entry point can be a request, a message, a
schedule, a signal, or a console invocation. Enumerate by construct, and not
by convention. The families that a reviewer misses are the ones that do not
look like a view. Three examples are a task that consumes a queue, a command
that an operator runs, and a receiver that fires on a save.

Three rules keep the inventory honest.

- **Enumerate from the declaration, not from the documentation.** A generated
  schema, an API reference, and a README each describe what someone pointed
  them at. The declaration is the code that runs.
- **Resolve to the full path, not the leaf pattern.** A route is every prefix
  that an `include()` chain contributed, joined together. The leaf module is
  the one file that does not hold that information.
- **A family with no members is a recorded result.** "No Channels routing in
  this project" belongs in the ledger. "Channels not mentioned" does not
  belong there, because the next reader cannot tell it from an oversight.

### Django & DRF implementation layer

Each row names a family, the place where a Django project declares it, the
search that finds it, and the reference that owns its rules. This file does
not repeat those rules. The row exists to record that you looked for the
family.

| Family | Declared in | Find it with | Rules |
|---|---|---|---|
| URLconf routes | `ROOT_URLCONF` and every module an `include()` chain reaches | `path(`, `re_path(`, `include(`, `format_suffix_patterns` | `authorization-architecture.md`, "Default-deny architecture" |
| DRF routers, viewsets, and views | a `urls.py` that constructs a router; the view modules it names | `DefaultRouter`, `SimpleRouter`, `.register(`, `ViewSet`, `APIView`, `GenericAPIView` | `api-drf-specific.md`, "Where the object check runs, and the routes that skip it" |
| Viewset actions, including `detail=False` | the viewset body, not the router | `@action(` | `api-drf-specific.md`, "Function-level authorization on actions (API5)" |
| Django Ninja operations | the module that constructs `NinjaAPI()` or a `Router()` | `NinjaAPI(`, `Router(`, `@api.`, `@router.` | `graphql-and-alternative-api-surfaces.md`, "Django Ninja: nothing is authenticated by default" |
| GraphQL fields and resolvers | the schema module and every type it composes | `strawberry.type`, `ObjectType`, `Mutation`, `resolve_`, `DjangoObjectType` | `graphql-and-alternative-api-surfaces.md`, "Resolver authorization: a check at the root is not a check" |
| gRPC methods | the servicer class, and the `service` blocks in the `.proto` behind it | `grpc.server(`, `Servicer_to_server`, `service ` in `*.proto` | `graphql-and-alternative-api-surfaces.md`, "gRPC: nothing from the DRF request cycle applies" |
| Channels consumers | `ASGI_APPLICATION` and the routing module it reaches | `ProtocolTypeRouter`, `URLRouter`, `Consumer`, `websocket_urlpatterns` | `async-and-channels.md`, "WebSocket authentication and origin validation" |
| Celery tasks and beat schedules | task modules, `beat_schedule`, and the `PeriodicTask` rows a database scheduler holds | `@shared_task`, `@app.task`, `.delay(`, `.apply_async(`, `beat_schedule` | `a08-integrity-and-deserialization.md`, "Celery and task queues" |
| Built-in framework tasks (Django 6.0+) | task modules, and the `TASKS` setting that names the backend | `from django.tasks`, `@task`, `.enqueue(`, `.aenqueue(`, `TASKS` | `a08-integrity-and-deserialization.md`, "Django's built-in tasks framework" |
| Management commands | `<app>/management/commands/` | `BaseCommand`, `add_arguments`, `call_command(` | `a05-injection.md`, "OS command injection" |
| Signals and lifecycle hooks | `signals.py` and whatever `AppConfig.ready()` imports | `@receiver`, `post_save`, `pre_delete`, `m2m_changed`, `.connect(` | `a09-logging-and-alerting.md`, "Lifecycle hooks and audit guarantees" |
| Admin registrations, custom admin views, and admin actions | `admin.py`, plus any `get_urls()` override | `admin.register`, `ModelAdmin`, `get_urls`, `actions =`, `@admin.action` | `authorization-architecture.md`, "Django admin: the permission surface"; exposure of the surface itself in `a01-broken-access-control.md`, "Admin exposure" |
| Inbound webhook receivers | a URLconf route that authenticates nothing because the sender cannot log in | `csrf_exempt`, `AllowAny` on a POST route, `request.body` | `a08-integrity-and-deserialization.md`, "Webhook and callback integrity" |
| MCP tools published over the application | the tool-registration module, and any viewset it republishes | the integration package's registration decorator or `ModelAdmin`-style class, plus every viewset it names | `agent-and-llm-interfaces.md`, "What survives when a DRF view is republished as a tool" |
| Middleware | `MIDDLEWARE`, in order | `MIDDLEWARE`, `__call__`, `process_view`, `process_exception` | `authorization-architecture.md`, "Default-deny architecture" |

Middleware is the family that an inventory most often omits. It is also the
family that is an entry point for every request at the same time. Read
`MIDDLEWARE` in declared order. A component above the authentication
middleware runs for anonymous traffic. A component that returns a response
stops every component below it. A component that writes to `request`
establishes a value that every view below it treats as trustworthy.

The include chain is the other frequent miss. The grep that finds the route
does not land in the file that defines the route:

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
every module in the tree and reports the families above as declarations. It
resolves each route through the include chain to its full prefix. It reports
each router registration at the prefix where the project mounts it. It reports
each action with what the decorator declares. With `--settings`, it also
reports `MIDDLEWARE` in declared order.

Every HTTP-reachable row states one of three facts about authorization. The
site declares it. A base class or a framework default supplies it, and it is
therefore not visible at the site. Alternatively it is absent. The second fact
and the third fact are different, and the run keeps them apart.

The closing line names the families found, and the families looked for and not
found. Phase 6 records that line. Read the code to confirm what the run
surfaces. The run is a starting set for the phase, not the output of the
phase.

The script finds declarations, and only declarations. Some routes register at
runtime. Three examples are a URLconf assembled in a loop, a viewset from a
factory, and a tool registered from a table at app load.

No parser can see these, so they appear in no run and in no diff of two runs.
Your reading closes that residual gap. This is the reason for the first rule
above. A tool that reads declarations reports what the project declared, and
the question of what else runs stays yours.

The served OpenAPI schema is not the inventory. `api-drf-specific.md`,
"Endpoint inventory (API9)" owns that point. It also owns the three techniques
behind the point, and the diff that makes a schema useful. Anything in the URL
map that is absent from the schema is a shadow-endpoint candidate. Take the
method from there, and do not derive it again here.

The phase hands its list to every later phase. It is finished when every
family in the table has a recorded result. That result is either the members
enumerated at their resolved paths, or the family recorded absent. The phase
is not finished when the routes look complete. Routes are the family that a
reviewer finds without effort. A sweep that stops there enumerates only the
surface it was already going to read.

**Write-time.** You can add a route, a task, a consumer, a command, a
receiver, or a tool. Name the family it joins before you write the body. Then
write the access rule of that family in the same edit that makes the code
reachable. The decorator selects the family, and every control that applies to
the new code follows from that family.

## Phase 2 — principals and trust boundaries

An entry point is only half of the question. The other half is who arrives at
the entry point. The useful form of that question is not "is this
authenticated". The useful form is "what proves that the caller is this
principal, and what does this principal reach".

### Principle layer

Enumerate the principals that the application actually distinguishes, and not
the principals that its documentation names. A principal that the code cannot
tell from another principal is not a principal. It is a comment. Then
enumerate the boundaries. A boundary is a place where something crosses from
one trust domain into another. The check at that crossing either exists or
does not exist.

`authorization-architecture.md` owns the privilege model that expresses these
principals, and it owns the choice between RBAC, ABAC, and ReBAC.
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

The phase hands phase 4 a principal set, and the boundaries that each entry
point crosses. It is finished when every entry point from phase 1 carries at
least one principal. That includes every entry point whose principal is
anonymous. Anonymous is the answer that nobody writes down, and it is the
answer that most often proves wrong.

**Write-time.** When you generate an endpoint, a task, or a tool, write down
which principals reach it before you write the body. Derive tenant, owner, and
role from the authenticated identity in that same edit. A handler that does
not distinguish a principal at generation time cannot distinguish it later,
unless you change the handler.

## Phase 3 — sources to sinks

`a05-injection.md`, "Tracing input to a sink" owns the method. The inventory
in that section is the sink map for the whole sweep, not for the injection
topic alone. It is complete by design, so no file needs a partial copy of it.
Read it there, and walk it one time for each entry point.

The pairing rule belongs to the sweep rather than to that file. It decides how
much of the result is worth carrying forward:

- **A sink with no source reaching it is not a finding.** A `subprocess` call
  with a constant argument vector is a grep hit, and reporting it teaches the
  reader to distrust the rest of the report.
- **A source with no sink is a validation question, not an injection one.** It
  belongs to the bound that the flow needs, not to this phase — see
  `a06-insecure-design.md`, "Algorithmic resource exhaustion".
- **The second-order path is found as two unrelated hits unless the stored
  field is tracked on purpose.** The writer holds no sink, and the reader
  holds no request, so each half reviews clean. Carry the field name forward
  from phase 1 as a source in its own right. That name is the only property
  the two halves share.
- **The middle of the path is retrieved, not inferred from the two ends.** A
  view that calls a service that calls a helper is three files. The
  construction that decides the question sits in whichever file nobody opened.
  Open each function between the entry point and the sink, and read the call
  it makes. The defect that survives a review is the one whose two ends each
  look correct alone. The parameter is validated where it arrives, and the
  sink is called with a variable that looks local. The layer that joined the
  two is where the value stopped being data.

The phase hands phase 4 the source-to-sink pairs. It is finished when you have
walked every entry point from phase 1 one time against that inventory. Where
an entry point reaches no sink, walk it and record that result. An entry point
that paired with nothing leaves the same blank line as one that nobody walked.
Only a record that separates the two shows the difference.

**Write-time.** Some generated code writes a value to a model field that
another process later hands to an interpreter. Constrain the field where the
code writes it. Keep the value as data where the code reads it. Make both
changes together. A developer edits the writer and the reader on different
days, and neither side then shows the other.

## Phase 4 — hypothesis generation and ordering

Generate candidates for each entry point, and not for each keyword. Take each
route, task, consumer, or tool from phase 1. Ask what makes this specific one
fail. Ask which principal from phase 2 has no check. Ask which sink from phase
3 it reaches. Ask which of its parameters the server must own.

A keyword sweep produces leads already sorted by the frequency of the keyword.
An entry-point sweep produces leads in no order, and they therefore need an
order.

Order by expected impact against effort to confirm. The default:

1. **Object- and function-level authorization.** This class is first because
   it has the highest yield in a Django codebase, and it is among the cheapest
   to settle. The queryset and the permission list are usually two files, and
   the answer is either in them or absent from them.
2. **Authentication and session handling.** This class is second because a
   failure here invalidates the authorization work above it. Confirmation
   usually needs a settings module and a backend, and not a data path.
3. **Injection at the sinks phase 3 paired.** This class is third because
   phase 3 already did the pairing. Only the construction at each site is left
   to read.
4. **Flows that move money, entitlements, or state.** This class is fourth
   because the impact is unambiguous and the confirmation costs the most.
   Confirmation needs reasoning about order, concurrency, and retries, and not
   a declaration to read.
5. **Configuration and deployment posture.** This class is last because much
   of it is confirm-with-operator from phase 0. A settings finding is also
   worth less than an authorization finding on the same application.

The order is a default, not a gate. A surface with a known-weak pattern moves
to the front of the queue immediately. Two examples are a viewset with
`queryset = Model.objects.all()` and a `pk` in its route, and a `@shared_task`
that takes a tenant id as an argument. Two more are a `.proto` served with no
interceptor, and a signed cookie read with no salt. Record the change of order
in the ledger, so that the deferred phases are visibly deferred and not
quietly skipped.

The phase hands phase 5 an ordered list of hypotheses. Each hypothesis
attaches to an entry point, and not to a keyword. The phase is finished when
every entry point from phase 1 is triaged. Triage means that you generated a
hypothesis against the entry point, or recorded that it generates none. Triage
is not investigation. Phase 5 is the investigation, it is the expensive half,
and on a large tree it is the half that runs out of budget.

### Budget on a large tree

A tree can hold more entry points than you can read closely. That tree forces
a choice about where the reading goes. The failure is not a bad choice. The
failure is a silent choice. A silent choice delivers a partial audit in the
shape of a complete one, and puts nothing on the page that shows the
difference. Two rules keep the choice visible.

**Enumerate exhaustively, read selectively.** Phase 1 is cheap, because it
reads declarations and not logic. Complete phase 1 over the whole tree at any
size. At a large size, use `scripts/entrypoint_inventory.py --json`, and take
its JSON Lines output one record at a time.

Never sample phase 1. You cannot sample a family that nobody enumerated. You
can only miss it.

The close reading in phases 3 and 5 is what you ration, and you ration it per
area. Make a bounded pass over each area that the inventory named, before an
unbounded pass over any single area. The reason is the premise of this phase.
An entry-point sweep produces leads in no order, so the first interesting lead
is not the most valuable one. A budget spent on that lead is spent before you
price anything else.

Treat this as a preference with a reason, and not as a gate. A lead that is
already close to confirmed is worth the finish. The default is still breadth
first, because depth first on the first lead is the shape of a review that
nobody decided.

**A sample is recorded as a sample.** Some families are large and repetitive,
such as forty viewsets over one base class, or a hundred tasks in one module.
Read the base class, the shared defaults, and a named subset of the members.
Then write into the ledger which members you read, and the basis on which you
chose them.

The ledger does not prevent a sample in place of a sweep, and it is not meant
to. The ledger makes the substitution visible. The reader then sees twelve of
eighty-three viewsets read as the ones with a `pk` in the route. The
alternative is a findings list that reads as eighty-three files opened.

## Phase 5 — verification

This phase is a gate rather than advice, because a pattern match is the cheap
operation and restraint is the expensive one. A report with four real findings
and eleven confident wrong ones is worse than no report. The reader cannot
tell which four are real. The reader therefore stops trusting all fifteen, and
the four real findings go down with the rest.

### The discharge gate

Promote a hypothesis to a finding only after you **discharge and record** each
of the six items below. The record states what you read and what it showed.
Never assume an item. A later reader needs the record to disagree with the
finding. A reader cannot tell an unwritten discharge from a discharge that
never happened.

Recorded means the retrieved text, not remembered behavior. Name the file that
the discharge rests on. Quote the line that it turns on. A claim about a
decorator, a base class, or a library function can be made without a read of
the source. Such a claim is how a report describes code that the project does
not have.

That failure costs more than the finding was worth. One citation that a reader
checks and cannot find makes every other line in the report a line they must
now confirm by hand. The real findings then go down with the wrong one.

- **Attacker control.** Name the principal that supplies the value. Name the
  parameter that carries it. Name the route it arrives on. Name all three. A
  value that only a deploy-time configuration sets is not attacker-controlled.
  A hypothesis that cannot name the three does not yet describe an attack.
- **Reachability.** The route resolves through its `include()` chain. The
  permission classes in force admit the principal. No earlier guard returns
  first, such as a middleware, a `dispatch` override, or a scoped
  `get_queryset`. A view that no URLconf reaches is dead code, and dead code
  is a hygiene note rather than a finding.
- **Protections examined.** Identify the framework behavior that had to stop
  this defect. Then show that behavior absent, disabled, or insufficient.
  Several protections exist by default: ORM parameterization, template
  autoescaping, `ALLOWED_HOSTS`, the CSRF middleware, `safe_join`, and the
  storage API. So do the DRF permission and throttle classes, and the declared
  field set of a serializer. A finding that does not say why the default
  failed here is not finished.
- **Sanitization insufficiency.** Where validation or scoping is present, show
  the specific input it does not cover, or the path that skips it. A statement
  that the validation looks thin is an impression, not a discharge.
- **Concrete impact.** Name which data, whose privilege, which money, and
  which account. A sentence that fits any finding is not an impact statement.
- **Benign patterns ruled out.** You consulted the catalog below, and the
  catalog in the topic reference that owns this control. The case in hand is
  not one of them.

Then dispose of the hypothesis. The three outcomes are not interchangeable:

- **Discharges all six — a finding.** Write it against the schema in
  `00-methodology-and-severity.md`, "Finding schema".
- **Discharges everything but reachability — a "worth checking" item.** Name
  the exact item that settles it: the settings value, the URLconf, or the
  permission default that the deployment runs. Do not write it as a finding
  with a hedge in it.
- **Fails attacker control, or matches a benign pattern — dropped.** Do not
  mention it anywhere. A dropped hypothesis is not a caveat. A list of items
  that turned out to be correct is padding, and it pushes the surviving
  findings down the page.

The phase hands those dispositions to the write-up. It is finished when every
hypothesis that phase 4 ordered carries one of the three. A hypothesis with
none of the three reaches the report as a hedge, and this gate exists to stop
that.

Every finding carries the shortest confirmed source-to-sink path, and the
specific protection that failed. Write two lines, not a narrative. The path is
the parameter, the call that carries the parameter, and the sink. The
protection is the one named above, together with the reason it did not apply
here. `00-methodology-and-severity.md`, "Finding schema" owns the position of
those lines in the write-up. The baseline table beside it owns what the
confirmed class is worth.

### Commonly mistaken for a finding

The general rule comes first, because it generates the cases. **A pattern is
judged by the property that makes it dangerous, not by the identifier that
names it.** `raw`, `pickle`, `mark_safe`, `shell=True`, and `random` each name
a mechanism. The danger is a specific property of the use. Two such properties
are a statement built by interpolation, and bytes that a second principal can
write. Three more are markup assembled from a request, an argument that
varies, and a value that has to be unguessable.

Where the property is absent, the identifier is only an identifier.

Four cases are cross-cutting and belong to no single topic file:

- **Dead code.** A view, task, or handler that nothing reaches looks the same
  as a reachable one. It is also the easiest place to write an unreachable
  defect with confidence. The decision is whether a URLconf, a router
  registration, a beat schedule, or a caller reaches it. Where nothing reaches
  it, write a hygiene note that says so.
- **A control enforced in a layer you did not open.** Two examples are a view
  with no `permission_classes` under a restrictive project default, and a
  queryset that reads unscoped over a manager that scopes. A third is a header
  that the proxy sets instead of Django. The decision needs the settings
  module, the manager, and the middleware list. Read all three before you
  conclude that the control is absent. The per-file catalogs at the end of
  this section carry the specific pairs.
- **Test, fixture, and factory code.** Examples are a hardcoded credential,
  `AllowAny`, `DEBUG = True`, or a disabled certificate check inside `tests/`,
  `conftest.py`, or a factory. The decision is whether the production import
  chain or a production route reaches that module. That is a question about
  imports, and not about the line.
- **A defense-in-depth gap written up as an exploit.** Examples are a missing
  header, a short-lived token that does not rotate, and a permissive default
  that no route inherits. The decision is whether the gap enables an attacker
  action today. Where it enables none, rate it Low and say so. Never invent
  the chain that would make it a High. That invention is the failure this
  phase exists to stop.

The other cases sit beside the controls they qualify, under this same heading,
in the references that own them. `a05-injection.md` owns the SQL, shell,
template, and dictionary-expansion cases. `a01-broken-access-control.md` owns
scoping, SSRF, and path joins. `a02-security-misconfiguration.md` owns the
settings modules that no production entry point imports.

`a08-integrity-and-deserialization.md` owns who can write the bytes that a
deserializer reads. `api-drf-specific.md` owns permission defaults, CSRF, and
serializer field sets. `a04-cryptographic-failures.md` owns the uses of
`random` that need no unguessability.

## Phase 6 — the coverage ledger

The ledger is working state. The sweep fills it in as the sweep runs, and
reports it at the end. Its one job is to keep *examined and clean* separate
from *not examined*. A report that joins the two says nothing. The reader
takes silence for coverage, and the next incident comes from the surface that
nobody opened.

Write the ledger down as the sweep runs. Read it back at each phase boundary.
Do not hold it in your memory.

Attention over a long input is a budget rather than a constant. A model uses
material in the middle of a long context measurably less reliably than the
same material near either end. Reliability falls further as the input grows,
at every position. A sweep of a real codebase has produced that condition by
phase 5.

Therefore derive the order in phase 4 again from the ledger record, and not
from the last few files you read. A family that the ledger still lists as
unexamined stays on the list, even when nothing has referred to it for a long
time. A review that narrows late narrows toward the most recent files it read.
The written ledger is the only record that still holds what the review did not
read.

Record five dimensions. Record each one as a count or a list, and not as a
judgment:

- **Entry-point families** examined against families found, from phase 1.
  Include the families that you found to be absent.
- **Authorization surfaces exercised** — object, function, field, and tenant.
  Record each one separately. A sweep that checked object-level scoping on
  every route has still said nothing about field-level exposure.
- **Data-lifecycle paths walked** — delete, erasure fan-out, retention, and
  export. A route-driven sweep does not reach these paths.
- **Reference files loaded.** This is the honest record of which rule sets you
  applied, rather than recalled.
- **Explicit non-goals** for this pass. State each one as a decision, and not
  as an omission.

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
into the fourth section of the report. `00-methodology-and-severity.md`,
"Report structure" owns the shape of that section. Every line that reads *not
examined* becomes a line there. Every line that reads *examined and clean*
stays out of it. A limitations section that lists what you read hides the two
lines that matter.

**Write-time.** When you generate a feature that adds an entry point, record
the family it joined and the principals that reach it. Put that record in the
security-decisions note, whose shape `00-methodology-and-severity.md`, "The
security-decisions note" owns. The next review starts from an inventory, and a
surface introduced without one is the surface that inventory will omit.

## Attack-chain reasoning

After you confirm an issue, ask what it enables next. Most real compromises
are three cheap defects in sequence. Rated alone, each of the three is a
Medium that nobody schedules.

Rate the chain, not the link. Report a chain as **one finding at the severity
of its outcome**, and name the links in order inside it. Do not report it as
several low-severity findings, which read as unrelated and close one at a
time. Where you confirm a link and the next one is only plausible, say so at
that link. Do not downgrade the whole chain. The reader needs to know which
hop is the assumption.

These are the chains worth a search, with the file that owns each hop:

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

**Write-time.** Sometimes you generate the second step of a flow. Two examples
are the handler that consumes a token from another endpoint, and the worker
that acts on a row that a request created. A third is the callback that
completes a purchase. State in that same edit what the step verifies again,
rather than inherits. A chain is built from steps, and each step was correct
on the assumption that the previous step had already checked.

## Mapping to the OWASP Testing Guide

The Web Security Testing Guide answers a third question, and the three
standards do not substitute for one another. The Top 10 ranks the most
frequent defects, and it is the spine of the topic references. ASVS lists what
must be demonstrably true before a person approves the application.
`00-methodology-and-severity.md` maps ASVS at chapter level, because that is
an output-side question.

The WSTG says **how to go and look**. That is the input-side question that
this file owns, and it is the reason the mapping is here. The guide is the
closest published counterpart to the phases above. It is written for a person
who exercises a running target, and not for a person who reads a repository.
Most of this section is about the difference between those two positions.

**Map at section level, and cite nothing finer.** The referencing guidance of
the guide states that its test identifiers can change between versions. It
tells a person who cites one to carry the version inside the identifier. Use
the `WSTG-v42-INFO-02` form, and not a bare `WSTG-INFO-02`. A reader takes a
bare identifier to name the current content, which is not the content it named
on the day of writing.

The ASVS mapping avoids the same defect when it cites chapters instead of
requirement numbers, and the answer here is the same. A section name stays
correct for as long as the section exists. The current stable release is v4.2,
and v5.0 is in development as of 10 August 2026. The release of v5.0 renumbers
identifiers, and that event requires a new version of this table.

Chapter 4, "Web Application Security Testing", is the only chapter that
carries material a source reviewer can act on. These are its twelve sections:

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
declared, not missing. A reader who knows what this skill deliberately omits
can trust what it says it covers.

- **4.11 Client-side Testing is a permanent non-goal**, on the same reasoning
  as ASVS V3. DOM XSS, clickjacking, browser storage, web messaging, and
  cross-site script inclusion are properties of a document that a browser
  executes. They are not properties of Django code. Only the half that a
  server controls appears here, as headers and cookie flags in
  `a02-security-misconfiguration.md`.
- **Anything requiring a proxy, intercepted traffic, or a live deployment is a
  non-goal as a procedure.** This skill reads source, and does not exercise a
  deployment. The non-goals include padding-oracle testing in 4.9, request
  splitting and smuggling in 4.7, and the timing-dependent tests in 4.10.
  Where the weakness underneath is still worth a name, name it as a
  recommendation to the person who operates that layer.
  `deployment-and-runtime.md`, "Request smuggling and the parser chain" is the
  worked case.
- **Within 4.1, the reconnaissance tests are non-goals.** Search-engine
  discovery, server fingerprinting, and an external map of the architecture
  all need a running target. Two tests have a source analog, and this skill
  covers each by a different means. Phase 1 of this file identifies the entry
  points, read from the declarations rather than from the traffic. The
  settings and operational-endpoint material in the table above covers what
  the application publishes about itself.
- **Within 4.2, the split is by where the configuration lives**, and not by
  the interest of the topic. Read directly what a settings module or a DNS
  zone declares. What the network infrastructure does with a request is a
  deployment property. The answer of the server chain to an unusual HTTP
  method is also one. Both belong to the person who operates that layer.
  `SKILL.md`, "Ownership and boundaries" draws the same line for the whole
  skill.
- **This skill also sweeps surfaces the WSTG has no section for**, so a
  guide-complete test is not a complete review. The guide is written for a web
  application reached over HTTP. Phase 1 enumerates Celery tasks and beat
  schedules, management commands, signal receivers, admin actions, and MCP
  tools. A tester with a proxy sees none of these.

Carry a WSTG identifier in a finding **only where the project is genuinely
tested against the guide**. That means a penetration test scoped in WSTG
terms, or a report that must reconcile with one. Everywhere else the
identifier is a third token that the reader has no use for.
`00-methodology-and-severity.md`, "Mapping to ASVS 5.0" already describes the
optional position it would hold.

CWE and the OWASP mapping are not optional. Where a finding carries a WSTG
identifier, name the section rather than a test. Where a test identifier is
unavoidable, write it with the version tag, for the reason above.

## Holding the fix: the security regression harness

The phases above end at a report. The report does not decide whether the same
defect returns in eighteen months. Two other facts decide that. The first is
whether each closed finding got a test. The second is whether that test runs
on every commit. The next refactor removes a fix that has no test.

### Principle layer

**One test per closed finding, and the test states the attack.** Write the
request that an attacker sends. Then assert the outcome that must not happen.
Some tests assert only that the patch is still present. Such a test checks
that the filter call is in the queryset. It can instead check that the
permission class is in the list, or that the code escapes the value.

Such a test couples to the shape of the fix, and not to the property that the
fix established.

It fails on the next refactor that keeps the property, and it passes on the
next change that removes the property. Both directions are wrong, and the
second direction is the one that matters.

**Assert the deny path, and the state behind it.** A status code says that the
handler refused the request. The row says that the handler wrote nothing. A
test that reads only the status code passes against a handler that returns 403
after it commits the side effect.

`authorization-architecture.md`, "Authorization test suites" owns the matrix
that these tests belong in. That matrix sets principals against actions
against expected allow or deny, and it names the false-confidence patterns
that make a suite worthless. The harness adds the run time: every commit,
rather than the day of the audit.

**A test is proven by failing, not by passing.** Introduce the defect again on
purpose. Revert the fix on a scratch branch, and run the suite. A suite that
stays green does not hold that fix, whatever it asserts. Do this while the
revert is still one command away, which is the day the fix lands and not the
next audit.

**Fixture and factory data carries no real secret and no real personal data.**
A developer commits fixtures, and every machine that checks the repository out
copies them. Build artifacts also keep them long after the branch is gone. A
fixture built from a production row is therefore a copy of production in a
place that has none of the controls of production.
`data-lifecycle-and-privacy.md` owns the copies that an erasure must reach,
and this is one of them.

**A tool that reports without failing gates nothing.** Check that property for
every step in the pipeline, rather than the presence of the step. The control
is what the step does with the result. That takes two shapes: a tool whose
exit code is the verdict, and a tool that gives no verdict. The difference is
between a read of `$?` and a read of the output.

**Record which closed findings have a test** in the same grammar that the
sweep uses for coverage. A finding with a regression test and a finding that
nobody reached are different states. A list that does not separate them reads
as the first state. "Phase 6 — the coverage ledger" above owns that
distinction, and this is one more dimension of it.

### Django & DRF implementation layer

```python
# Wrong: asserts the shape of the fix. It breaks when the queryset moves
# into a manager, and it passes if the filter is later applied to the wrong
# field.
def test_invoice_queryset_is_scoped(self):
    view = InvoiceViewSet()
    self.assertIn("owner", str(view.get_queryset().query))

# Correct: states the attack, and checks that nothing moved.
def test_other_tenants_invoice_is_not_readable(self):
    self.client.force_login(self.tenant_b_user)
    url = f"/api/invoices/{self.tenant_a_invoice.pk}/"
    self.assertEqual(self.client.get(url).status_code, 404)
    self.tenant_a_invoice.refresh_from_db()
    self.assertEqual(self.tenant_a_invoice.status, "open")
```

The pipeline carries the rest. Both of its traps are about the meaning of the
exit code of a step.

`manage.py check --deploy --fail-level WARNING` is the configuration gate. The
level is load-bearing, and the default level is not the one to use.
`a02-security-misconfiguration.md`, "check --deploy" owns the reason. "Writing
a deployment guardrail check" in that same file owns the project assertions
that make the gate worth more than the Django baseline.

**The bundled scanners always exit 0, by design.** `dangerous_patterns.py`
and `settings_scan.py` — and `entrypoint_inventory.py` beside them — return
zero whatever they find. `scripts/README.md`, "Invariants" states it as a
property rather than an accident: output is the product, and these are aids
rather than gates. A step that runs one and trusts `$?` passes on every
finding it just printed, and those findings scroll past in a log nobody
opens.

```
# Wrong: the scanner prints six HIGH hits and the step succeeds.
python scripts/dangerous_patterns.py . --min-severity HIGH

# Correct: the project turns the records into the exit code.
python scripts/dangerous_patterns.py . --json --min-severity HIGH \
    | python ci/fail_on_findings.py --baseline ci/known_findings.json
```

`--min-severity` filters the printed output, and never the value returned to
the shell. Both scanners put a `severity` on every finding record in their
JSON Lines output. A `dangerous_patterns.py` hit also carries a stable `rule`
identifier. A baseline file keys on that identifier, so the gate fails on a
*new* hit rather than on the backlog.

Run `--selftest` in the same job, and read its output the same way. It also
exits 0 whether the fixtures pass or fail. A scanner whose rules have quietly
stopped matching produces a clean run that nobody can tell from a clean tree.

The dependency scanner is the opposite case, and the difference matters.
`pip-audit` exits 1 when it finds an unfixed vulnerability, verified against
2.10.1 on 14 August 2026. There the exit code *is* the control.
`a03-software-supply-chain.md`, "SBOM, scan gate, and provenance" owns the
ways a workflow discards that exit code.

`override_settings` proves a code path, not a deployed value. A test that pins
`SECURE_SSL_REDIRECT` shows what the code does when the setting is true. It
says nothing about whether production sets it, which is the job of the deploy
check. Keep the two apart. Never let a green test take the place of a gate.

**Write-time.** Sometimes you generate the fix for a defect that somebody
found in a review, in an incident, or in a report. Write the test that
reproduces the attack in the same change. Then confirm that the test fails
against the code without the fix. A test written a week after the fix is
written from the patch, and not from the attack.

## Write-time: the inventory run forward

The workflow has a forward grammar. It asks the same four questions before the
code exists, instead of after. Ask these four questions before you generate a
feature.

Name the entry-point family that the feature adds. Name the principals that
reach it. Name the sinks that it introduces. Then name the standing defaults
that follow from those three answers.

This file does not restate the defaults. `00-methodology-and-severity.md`,
"The write-time contract" holds the six standing rules. It also holds the
index of which reference carries the per-task rule for each generation moment.

This file adds the trigger. Consult that index at the moment a new entry point
is declared, because the family selects the row that applies. A feature
written without that question gets the defaults of whichever file the author
had open.

## Review checklist

### Stack-neutral

- [ ] Scope and mode were stated before the sweep. Anything outside scope was
      recorded as a decision, rather than discovered as a gap at write-up.
- [ ] Every claim about a control outside the repository is carried as a
      question to its operator, with the answer that would settle it. No such
      claim is assumed present or absent.
- [ ] Entry points were enumerated from declarations, resolved to full paths,
      and families with no members were recorded as examined rather than left
      unmentioned.
- [ ] Principals were enumerated by what proves each one, and every trust
      boundary the feature crosses was named.
- [ ] Sources were paired to sinks before anything became a finding. The
      stored-then-used path was tracked across requests, and not left as two
      unrelated hits.
- [ ] The functions between an entry point and its sink were opened and read,
      rather than the path inferred from its two ends.
- [ ] Work was ordered by impact against effort to confirm, and any surface
      that jumped the queue is recorded together with what was deferred.
- [ ] Where the tree was too large to read closely, the inventory still
      covered all of it. The close reading was budgeted per area, and not
      spent on the first lead. Every family read as a sample is recorded in
      the ledger as a sample, together with the basis of the choice.
- [ ] Each finding discharges all six gate items. Those items are attacker
      control, reachability, and the protections that had to stop it. They
      also are the insufficiency of the sanitization present, concrete impact,
      and the benign-pattern catalog. Each discharge is recorded rather than
      assumed.
- [ ] Every discharge names the file and quotes the line it rests on. No
      discharge rests on a memory of what a decorator, a base class, or a
      library function does.
- [ ] Every finding carries the shortest confirmed source-to-sink path and the
      protection that failed. Every hypothesis that failed attacker control or
      matched a benign pattern was dropped, and not carried into the report as
      a caveat.
- [ ] Confirmed issues were escalated one step before write-up, which asks
      what the issue enables next. A chain is one finding at the severity of
      its outcome, with its links named.
- [ ] The ledger separates examined-and-clean from not-examined on every
      dimension. Its not-examined lines are the lines that the limitations
      section of the report carries.
- [ ] Each phase closed on the coverage property that ends it, and not on an
      amount of reading. Each phase handed the next phase a written artifact,
      and the ledger was read back at each boundary rather than recalled.
- [ ] Every closed finding carries one regression test. That test states the
      attack rather than the patch, and asserts the deny path together with
      the state behind it. It was confirmed to fail against the code without
      the fix.
- [ ] Fixture and factory data carries no real secret and no real personal
      data. Which closed findings have a test is recorded rather than assumed.

### Django & DRF

- [ ] The URLconf was walked through every `include()` chain, and each route
      recorded at its resolved prefix rather than at its leaf pattern.
- [ ] Routers, viewsets, `@action` methods including `detail=False`, and plain
      `APIView` subclasses were each enumerated. None of them was inferred
      from the served schema.
- [ ] The non-DRF surfaces were looked for by name — Django Ninja, GraphQL,
      gRPC, Channels — and their absence recorded where they are absent.
- [ ] The families that are not routes were enumerated. Those families are
      Celery tasks and beat entries, management commands, and signal
      receivers. They also are admin registrations and actions, webhook
      receivers, and MCP tools.
- [ ] `MIDDLEWARE` was read in declared order, including what runs above
      authentication and what writes to `request`.
- [ ] The worker, the service account, and the operator who impersonates were
      each treated as a principal in its own right. None of them was folded
      into "authenticated user".
- [ ] Object, function, field, and tenant authorization were each exercised
      separately and recorded separately in the ledger.
- [ ] The pipeline runs `check --deploy` at a fail level that can fail the
      job. It gates the bundled scanners on their records, and not on an exit
      code that is always 0.
