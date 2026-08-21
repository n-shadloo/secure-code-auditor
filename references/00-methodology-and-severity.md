# Methodology, Severity, and Report Format

This file owns **how a finding is scored and written**. It owns the mode
selection, the severity rubric, and the confidence score beside it. It owns
the finding schema, the report structure, and the ASVS 5.0 chapter mapping. It
owns the standing write-time contract. It also owns the convention that states
every control in this skill in a review form and a write-time form together.
This file does not own how a reviewer sweeps a codebase.

`01-audit-workflow.md` owns the phase order and the entry-point inventory. It
also owns the principal model, the trust-boundary model, the hypotheses and
their order, the coverage ledger, and attack-chain reasoning. Review-time
loads that file first. That file hands this file the coverage that "Report
structure" below turns into a limitations section. The split is procedural
against evaluative. That file decides which code a reviewer opens and in which
order, and this file decides what an opened file is worth.

This file owns no vulnerability and no control. Each per-task rule stays
beside the control it governs, in the reference that owns that control. The
write-time table below is an index to those files, not a copy of them.
`SKILL.md` owns the router that chooses between them. `SKILL.md` also owns the
ownership rules that settle a topic more than one file could claim.

## Contents
- [Operating principles](#operating-principles)
- [Choosing the mode](#choosing-the-mode)
- [Severity rubric](#severity-rubric)
- [Confidence](#confidence)
- [Finding schema](#finding-schema)
- [Mapping to ASVS 5.0](#mapping-to-asvs-50)
- [Report structure](#report-structure)
- [What to exclude](#what-to-exclude)
- [Worked examples](#worked-examples)
- [The write-time contract](#the-write-time-contract)
- [When a secure default conflicts with the request](#when-a-secure-default-conflicts-with-the-request)
- [The security-decisions note](#the-security-decisions-note)
- [How write-time rules are written](#how-write-time-rules-are-written)
- [Review checklist](#review-checklist)

## Operating principles

1. **Investigate, don't pattern-match.** A keyword (`raw`, `mark_safe`,
   `pickle`) is a lead, not a finding. Trace the attacker-controlled data to
   the sink. Then confirm that the deployed configuration keeps the path
   reachable. If you cannot establish reachability, decrease the confidence
   score. You can also move the item to "worth checking".
2. **Prefer confirmed over comprehensive.** A short list of real, exploitable
   issues with concrete fixes is worth more than a long list of maybes.
3. **Read-only by default in review mode.** Do not rewrite the project unless
   the user asks. A finding describes the fix. It does not apply the fix.
4. **Every finding is actionable.** Give the location, the reason it matters,
   and code the developer can apply. Do not write "consider reviewing your
   auth", because that sentence names no location and no action.
5. **State the boundary.** Say what you reviewed and what you did not review.
   The reader interprets silence as assurance.

## Choosing the mode

- **Review-time** when the user asks for a review, an audit, or a scan. It
  also applies to code pasted for a security opinion, and to code immediately
  after the developer builds a feature. Load `01-audit-workflow.md` before the
  topic file, because that file owns the sweep behind this report. Output: a
  findings report.
- **Write-time** when you generate or edit backend code. Output: secure code
  plus a security-decisions note. The sections below give the standing
  defaults, the rule for a conflict with the request, and the shape of the
  note.
- Ambiguous → apply the guardrails while you write the code, then offer a
  review.

## Severity rubric

| Severity | Test |
|---|---|
| **Critical** | Trivially or remotely exploitable with severe impact: RCE, authentication bypass, mass PII/credential exposure, or manipulation of money/orders/balances. Little or no precondition. |
| **High** | Directly exploitable under realistic conditions: horizontal/vertical privilege escalation, account takeover, IDOR exposing another user's data, injection with real impact. |
| **Medium** | Requires specific conditions, a chained precondition, or is a meaningful defense-in-depth failure (e.g., missing lockout on login, overly broad CORS without credentials, verbose errors leaking internals). |
| **Low** | Hardening and defense-in-depth with limited direct impact (missing header, non-rotating token with short TTL, minor info disclosure). |

When severity is borderline, decide on **realistic impact × ease of
exploitation** and say which way you leaned. Two inputs to that product are
misread often enough to name:

- **A race is scored on how reliably its window can be won, not on the fact
  that it is a race.** "Requires specific conditions" describes an
  interleaving that an attacker hits only by luck. It does not describe an
  interleaving that a machine caller opens on demand with concurrent requests
  to an endpoint. Some windows are reliably winnable, and the collision moves
  money, an entitlement, or a limit that had to hold. Rate such a finding High
  or Critical on its impact, and not Medium on its difficulty.
- **Impact has a regulatory dimension as well as an attacker-value one.**
  Personal data can survive the deletion that the operator promised. A
  retention period can also exist that nothing enforces. Each has little
  direct attack value and a real consequence. Score the finding on the data
  and on the commitment made about that data, not on exploitability alone.
  Then say which dimension carried the rating.

### Baseline severity by finding class

The rubric and the table below do different jobs, and the table does not
replace the rubric. The rubric decides the borderline case. The table makes
the ordinary case reproducible across runs. Reproducibility matters here,
because a reader compares the output of two reviews of the same code. Start at
the baseline for the class. Apply a maximum of one step for a factor that the
row names, and name that factor in the finding.

A few rows name their landing point explicitly. Those factors change which
class the finding is in, not its degree. Where the table and the rubric
disagree, the rubric wins, and the finding says so.

| Finding class | Baseline | One step up | One step down |
|---|---|---|---|
| Object-level authorization failure returning another principal's data | High | The data is personal or financial, or the identifier is sequential so the whole set can be walked → Critical on mass exposure | Authentication is required, the identifier is a server-generated random value rather than a sequence, and the fields exposed are neither personal nor financial |
| Function-level authorization failure on a privileged action | High | The action grants a role, an entitlement, or money, or the route is reachable pre-authentication → Critical | The caller must already hold a privileged role and the action only widens what that role could already do |
| Authentication bypass | Critical | — | A precondition the attacker cannot create is required: a second factor, a valid credential for another account, or a state only an operator sets |
| Injection reaching an interpreter | High | The interpreter executes code — a shell, `eval`, a deserializer, a template rendering attacker-authored source — or the path is reachable pre-authentication → Critical | The value reaching the sink comes from a constrained server-side set, so a second, unconfirmed defect would have to widen it first |
| Formula injection through an exported file | Medium | The export is read by an operator or an analyst whose machine reaches internal systems the application cannot, or any caller can write the cells another organization opens | Every value in the file comes from a server-side set or a column the server renders as a number, so no cell carries text a caller authored |
| SSRF | High | A metadata endpoint or another credential-bearing internal service is reachable and returns a live credential → Critical | The destination set reaches nothing internal and the response is never reflected to the caller |
| Insecure deserialization | Critical, where any other principal can write the bytes | — | Only a compromise of another service could write them → High. Only this application writes them and nothing else reaches the store → not a finding; keep the design objection, drop the RCE claim |
| Race on money, entitlements, or a limit that had to hold | High | The window is reliably winnable by firing concurrent requests and the collision is unbounded → Critical | The interleaving needs a state the attacker cannot arrange, rather than one a machine caller opens on demand |
| Race on a non-material counter | Low | The counter feeds billing, a quota, or an authorization decision — at which point it is the row above | — |
| Personal data surviving a promised deletion | High | The data is special-category, or the surviving copy is reachable by a principal who should not read it | The copy is internal, access-controlled, and covered by a retention job that will reach it |
| Secret committed to history | High | The credential is live and reaches production data, money, or the signing of sessions → Critical | The value is a test or CI fixture, or rotation is confirmed complete → Low |
| Missing security header | Low | The header is the only control for a behavior this application actually has, and no equivalent is set at the edge → Medium | — |
| Verbose error output | Medium | The traces reach an unauthenticated response body and disclose settings, queries, or credentials. A production path reaching `DEBUG = True` is the settings finding rather than this one, and `a02-security-misconfiguration.md` rates it Critical | The detail reaches a log or an authenticated internal surface rather than the response body → Low |

Five factors do most of the movement, and a finding that does not settle them
has not earned its rating. Settle whether the path demands authentication.
Settle whether the object identifier is guessable. Settle whether the affected
data is personal or financial. Settle whether the path is reachable
pre-authentication. Settle whether you confirmed a chain or only supposed one.

The last factor inflates a rating more than the others. A chain rates at the
severity of its outcome only where you confirm every hop.
`01-audit-workflow.md`, "Attack-chain reasoning" owns the statement of which
hop is still an assumption.

## Confidence

Score how sure you are the issue is real and reachable:

- **High (report it):** you traced the path and it holds. ≥80%.
- **Medium:** plausible but you couldn't fully confirm reachability. Put in
  "worth checking" with the specific thing to verify.
- **Low:** speculative. Omit, or mention once as a caveat.

Do not inflate severity to compensate for low confidence, or vice versa.

## Finding schema

Each finding uses this shape:

```
### [SEVERITY] Short title
- Location: path/to/file.py:LINE (and any related lines)
- Category: <e.g. Broken Object Level Authorization>  |  CWE-XXX  |  OWASP A0X:2025 (and APIX:2023 if relevant)  |  ASVS Vx(.y) — optional, see below
- Confidence: High | Medium
- Problem: one or two sentences on exactly what is wrong.
- Evidence: the shortest source-to-sink path this was confirmed on, and the
  protection that failed. Two lines, not a narrative.
- Impact: the concrete attack or exposure this enables.
- Fix: the specific change, with a minimal code snippet.
```

`Evidence` is the product of the verification gate. It is not a restatement of
`Problem`. The path names the parameter, the call that carries the parameter,
and the sink. The protection names the default that had to stop this defect.
It also names the reason that default did not apply here.

`01-audit-workflow.md`, "Phase 5 — verification" owns the gate. Discharge that
gate before you write this line.

## Mapping to ASVS 5.0

OWASP released ASVS 5.0.0 on 30 May 2025, and it is still the current version
as of 10 August 2026. It holds approximately 350 requirements in 17 chapters
at three cumulative levels. L1 is approximately a fifth of the standard. L2 is
approximately seventy per cent of it, and L2 includes all of L1. L3 is the
remainder.

ASVS answers a different question from the Top 10 spine of this skill. The Top
10 ranks the most frequent defects. ASVS lists what must be demonstrably true
before a person approves the application. A reviewer discovers a finding
against the first standard, and defends it against the second.

Carry an ASVS identifier only where the project is genuinely held to the
standard. That means a regulated environment, a customer security review, or a
contracted verification level. Everywhere else the identifier is a third token
that the reader has no use for. CWE and the OWASP mapping are not optional.
The ASVS identifier is optional.

An LLM Top 10 2026 or Agentic Top 10 entry token is admissible in the same
optional position, and on the same held-to-it terms.
`agent-and-llm-interfaces.md` maps that token section by section. A WSTG
section is admissible in that position on those same terms, where the
engagement uses testing-guide language. `01-audit-workflow.md`, "Mapping to
the OWASP Testing Guide" owns that mapping. That file also owns the
version-tag discipline that every test identifier must carry.

**Cite the chapter, and a section only where one sub-chapter is the whole
subject** — `V8` for an authorization finding, `V15.4` for a concurrency one.
Do not cite requirement numbers. ASVS 5.0 renumbered against 4.0.3. The third
component is the part that moves between releases. It is also the most
expensive part to keep true across twenty-three files. A chapter token stays
correct for as long as the chapter exists.

| ASVS 5.0 chapter | Where this skill covers it |
|---|---|
| V1 Encoding and Sanitization | `a05-injection.md`, which owns server-side output and the sink inventory behind it |
| V2 Validation and Business Logic | `a06-insecure-design.md` for which flows are worth attacking; `a10-exceptional-conditions.md` for state transitions the database arbitrates |
| V3 Web Frontend Security | **Non-goal.** Only the half a server controls appears, as headers and cookie flags in `a02-security-misconfiguration.md` |
| V4 API and Web Service | `api-drf-specific.md`; `graphql-and-alternative-api-surfaces.md` where the client composes the request |
| V5 File Handling | `file-uploads.md`, from the request through storage to the reader |
| V6 Authentication | `a07-authentication-failures.md` for the human principal, `service-identity-and-secrets.md` for the machine one, `a04-cryptographic-failures.md` for the hashing family underneath both |
| V7 Session Management | `a07-authentication-failures.md`, with the cookie matrix in `a02-security-misconfiguration.md` |
| V8 Authorization | `authorization-architecture.md` for the model, `a01-broken-access-control.md` for the per-request failure, `privileged-access-and-impersonation.md` for operator privilege |
| V9 Self-contained Tokens | `a07-authentication-failures.md` for tokens minted from a human login; `service-identity-and-secrets.md` for inbound machine tokens and JWKS |
| V10 OAuth and OIDC | `a07-authentication-failures.md` for the client and relying party; `service-identity-and-secrets.md` for client credentials and sender-constrained tokens. Partial — see below |
| V11 Cryptography | `a04-cryptographic-failures.md`; encrypted columns and blind indexes in `data-layer-and-database.md` |
| V12 Secure Communication | `deployment-and-runtime.md` for TLS termination and HSTS; `data-layer-and-database.md` for verified database TLS |
| V13 Configuration | `a02-security-misconfiguration.md` for what a settings module declares, `deployment-and-runtime.md` for what the runtime does with it, `a03-software-supply-chain.md` for dependencies and SBOM |
| V14 Data Protection | `data-lifecycle-and-privacy.md`; cache-mediated leaks in `a01-broken-access-control.md`; log leakage in `a09-logging-and-alerting.md` |
| V15 Secure Coding and Architecture | `a10-exceptional-conditions.md` owns V15.4 Safe Concurrency; `a03-software-supply-chain.md` carries the dependency half of V15.2; `a08-integrity-and-deserialization.md` the trust boundaries between systems |
| V16 Security Logging and Error Handling | `a09-logging-and-alerting.md` for what is recorded; `a10-exceptional-conditions.md` for the error path itself |
| V17 WebRTC | **Non-goal.** |

### Where the two do not line up

Say this rather than stretching a mapping to hide it.

- **V3 and V17 are permanent non-goals**, not gaps. This is a backend skill.
  The DOM, subresource integrity, and TURN or DTLS-SRTP signaling are outside
  its scope by design. An addition of them makes this skill worse at its job.
- **V10 is partial.** This skill covers the client side, the relying-party
  side, and the resource-server side in depth. It covers the
  authorization-server and OpenID-provider duties in V10.4 and V10.6 only as
  far as the configuration of `django-oauth-toolkit`. That coverage is thinner
  than the chapter. It matters only for the uncommon case where the
  application is itself the issuer.
- **This skill also covers ground ASVS scopes out**, so an ASVS-clean
  application is not a reviewed application. ASVS excludes infrastructure and
  operational configuration. `a02-security-misconfiguration.md` owns the DNS
  records that decide whether a person can forge the domain, and
  `deployment-and-runtime.md` owns the proxy, the process, and the image.
- **ASVS 5.0 has no chapter for agent and MCP tool surfaces.** That statement
  is still true, because the standard is older than the surface. Therefore
  `agent-and-llm-interfaces.md` carries no ASVS mapping, and it needs none. It
  carries a spine of its own instead: the LLM and Agentic Top 10s, mapped in
  that file.

## Report structure

1. **Summary** — one paragraph. Give the scope, which is the code you
   reviewed. Give the method, which is what you read and which scripts you
   ran. Give the counts by severity.
2. **Findings** — ordered Critical → Low, in the schema above.
3. **Worth checking** — medium-confidence items, each with the exact item to
   verify.
4. **Not reviewed / limitations** — the files, flows, or layers you did not
   cover (for example, "runtime Nginx/systemd config not provided", "no tests
   reviewed").

## What to exclude

Keep the signal high. Do not report:

- Pure denial-of-service theory, resource-exhaustion speculation, or opinions
  on rate-limit values. Record an anti-automation gap only where it is a real
  authorization or abuse issue.
- A secret that the code correctly reads from the environment. Report a secret
  only where it is **hardcoded** or committed.
- Framework internals whose configuration you cannot see, unless the code
  clearly misconfigures them.
- A client or browser concern with no server component.
- A style or performance issue with no security impact.
- Anything whose only evidence is the identifier that names it. Judge a
  pattern by the property that makes it dangerous, and not by the presence of
  `raw`, `pickle`, `mark_safe`, `shell=True`, or `random`. Two such properties
  are a statement that interpolation builds, and bytes that a second principal
  can write. Two more are markup that the code assembles from a request, and a
  value that has to be unguessable. Where the property is absent, the
  identifier is only an identifier, and you do not report a finding.
  `01-audit-workflow.md`, "Phase 5 — verification" carries the general rule
  and the cross-cutting cases. Each high-noise reference carries its own rule
  beside the control, under "Commonly mistaken for a finding".

## Worked examples

There are two examples, because the two defects fail in different ways. The
first example is the ordinary shape. It is a static defect, visible in one
view, and the code itself gives the confidence. The second example is the
shape that the schema handles worst for a reader who has not seen it before.
That defect exists only under concurrency. There `Impact` must argue about a
timing window, and `Confidence` is about reachability rather than about the
plain sense of the code.

```
### [High] Object endpoint returns any user's invoice (IDOR)
- Location: billing/views.py:42
- Category: Broken Object Level Authorization | CWE-639 | OWASP A01:2025, API1:2023
- Confidence: High
- Problem: InvoiceDetail uses Invoice.objects.all() as the queryset and looks up
  by pk from the URL, with permission_classes = [IsAuthenticated]. Authentication
  is checked but ownership is not, so any logged-in user can read /invoices/<id>/
  for any id.
- Evidence: GET /invoices/<pk>/ -> InvoiceDetail -> Invoice.objects.all().get(
  pk=pk), with pk taken straight from the URL kwarg.
  The protection that failed is queryset scoping: no get_queryset() override,
  and no object permission is declared, so no code compares the invoice's
  account to the requester's.
- Impact: Authenticated horizontal privilege escalation; full read access to
  other tenants' billing records by incrementing the id.
- Fix: scope the queryset to the requester.

    class InvoiceDetail(RetrieveAPIView):
        serializer_class = InvoiceSerializer
        permission_classes = [IsAuthenticated]

        def get_queryset(self):
            return Invoice.objects.filter(account=self.request.user.account)
```

The second carries an ASVS chapter because that engagement was a verification
review against L2. In an ordinary review the identifier would be left off and
the line would end at the OWASP mapping.

```
### [High] Concurrent debits can overdraw a wallet (TOCTOU)
- Location: wallet/services.py:88 (debit), wallet/api.py:31 (caller)
- Category: Race condition / TOCTOU | CWE-367 | OWASP A06:2025 | ASVS V15.4
- Confidence: High
- Problem: debit() reads the wallet row, compares balance to amount in Python,
  then writes back balance - amount as a separate statement. Nothing serializes
  the two: no transaction wraps them, the read takes no lock, and the column
  carries no constraint. The route is reachable by any authenticated holder of
  the wallet and no throttle applies to it.
- Evidence: POST /wallet/debit/ -> api.py debit view -> services.debit(), where
  the amount arrives in the request body and the balance is read and written
  back as two statements. The protection that failed is serialization of those
  two: no transaction.atomic(), no select_for_update() on the read, and no
  CheckConstraint on the column.
- Impact: Two concurrent requests both read the same starting balance, both
  pass the check, and the second writes a total computed from a stale copy, so
  the wallet goes negative by up to the amount of the smaller debit. The window
  is not incidental — a caller opens it on demand by firing concurrent requests
  at the route — so this is rated on the value of the collision rather than on
  the difficulty of the interleaving.
- Fix: make the check and the debit one statement the database arbitrates, and
  treat zero affected rows as the insufficient-funds case.

    from django.db import transaction
    from django.db.models import F

    with transaction.atomic():
        debited = Wallet.objects.filter(pk=pk, balance__gte=amount).update(
            balance=F("balance") - amount
        )
        if not debited:
            raise InsufficientFunds

  Add a CheckConstraint on balance >= 0 so the invariant also holds on the
  paths this view does not own. See a10-exceptional-conditions.md for when a
  row lock is the better instrument and the four ways select_for_update()
  silently does nothing.
```

## The write-time contract

Review-time and write-time are the same controls in two grammars. A review
rule is a predicate over code that already exists — *flag X when Y*. A
write-time rule is an action before the code exists — *when generating Y,
write Z*. The second does not follow from the first. An agent can agree that a
view needs authorization, and still emit a viewset with no permission class.
Agreement with a statement and execution of an instruction are different
operations, and nothing in the generation moment asks for the second.

### Principle layer

The contract is that the secure form is the default form and departing from it
is the deliberate act. Six standing rules cover most of what a backend agent
writes:

- **Deny by default.** A new route, task, or tool stays unreachable until it
  states its access rule. A permissive framework default otherwise becomes the
  policy of every endpoint that nobody annotated.
- **Bind data to the principal.** The server sets ownership, tenant, role, and
  money from the authenticated identity. The server never accepts them from
  the request body, because a client that can name the owner is the owner.
- **Keep input as data.** Every value that reaches an interpreter arrives as a
  bound parameter, an element of an argument vector, or an escaped term. The
  alternative lets the input decide what the operation means.
- **Constrain before consuming.** Check size, type, count, and destination
  before the expensive or irreversible step. A limit applied after that step
  is a report rather than a control.
- **Configuration comes from the environment.** The code reads secrets and
  per-environment values at startup, and validates them there. A value
  committed to the repository is public for the life of that history.
- **State what was decided.** Put the security-relevant choices in a short
  note. The reader cannot tell an unstated default from an oversight, and must
  otherwise derive it again.

### Django & DRF implementation layer

This file does not collect the per-task rules. Each rule stays beside the
control it belongs to, in the reference that owns that control. The agent
therefore has the rule in context at the moment it generates the code that the
rule governs. This table is an index to those rules, not a copy of them:

| Generation moment | Rule lives in |
|---|---|
| A serializer, a viewset, an `@action`, a filter or paginator | `api-drf-specific.md` |
| A queryset behind a list, detail, or bulk route | `api-drf-specific.md`, with the privilege model in `authorization-architecture.md` |
| A query, a `subprocess` call, a management command, server-rendered output | `a05-injection.md` |
| A settings module | `a02-security-misconfiguration.md` |
| An upload field or handler | `file-uploads.md` |
| A view that reads or serves a file whose name derives from a request | `a01-broken-access-control.md`, "Path traversal" |
| A Celery task or its serializer configuration | `a08-integrity-and-deserialization.md` |
| An outbound HTTP call whose URL derives from input | `a01-broken-access-control.md`, "SSRF" |
| A new limit, quota, or business flow | `a06-insecure-design.md` |
| A data migration | `a03-software-supply-chain.md`, "Migration and data-integrity safety" |
| A token, a secret, or the check that compares one | `a04-cryptographic-failures.md` |
| A login, signup, reset, invite, or MFA endpoint | `a07-authentication-failures.md` |
| A custom user model, or the identifier field it authenticates on | `a07-authentication-failures.md`, "The user model as an identity contract" |
| A path that deactivates, suspends, or offboards an account | `authorization-architecture.md`, "Identity lifecycle and provisioning desynchronization" |
| A log line or an audit record | `a09-logging-and-alerting.md` |
| An export that writes a CSV, TSV, or workbook cell | `a05-injection.md`, "Export channels and formula injection" |
| A transaction, a state transition, or a retryable handler | `a10-exceptional-conditions.md` |
| A new route of any kind reaching the URLconf | `authorization-architecture.md`, "Default-deny architecture", with the pattern's own shape — anchoring, converter, and where it sits among the routes that could also match — in `a01-broken-access-control.md`, "URL resolution as an access-control surface" |
| A language switch view, or `LocaleMiddleware` added to a project that caches | `a01-broken-access-control.md`, "Locale redirects and language negotiation" |
| An impersonation or break-glass path | `privileged-access-and-impersonation.md` |
| A GraphQL type or resolver | `graphql-and-alternative-api-surfaces.md` |
| A Django Ninja route | `graphql-and-alternative-api-surfaces.md`, "Django Ninja: nothing is authenticated by default" |
| A gRPC servicer or a `.proto` service definition | `graphql-and-alternative-api-surfaces.md`, "gRPC: nothing from the DRF request cycle applies" |
| A Channels consumer or its routing | `async-and-channels.md` |
| An MCP tool over a Django application | `agent-and-llm-interfaces.md` |
| A field holding a value the database must not read | `data-layer-and-database.md` |
| A model field holding personal data | `data-lifecycle-and-privacy.md` |
| A model field that names its own target — a content type beside an object id | `a01-broken-access-control.md`, "Generic relations and the client-chosen content type" |
| A verifier for an inbound machine token | `service-identity-and-secrets.md` |
| A Dockerfile | `deployment-and-runtime.md` |

## When a secure default conflicts with the request

Apply the secure default. Then state it in one line that names the risk and
the exact opt-out. If the user confirms that they want the other form, write
that form. Leave a short comment at the site that records what the change gave
up. Never downgrade a default in silence, and never refuse in silence. An
unrequested refusal surprises the user as much as an unnoticed downgrade, and
the user learns of each one late.

Three changes need a firmer stop, because they are almost never the intent and
their effect is not local. The first is to disable TLS certificate
verification. The second is to admit `pickle` on a broker or a cache that
other software can reach. The third is to write a production credential into
the repository. **Warning: each of these three changes can expose production
data or permit remote code execution.** State the consequence and get an
explicit confirmation before you write any of them.

## The security-decisions note

Write-time does not produce a findings report. A report records defects in
code that the agent did not write. A finding that says "the viewset I just
wrote has a permission class" adds no information. It also trains the reader
to read the important paragraph too quickly.

The output is the code, followed by a few bullets:

- each secure default that you applied where the easier alternative was
  different, in a few words each;
- anything the request forced that this contract would not select, with the
  residual risk named;
- anything the code cannot do for itself and leaves to the caller — a setting,
  a migration, a bucket policy, or an environment variable.

Write nothing else. Give no severity rating and no CWE mapping. Do not restate
a control that was never in question. If there is genuinely nothing to report,
write nothing.

A worked note, accompanying a new orders endpoint:

```
Security decisions
- permission_classes set explicitly to [IsAuthenticated, IsTenantMember];
  DRF's default is AllowAny, so leaving it off would have published the route.
- get_queryset() filters on request.user.tenant, so the detail route cannot be
  walked by id.
- owner is set in perform_create() and is read-only on the serializer, because
  object permissions do not run on create.
- You asked for CSV export with no page limit. It streams the whole scoped
  queryset, so one large tenant can hold a worker for the duration; the
  throttle class is wired but left disabled as requested.
- ORDERS_EXPORT_BUCKET has to exist in the environment. There is no default,
  and startup fails without it.
```

## How write-time rules are written

This skill states every control in both grammars. The two forms sit together
under the control, and not in separate files. A control with only a review
form is incomplete. It tells a reviewer what to look for, and tells a writer
nothing.

The write-time form is a positive imperative in framework vocabulary, with one
clause of reason. Its shape is *when [the generation moment], [the concrete
action], because [the reason]*. Three properties do the work. Each one fails in
a specific way when the author drops it:

- **The moment** is the property that makes the rule fire. A rule with no
  trigger is a true statement that a reader agrees with and does not apply.
- **The action in framework vocabulary** is the property that makes the rule
  executable. "Authorize the view" is advice.
  `permission_classes = [IsAuthenticated]` is an edit.
- **The reason** is the property that lets the rule reach the case it does not
  list. Therefore the rules here are not bare absolutes. A reader applies a
  rule with no stated reason exactly, and then applies it beyond its purpose.

Prefer the positive form. Where a prohibition is genuinely the shorter
statement, give the alternative in the same sentence. Do not leave the reader
to infer the alternative.

The global rules are the contract, the conflict rule, and this convention.
They live in this file, and the sections above index them. A per-task rule
lives beside its control, and this file does not copy it back.

## Review checklist

- [ ] The mode was chosen deliberately and the output matches it: a findings
      report for review-time, code plus a security-decisions note for
      write-time.
- [ ] Every finding names a source, a sink, and the path between them, rather
      than resting on a keyword match.
- [ ] Every hypothesis discharged the six-item gate in `01-audit-workflow.md`,
      "Phase 5 — verification" before it became a finding. Each finding
      carries its `Evidence` line — the shortest confirmed source-to-sink path
      and the protection that failed.
- [ ] Severity started from the baseline for the finding class. It moved a
      maximum of one step for a factor that the table names, and the finding
      states that factor. Where the rubric decided against the table, the
      finding says which way it leaned.
- [ ] Severity and confidence were scored separately, and neither one was
      inflated to cover for the other.
- [ ] A concurrency finding was rated on how reliably its window can be won
      and on the cost of the collision. It was not filed as Medium only
      because it is a race. A finding about surviving personal data was rated
      on the commitment made about that data, not on attacker value alone.
- [ ] Findings carry CWE and the OWASP mapping. An ASVS chapter appears only
      where the project is actually held to the standard. It is a chapter or a
      section, not a requirement number.
- [ ] The report states what was not reviewed.
- [ ] At write-time the secure default was applied first, and anything the
      request forced is named with its residual risk instead of left silent.
- [ ] Any control added to this skill carries both a review form and a
      write-time form. The two sit under the control, rather than split across
      files.
