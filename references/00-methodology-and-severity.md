# Methodology, Severity, and Report Format

This file owns **how a review is conducted and how its output is written** —
mode selection, the severity rubric and the confidence score beside it, the
finding schema and report structure, the ASVS 5.0 chapter mapping and when to
cite one, the standing write-time contract, and the convention that every
control in this skill is stated in a review form and a write-time form
together. It owns no vulnerability and no control. Each per-task rule lives
beside the control it governs, in the reference that owns it, and the
write-time table below is an index to those files rather than a copy of them.
`SKILL.md` owns the router that chooses between them and the ownership rules
that settle a topic more than one file could claim.

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
   `pickle`) is a lead, not a finding. Trace whether attacker-controlled data
   actually reaches the sink and whether the path is reachable in the deployed
   configuration. If you can't establish reachability, downgrade confidence or
   move it to "worth checking".
2. **Prefer confirmed over comprehensive.** A short list of real, exploitable
   issues with concrete fixes is worth more than a long list of maybes.
3. **Read-only by default in review mode.** Don't rewrite the project unless the
   user asks. Findings describe the fix; they don't silently apply it.
4. **Every finding is actionable.** Location, why it matters, and code the
   developer can apply. No vague "consider reviewing your auth".
5. **State the boundary.** Say what you reviewed and what you didn't. Silence
   reads as false assurance.

## Choosing the mode

- **Review-time** when asked to review/audit/scan, when code is pasted for a
  security opinion, or right after a feature is built. Output: a findings report.
- **Write-time** when generating or editing backend code. Output: secure code
  plus a security-decisions note. The standing defaults, the rule for when one
  of them conflicts with what was asked for, and the shape of the note are all
  below.
- Ambiguous → guardrails while coding, then offer a review.

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
  that it is a race.** "Requires specific conditions" describes an interleaving
  an attacker has to be lucky to hit; it does not describe one a machine caller
  opens on demand by firing concurrent requests at an endpoint. Where the
  window is reliably winnable and the collision moves money, entitlements, or a
  limit that was supposed to hold, the finding is High or Critical on its
  impact rather than Medium on its difficulty.
- **Impact has a regulatory dimension as well as an attacker-value one.**
  Personal data that survives the deletion it was promised, or a retention
  period nothing ever enforces, has little direct attack value and real
  consequence. Score it on the data and the commitment made about it, not on
  exploitability alone, and say which dimension carried the rating.

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
- Impact: the concrete attack or exposure this enables.
- Fix: the specific change, with a minimal code snippet.
```

## Mapping to ASVS 5.0

OWASP ASVS 5.0.0, released 30 May 2025 and still the current version, holds
around 350 requirements in 17 chapters at three cumulative levels — L1 is
roughly a fifth of the standard, L2 about seventy per cent of it including all
of L1, and L3 the remainder. It answers a different question from the Top 10
spine this skill is organised on. The Top 10 ranks what goes wrong most often;
ASVS enumerates what has to be demonstrably true before someone signs the
application off. A finding is discovered against the first and defended against
the second.

Carry an ASVS identifier only where the project is genuinely being held to the
standard — a regulated environment, a customer security review, a contracted
verification level. Everywhere else it is a third identifier for a reader with
no use for it. CWE and the OWASP mapping are not optional; this one is.

**Cite the chapter, and a section only where one sub-chapter is the whole
subject** — `V8` for an authorization finding, `V15.4` for a concurrency one.
Do not cite requirement numbers. ASVS 5.0 renumbered against 4.0.3, and the
third component is both the part that moves between releases and the most
expensive thing to keep true across twenty-three files. A chapter token stays
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

- **V3 and V17 are permanent non-goals**, not gaps. This is a backend skill;
  DOM handling, subresource integrity, and TURN or DTLS-SRTP signaling are
  outside its scope by design and adding them would make it worse at its job.
- **V10 is partial.** The client, relying-party, and resource-server side is
  covered in depth. The authorization-server and OpenID-provider duties in
  V10.4 and V10.6 are covered only as far as configuring
  `django-oauth-toolkit` goes, which is thinner than the chapter, and matters
  only for the uncommon case where the application is itself the issuer.
- **This skill also covers ground ASVS scopes out**, so an ASVS-clean
  application is not a reviewed one: ASVS excludes infrastructure and
  operational configuration, while `a02-security-misconfiguration.md` owns the
  DNS records that decide whether the domain can be forged and
  `deployment-and-runtime.md` owns the proxy, the process, and the image.
- **ASVS 5.0 has no chapter for agent and MCP tool surfaces.**
  `agent-and-llm-interfaces.md` has no mapping and does not need one; the
  standard predates the surface.

## Report structure

1. **Summary** — one paragraph: scope (what was reviewed), how it was reviewed
   (read + which scripts), and counts by severity.
2. **Findings** — ordered Critical → Low, using the schema above.
3. **Worth checking** — medium-confidence items with the exact thing to verify.
4. **Not reviewed / limitations** — files, flows, or layers you didn't cover
   (e.g., "runtime Nginx/systemd config not provided", "no tests reviewed").

## What to exclude

Keep the signal high. Don't report:

- Pure denial-of-service theory, resource-exhaustion speculation, or
  rate-limit-tuning opinions (note anti-automation gaps only where they're a
  real authz/abuse issue).
- Secrets that are correctly loaded from the environment (flag secrets only when
  **hardcoded** or committed).
- Framework internals you can't see configured, unless the code clearly
  misconfigures them.
- Client/browser-only concerns with no server component.
- Style or performance issues with no security impact.

## Worked examples

Two, because they fail differently. The first is the ordinary shape: a static
defect, visible in one view, where confidence comes from reading the code. The
second is the shape the schema handles worst if you have not seen it done — a
defect that exists only under concurrency, where `Impact` has to argue about a
timing window and `Confidence` is about reachability rather than about whether
the code says what it appears to say.

```
### [High] Object endpoint returns any user's invoice (IDOR)
- Location: billing/views.py:42
- Category: Broken Object Level Authorization | CWE-639 | OWASP A01:2025, API1:2023
- Confidence: High
- Problem: InvoiceDetail uses Invoice.objects.all() as the queryset and looks up
  by pk from the URL, with permission_classes = [IsAuthenticated]. Authentication
  is checked but ownership is not, so any logged-in user can read /invoices/<id>/
  for any id.
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
  then writes back balance - amount as a separate statement. Nothing serialises
  the two: no transaction wraps them, the read takes no lock, and the column
  carries no constraint. The route is reachable by any authenticated holder of
  the wallet and no throttle applies to it.
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

Review-time and write-time are the same controls in two grammars. A review rule
is a predicate over code that already exists — *flag X when Y*. A write-time
rule is an action taken before the code exists — *when generating Y, write Z*.
The second does not follow from the first. An agent can agree that views should
be authorized and still emit a viewset with no permission class, because
agreeing with a statement and executing an instruction are different
operations, and nothing in the moment of writing asked for the second.

### Principle layer

The contract is that the secure form is the default form and departing from it
is the deliberate act. Six standing rules cover most of what a backend agent
writes:

- **Deny by default.** A new route, task, or tool is unreachable until its
  access rule is stated, because a permissive framework default silently
  becomes the policy of every endpoint nobody annotated.
- **Bind data to the principal.** Ownership, tenant, role, and money are set
  from the authenticated identity on the server, never accepted from the
  request body, because a client that can name the owner is the owner.
- **Keep input as data.** Every value that reaches an interpreter arrives as a
  bound parameter, an element of an argument vector, or an escaped term,
  because the alternative is letting input decide what the operation means.
- **Constrain before consuming.** Size, type, count, and destination are
  checked ahead of the expensive or irreversible step, because a limit applied
  afterwards is a report rather than a control.
- **Configuration comes from the environment.** Secrets and per-environment
  values are read at startup and validated there, because a value committed to
  the repository is published for the life of that history.
- **State what was decided.** The security-relevant choices go in a short note,
  because an unstated default is indistinguishable from an oversight and the
  next reader has to re-derive it either way.

### Django & DRF implementation layer

The per-task rules are not collected here. Each lives beside the control it
belongs to, in the reference that owns that control, so that it is already
loaded at the moment the agent is writing the thing it governs. This table is
an index to them, not a copy:

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
| A log line or an audit record | `a09-logging-and-alerting.md` |
| A transaction, a state transition, or a retryable handler | `a10-exceptional-conditions.md` |
| A new route of any kind reaching the URLconf | `authorization-architecture.md`, "Default-deny architecture" |
| An impersonation or break-glass path | `privileged-access-and-impersonation.md` |
| A GraphQL type or resolver | `graphql-and-alternative-api-surfaces.md` |
| A Django Ninja route | `graphql-and-alternative-api-surfaces.md`, "Django Ninja: nothing is authenticated by default" |
| A Channels consumer or its routing | `async-and-channels.md` |
| An MCP tool over a Django application | `agent-and-llm-interfaces.md` |
| A field holding a value the database must not read | `data-layer-and-database.md` |
| A model field holding personal data | `data-lifecycle-and-privacy.md` |
| A verifier for an inbound machine token | `service-identity-and-secrets.md` |
| A Dockerfile | `deployment-and-runtime.md` |

## When a secure default conflicts with the request

Apply the secure default, then say so in one line that names the risk and the
exact opt-out. If the user confirms they want the other form, write it, and
leave a short comment at the site recording what was traded away. Never
silently downgrade, and never silently refuse — an unrequested refusal is as
much a surprise as a downgrade nobody noticed, and both end with the user
finding out later.

Three changes are worth a firmer stop, because they are almost never what was
meant and the blast radius is not local: turning off TLS certificate
verification, admitting `pickle` on a broker or cache that anything else can
reach, and writing a production credential into the repository. State the
consequence and get an explicit confirmation before writing any of them, rather
than applying the one-line note and moving on.

## The security-decisions note

Write-time does not produce a findings report. A report documents defects in
code the agent did not write; restating "the viewset I just wrote has a
permission class" as a finding is theatre, and it teaches the reader to skim
the one paragraph that mattered.

The output is the code, followed by a few bullets:

- each secure default applied where the frictionless alternative was different,
  a few words each;
- anything the request forced that this contract would not have chosen, with
  the residual risk named;
- anything the code cannot do for itself and is leaving to the caller — a
  setting, a migration, a bucket policy, an environment variable.

Nothing else. No severity ratings, no CWE mapping, no restating controls that
were never in question. If there is genuinely nothing to report, say nothing.

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

Every control in this skill is stated in both grammars, and the two sit
together under the control rather than in separate files. A control carrying
only a review form is incomplete: it tells a reviewer what to look for and
tells a writer nothing.

The write-time form is a positive imperative in framework vocabulary carrying
one clause of reason — *when [the generation moment], [the concrete action],
because [the reason]*. Three properties do the work, and each fails a specific
way when dropped:

- **Naming the moment** is what makes the rule fire. A rule with no trigger is
  a true statement that gets agreed with and not acted on.
- **Naming the action in framework vocabulary** is what makes it executable.
  "Authorize the view" is advice; `permission_classes = [IsAuthenticated]` is
  an edit.
- **Carrying the reason** is what lets the rule reach the case it did not
  enumerate. This is why the rules here are not written as bare absolutes: a
  rule with no stated why is followed to the letter and past the point.

Prefer the positive form. Where a prohibition is genuinely the shorter
statement, pair it with the alternative in the same sentence rather than
leaving the reader to infer one.

Global rules — the contract, the conflict rule, and this convention — live in
this file and are indexed above. Per-task rules live beside their control and
are not copied back here.

## Review checklist

- [ ] The mode was chosen deliberately and the output matches it: a findings
      report for review-time, code plus a security-decisions note for
      write-time.
- [ ] Every finding names a source, a sink, and the path between them, rather
      than resting on a keyword match.
- [ ] Severity and confidence were scored separately, and neither was inflated
      to cover for the other.
- [ ] A concurrency finding was rated on how reliably its window can be won
      and what the collision costs, rather than filed as Medium for being a
      race; a finding about surviving personal data was rated on the
      commitment made about that data, not on attacker value alone.
- [ ] Findings carry CWE and the OWASP mapping. An ASVS chapter appears only
      where the project is actually held to the standard, and it is a chapter
      or a section rather than a requirement number.
- [ ] The report states what was not reviewed.
- [ ] At write-time the secure default was applied first, and anything the
      request forced is named with its residual risk instead of left silent.
- [ ] Any control added to this skill carries both a review form and a
      write-time form, co-located under the control rather than split across
      files.
