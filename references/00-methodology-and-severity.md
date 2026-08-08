# Methodology, Severity, and Report Format

## Contents
- [Operating principles](#operating-principles)
- [Choosing the mode](#choosing-the-mode)
- [Severity rubric](#severity-rubric)
- [Confidence](#confidence)
- [Finding schema](#finding-schema)
- [Report structure](#report-structure)
- [What to exclude](#what-to-exclude)
- [Worked example](#worked-example)
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
exploitation** and say which way you leaned.

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
- Category: <e.g. Broken Object Level Authorization>  |  CWE-XXX  |  OWASP A0X:2025 (and APIX:2023 if relevant)
- Confidence: High | Medium
- Problem: one or two sentences on exactly what is wrong.
- Impact: the concrete attack or exposure this enables.
- Fix: the specific change, with a minimal code snippet.
```

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

## Worked example

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
| A Celery task or its serializer configuration | `a08-integrity-and-deserialization.md` |
| An outbound HTTP call whose URL derives from input | `a01-broken-access-control.md`, "SSRF" |
| A new limit, quota, or business flow | `a06-insecure-design.md` |

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
- [ ] The report states what was not reviewed.
- [ ] At write-time the secure default was applied first, and anything the
      request forced is named with its residual risk instead of left silent.
- [ ] Any control added to this skill carries both a review form and a
      write-time form, co-located under the control rather than split across
      files.
