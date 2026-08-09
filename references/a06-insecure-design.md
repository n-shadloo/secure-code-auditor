# A06:2025 — Insecure Design

Flaws that are missing controls by design rather than buggy code: absent rate
limits and anti-automation, business-logic and notification abuse, and unsafe
defaults. Overlaps OWASP API4:2023 (Unrestricted Resource Consumption) and
API6:2023 (Unrestricted Access to Sensitive Business Flows).

This file owns **which flows need a limit, and why** — the catalogue of what is
worth attacking when nothing caps it, and the design rule that every input
which multiplies work carries a server-enforced bound. It does not own the
mechanism that enforces one: `api-drf-specific.md` owns DRF throttling and the
reasons a configured rate is not the effective one,
`a07-authentication-failures.md` owns login lockout,
`agent-and-llm-interfaces.md` owns per-agent cost and concurrency limits, and
`a10-exceptional-conditions.md` owns the race and idempotency mechanics that
decide whether a limit holds under concurrent requests.

## Contents
- [Principle](#principle)
- [Rate limiting and anti-automation](#rate-limiting-and-anti-automation)
- [Algorithmic resource exhaustion](#algorithmic-resource-exhaustion)
- [Business-logic abuse](#business-logic-abuse)
- [Email and notification abuse](#email-and-notification-abuse)
- [Secure defaults and limits](#secure-defaults-and-limits)
- [Review checklist](#review-checklist)

## Principle

Some vulnerabilities aren't a broken line of code; they're a control that was
never designed in. If a sensitive flow (login, password reset, checkout, invite,
coupon redemption) has no limit on how fast or how often it can be driven, it
will be abused even when each individual request is "valid". The principle is to
**design abuse cases alongside features**: identify the flows worth attacking,
put limits and validations on them, and fail safe. This is a design review, not
just a code diff.

## Rate limiting and anti-automation

**Important:** DRF's throttling is explicitly **not** a security control. The
DRF documentation says so directly: it should not be treated as a defense
against brute forcing or denial of service, because the default classes key on
an IP origin an attacker can spoof and the counter is a non-atomic cache
operation. Throttles also run *after* authentication, so they don't protect the
auth step itself. The mechanics behind those caveats — the non-atomic
read-modify-write, the per-process cache, and the ordering inside `initial()` —
are in `api-drf-specific.md`, "Throttling as quota, not security (API4)". This
file owns which flows need anti-automation in the first place.

Package choices do not replace layered design. `django-axes==8.3.1` passes the
maintained-package gate for login-attempt monitoring and lockout on Django 6.0,
provided proxy trust and client-IP extraction are correct; use account plus
network/device signals and avoid attacker-triggered permanent denial of service.
`django-ratelimit==4.1.0` and `django-defender==0.9.8` do not pass the 9 Aug 2026
maintenance gate for new use. For general endpoints and business flows, combine
maintained edge/platform limits with application-level, account/tenant-aware
quotas and transactional invariants. Fail closed on sensitive flows, but define
degraded behavior so a cache outage does not silently remove protection.

Request rate and cost are separate controls, and a machine caller defeats the
first without breaching it. A retry loop or an automation running for hours
stays inside any per-minute cap while exhausting a budget, and a limit keyed on
IP is useless when a whole fleet shares one egress address. Where a flow spends
money, tokens, or heavy database work per call, cap the resource itself and the
concurrency, per principal identity, in addition to the request rate. See
`agent-and-llm-interfaces.md`, "Cost and concurrency limits, not only request
rate".

## Algorithmic resource exhaustion

Maps to CWE-400 (Uncontrolled Resource Consumption) and CWE-770 (Allocation of
Resources Without Limits), with CWE-674 (Uncontrolled Recursion) wherever the
input nests. OWASP API4:2023 Unrestricted Resource Consumption is the
API-security mapping. The Top 10:2025 has no denial-of-service category, so
this file owns the design question — which inputs need a bound — while each
file named in the table below owns the mechanics of enforcing one.

A rate limit counts requests. This is about the cost of a single one. Where
the work a request performs grows with a number the caller chose, the request
rate never sees it: `?page_size=100000` on a list endpoint, a serializer that
queries once per row over a queryset with no ceiling, a selection set whose
depth the client picks, a `count()` over a client-filtered table on every page
of a scan, an archive that expands to a thousand times its compressed size.
Each is a valid request costing the server orders of magnitude more than the
attacker spent making it, and that asymmetry is the vulnerability. It is also
why the defect survives review: nothing looks wrong at the size the developer
tested with.

**The design rule is that every unbounded input to an algorithm gets a bound
the server enforces.** Not a bound the client is asked to respect, not a
default the client may override upward, and not one that holds only on the
path that was benchmarked. Three questions settle whether a flow has one:

- What does the caller control that multiplies work — a count, a depth, a page
  size, a date range, a compression ratio, a number of nested items?
- What is the ceiling, and which layer enforces it: the edge, the framework,
  the application, or nothing?
- What happens at the ceiling — a rejection, a truncation the caller is told
  about, or an out-of-memory kill that takes the worker's other requests with
  it?

### Django & DRF

- **A page-size query parameter without `max_page_size` removes the ceiling
  rather than adding one.** `PageNumberPagination` ships with
  `page_size_query_param = None`, so the client cannot change the page size at
  all; setting it hands the client control bounded only by `max_page_size`,
  which is also `None` and therefore no bound. Set the two together or neither.
  `LimitOffsetPagination` is the sharper default because it accepts a client
  `limit` out of the box with `max_limit = None` behind it.
- **No `PAGE_SIZE` means no pagination at all.** `DEFAULT_PAGINATION_CLASS`
  is `None` out of the box, and a list view without a paginator returns every
  row the queryset matched. The failure is an absence, so it is invisible in a
  diff and shows up only under production data volumes.
- **Serialization cost is per row and it compounds.** A
  `SerializerMethodField` that runs a query, or a nested serializer over a
  reverse relation, multiplies by the page size, and a page size the client
  raised multiplies it again. `depth` on a `ModelSerializer` walks relations
  automatically to the depth given, which is the form of this that no one
  reads back off the class body.
- **A large read is streamed and value-scoped rather than materialized.**
  `.iterator()` keeps the whole result set out of the queryset cache, `.only()`
  and `.values()` cut the per-row payload, and a server-side statement timeout
  bounds what either can cost when the estimate is wrong
  (`data-layer-and-database.md`, "Connection exhaustion and query timeouts").
- **`count()` is a scan the caller triggers.** `PageNumberPagination` and
  `LimitOffsetPagination` issue one per request over whatever the filters
  produced, so on a large table under a client-controlled filter it is an
  expensive query available on demand. `CursorPagination` issues none, which
  is a resource argument for it independent of the disclosure argument in
  `api-drf-specific.md`, "Pagination and filter leakage".
- **Recursion depth is an input like any other.** Parsed structures nest —
  request bodies, selection sets, XML entities, archive members, and any
  self-referential model walked in Python. Bound the depth at the parser or
  the validator, before the recursion runs; catching `RecursionError`
  afterwards has already paid the cost and leaves the interpreter in a state
  no security decision should be made from.

Each surface enforces its own version of the bound, and the mechanics are not
restated here:

| Surface | The bound that applies | Owner |
|---|---|---|
| Request body, field count, file count | Edge body cap plus the Django `DATA_UPLOAD_*` thresholds | This file, "Secure defaults and limits" |
| Uploaded files and their expansion | Per-file and aggregate size, count, quota, and decompression ratio | `file-uploads.md`, "Size, count, and quota limits" |
| List responses | An enforced `PAGE_SIZE`, `max_page_size`, and filter and ordering allowlists | `api-drf-specific.md`, "Pagination and filter leakage" |
| Client-composed documents | Depth, alias, token, and cost limits applied before execution, and batch size | `graphql-and-alternative-api-surfaces.md`, "Bounding the document: depth, aliases, tokens, and cost" |
| Long-lived connections | Message size and rate, queued work, fan-out, idle and absolute lifetime | `async-and-channels.md`, "Long-lived consumers and resource limits" |
| Database connections and query time | Pool `max_size` and a server-side statement timeout | `data-layer-and-database.md`, "Connection exhaustion and query timeouts" |
| A pattern run over input | An input length cap before the regex, and no pattern compiled from input | `a10-exceptional-conditions.md`, "Regular expressions and algorithmic cost" |
| Model tokens and tool calls | Per-agent cost and concurrency budgets | `agent-and-llm-interfaces.md`, "Cost and concurrency limits, not only request rate" |

Severity is rated on what one request costs and how repeatable it is, not on
the word "denial of service": a single call that pins a worker for minutes or
exhausts the connection pool is High, while a bound that is merely generous is
a hardening finding.

**Write-time.** When generating an endpoint, a serializer, or a parser whose
work scales with something in the request, write the ceiling into the same
declaration — `max_page_size` beside `page_size_query_param`, a depth or count
limit beside the field that accepts the nested input, `.iterator()` and an
explicit field list on the read that is expected to grow — because the value
that makes the bound obviously necessary only exists in production, and by
then the endpoint has callers relying on its absence. Where the caller does
not need to choose the size at all, do not expose the parameter, since a
bound that is never reachable cannot be tuned wrong.

## Business-logic abuse

Investigate flows where "valid" requests cause harm:

- Checkout/payment: amounts, prices, or discounts taken from the client rather
  than resolved server-side (see the DRF file's payment section). Quantity/price
  never trusted from the request.
- Idempotency: repeated submits creating duplicate orders/charges — enforce with
  a unique constraint or idempotency key. The key design itself, including the
  request fingerprint that stops a reused key answering a different request,
  lives in `a10-exceptional-conditions.md`, "Idempotency".
- Referral/coupon/invite systems that can be replayed or self-referred.
- State machines that can be skipped (e.g. marking an order paid without a
  payment event), or transitioned twice concurrently because the guard is a
  Python check rather than a conditional update. This file catalogues the flows
  worth attacking; `a10-exceptional-conditions.md`, "Races, TOCTOU, and
  adversarial sequencing" owns the concurrency mechanics that enforce them.

## Email and notification abuse

Maps primarily to CWE-799 (Improper Control of Interaction Frequency),
CWE-204 (Observable Response Discrepancy), and CWE-918 (SSRF), with overlap
across OWASP A06:2025, A07:2025, API4:2023, and API6:2023.

### Principle layer

An endpoint that sends email, SMS, push notifications, invitations, shares, or
previews transfers money, reputation, attention, and sometimes credentials.
Attackers can drive a valid workflow as a spam relay, mailbox-flooding tool,
account-enumeration oracle, or SSRF client. The invariant is: **a notification
trigger must disclose no target existence, must be bounded across every useful
abuse dimension, and must authorize both the action and its destination.**

- Return the same status, body, and materially similar response path whether or
  not a reset, magic-link, or invitation target exists. Do not use a literal
  sleep as the primary timing defense; queue a uniform request shape and keep
  the observable request path small.
- Layer limits by source, unauthenticated client, authenticated actor, tenant,
  normalized destination, target account, template/action, and time window.
  Include cooldowns, rolling windows, daily caps, concurrent/outstanding-token
  caps, and global circuit breakers. A single IP limit is bypassable; a single
  destination limit can be weaponized to deny a victim service.
- Authorize invite/share actions and constrain recipients, role, object,
  template, sender identity, and redirect/link destination. Do not let a client
  supply arbitrary message templates, sender headers, or URLs.
- Deduplicate and make enqueue/send operations idempotent. Retries must not send
  duplicates, create extra valid tokens, or bypass quotas.
- Treat remote image, document, Open Graph, and link-preview fetching as SSRF.
  Allowlist schemes and destinations, resolve and reject private/link-local
  addresses, re-check redirects, and cap time and response bytes.
- Log aggregate outcomes and abuse signals without recording reset tokens,
  magic links, message bodies, or unnecessary destination data.

### Django & DRF implementation layer

Django's password-reset views use a generic success flow, but the real-account
path performs more work and may send mail while a nonexistent account does not.
Keep the HTTP response generic and enqueue the same normalized request shape for
background handling after edge and application limits. The worker may determine
that no eligible account exists, but that outcome must not be reflected to the
caller. Build links from a configured canonical application origin, not an
untrusted `Host` header.

DRF throttles are quota tools and can be fuzzy under concurrency; they are not
the sole control for reset, magic-link, invite, share, or messaging abuse. Add
edge controls plus atomic Redis/database counters or a maintained limiter.
Store rate keys as keyed digests when raw destinations would expose personal
data. Apply destination and target-account limits silently so the response does
not become an enumeration oracle.

For reset and magic-link workflows:

- use Django's time-bounded reset tokens or a cryptographically random,
  single-use, hashed-at-rest token;
- bind the token to the intended account, purpose, and redirect allowlist;
- cap outstanding valid tokens and invalidate or supersede them on use,
  password change, email change, or account disablement;
- do not auto-login or reveal account state merely because a request was made;
  and
- notify the account of meaningful security changes without placing a usable
  credential in logs or analytics.

For invite/share workflows, load the shareable object through a
requester-scoped queryset, cap recipient count and privilege, reject
self-escalation and cross-tenant targets, require a verified sender identity
where appropriate, and make repeated submissions idempotent.

Security-relevant database state and outbound messages must not disagree. Write
the durable event in a transaction and enqueue only after commit:

```python
from functools import partial

from django.core.exceptions import PermissionDenied
from django.db import transaction


@transaction.atomic
def create_invite(*, actor, project, recipient_email, idempotency_key):
    if not project.admins.filter(pk=actor.pk).exists():
        raise PermissionDenied
    enforce_invite_limits(
        actor=actor,
        tenant=project.tenant,
        recipient_email=recipient_email,
    )
    invite, _ = Invite.objects.get_or_create(
        project=project,
        idempotency_key=idempotency_key,
        defaults={
            "created_by": actor,
            "recipient_email": recipient_email,
        },
    )
    transaction.on_commit(
        partial(enqueue_invite_once, invite_id=invite.pk),
    )
    return invite
```

`get_or_create()` above is race-safe only because a unique constraint on
`(project, idempotency_key)` exists in the model and in a migration; without
one it silently creates duplicates under concurrent submits, which is the
failure this flow is meant to prevent.

The worker must also be idempotent and re-check that the invite is pending,
unexpired, and still authorized before sending. Do not put full message bodies,
tokens, or unnecessary personal data in task arguments.

An email-preview or unfurl endpoint must use the SSRF controls in A01: approved
schemes and destinations, DNS/IP checks before connection, redirect
revalidation, strict connect/read timeouts, a response-byte cap, no ambient
cloud credentials, and no raw upstream response reflection. Prefer fetching in
a network-isolated worker.

Header injection remains covered in A05. Queue serialization and webhook
integrity are covered in A08; sensitive log handling is covered in A09.

### Notification-abuse review checklist

#### Stack-neutral

- [ ] Reset, magic-link, invite, share, and messaging endpoints return a
      non-enumerating response and follow a materially uniform request path.
- [ ] Atomic limits cover source, actor, tenant, destination, target, action,
      cooldown, outstanding state, and global volume without enabling a trivial
      denial of service against one destination.
- [ ] Recipients, roles, objects, templates, senders, and link destinations are
      server-authorized and allowlisted; retries and duplicate requests are
      idempotent.
- [ ] Tokens are purpose-bound, short-lived, single-use, hashed at rest where
      stored, capped, and revoked on relevant account changes.
- [ ] Preview fetches use full SSRF defenses and bounded, isolated processing.
- [ ] Logs, queues, and analytics contain no usable token, magic link, message
      body, or unnecessary destination data.

#### Django & DRF

- [ ] Password-reset/magic-link requests use generic responses, a canonical
      configured origin, and a queue path that does not expose account existence.
- [ ] DRF throttling is supplemented by edge limits and atomic application
      counters for security-sensitive notification flows.
- [ ] Invite/share objects are loaded through requester-scoped querysets, and
      outbound work is registered with `transaction.on_commit()`.
- [ ] Workers deduplicate and re-check pending, expiry, and authorization state
      before sending.

## Secure defaults and limits

- Enforce a hard request-body limit at the reverse proxy/gateway, plus
  endpoint-specific per-file, aggregate, count, processing, and per-principal
  quotas (see `file-uploads.md` and deployment).
- `DATA_UPLOAD_MAX_MEMORY_SIZE` excludes uploaded-file bytes, while
  `FILE_UPLOAD_MAX_MEMORY_SIZE` is the memory-to-temporary-file threshold; do
  not describe either as a hard file-size rejection control.
- `DATA_UPLOAD_MAX_NUMBER_FIELDS` and `DATA_UPLOAD_MAX_NUMBER_FILES` cap
  multipart complexity — don't raise them casually.
- Database connections are an exhaustible resource with a hard server-side
  ceiling. Cap them at a pool you control rather than at worker count, and set a
  server-side statement timeout so one slow query cannot hold a connection
  indefinitely (`data-layer-and-database.md`).
- New features should default to the least-privileged, least-exposed setting;
  opening up is a deliberate act.

**Write-time.** When generating a flow that costs something to run — mail,
money, model tokens, an export, a third-party call — give it its limit in the
same change that introduces the flow, keyed on the principal rather than on the
address, because a flow ships without a limit exactly once and the limit is
then written under incident conditions. Where the flow is security-sensitive,
that limit has to be an atomic counter or a database constraint rather than a
throttle class; the distinction and the mechanics behind it are in
`api-drf-specific.md`, "Throttling as quota, not security (API4)".

## Review checklist

- [ ] Login and sensitive flows have real anti-automation (lockout + limits),
      not just DRF throttles.
- [ ] Expensive flows cap cost and concurrency per principal identity, not only
      requests per minute, and do not key the limit on IP for machine callers.
- [ ] Every caller-controlled value that multiplies work — page size, depth,
      nesting, date range, batch or expansion factor — has a ceiling the
      server enforces, and the ceiling is reached by a rejection rather than
      by an out-of-memory kill.
- [ ] Money/quantity/discount resolved server-side; idempotency enforced, with
      a unique constraint actually behind the key rather than a Python check.
- [ ] Replayable/self-referable business flows are constrained.
- [ ] Notification triggers are non-enumerating, authorized, idempotent, and
      bounded by source, actor, tenant, destination, target, and global volume.
- [ ] Upload/body/count/processing limits exist at edge and application layers;
      Django memory thresholds are not mistaken for hard upload caps.
- [ ] Database connection concurrency is bounded by a pool and queries are
      time-limited server-side, rather than left to worker count.
