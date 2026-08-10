# A06:2025 — Insecure Design

Flaws that are missing controls by design rather than buggy code: absent rate
limits and anti-automation, business-logic and notification abuse, and unsafe
defaults. Overlaps OWASP API4:2023 (Unrestricted Resource Consumption) and
API6:2023 (Unrestricted Access to Sensitive Business Flows).

This file owns **which flows are worth attacking, and why** — the inventory
of the paths that move money, credits, entitlements, or durable status, the
catalog of what goes wrong when nothing caps a flow, and the design rule that
every input which multiplies work carries a server-enforced bound. It does not
own the mechanism that enforces any of it: `api-drf-specific.md` owns DRF
throttling and the reasons a configured rate is not the effective one,
`a07-authentication-failures.md` owns login lockout,
`agent-and-llm-interfaces.md` owns per-agent cost and concurrency limits, and
`a10-exceptional-conditions.md` owns the race and idempotency mechanics that
decide whether a limit or a transition holds under concurrent requests.

## Contents
- [Principle](#principle)
- [Rate limiting and anti-automation](#rate-limiting-and-anti-automation)
- [Algorithmic resource exhaustion](#algorithmic-resource-exhaustion)
- [Business-logic abuse](#business-logic-abuse)
- [Abuse of side-effecting actions](#abuse-of-side-effecting-actions)
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

Maps to CWE-840 (Business Logic Errors) and CWE-841 (Improper Enforcement of
Behavioral Workflow), with CWE-472 (External Control of Assumed-Immutable Web
Parameter) wherever the client supplies a value the server should have
resolved for itself. OWASP API6:2023 Unrestricted Access to Sensitive Business
Flows is the API-security mapping.

### Principle layer

The severity rubric already rates manipulation of money, orders, and balances
at the Critical tier, and `a10-exceptional-conditions.md` already carries the
mechanics that hold such a flow together under concurrency. Neither answers
the question that has to come first: **which paths in this codebase move
money, credits, entitlements, or durable status at all.** A reviewer who never
enumerates them reviews the checkout view because it is named `checkout`, and
never opens the management command that grants the same credit without one.

So the work runs in three steps and the order matters. Enumerate every
transition that writes one of those values, including the transitions that
never touch a view. For each, ask whether its invariant is held by the
database or only by Python. Then ask what a failure part-way through leaves
behind — a captured payment with no local order, an entitlement with no
subscription, a status a retry can enter twice.

A flow is worth attacking when a request that passes every validator still
produces a result the business would not have agreed to: an order that ships
without a payment, a plan that upgrades without a charge, a coupon that
redeems twice, a refund larger than the capture behind it, a trial that
restarts. None of those is a broken line of code, which is why they survive
both a diff review and a scanner, and why the enumeration is the control.

### Django & DRF implementation layer

#### Finding every path that moves money or status

Start from the data rather than from the views, because the views are the
subset a reviewer would have found anyway. Three sweeps; the flow inventory is
their union.

**The fields.** Read the model layer for the value rather than for one
domain's vocabulary: a balance, a quantity, a price or amount, a currency, a
credit, a plan, a tier, a role, a seat, an expiry, and any field named
`status`, `state`, or `is_active`. A `DecimalField` or a
`PositiveIntegerField` on a model whose name is not obviously financial is
where the second wallet usually lives. Record each field against its model,
because every sweep below is a search for code that writes one of them.

**The transitions.** For each recorded field, find every assignment to it and
every queryset call that can set it. Views are the half that is easy to find.
The half that decides the review is everything writing the same field without
passing through one:

- management commands under `<app>/management/commands/`, which run with no
  request, no permission class, and often no transaction;
- Celery tasks and beat schedules, which write on a redelivery as readily as
  on the first attempt;
- admin actions and a `ModelAdmin.save_model` override, which reach an
  operator's fingers and no serializer at all;
- signal receivers, which write in response to another model's save and are
  skipped entirely by the bulk paths below;
- data migrations, which write once, under the invariants of the day they were
  written, and are never re-reviewed;
- `update()`, `bulk_create()`, and `bulk_update()` on a queryset, which write
  without `save()`, without `full_clean()`, and without the save signals, and
  `QuerySet.delete()`, which does not call the model's own `delete()`
  (`api-drf-specific.md`, "Bulk endpoints" owns the authorization half);
- `loaddata` and any import feature behind it, which write through
  `save_base(raw=True)` and therefore skip a model's own `save()` entirely
  (`a08-integrity-and-deserialization.md`, "Insecure deserialization").

`scripts/entrypoint_inventory.py` produces the entry-point half of this sweep
— routes at their resolved prefixes, router registrations and actions, tasks,
commands, signals, admin, and middleware — and `01-audit-workflow.md`,
"Phase 1 — entry-point inventory" owns how it is run and what it structurally
cannot see. What this section adds is the question to ask of each row it
returns: which of the recorded fields can this entry point write, and through
which of the paths above.

**The external events.** The last sweep is where an inbound callback meets a
state machine. A provider's webhook, a partner's callback, a scheduled
reconciliation job, and a queue consumer each drive a transition on an event
this codebase did not originate, so the guard on the transition is the only
thing between a forged or replayed event and a status change. Enumerate them
with the receivers themselves: a `csrf_exempt` POST route, a view with
`authentication_classes([])`, and any handler reading `request.body`.
`a08-integrity-and-deserialization.md`, "Webhook and callback integrity" owns
what such a receiver has to prove before its payload is believed at all; this
sweep is about what the payload is then allowed to change.

The inventory is finished when every recorded field has a complete list of
writers, not when the views look covered. Record a field whose writers you
sampled rather than enumerated as sampled, on the budget rule in
`01-audit-workflow.md`.

**Write-time.** When generating a model field that holds a balance, a price, a
quantity, a credit, a plan or tier, an expiry, or a status, write down in the
same change which code is allowed to write it and give the field its database
constraint there, because the second writer is always added later by someone
who has not read the first, and the field is the only place all of them meet.
When generating any of the non-view writers above — a command, a task, an
admin action, a receiver, a data migration — state which of those fields it
writes before writing its body, since the path that skips the serializer is
also the path that skips every check written into one.

#### The invariant question

For each transition found, one question decides the finding: **is the
invariant enforced by the database, or only by Python?** The database is the
only layer every writer in the sweep above shares, so an invariant held
anywhere else holds on the paths that were remembered and not on the paths
that were not.

| The invariant | The database form | The form that holds on one path only |
|---|---|---|
| A value stays in range — non-negative, non-zero, at most a ceiling | `CheckConstraint(condition=Q(balance__gte=0))` | `if balance >= amount:` before a `save()` |
| At most one live row of a kind — one active subscription, one redemption per coupon per account | `UniqueConstraint(fields=[...])`, with `condition=Q(cancelled_at__isnull=True)` where a cancelled or superseded row must stop blocking a new one | `.exists()` before a `.create()` |
| A transition runs from exactly one prior state | `.update()` filtered on that prior state, with the affected-row count as the answer | `get()`, an `if` on `status`, and a later `save()` |
| An arithmetic change applies to the committed value | `F("balance") - amount` | `obj.balance = obj.balance - amount` |
| A field is never set by a client | absent or read-only on every serializer, written server-side | a `validate_amount` on one of several serializers |

The right-hand column is not a list of bad code. Each entry is a check that
works, in the one place it runs, which is exactly why it survives review. Four
shapes account for most of them:

- **A Python comparison before a `save()`** is correct until a second caller
  interleaves with it. The race mechanics, the choice between a constraint and
  a lock, and the four ways `select_for_update()` silently does nothing are in
  `a10-exceptional-conditions.md`, "Races, TOCTOU, and adversarial
  sequencing"; that file also owns the conditional-`update()` and constraint
  forms named above.
- **A `clean()` method** runs only where something calls `full_clean()`.
  Django's `save()` does not, so a `clean()` is enforced on the ModelForm and
  admin paths and nowhere else.
- **A serializer `validate_` method** is a check on one entry point. It is not
  an invariant. The sweep above exists precisely because a field has other
  writers, and a serializer method reaches none of them — not the command,
  not the task, not the admin action, not the second serializer someone adds
  for the mobile client.
- **A signal receiver** is skipped by every bulk path in the sweep, so an
  invariant maintained in `post_save` disappears the day a slow loop is
  rewritten as `bulk_update()` for reasons that have nothing to do with it.

A constraint added to a table that already violates it fails at deploy time;
`a03-software-supply-chain.md`, "Migration and data-integrity safety" owns
sequencing that.

**Write-time.** When generating a transition on any inventoried field, write
the invariant as a `CheckConstraint` or a `UniqueConstraint` in the model's
`Meta` and in the migration in the same change, and express the transition
itself as a conditional `update()` whose affected-row count decides the
outcome, because a check in Python binds the caller you are writing and the
database binds every caller you are not. Where a serializer `validate_` method
is the natural place to give the client a good error, write it in addition to
the constraint rather than instead of it, since its job is the message and the
constraint's job is the guarantee.

#### Amount and currency binding

The server resolves price, currency, quantity limits, discount eligibility,
and tax from its own records, keyed by an identifier the client supplies. **A
client that sends an amount is proposing one**, and a flow that accepts the
proposal has moved pricing into the request body. The same holds for anything
derived from an amount: a discount percentage, a tax rate, a shipping cost, a
loyalty multiplier, and the currency the total is denominated in — a total
that is correct in one currency and labelled as another is a manipulation that
passes every numeric validator.

In DRF the form is that the field is absent from the serializer or read-only
on it, and the value is set in `perform_create()` or in the service layer
underneath it. `api-drf-specific.md`, "Serializer exposure and mass assignment
(API3)" owns the exposure rules themselves, including why `read_only_fields`
does not reach a declared field.

```python
# Wrong: unit_price and currency are writable, so the order is priced by
# whoever sends the request, and quantity carries no ceiling at all.
class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity", "unit_price", "currency"]
```

```python
# Correct: the client names what it wants and the server resolves what that
# costs. Price and currency are read-only on the serializer and written from
# the catalogue row, so no request body reaches them on this path -- and the
# CheckConstraint on the model holds them on the paths that are not this one.
class OrderItemSerializer(serializers.ModelSerializer):
    quantity = serializers.IntegerField(min_value=1, max_value=100)

    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity", "unit_price", "currency"]
        read_only_fields = ["id", "unit_price", "currency"]


class OrderItemViewSet(viewsets.ModelViewSet):
    serializer_class = OrderItemSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        product = serializer.validated_data["product"]
        serializer.save(unit_price=product.price, currency=product.currency)
```

A coupon or discount is the same rule with a second half. The eligibility test
belongs on the server, and the redemption needs a uniqueness invariant behind
it — per coupon, per account, per order — or the code is a replay. Where
the reward accrues to a referrer, the self-referral case is a check that the
beneficiary and the actor are different principals, and it is one the database
can hold as a `CheckConstraint` rather than a Python comparison.

**Write-time.** When generating an endpoint that prices, charges, discounts,
or credits anything, accept only identifiers and quantities from the request
and resolve every monetary value from the server's own row in
`perform_create()` or the service layer, because a field that is merely
validated is still a field the client chose. Give the quantity its
`min_value` and `max_value` on the serializer field in the same edit, since a
negative or enormous quantity multiplied by a correct price is the same
manipulation arriving through arithmetic.

#### Capture, refund, and reversal

Each of these is a transition that must happen exactly once and is driven by
an event from a system you do not control, so each inherits both sets of
mechanics: `a08-integrity-and-deserialization.md`, "Webhook and callback
integrity" for the signature, timestamp, replay tolerance, and event
de-duplication the callback has to satisfy, and
`a10-exceptional-conditions.md`, "Idempotency" for the key, the request
fingerprint, and the stored response. Neither is restated here.

What A06 owns is the design question those mechanics serve, and it is three
questions about the flow rather than about the handler.

- **Which transitions are irreversible?** A capture that has settled, an email
  that has been delivered, a file handed to a third party, and a payout that
  has left are outside your database's control the moment they complete.
  Everything before such a step can be rolled back by a transaction;
  everything after it cannot, so the ordering of the irreversible step against
  the commit is the design (`a10-exceptional-conditions.md`, "Side effects and
  the commit boundary").
- **Which are compensating rather than reversing?** A refund is a second,
  forward transaction that happens to move value the other way. It is not an
  undo: it has its own identifier, its own failure modes, its own fees, and
  its own reasons to be refused. Modelling it as a status change back to the
  previous state loses the record that both events happened, and a system that
  cannot distinguish "never charged" from "charged and refunded" cannot answer
  a dispute or bound a second refund against the same capture.
- **What does a partial failure leave behind?** The gap between the external
  system and the local record is the one place a transaction cannot reach.
  Either side can succeed alone: a capture that settled while the response
  timed out leaves money taken and no local order, and a local order marked
  paid before the provider confirmed leaves goods shipped against nothing.
  Decide which direction the flow fails in, make the recoverable side the one
  that is retried, and give the pair a reconciliation path that reads the
  external system's own record rather than trusting the local one.

The severity follows from the third question rather than from the first two.
Where a partial failure is recoverable by a job that reconciles, it is a
design finding; where it silently grants goods, credit, or entitlement, it is
the Critical-tier impact the rubric names.

**Write-time.** When generating a capture, refund, or reversal path, write the
local record and the external call as two steps with a stated order — the
durable row first, the irreversible call registered through
`transaction.on_commit()` — and give the flow a status that distinguishes
attempted, confirmed, and reconciled rather than a boolean, because the state
you cannot represent is the state the reconciliation job cannot repair. Store
the provider's own identifier for the operation on the local row in the same
edit, since it is the only key a later reconciliation can join on.

#### Entitlement grant and revocation

The question for every entitlement is whether the grant and the revocation are
symmetric. A grant is a deliberate feature that someone specified, tested, and
demonstrated. Revocation is a consequence nobody demonstrates, so it is where
the asymmetry lives, and the failure is silent: the customer keeps what they
stopped paying for and nothing raises an error.

Four shapes cover most of it, and each has a different owner for its
mechanics.

- **The entitlement that survives its subscription.** The plan lapses, is
  cancelled, or fails a renewal, and the row granting access is never revisited
  because the grant was written as a durable fact rather than as a derivation
  from the subscription's current state. Prefer deriving the entitlement from
  the subscription at read time; where it is materialised for performance, the
  revocation path is a feature that has to be written and tested, not an
  implication.
- **The seat that survives its removal from a team.** Membership is deleted
  and the objects, invitations, API tokens, and shares created under it stay
  live and still resolve. Enumerating what a principal's access reaches, so
  that removing the principal reaches all of it, is
  `authorization-architecture.md`, "Permission-model decay and access review".
- **The cached permission that outlives the role change.** The decision was
  correct when it was computed and is served from a cache, a session, a
  denormalised column, or a token whose claims were minted before the change.
  A revocation that does not invalidate the cache is a revocation with a
  latency nobody has measured; state the window and make it deliberate.
- **The trial that can be restarted.** A trial, an introductory rate, a
  one-per-account credit, and a first-order discount are all the same
  invariant — at most one per identity, for the life of that identity — and
  it fails when the identity is one a caller can re-mint. Key uniqueness on
  something durable and hold it with a `UniqueConstraint`; a check against an
  email address that a plus-address or a re-registration defeats is a check
  against the wrong column.

Where the revocation is a deletion rather than a state change, whether the
copy is actually gone is `data-lifecycle-and-privacy.md`, "Where a record
survives" — the search index, the export, and the cache each hold their own
copy of the thing that was revoked.

**Write-time.** When generating an entitlement grant, write its revocation in
the same change and name what triggers it — cancellation, non-payment, role
change, membership removal, expiry — because a grant with no revocation path
is a permanent grant with a plan to write one. Derive the entitlement from the
subscription or the membership at read time where the query allows it, since a
derived entitlement cannot fall out of step with the thing it was derived
from, and materialise it only with an invalidation path written beside it.

### Money and entitlement review checklist

#### Stack-neutral

- [ ] Every field holding a balance, price, quantity, currency, credit, plan,
      tier, seat, expiry, or status has a complete list of the code that
      writes it, including the writers that never pass through a request.
- [ ] Each such transition's invariant is enforced by the datastore rather
      than by a check on one entry point; a serializer or form validator is
      credited as a message, not as a guarantee.
- [ ] Prices, currencies, discounts, tax, and quantity ceilings are resolved
      from server-side records keyed by a client-supplied identifier, and no
      monetary value is accepted from the request body.
- [ ] Coupons, referrals, invitations, and trials carry a uniqueness
      invariant keyed on something the caller cannot re-mint, and
      self-referral is excluded.
- [ ] Capture, refund, and reversal are each exactly-once, driven by an
      authenticated event, and the flow states which direction a partial
      failure fails in and what reconciles it.
- [ ] Refunds and other compensating actions are modelled as forward
      transactions with their own identifiers rather than as a status change
      back to the prior state.
- [ ] Every entitlement grant has a revocation path with a named trigger, and
      the caches, tokens, sessions, and denormalised copies it has to reach
      are enumerated.

#### Django & DRF

- [ ] The inventory covers management commands, Celery tasks and beat
      schedules, admin actions and `save_model`, signal receivers, data
      migrations, `update()`/`bulk_create()`/`bulk_update()`, and `loaddata`,
      not only viewsets and views.
- [ ] Value bounds are `CheckConstraint`s and "at most one live row" is a
      `UniqueConstraint`, with `condition=` where a cancelled or superseded
      row must stop blocking; both are present in `Meta.constraints` and in a
      migration.
- [ ] State changes are a conditional `.update()` whose affected-row count is
      the guard, rather than `get()` → `if` → `save()`.
- [ ] Monetary fields are absent or `read_only` on every serializer that
      reaches them and are written in `perform_create()` or the service layer.
- [ ] Irreversible external calls are registered with
      `transaction.on_commit()`, and the provider's own operation identifier
      is stored on the local row for reconciliation.

## Abuse of side-effecting actions

The notification material below is the worked instance of a wider pattern, and
it is the pattern that decides whether a flow the section never names still
needs a bound. **Any action a caller can trigger that consumes a limited
resource, notifies a third party, or performs irreversible work is a flow
worth attacking, whether or not it sends mail.** Invitations and shares,
exports and generated reports, magic links, referral and promotional credits,
outbound webhook deliveries, re-index and re-send operations, and every
"resend", "retry", and "regenerate" control belong to it. Each is a valid
request whose cost lands somewhere the caller does not pay.

Three properties put a flow in this class, and any one of them is enough: it
spends a budget that is not the caller's — money, model tokens, a provider's
send quota, a worker pool; it reaches a third party, so the harm is to someone
who never made a request; or it cannot be taken back, so a duplicate is not a
duplicate of a read.

This file decides which of them need a limit. `api-drf-specific.md`,
"Throttling as quota, not security (API4)" owns the mechanics — why a
configured rate is not the effective one, and the owned atomic counter that a
limit which must actually hold needs instead of a throttle class. The
consumption side of the same question, where the caller controls how much work
one request performs rather than how many requests there are, is "Algorithmic
resource exhaustion" above.

**Write-time.** When generating any action that spends a budget, contacts a
third party, or cannot be undone, give it a per-principal bound and an
idempotency story in the same change that introduces it, because the flow is
identified as needing one exactly once — at the moment it is written — and
after that it is a flow with callers. Where the bound is security-relevant
rather than a fair-use quota, make it an atomic counter or a database
constraint rather than a throttle class, on the reasoning in the DRF file
named above.

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
- [ ] Every path that moves money, credits, entitlements, or durable status
      has been enumerated from the fields those values live in, including the
      writers that never pass through a view, and each transition's invariant
      is held by the database rather than by one entry point's validator.
- [ ] Money/quantity/discount resolved server-side; idempotency enforced, with
      a unique constraint actually behind the key rather than a Python check.
- [ ] Replayable/self-referable business flows are constrained, and every
      entitlement grant has a revocation path with a named trigger.
- [ ] Actions that spend a budget, notify a third party, or cannot be undone
      carry a per-principal bound, whether or not they send mail.
- [ ] Notification triggers are non-enumerating, authorized, idempotent, and
      bounded by source, actor, tenant, destination, target, and global volume.
- [ ] Upload/body/count/processing limits exist at edge and application layers;
      Django memory thresholds are not mistaken for hard upload caps.
- [ ] Database connection concurrency is bounded by a pool and queries are
      time-limited server-side, rather than left to worker count.
