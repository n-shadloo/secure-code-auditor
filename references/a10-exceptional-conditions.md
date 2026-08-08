# A10:2025 — Mishandling of Exceptional Conditions

New in 2025. Errors, edge cases, and failure modes handled in ways that leak
information or fail open, plus the concurrency and duplicate-effect defects
that appear when one security decision is spread across two statements.

A10:2025's own weakness list is the error-handling half of that: CWE-209 and
CWE-215 for sensitive information in errors and debug output, CWE-636 for not
failing securely, and CWE-703, CWE-754, and CWE-755 for improper check or
handling of exceptional conditions. Race conditions are not in it — OWASP 2025
maps CWE-362 and CWE-841 to A06:2025 Insecure Design. They are documented here
anyway, because the question a reviewer asks is the one this category is
about: what does this code do when the expected sequence does not hold?
`a06-insecure-design.md` keeps the catalogue of business flows worth attacking;
this file keeps the mechanics and the fixes.

## Contents
- [Principle](#principle)
- [Don't leak on error](#dont-leak-on-error)
- [Fail closed](#fail-closed)
- [Races, TOCTOU, and adversarial sequencing](#races-toctou-and-adversarial-sequencing)
- [Idempotency](#idempotency)
- [Regular expressions and algorithmic cost](#regular-expressions-and-algorithmic-cost)
- [Review checklist](#review-checklist)

## Principle

How software behaves when something goes wrong is a security property. Three
failure patterns dominate: **leaking** (stack traces, internal messages, and
detailed errors handed to the attacker), **failing open** (an exception or edge
case skips a security check and the request proceeds), and **assuming a
sequence** (code that is correct run alone and wrong when a second caller
interleaves with it, or when a retry delivers the same request twice). The
principle is **fail closed and fail quiet**: on error, deny the action and
return a generic message, while logging the detail server-side. Handle the
unexpected explicitly rather than letting a swallowed exception or an unlucky
interleaving decide security for you.

## Don't leak on error

- `DEBUG = False` in production; provide custom `handler400/403/404/500` and error
  templates that reveal nothing internal.
- Don't return raw exception strings, SQL errors, or stack traces in API
  responses. Catch, log server-side, and return a generic error with an id the
  user can quote to support.

## Fail closed

Maps to CWE-636 (Not Failing Securely) and CWE-755.

- Permission and authentication code must default to deny. Watch for
  `try/except` blocks around auth checks that fall through to "allowed" on error,
  or a permission function that returns `None`/falls off the end (treat as deny,
  and make it explicit).
- Feature flags and config lookups that gate access should default to the safe
  (closed) state if the flag/store is unavailable.

Three shapes account for most of them, and all three are greppable:

```python
# Wrong: any failure inside the check is read as permission granted, so a
# database blip or a typo in check_policy grants access to everyone.
def has_access(user, obj):
    try:
        return check_policy(user, obj)
    except Exception:
        return True


# Wrong: no explicit return, so the function yields None. None is falsy, but a
# caller written as `if perm is not False:` reads it as allowed.
def can_edit(user, obj):
    if user.is_staff:
        return True
```

```python
# Correct: the failure is recorded where an operator can see it, and the answer
# to the security question is still no.
import logging

logger = logging.getLogger(__name__)


def has_access(user, obj):
    try:
        return bool(check_policy(user, obj))
    except Exception:
        logger.exception("policy check failed for object %s", obj.pk)
        return False
```

The third shape is a flag or configuration lookup that opens the gate when its
store is unreachable: `if flags.get("require_approval"):` evaluates false while
the flag service is down, and the approval step quietly disappears. Resolve the
unavailable case explicitly and pick the closed state for it.

DRF's own `exception_handler` cannot turn a denial into a success. It handles
`APIException` subclasses, Django's `Http404`, and Django's `PermissionDenied`,
and returns `None` for anything else — at which point the exception is
re-raised and Django returns a 500. The risk is a **custom** handler, or a
middleware `process_exception`, that catches broadly and returns a non-error
response: a 403 or a crash then reaches the caller as a 200, and the 4xx/5xx
rate that would have raised an alert stays flat. Grep for a configured
`EXCEPTION_HANDLER`, for `process_exception`, and for `except Exception` in
middleware, and check what each one returns.

## Races, TOCTOU, and adversarial sequencing

Maps to CWE-362 (concurrent execution using a shared resource with improper
synchronization) and CWE-367 (time-of-check time-of-use). OWASP 2025 places
CWE-362 and CWE-841 under A06:2025, where the business consequences —
double-spend, duplicate provisioning, a skipped workflow step — are catalogued.

### Principle layer

A check and the action it authorises must be a single atomic step against the
authoritative store. If any other actor can change the checked fact between the
check and the use, the check is advisory rather than enforcing. Nothing about
that is Django-specific; the same defect appears in Go, Rails, or hand-written
SQL, and the same two defences close it.

- **A constraint expresses an invariant about the data** — uniqueness, a value
  range, non-overlapping intervals. It is declarative, enforced on every path
  including the ones the application does not know about, and the loser of a
  concurrent race fails loudly instead of writing a corrupt row.
- **A lock serialises operations on a specific existing row** — the
  read-modify-write on a balance or a counter. It is a serialization tool, not
  an integrity guarantee: it protects only the rows it actually selected.

Prefer the constraint wherever the invariant can be expressed as one, and push
it down to the layer that cannot be bypassed. The database is the only actor
that every request path shares.

Exploiting a window no longer means winning a hand-timed race. A machine caller
fires hundreds of identical concurrent requests trivially, so a gap that reads
as "hard to hit" is now cheap to hit at scale. The tool-call side of that is in
`agent-and-llm-interfaces.md`, "Server-enforced confirmation for irreversible
actions", where the confirmation token is consumed exactly once precisely so a
duplicated call cannot re-run the effect.

### Django & DRF implementation layer

#### Locking a row, and where the lock does nothing

```python
# Wrong: the check and the debit are separate statements over a value that was
# copied into Python. Two concurrent requests both read 100, both pass the
# check, and both write a balance computed from the stale copy.
account = Account.objects.get(pk=pk)
if account.balance < amount:
    raise InsufficientFunds
account.balance = account.balance - amount
account.save(update_fields=["balance"])
```

```python
# Correct: the row is locked for the rest of the transaction, so the second
# caller waits for the first to commit and then reads the new balance. F() puts
# the arithmetic in the database, so no stale value is written back.
from django.db import transaction
from django.db.models import F

with transaction.atomic():
    account = Account.objects.select_for_update().get(pk=pk)
    if account.balance < amount:
        raise InsufficientFunds
    account.balance = F("balance") - amount
    account.save(update_fields=["balance"])
```

That fix has four ways of not working, and reviews miss all of them:

- **Outside a transaction it is not a lock.** Evaluating a queryset carrying
  `select_for_update()` in autocommit mode raises `TransactionManagementError`
  on backends that support `SELECT ... FOR UPDATE`, because the rows are not
  locked. The error is raised at *evaluation*, not construction — querysets are
  lazy, so the line that builds the queryset is never the line that fails.
- **On SQLite there is no error at all.** Django's documentation is explicit
  that on a backend without `SELECT ... FOR UPDATE` the call has no effect and
  raises nothing in autocommit mode. A suite that runs on SQLite proves nothing
  about the locking path, and production on PostgreSQL is then the only place
  the lock has ever existed.
- **The lock covers the rows it selected and nothing else.** If the invariant
  depends on a different row, on an aggregate over many rows, or on the
  *absence* of a row, locking the row being mutated protects none of it.
- **The options are not portable.** `nowait=True` and `skip_locked=True` are
  mutually exclusive and raise `ValueError` when both are set, and passing
  `nowait`, `skip_locked`, `no_key`, or `of` to a backend that does not support
  them raises `NotSupportedError`. That is deliberate — it stops code from
  blocking unexpectedly — but it means "add `skip_locked` so the workers stop
  queueing behind each other" can crash on the wrong backend.

Isolation level decides what the locked read sees. Django defaults to
`READ COMMITTED` on both PostgreSQL and MySQL, and under `READ COMMITTED` the
locked read re-reads the latest committed row once it acquires the lock, which
is what makes the balance pattern above correct. Raising the isolation level is
a data-layer decision with its own retry requirements, not something to change
from a view (`data-layer-and-database.md`, "Transaction isolation and
serialization failures").

`ATOMIC_REQUESTS` wraps every view in a transaction, which removes a whole
class of "the check committed but the write did not" bugs. Understand the
trade-off before enabling it: it holds a connection and an open transaction for
the whole of every view, so exclude long-running, streaming, and
external-call views (`data-layer-and-database.md`, "Connection exhaustion and
query timeouts"). It also has no retry of its own, so it does not combine with
a raised isolation level without one.

#### Push the invariant into a constraint

A lock cannot enforce the absence of a row, because there is no row to lock. A
constraint can.

```python
# Correct: uniqueness and the value bound are properties of the data, so the
# database holds them on every path — admin, shell, migration, and raw SQL.
from django.db import models


class Reservation(models.Model):
    room = models.ForeignKey("Room", on_delete=models.CASCADE)
    slot = models.DateTimeField()
    seats = models.PositiveIntegerField()
    cancelled_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["room", "slot"],
                condition=models.Q(cancelled_at__isnull=True),
                name="reservation_one_live_booking_per_slot",
            ),
            models.CheckConstraint(
                condition=models.Q(seats__gt=0),
                name="reservation_seats_positive",
            ),
        ]
```

- Uniqueness, or "at most one of these at a time", is a `UniqueConstraint`;
  `condition=` makes it partial, which is how a soft-deleted or cancelled row
  stops blocking a new one. Never enforce uniqueness with `.exists()` followed
  by `.create()`.
- Value bounds — non-negative, non-zero, a maximum — are `CheckConstraint`s.
  They also close the negative-amount and quantity-manipulation abuse that
  arrives as an entirely valid-looking request (CWE-190, CWE-191).
- Non-overlapping intervals, which is what booking and reservation systems
  actually need, are PostgreSQL exclusion constraints, available through
  `ExclusionConstraint` in `django.contrib.postgres.constraints`.
- A constraint added to a table that already violates it fails at deploy time.
  Sequencing that safely is in `a03-software-supply-chain.md`, "Migration and
  data-integrity safety".

A distributed lock in Redis is not a substitute for either defence. A lock is
only as safe as the guarantee that a second holder cannot act, and in an
asynchronous system — garbage-collection pauses, network delay, clock skew —
that requires a fencing token which the protected resource itself checks.
Neither a single-instance `SET NX PX` nor Redlock provides one; Martin
Kleppmann's analysis of Redlock is the standard reference, and single-instance
Redis adds asynchronous-replication failover on top. For a Django service the
correct default is a unique constraint plus `transaction.atomic()`, which is a
fenced, consensus-backed lock you are already running. Reserve a Redis lock for
best-effort de-duplication where an occasional double execution is merely
wasteful, and say plainly in the review that that is all it is.

#### `get_or_create` and `update_or_create`

Django's own documentation states the guarantee precisely: the method is atomic
*assuming that the database enforces uniqueness of the keyword arguments*. With
no matching unique constraint, concurrent calls insert duplicate rows and
nothing raises. With one, the loser's `INSERT` raises `IntegrityError`, which
Django catches and retries as a `get()`.

That retry has an edge of its own. Under MySQL's own default of
`REPEATABLE READ`, the retrying `get()` can fail to see the row that just
committed and the `IntegrityError` escapes; Django's databases reference names
exactly this as the reason it defaults MySQL to `READ COMMITTED` instead. A
project that has overridden the isolation level has reintroduced it.

So a `get_or_create()` in a security-relevant flow is two questions, not one:
is there a unique constraint on the lookup fields, in `Meta.constraints` and in
a migration, and has anything changed the isolation level underneath it?

#### Enforcing a state transition

```python
# Wrong: two concurrent "mark paid" calls both read status == "pending", both
# pass the guard, and the second silently overwrites the first.
order = Order.objects.get(pk=pk)
if order.status != "pending":
    raise Conflict
order.status = "paid"
order.save(update_fields=["status"])
```

```python
# Correct: the WHERE clause is the guard, so the database picks the winner and
# reports how many rows it actually changed. Zero means someone else went first.
updated = Order.objects.filter(pk=pk, status="pending").update(status="paid")
if not updated:
    raise Conflict
```

A state machine that is checked in Python and saved later is decorative
(CWE-841). A declarative transitions package does not fix that on its own: the
guard is still an in-memory check followed by a `save()`, and no row lock is
added. The bypassable shape to grep for is `get()` → `if` → `save()`; the
enforced shapes are a conditional `.update()` or a `select_for_update()` read
inside `atomic()`.

#### Side effects and the commit boundary

```python
# Wrong: the broker is faster than the commit. The worker can dequeue and look
# for the row before it exists — or after the transaction has rolled back, in
# which case the receipt goes out for an order that was never placed.
order = Order.objects.create(...)
send_receipt.delay(order.pk)
```

```python
# Correct: registered now, dispatched only if the outermost block commits.
from functools import partial

from django.db import transaction

with transaction.atomic():
    order = Order.objects.create(...)
    transaction.on_commit(partial(send_receipt.delay, order.pk))
```

- Callbacks run after the **outermost** `atomic()` commits, in registration
  order. One registered inside a nested block does not run if a rollback to
  that savepoint or to an earlier one happened during the transaction.
- Delivery is at-least-once. A worker that finishes the work and dies before
  acknowledging causes a redelivery, so every task must be safe to run twice:
  re-check state before acting rather than assuming the first run did not
  happen. That is the same design as the next section, applied to a worker.
- Two tasks enqueued in order are not guaranteed to execute in order or on the
  same worker. Never let task B assume it can see task A's effect; have it
  check.
- Under `TestCase`, which wraps each test in a transaction that is never
  committed, `on_commit` callbacks never run at all. Use
  `captureOnCommitCallbacks()` or `TransactionTestCase`, or the tests silently
  cover none of this while continuing to pass.

`a09-logging-and-alerting.md`, "Lifecycle hooks and audit guarantees" owns the
ordering mechanism itself, the transactional outbox, and which Django write
paths run which hooks. It is not restated here.

**Write-time.** When generating a transaction or a state transition, choose
between a constraint and a lock before writing either: express the invariant
as a `UniqueConstraint` or a `CheckConstraint` wherever it is a property of
the data, and reserve `select_for_update()` inside `atomic()` for the
read-modify-write on a row that already exists, because the constraint also
holds on the admin, shell, and migration paths this view does not own. Write
the transition as a conditional `.update()` whose `WHERE` clause carries the
guard and whose returned count decides the outcome, rather than a `get()`, an
`if`, and a later `save()`. Register every external effect through
`transaction.on_commit()` in the edit that introduces it, and give any handler
a retry can reach the idempotency-key shape below, because the retry arrives
whether or not the handler was designed for one.

#### Reading code for a race

Grep produces starting points, not findings. A race is a property of the gap
between two statements and of whether a constraint or a lock closes that gap,
and neither of those is visible in a single line.

1. **Find the shapes.** Existence and aggregate checks — `.exists(`, `.count(`,
   `.first(`, `get_or_create`, `update_or_create`. A guard immediately above a
   mutation — `if not ...:` on the lines before a `.create(`, `.save(`, or
   `.update(`. Read-modify-write arithmetic — `obj.field = obj.field - n`
   followed by `.save(`, rather than an `F()` expression. Weight the hits that
   sit near money, stock, quota, credit, slug, or email vocabulary.
2. **Trace each hit from the check to the use.** Name the checked fact — a
   specific row, an aggregate, or the absence of a row — and name the mutation.
   Then answer three questions. Are the check and the mutation inside one
   `transaction.atomic()`? Does the check read the exact row being mutated,
   under `select_for_update()`? Is there a `UniqueConstraint` or
   `CheckConstraint` behind it, in `Meta.constraints` *and* in a migration,
   that would turn a lost race into a loud failure?
3. **Decide whether the gap is already closed.** It is closed if the invariant
   is uniqueness or a bound with a matching constraint behind it, or if it is a
   read-modify-write on one row done with `select_for_update()` and `F()`
   inside `atomic()`. It is a real finding if the only guard is a Python-side
   `if` or `.exists()` with neither constraint nor lock, if `select_for_update()`
   is evaluated outside `atomic()`, or if the check reads something the lock
   does not cover.

## Idempotency

Maps to CWE-362. `a06-insecure-design.md` catalogues the business flows where
duplicate effects hurt, and `a08-integrity-and-deserialization.md` owns webhook
event de-duplication; both defer here for the design.

### Principle layer

Retries are not an anomaly to be designed away. Clients retry, load balancers
retry, SDKs retry, and queues redeliver, so an endpoint that must not run twice
will be called twice. A client-supplied key plus a stored fingerprint of the
request turns an at-least-once channel into exactly-once effects. Four rules
make that work, and each one is a place implementations go wrong:

- **The datastore arbitrates uniqueness, not the application.** Two requests
  carrying the same key arrive at the same moment; a unique constraint lets
  exactly one insert win and tells the other that it lost. An `.exists()` check
  followed by a `.create()` is the race this whole file is about.
- **Scope the key per actor.** One tenant's key must not collide with the same
  string sent by another, so the constraint is on the pair, not on the key.
- **A key replayed with different parameters is an error, not a replay.** Store
  a fingerprint of the canonical request body and compare it. Answering a
  second, different request with the first one's stored result is worse than
  the duplicate it was meant to prevent.
- **Store the outcome and replay it**, failures included, so a client that
  never saw the first response gets the same answer rather than a second
  execution. Prune keys past a horizon — twenty-four hours is the common
  choice — after which a reused key starts fresh.

`Idempotency-Key` is the de-facto header name, established by payment
processors rather than by a ratified standard: the IETF HTTPAPI working group's
draft for it expired without being published as an RFC, so there is nothing
normative to cite and no interoperability guarantee to lean on. `GET` and
`DELETE` need no key, being idempotent by definition.

### Django & DRF implementation layer

```python
# The unique constraint is the concurrency arbiter. Without it the design
# degrades into the exists()-then-create() race it exists to prevent.
from django.conf import settings
from django.db import models


class IdempotencyRecord(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE
    )
    key = models.CharField(max_length=255)
    request_fingerprint = models.CharField(max_length=64)
    response_status = models.PositiveSmallIntegerField(null=True)
    response_body = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["actor", "key"],
                name="idempotency_record_actor_key_unique",
            ),
        ]
```

```python
# Correct: let the insert race and treat losing it as information. The inner
# atomic() is a savepoint, so catching IntegrityError from the insert alone
# leaves the outer transaction usable and does not swallow one raised by the
# effect itself.
import hashlib
import json

from django.db import IntegrityError, transaction
from rest_framework.response import Response


def request_fingerprint(body):
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def handle(actor, key, body):
    digest = request_fingerprint(body)
    with transaction.atomic():
        try:
            with transaction.atomic():
                record = IdempotencyRecord.objects.create(
                    actor=actor, key=key, request_fingerprint=digest
                )
        except IntegrityError:
            first = IdempotencyRecord.objects.get(actor=actor, key=key)
            if first.request_fingerprint != digest:
                # Same key, different request. Replaying the stored result
                # would answer one operation with another one's outcome.
                return Response(status=409)
            return Response(first.response_body, status=first.response_status)

        result = perform_effect(actor, body)
        record.response_status = 200
        record.response_body = result
        record.save(update_fields=["response_status", "response_body"])
    return Response(result, status=200)
```

The record, the effect, and the stored response commit together, and that is
what makes the replay branch safe: a record exists only if its effect
succeeded, so there is no half-written row for a retry to trip over. Two
consequences follow from it.

- The effect has to be database work. An external call belongs in
  `transaction.on_commit()`, and a payment capture that cannot be rolled back
  needs the provider's own idempotency key in addition to this one — the
  guarantee has to hold on their side of the call too.
- A genuinely simultaneous duplicate blocks on the unique index until the first
  transaction finishes, rather than getting an immediate answer. Committing the
  insert in its own transaction first buys an instant "still in flight" 409, at
  the cost of records that can be left with no stored response when the effect
  fails, which then needs its own expiry and repair path. Choose deliberately;
  do not end up with the second shape by accident.

Keys are opaque: a random value the client generates, up to 255 characters.
Never derive one from an email address, an account number, or anything else
whose presence in this table is itself a disclosure.

## Regular expressions and algorithmic cost

Maps to CWE-1333 (inefficient regular expression complexity), with CWE-400 and
CWE-770 where the resource is simply unbounded. OWASP API4:2023 Unrestricted
Resource Consumption is the API-security mapping; the Top 10:2025 has no
denial-of-service category, so the general class — which caller-controlled
inputs need a bound, and the table of which surface enforces each one — is
owned by `a06-insecure-design.md`, "Algorithmic resource exhaustion". This
section owns the regular expression itself.

A backtracking engine can take time exponential in the length of its input on a
pattern with nested or overlapping quantifiers, so one request costs a CPU core
for minutes. CPython's `re` is a backtracking engine with no built-in
protection. Python 3.11 added atomic groups `(?>...)` and possessive
quantifiers (`*+`, `++`, `?+`, `{m,n}+`), which allow a specific dangerous
pattern to be rewritten so that it cannot backtrack, but there is still no
timeout parameter on any `re` function.

Django's own history shows the pattern class reaching a framework rather than
an application: CVE-2023-36053 in `EmailValidator` and `URLValidator`, and
CVE-2024-27351, CVE-2023-43665, and CVE-2019-14232 in
`django.utils.text.Truncator`, which backs the `truncatechars_html` and
`truncatewords_html` template filters. All are fixed on supported versions, so
they are useful as exemplars rather than as live findings.

In application code the reachable paths are: custom `RegexValidator` patterns;
`re.search` or `re.match` run over request data in a serializer, a filter, or a
search view; `__regex` and `__iregex` ORM lookups fed from query parameters;
and anywhere a pattern is *compiled from* user input.

The mitigations, in the order that pays:

1. **Cap the input length before it reaches the regex.** Catastrophic
   backtracking needs a long subject, so a `max_length` on the field or
   serializer is the cheapest control here and the one to apply by default.
2. **Never compile a pattern from user input.** Where a feature genuinely
   requires it, run it on an engine with a linear-time guarantee instead of on
   `re` (`security-hardening-libraries.md`, "Concurrency, idempotency, and
   regular expressions").
3. **Keep Django and Python patched**, so the framework paths above stay fixed.
4. Rewrite a known-dangerous in-house pattern with possessive quantifiers or an
   atomic group on Python 3.11 and above.

## Review checklist

### Stack-neutral

- [ ] On error in a security-relevant path the code denies and returns a
      generic message: no `except` that yields "allowed", no permission
      function falling off the end, and no flag or config lookup that opens the
      gate when its store is unavailable.
- [ ] Every read-check-write on money, stock, quota, or uniqueness is one
      atomic step, closed either by a database constraint or by a lock on the
      exact row being mutated.
- [ ] Invariants that are properties of the data — uniqueness, value bounds,
      non-overlap — are database constraints rather than application checks.
- [ ] Must-run-once endpoints carry an idempotency key scoped per actor, with a
      unique constraint arbitrating concurrent arrivals, a stored request
      fingerprint that rejects a mismatched replay instead of answering it, a
      stored response, and an expiry.
- [ ] External side effects are dispatched only after the work commits, and
      every consumer is safe to run more than once under redelivery.
- [ ] State transitions are decided by the datastore, not by a check in
      application memory that a later write trusts.
- [ ] No distributed lock is relied on for correctness without a fencing token
      the protected resource itself checks.
- [ ] User input reaching a regular expression is length-capped, and no pattern
      is compiled from user input on a backtracking engine.

### Django & DRF

- [ ] `DEBUG = False`; custom error handlers; no exception/stack detail in
      responses.
- [ ] No custom `EXCEPTION_HANDLER` and no middleware `process_exception`
      converts a `PermissionDenied` or an unhandled exception into a 2xx.
- [ ] No `select_for_update()` is evaluated outside `transaction.atomic()`, and
      the locking paths are exercised on the production backend rather than
      only on SQLite, where the call is a silent no-op.
- [ ] `get_or_create()` and `update_or_create()` lookups are backed by a
      matching unique constraint; uniqueness is never enforced by `.exists()`
      followed by `.create()`.
- [ ] Value bounds are `CheckConstraint`s and interval overlaps are exclusion
      constraints, present in `Meta.constraints` and in a migration.
- [ ] Read-modify-write uses `F()` expressions rather than arithmetic on a
      value read into Python.
- [ ] Task dispatch and other external effects are registered with
      `transaction.on_commit()`, and tests use `captureOnCommitCallbacks()` or
      `TransactionTestCase` so those callbacks actually run.
- [ ] State changes use a conditional `.update(...)` or a locked read, not
      `get()` → `if` → `save()`.
