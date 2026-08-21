# A10:2025 — Mishandling of Exceptional Conditions

New in 2025. This category covers errors, edge cases, and failure modes that
leak information or fail open. It also covers the concurrency defects and the
duplicate-effect defects that appear when one security decision is spread
across two statements.

The weakness list of A10:2025 is the error-handling half of that. It holds
CWE-209 and CWE-215 for sensitive information in errors and debug output. It
holds CWE-636 for code that does not fail securely. It holds CWE-703, CWE-754,
and CWE-755 where code checks or handles an exceptional condition improperly.
Race conditions are not in it, because OWASP 2025 maps CWE-362 and CWE-841 to
A06:2025 Insecure Design. This file documents them anyway. A reviewer asks the
question that this category is about: what this code does when the expected
sequence does not hold. `a06-insecure-design.md` keeps the catalog of business
flows worth attacking, and this file keeps the mechanics and the fixes.

## Contents
- [Principle](#principle)
- [Don't leak on error](#dont-leak-on-error)
- [Fail closed](#fail-closed)
- [Races, TOCTOU, and adversarial sequencing](#races-toctou-and-adversarial-sequencing)
- [Idempotency](#idempotency)
- [Regular expressions and algorithmic cost](#regular-expressions-and-algorithmic-cost)
- [Review checklist](#review-checklist)

## Principle

The behavior of software when something goes wrong is a security property.
Three failure patterns dominate. The first is **leaking**: stack traces,
internal messages, and detailed errors go to the attacker. The second is
**failing open**: an exception or an edge case skips a security check, and the
request proceeds. The third is **assuming a sequence**: the code is correct
when it runs alone. It is wrong when a second caller interleaves with it, or
when a retry delivers the same request twice.

The principle is **fail closed and fail quiet**. On error, deny the action and
return a generic message, and log the detail server-side. Handle the unexpected
explicitly. Do not let a swallowed exception or an unlucky interleaving decide
security for you.

## Don't leak on error

- `DEBUG = False` in production; provide custom `handler400/403/404/500` and error
  templates that reveal nothing internal.
- Do not return raw exception strings, SQL errors, or stack traces in API
  responses. Catch the exception, log it server-side, and return a generic
  error with an id that the user can quote to support.

## Fail closed

Maps to CWE-636 (Not Failing Securely) and CWE-755.

- Permission code and authentication code must default to deny. Look for a
  `try/except` block around an auth check that returns "allowed" on error. Look
  also for a permission function that returns `None` or reaches its end with no
  return. Treat each one as deny, and make that deny explicit.
- A feature flag or a config lookup that gates access should default to the
  safe (closed) state when the flag store is unavailable.

Three shapes account for most of them, and you can grep for all three:

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

The third shape is a flag lookup or a configuration lookup that opens the gate
when its store is unreachable. `if flags.get("require_approval"):` evaluates
false while the flag service is down, and the approval step quietly disappears.
Resolve the unavailable case explicitly, and select the closed state for it.

The `exception_handler` of DRF cannot turn a denial into a success. It handles
`APIException` subclasses, Django's `Http404`, and Django's `PermissionDenied`.
It returns `None` for anything else, and Django then re-raises the exception
and returns a 500. The risk is a **custom** handler, or a middleware
`process_exception`, that catches broadly and returns a non-error response. A
403 or a crash then reaches the caller as a 200, and the 4xx/5xx rate that
would have raised an alert stays flat. Grep for a configured
`EXCEPTION_HANDLER`, for `process_exception`, and for `except Exception` in
middleware, and check what each one returns.

## Races, TOCTOU, and adversarial sequencing

Maps to CWE-362 (concurrent execution using a shared resource with improper
synchronization) and CWE-367 (time-of-check time-of-use). OWASP 2025 places
CWE-362 and CWE-841 under A06:2025. That category catalogs the business
consequences: double-spend, duplicate provisioning, and a skipped workflow
step.

### Principle layer

A check and the action it authorizes must be a single atomic step against the
authoritative store. If any other actor can change the checked fact between the
check and the use, the check only gives advice and does not enforce. Nothing
about that is Django-specific. The same defect appears in Go, Rails, or
hand-written SQL, and the same two defenses close it.

- **A constraint expresses an invariant about the data** — uniqueness, a value
  range, non-overlapping intervals. It is declarative, and the database
  enforces it on every path, including the paths the application does not know
  about. The loser of a concurrent race fails loudly and does not write a
  corrupt row.
- **A lock serializes operations on a specific existing row** — the
  read-modify-write on a balance or a counter. It is a serialization tool, not
  an integrity guarantee: it protects only the rows it actually selected.

Prefer the constraint wherever you can express the invariant as one, and move
it to the layer that nothing can bypass. The database is the only actor that
every request path shares.

To exploit a window, an attacker no longer has to win a hand-timed race. A
machine caller fires hundreds of identical concurrent requests easily. A gap
that reads as "hard to hit" is now cheap to hit at scale.
`agent-and-llm-interfaces.md`, "Server-enforced confirmation for irreversible
actions" holds the tool-call side of that. The confirmation token there is
consumed exactly once, precisely so that a duplicated call cannot re-run the
effect.

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

That fix has four failure modes, and reviews miss all of them:

- **Outside a transaction it is not a lock.** A queryset that carries
  `select_for_update()` raises `TransactionManagementError` when you evaluate
  it in autocommit mode, on backends that support `SELECT ... FOR UPDATE`. The
  database does not lock the rows. Django raises the error at *evaluation*, not
  at construction. Querysets are lazy, so the line that builds the queryset is
  never the line that fails.
- **On SQLite there is no error at all.** Django's documentation is explicit
  that on a backend without `SELECT ... FOR UPDATE` the call has no effect and
  raises nothing in autocommit mode. A suite that runs on SQLite proves nothing
  about the locking path. Production on PostgreSQL is then the only place where
  the lock has ever existed.
- **The lock covers the rows it selected and nothing else.** The invariant can
  depend on a different row, on an aggregate over many rows, or on the
  *absence* of a row. A lock on the row that you mutate then protects none of
  it.
- **The options are not portable.** `nowait=True` and `skip_locked=True` are
  mutually exclusive, and Django raises `ValueError` when you set both. Django
  raises `NotSupportedError` when you pass `nowait`, `skip_locked`, `no_key`,
  or `of` to a backend that does not support them. That behavior is deliberate,
  because it stops code that blocks unexpectedly. But it also means that "add
  `skip_locked` so the workers stop queueing behind each other" can crash on
  the wrong backend.

The isolation level decides what the locked read sees. Django defaults to
`READ COMMITTED` on both PostgreSQL and MySQL. Under `READ COMMITTED` the
locked read reads the latest committed row again after it acquires the lock,
which makes the balance pattern above correct. A change to the isolation level
is a data-layer decision with its own retry requirements. Do not make that
change from a view (`data-layer-and-database.md`, "Transaction isolation and
serialization failures").

`ATOMIC_REQUESTS` wraps every view in a transaction, which removes a whole
class of "the check committed but the write did not" bugs. Understand the
trade-off before you enable it. It holds a connection and an open transaction
for the whole of every view. Exclude long-running views, streaming views, and
external-call views (`data-layer-and-database.md`, "Connection exhaustion and
query timeouts"). It also has no retry of its own, so it does not combine with
a raised isolation level unless you add one.

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

- Uniqueness, or "at most one of these at a time", is a `UniqueConstraint`.
  `condition=` makes it partial, which is how a soft-deleted or cancelled row
  no longer blocks a new one. Never enforce uniqueness with `.exists()` and a
  later `.create()`.
- Value bounds — non-negative, non-zero, a maximum — are `CheckConstraint`s.
  They also close the negative-amount abuse and the quantity-manipulation abuse
  that arrive as a request that looks entirely valid (CWE-190, CWE-191).
- Non-overlapping intervals are PostgreSQL exclusion constraints, available
  through `ExclusionConstraint` in `django.contrib.postgres.constraints`.
  Booking systems and reservation systems actually need this constraint. A
  scalar column beside a range needs the `btree_gist` extension, which the
  `BtreeGistExtension` migration operation installs.
- A constraint that you add to a table that already violates it fails at deploy
  time. `a03-software-supply-chain.md`, "Migration and data-integrity safety"
  holds the safe sequence for that change.

A distributed lock in Redis does not replace either defense. A lock is only as
safe as the guarantee that a second holder cannot act. In an asynchronous
system, with garbage-collection pauses, network delay, and clock skew, that
guarantee needs a fencing token which the protected resource itself checks.
Neither a single-instance `SET NX PX` nor Redlock provides one. Martin
Kleppmann's analysis of Redlock is the standard reference, and single-instance
Redis also adds asynchronous-replication failover.

For a Django service the correct default is a unique constraint with
`transaction.atomic()`. That combination is a fenced, consensus-backed lock
that you already run. Reserve a Redis lock for best-effort de-duplication where
an occasional double execution is merely wasteful. Say plainly in the review
that this is all it is.

#### `get_or_create` and `update_or_create`

Django's own documentation states the guarantee precisely: the method is atomic
*assuming that the database enforces uniqueness of the keyword arguments*. With
no matching unique constraint, concurrent calls insert duplicate rows and
nothing raises. With one, the loser's `INSERT` raises `IntegrityError`, which
Django catches and retries as a `get()`.

That retry has an edge of its own. Under the MySQL default of
`REPEATABLE READ`, the `get()` in the retry can fail to see the row that just
committed, and the `IntegrityError` escapes. Django's databases reference names
exactly this as the reason it defaults MySQL to `READ COMMITTED` instead. A
project that has overridden the isolation level has reintroduced the problem.

So a `get_or_create()` in a security-relevant flow raises two questions, not
one. The first is whether a unique constraint covers the lookup fields, in
`Meta.constraints` and in a migration. The second is whether anything has
changed the isolation level under it.

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

A state machine that Python checks and saves later enforces nothing (CWE-841).
A declarative transitions package does not fix that on its own. The guard is
still an in-memory check with a `save()` after it, and the package adds no row
lock. Grep for the bypassable shape `get()` → `if` → `save()`. The enforced
shapes are a conditional `.update()` or a `select_for_update()` read inside
`atomic()`. `a06-insecure-design.md`, "Business-logic abuse" holds the flow
inventory that decides which transitions you must enforce at all.

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
  order. A callback that you register inside a nested block does not run if a
  rollback happened during the transaction. That rollback can be to that
  savepoint or to an earlier one.
- Delivery is at-least-once, and that guarantee begins at the broker. The
  enqueue itself is lost when the process dies between the commit and the
  callback. `on_commit` therefore orders the work but does not make it durable.
  Where the record must not be lost, use the transactional outbox in
  `a09-logging-and-alerting.md`, "Lifecycle hooks and audit guarantees". The
  dispatcher that drains it belongs to queue delivery and retry mechanics,
  which this file does not cover. Past the broker, a worker that finishes the
  work and dies before it acknowledges causes a redelivery. Every task must
  therefore be safe to run twice. Re-check the state before you act. Do not
  assume that the first run did not happen. That is the same design as the next
  section, applied to a worker.
- Two tasks that you enqueue in order have no guarantee to execute in order or
  on the same worker. Never let task B assume that it can see the effect of
  task A. Make task B check.
- Under `TestCase`, which wraps each test in a transaction that never commits,
  `on_commit` callbacks never run at all. Use `captureOnCommitCallbacks()` or
  `TransactionTestCase`. Without one of them the tests silently cover none of
  this and still pass.

`a09-logging-and-alerting.md`, "Lifecycle hooks and audit guarantees" owns the
order mechanism itself, the transactional outbox, and which Django write paths
run which hooks. This file does not restate it.

**Write-time.** When you generate a transaction or a state transition, choose
between a constraint and a lock before you write either. Express the invariant
as a `UniqueConstraint` or a `CheckConstraint` wherever it is a property of the
data. Reserve `select_for_update()` inside `atomic()` for the read-modify-write
on a row that already exists. The constraint also holds on the admin, shell,
and migration paths that this view does not own.

Write the transition as a conditional `.update()`. Its `WHERE` clause carries
the guard, and its returned count decides the outcome. Do not write a `get()`,
an `if`, and a later `save()`. Register every external effect through
`transaction.on_commit()` in the edit that introduces it. Give the
idempotency-key shape below to any handler that a retry can reach. The retry
arrives whether or not the handler was designed for one.

#### Reading code for a race

Grep produces starting points, not findings. A race is a property of the gap
between two statements, and of whether a constraint or a lock closes that gap.
Neither of those is visible in a single line.

1. **Find the shapes.** Existence checks and aggregate checks — `.exists(`,
   `.count(`, `.first(`, `get_or_create`, `update_or_create`. A guard
   immediately above a mutation — `if not ...:` on the lines before a
   `.create(`, `.save(`, or `.update(`. Read-modify-write arithmetic —
   `obj.field = obj.field - n` with a `.save(` after it, rather than an `F()`
   expression. Weight the hits that sit near money, stock, quota, credit, slug,
   or email vocabulary.
2. **Trace each hit from the check to the use.** Name the checked fact — a
   specific row, an aggregate, or the absence of a row — and name the mutation.
   Then answer three questions. The first is whether the check and the mutation
   sit inside one `transaction.atomic()`. The second is whether the check reads
   the exact row that the code mutates, under `select_for_update()`. The third
   is whether a `UniqueConstraint` or a `CheckConstraint` stands behind it, in
   `Meta.constraints` *and* in a migration. Such a constraint turns a lost race
   into a loud failure.
3. **Decide whether the gap is already closed.** The gap is closed if the
   invariant is uniqueness or a bound with a matching constraint behind it. It
   is also closed if it is a read-modify-write on one row with
   `select_for_update()` and `F()` inside `atomic()`. It is a real finding if
   the only guard is a Python-side `if` or `.exists()` with neither constraint
   nor lock. It is also a real finding if the code evaluates
   `select_for_update()` outside `atomic()`, or if the check reads something
   that the lock does not cover.

## Idempotency

Maps to CWE-362. `a06-insecure-design.md` catalogs the business flows where
duplicate effects hurt, and `a08-integrity-and-deserialization.md` owns webhook
event de-duplication; both defer here for the design.

### Principle layer

Retries are not an anomaly that you can design away. Clients retry, load
balancers retry, SDKs retry, and queues redeliver. An endpoint that must not
run twice therefore will be called twice. A client-supplied key with a stored
fingerprint of the request turns an at-least-once channel into exactly-once
effects. Four rules make that work, and each one is a place where
implementations go wrong:

- **The datastore arbitrates uniqueness, not the application.** Two requests
  that carry the same key arrive at the same moment. A unique constraint lets
  exactly one insert win, and tells the other that it lost. An `.exists()`
  check with a `.create()` after it is the race that this whole file is about.
- **Scope the key per actor.** The key of one tenant must not collide with the
  same string from another tenant. The constraint is therefore on the pair, not
  on the key.
- **A key replayed with different parameters is an error, not a replay.** Store
  a fingerprint of the canonical request body, and compare it. Do not answer a
  second, different request with the stored result of the first. That outcome
  is worse than the duplicate the key was meant to prevent.
- **Store the outcome and replay it**, failures included. A client that never
  saw the first response then gets the same answer rather than a second
  execution. Prune keys past a horizon; twenty-four hours is the common choice.
  After that horizon a reused key starts fresh.

`Idempotency-Key` is the de-facto header name. Payment processors established
it, and no ratified standard defines it. The draft of the IETF HTTPAPI working
group for it expired, and nobody published it as an RFC. There is therefore
nothing normative to cite, and no interoperability guarantee. `GET` and
`DELETE` need no key, because they are idempotent by definition.

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

The fingerprint above digests the body alone. Canonicalize the method and the
route into it as well. One key sent to two endpoints then cannot replay the
wrong response.

The record, the effect, and the stored response commit together, which makes
the replay branch safe. A record exists only if its effect succeeded, so a
retry finds no half-written row. Two consequences follow from that.

- The effect has to be database work. An external call belongs in
  `transaction.on_commit()`. A payment capture that you cannot roll back needs
  the idempotency key of the provider in addition to this one. The guarantee
  has to hold on their side of the call too.
- A genuinely simultaneous duplicate blocks on the unique index until the first
  transaction finishes, and does not get an immediate answer. If you commit the
  insert in its own transaction first, you get an instant "still in flight"
  409. The cost is a record that can hold no stored response when the effect
  fails, which then needs its own expiry path and repair path. Choose
  deliberately, and do not reach the second shape by accident.

Keys are opaque: a random value that the client generates, up to 255
characters. Never derive one from an email address, an account number, or
anything else whose presence in this table is itself a disclosure.

## Regular expressions and algorithmic cost

Maps to CWE-1333 (inefficient regular expression complexity), with CWE-400 and
CWE-770 where the resource is simply unbounded. OWASP API4:2023 Unrestricted
Resource Consumption is the API-security mapping. The Top 10:2025 has no
denial-of-service category. `a06-insecure-design.md`, "Algorithmic resource
exhaustion" therefore owns the general class: which caller-controlled inputs
need a bound, and the table of which surface enforces each one. This section
owns the regular expression itself.

A backtracking engine can take time exponential in the length of its input, on
a pattern with nested or overlapping quantifiers. One request then costs a CPU
core for minutes. The `re` module of CPython is a backtracking engine with no
built-in protection. Python 3.11 added atomic groups `(?>...)` and possessive
quantifiers (`*+`, `++`, `?+`, `{m,n}+`). These let you rewrite a specific
dangerous pattern so that it cannot backtrack. But no `re` function has a
timeout parameter.

The history of Django shows this pattern class in a framework rather than in an
application. CVE-2023-36053 is in `EmailValidator` and `URLValidator`.
CVE-2024-27351, CVE-2023-43665, and CVE-2019-14232 are in
`django.utils.text.Truncator`, which backs the `truncatechars_html` and
`truncatewords_html` template filters. All are fixed on supported versions, so
they are useful as exemplars rather than as live findings.

In application code four paths are reachable. The first is a custom
`RegexValidator` pattern. The second is `re.search` or `re.match` over request
data in a serializer, a filter, or a search view. The third is a `__regex` or
`__iregex` ORM lookup that a query parameter feeds. The fourth is anywhere a
pattern is *compiled from* user input.

The mitigations follow, in the order that pays:

1. **Cap the input length before it reaches the regex.** Catastrophic
   backtracking needs a long subject. A `max_length` on the field or the
   serializer is therefore the cheapest control here, and the one to apply by
   default.
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
      generic message. There is no `except` that yields "allowed", and no
      permission function that reaches its end with no return. No flag or
      config lookup opens the gate when its store is unavailable.
- [ ] Every read-check-write on money, stock, quota, or uniqueness is one
      atomic step. A database constraint or a lock on the exact row that the
      code mutates closes it.
- [ ] Invariants that are properties of the data — uniqueness, value bounds,
      non-overlap — are database constraints rather than application checks.
- [ ] Must-run-once endpoints carry an idempotency key scoped per actor. A
      unique constraint arbitrates concurrent arrivals. A stored request
      fingerprint rejects a mismatched replay rather than answers it. A stored
      response and an expiry are present.
- [ ] The code dispatches external side effects only after the work commits,
      and every consumer is safe to run more than once under redelivery.
- [ ] The datastore decides state transitions, not a check in application
      memory that a later write trusts.
- [ ] No design relies on a distributed lock for correctness without a fencing
      token that the protected resource itself checks.
- [ ] User input that reaches a regular expression is length-capped, and no
      code compiles a pattern from user input on a backtracking engine.

### Django & DRF

- [ ] `DEBUG = False`; custom error handlers; no exception/stack detail in
      responses.
- [ ] No custom `EXCEPTION_HANDLER` and no middleware `process_exception`
      converts a `PermissionDenied` or an unhandled exception into a 2xx.
- [ ] No code evaluates `select_for_update()` outside `transaction.atomic()`.
      The tests exercise the locking paths on the production backend rather
      than only on SQLite, where the call is a silent no-op.
- [ ] A matching unique constraint backs every `get_or_create()` and
      `update_or_create()` lookup. No code enforces uniqueness with `.exists()`
      and a later `.create()`.
- [ ] Value bounds are `CheckConstraint`s and interval overlaps are exclusion
      constraints, present in `Meta.constraints` and in a migration.
- [ ] Read-modify-write uses `F()` expressions rather than arithmetic on a
      value read into Python.
- [ ] The code registers task dispatch and other external effects with
      `transaction.on_commit()`. Tests use `captureOnCommitCallbacks()` or
      `TransactionTestCase`, so those callbacks actually run.
- [ ] State changes use a conditional `.update(...)` or a locked read, not
      `get()` → `if` → `save()`.
