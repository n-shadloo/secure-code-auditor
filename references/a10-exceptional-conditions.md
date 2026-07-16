# A10:2025 — Mishandling of Exceptional Conditions

New in 2025. Errors, edge cases, and failure modes handled in ways that leak
information or fail open, plus race conditions in security-relevant flows.

## Contents
- [Principle](#principle)
- [Don't leak on error](#dont-leak-on-error)
- [Fail closed](#fail-closed)
- [Race conditions and TOCTOU](#race-conditions-and-toctou)
- [Review checklist](#review-checklist)

## Principle

How software behaves when something goes wrong is a security property. Two failure
patterns dominate: **leaking** (stack traces, internal messages, and detailed
errors handed to the attacker) and **failing open** (an exception or edge case
skips a security check and the request proceeds). The principle is **fail closed
and fail quiet**: on error, deny the action and return a generic message, while
logging the detail server-side. Handle the unexpected explicitly rather than
letting a swallowed exception decide security for you.

## Don't leak on error

- `DEBUG = False` in production; provide custom `handler400/403/404/500` and error
  templates that reveal nothing internal.
- Don't return raw exception strings, SQL errors, or stack traces in API
  responses. Catch, log server-side, and return a generic error with an id the
  user can quote to support.

## Fail closed

- Permission and authentication code must default to deny. Watch for
  `try/except` blocks around auth checks that fall through to "allowed" on error,
  or a permission function that returns `None`/falls off the end (treat as deny,
  and make it explicit).
- Feature flags and config lookups that gate access should default to the safe
  (closed) state if the flag/store is unavailable.

## Race conditions and TOCTOU

- Time-of-check/time-of-use gaps (check balance, then debit; check uniqueness,
  then insert) let concurrent requests double-spend or duplicate. Use database
  constraints and `select_for_update()` inside a transaction, or atomic
  operations (`F()` expressions), rather than read-modify-write in Python.
- For endpoints that must not run twice (payments, provisioning), combine an
  idempotency key/unique constraint with `transaction.atomic()`. Consider
  `ATOMIC_REQUESTS` for the app, understanding its performance trade-offs.

```python
from django.db import transaction

with transaction.atomic():
    account = Account.objects.select_for_update().get(pk=pk)
    if account.balance < amount:
        raise InsufficientFunds
    account.balance = F("balance") - amount
    account.save(update_fields=["balance"])
```

## Review checklist

- [ ] `DEBUG = False`; custom error handlers; no exception/stack detail in
      responses.
- [ ] Auth/permission code fails closed; no `except` that yields "allowed".
- [ ] Critical flows use DB constraints + `select_for_update`/atomic ops, not
      read-modify-write.
- [ ] Must-run-once endpoints are idempotent within a transaction.
