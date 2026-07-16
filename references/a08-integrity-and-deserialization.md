# A08:2025 — Software and Data Integrity Failures

Insecure deserialization, unsafe task serializers, unsigned/untrusted data, and
integrity of the pipeline that ships code. Payment webhook integrity lives here
and in the DRF file.

## Contents
- [Principle](#principle)
- [Insecure deserialization](#insecure-deserialization)
- [Celery and task queues](#celery-and-task-queues)
- [Signed cookies and data](#signed-cookies-and-data)
- [Webhook and callback integrity](#webhook-and-callback-integrity)
- [Pipeline integrity](#pipeline-integrity)
- [Review checklist](#review-checklist)

## Principle

Integrity failures occur when your system trusts data or code whose authenticity
it never verified — a serialized object from the network, an unsigned update, a
webhook that anyone could forge. The principle is **verify before you trust**:
sign and check data you round-trip, never deserialize untrusted input into live
objects, and authenticate the source of anything that drives a state change.

## Insecure deserialization

- **`pickle` on untrusted input is remote code execution.** Never
  `pickle.loads()` data that crossed a trust boundary (request body, cache entry
  an attacker can influence, message queue reachable by others).
- `yaml.load(data)` without a safe loader can construct arbitrary objects — use
  `yaml.safe_load()`.
- Prefer JSON for data interchange; it deserializes to plain types.

## Celery and task queues

- Set JSON serialization explicitly; the pickle serializer is RCE if the broker
  is reachable:

```python
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
```

- Secure the broker (Redis/RabbitMQ): authenticated, firewalled, never exposed to
  the internet. A world-reachable broker is a critical exposure even with JSON.
- Don't leak sensitive data into task arguments or the result backend (they're
  often logged/stored). See deployment for broker/queue exposure.

## Signed cookies and data

- Django's signed-cookie session backend stores data in a signed (not encrypted)
  cookie — clients can read it. Don't put secrets there; prefer server-side
  sessions for sensitive data.
- Use Django `signing`/`TimestampSigner` for any value you hand out and expect
  back; check the signature on return. Note the 2026 signed-cookie salt-namespace
  fix — keep Django patched and review custom `get_signed_cookie` salts.

## Webhook and callback integrity

For payment and third-party webhooks (Stripe et al.):

- **Verify the signature against the raw request body** — Stripe's
  `construct_event` (or equivalent), using the endpoint's signing secret. Parsing
  JSON first and re-serializing breaks the HMAC; read `request.body` and verify
  before parsing.
- Enforce the provider's timestamp tolerance to block replay; optionally
  IP-allowlist the provider.
- Make processing idempotent: a unique constraint on the event id in a
  processed-events table, inside the **same transaction** as the business effect.
- Never trust amounts/prices from the callback payload for authorization
  decisions; reconcile against your server-side record.

## Pipeline integrity

- Pin and verify dependencies (see A03); don't auto-pull unpinned code into
  builds.
- Protect deploy credentials and CI secrets; a compromised pipeline ships
  attacker code with your signature.

## Review checklist

- [ ] No `pickle.loads`/`yaml.load` on untrusted input; JSON used for interchange.
- [ ] Celery serializers forced to JSON; broker authenticated and not exposed.
- [ ] No secrets in signed-cookie sessions; signed values verified on return.
- [ ] Webhooks verify signature on the raw body, enforce timestamp/idempotency,
      and don't trust payload amounts.
- [ ] Build pipeline uses pinned deps and protected credentials.
