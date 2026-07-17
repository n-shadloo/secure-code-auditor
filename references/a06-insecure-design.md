# A06:2025 — Insecure Design

Flaws that are missing controls by design rather than buggy code: absent rate
limits and anti-automation, business-logic and notification abuse, and unsafe
defaults. Overlaps OWASP API4:2023 (Unrestricted Resource Consumption) and
API6:2023 (Unrestricted Access to Sensitive Business Flows).

## Contents
- [Principle](#principle)
- [Rate limiting and anti-automation](#rate-limiting-and-anti-automation)
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

**Important:** DRF's throttling is explicitly **not** a security control. The DRF
docs state it "should not be considered a security measure or protection against
brute forcing or denial-of-service attacks" — IP origins can be spoofed, and it
uses non-atomic cache operations. Also, throttles run *after* authentication, so
they don't protect the auth step itself.

Package choices do not replace layered design. `django-axes==8.3.1` passes the
maintained-package gate for login-attempt monitoring and lockout on Django 6.0,
provided proxy trust and client-IP extraction are correct; use account plus
network/device signals and avoid attacker-triggered permanent denial of service.
`django-ratelimit==4.1.0` and `django-defender==0.9.8` do not pass the 17 Jul 2026
maintenance gate for new use. For general endpoints and business flows, combine
maintained edge/platform limits with application-level, account/tenant-aware
quotas and transactional invariants. Fail closed on sensitive flows, but define
degraded behavior so a cache outage does not silently remove protection.

## Business-logic abuse

Investigate flows where "valid" requests cause harm:

- Checkout/payment: amounts, prices, or discounts taken from the client rather
  than resolved server-side (see the DRF file's payment section). Quantity/price
  never trusted from the request.
- Idempotency: repeated submits creating duplicate orders/charges — enforce with
  a unique constraint or idempotency key.
- Referral/coupon/invite systems that can be replayed or self-referred.
- State machines that can be skipped (e.g. marking an order paid without a
  payment event).

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
- New features should default to the least-privileged, least-exposed setting;
  opening up is a deliberate act.

## Review checklist

- [ ] Login and sensitive flows have real anti-automation (lockout + limits),
      not just DRF throttles.
- [ ] Money/quantity/discount resolved server-side; idempotency enforced.
- [ ] Replayable/self-referable business flows are constrained.
- [ ] Notification triggers are non-enumerating, authorized, idempotent, and
      bounded by source, actor, tenant, destination, target, and global volume.
- [ ] Upload/body/count/processing limits exist at edge and application layers;
      Django memory thresholds are not mistaken for hard upload caps.
