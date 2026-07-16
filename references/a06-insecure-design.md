# A06:2025 — Insecure Design

Flaws that are missing controls by design rather than buggy code: absent rate
limits and anti-automation, business-logic abuse, and unsafe defaults. Overlaps
OWASP API4:2023 (Unrestricted Resource Consumption) and API6:2023 (Unrestricted
Access to Sensitive Business Flows).

## Contents
- [Principle](#principle)
- [Rate limiting and anti-automation](#rate-limiting-and-anti-automation)
- [Business-logic abuse](#business-logic-abuse)
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

Layer defenses accordingly:

- **Login / credential endpoints:** account lockout / attempt tracking with
  `django-axes` (see the auth file), plus a per-account and per-IP limit.
- **Other sensitive flows:** an application limiter (e.g. `django-ratelimit`) or
  an atomic Redis counter for anything security-relevant.
- **Edge:** rate limiting and bot controls at Nginx/Cloudflare handle volumetric
  abuse before it reaches the app (see deployment).
- DRF throttles (`AnonRateThrottle`, `UserRateThrottle`, `ScopedRateThrottle`)
  are fine for basic fair-use quotas — just don't treat them as your brute-force
  defense.

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

## Secure defaults and limits

- Set request/body/upload size limits (`DATA_UPLOAD_MAX_MEMORY_SIZE`,
  `FILE_UPLOAD_MAX_MEMORY_SIZE`) and the web-server limit (see deployment); the
  Django 6.0.5 upload-limit-bypass CVEs are a reminder that the app-level number
  isn't sufficient alone.
- `DATA_UPLOAD_MAX_NUMBER_FIELDS` caps form-field count (DoS/hash-flooding
  defense) — don't raise it casually.
- New features should default to the least-privileged, least-exposed setting;
  opening up is a deliberate act.

## Review checklist

- [ ] Login and sensitive flows have real anti-automation (lockout + limits),
      not just DRF throttles.
- [ ] Money/quantity/discount resolved server-side; idempotency enforced.
- [ ] Replayable/self-referable business flows are constrained.
- [ ] Upload/body/field-count limits set at both app and web-server layers.
