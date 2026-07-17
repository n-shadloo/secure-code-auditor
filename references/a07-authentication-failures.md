# A07:2025 — Authentication Failures

Sessions, tokens/JWT (SimpleJWT), brute force and lockout, MFA, password reset,
enumeration, and the allauth/dj-rest-auth stack. Maps to OWASP API2:2023.

## Contents
- [Principle](#principle)
- [Sessions](#sessions)
- [JWT with SimpleJWT](#jwt-with-simplejwt)
- [Token storage for API clients](#token-storage-for-api-clients)
- [Brute force and lockout](#brute-force-and-lockout)
- [Password reset and enumeration](#password-reset-and-enumeration)
- [MFA](#mfa)
- [allauth / dj-rest-auth](#allauth--dj-rest-auth)
- [Review checklist](#review-checklist)

## Principle

Authentication proves identity; it fails through weak credentials, guessable or
long-lived tokens, missing lockout, unsafe reset flows, and account enumeration.
The principle is **make credentials strong, sessions/tokens short-lived and
revocable, guessing expensive, and recovery flows leak-free**. Bind sessions to
the client where you can, rotate on privilege change, and give users a way to see
and revoke active sessions.

## Sessions

- Cookie flags from A02: `SESSION_COOKIE_SECURE`, `HTTPONLY`, `SAMESITE`.
- Rotate the session key on login to prevent fixation
  (`django.contrib.auth.login` cycles the key — don't bypass it with a custom
  login that reuses the session).
- Consider `SESSION_EXPIRE_AT_BROWSER_CLOSE` and a sensible `SESSION_COOKIE_AGE`
  for sensitive apps. Treat any cached response that creates or changes a
  session cookie as sensitive; keep Django patched and see A01 for
  cache-authorization rules and the deployment file for cache infrastructure.

## JWT with SimpleJWT

For first-party clients, Django's session auth or DRF's built-in
`TokenAuthentication` is often simpler and safer than JWT; reach for JWT when you
actually need stateless, cross-service tokens. If you use `djangorestframework-simplejwt`
(current 5.5.1), harden it:

```python
from datetime import timedelta
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,     # needs token_blacklist app + migrations
    "ALGORITHM": "HS256",
    "SIGNING_KEY": env("JWT_SIGNING_KEY"),  # dedicated key, NOT settings.SECRET_KEY
}
```

- Keep access tokens short; rotate and blacklist refresh tokens (add
  `rest_framework_simplejwt.token_blacklist` to `INSTALLED_APPS`, run migrations,
  and periodically `flushexpiredtokens`).
- Use a **dedicated `SIGNING_KEY`** so you can invalidate all tokens without
  touching Django's `SECRET_KEY`.
- **Algorithm confusion:** with HS256 the signing key both signs and verifies; if
  you switch to RS256 use a proper key pair (`SIGNING_KEY` private, `VERIFYING_KEY`
  public) and pin the algorithm. Reject `alg=none`. Verify the library's
  configured algorithm matches intent.
- There is no clean server-side revocation for un-blacklisted access tokens — on
  logout/password-reset/breach, rotate keys or blacklist outstanding refresh
  tokens.

## Token storage for API clients

APIs are consumed by clients you don't control. Server-side defenses can't assume
a well-behaved client, so enforce everything on the backend. For guidance you
pass to client teams: never put long-lived tokens in browser `localStorage`
(XSS-stealable) — httpOnly cookies are safer for browser SPAs; native clients
should use the platform secure store. This is advisory only; the backend must not
rely on it.

## Brute force and lockout

Django doesn't throttle authentication. Add `django-axes` for attempt tracking
and lockout (per-username and/or per-IP). Behind a proxy, configure the correct
client-IP source so lockout can't be bypassed or abused via spoofed
`X-Forwarded-For` (see deployment; note allauth now distrusts `X-Forwarded-For`
by default and needs explicit proxy config). Pair with the rate-limit layering in
A06.

## Password reset and enumeration

- Use Django's reset flow (single-use, time-limited tokens). Don't build custom
  predictable tokens.
- Return the **same response** whether or not the email exists, and keep timing
  similar, so the endpoint doesn't confirm which accounts exist. Registration and
  login messages should avoid "no such user" vs "wrong password" distinctions.
  (Django has patched enumeration CVEs in this area; still write endpoints not to
  leak.)

## MFA

No built-in MFA. Use `django-otp` (TOTP), optionally `django-two-factor-auth`, or
allauth's MFA support. Require it at least for admin/staff.

## allauth / dj-rest-auth

- `django-allauth` (current 65.18.0): recent versions **distrust `X-Forwarded-For`
  by default** for rate limiting — set the trusted-proxy configuration or override
  client-IP resolution, or lockout/limits misbehave behind Nginx/Cloudflare.
  Configure email verification as mandatory where appropriate; review its rate
  limits and MFA options.
- `dj-rest-auth` (current 7.1.1) exposes login/registration/reset over the API —
  ensure it's wired to hardened SimpleJWT settings and that registration honors
  the same anti-enumeration and verification rules.

## Review checklist

- [ ] Session cookie flags set; session key rotates on login.
- [ ] SimpleJWT: short access TTL, rotation + blacklist, dedicated signing key,
      pinned algorithm, `alg=none` impossible.
- [ ] Login has lockout/attempt tracking; client-IP source correct behind proxy.
- [ ] Reset uses Django tokens; reset/login/registration don't enable enumeration.
- [ ] MFA available and required for admin/staff.
- [ ] allauth proxy/IP config set; dj-rest-auth wired to hardened settings.
