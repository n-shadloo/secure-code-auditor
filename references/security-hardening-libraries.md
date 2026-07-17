# Security-Hardening Libraries (Built-in First)

What to reach for, per need. **Prefer the built-in mechanism**; add a third-party
package only when the framework doesn't cover the need. Versions/status are
current as of 16 Jul 2026 — re-verify before relying on them, since packages move.

## Contents
- [Supply-chain warning](#supply-chain-warning)
- [Choosing built-in vs library](#choosing-built-in-vs-library)
- [The table](#the-table)
- [Notes on specific choices](#notes-on-specific-choices)

## Supply-chain warning

Every dependency you add is code you now trust and must keep patched (see A03).
Before adding one: confirm it's actively maintained (recent releases, responsive
issues), pin the version, verify integrity (hashes/lockfile), and run `pip-audit`.
Fewer, well-maintained dependencies beat many niche ones. An unmaintained
security package is worse than none, because it invites false confidence. Don't
add a library for something Django already does.

## Choosing built-in vs library

Django and DRF cover more than people assume: password hashing, CSRF, sessions,
clickjacking, security headers, signing, password validation, and (on 6.0+) CSP
are all built in. Reach outward mainly for CORS, WebSocket/protocol routing,
brute-force lockout, MFA, JWT, rich auth/registration, file-type detection, XML
safety, and HTML sanitization.

## The table

| Need | Built-in first | Library (only if needed), status Jul 2026 |
|---|---|---|
| Password hashing | `Argon2PasswordHasher` in `PASSWORD_HASHERS` | `argon2-cffi` (the backend Argon2 needs); maintained |
| Password policy | `AUTH_PASSWORD_VALIDATORS` | — |
| CSRF | `CsrfViewMiddleware` (built in) | — |
| Sessions | `django.contrib.sessions` (server-side backend for sensitive apps) | — |
| Clickjacking | `XFrameOptionsMiddleware` / `X_FRAME_OPTIONS` | — |
| Security headers | `SecurityMiddleware` (`SECURE_*`) | — |
| Content Security Policy | **`SECURE_CSP`** on Django **6.0+** | `django-csp` (only on pre-6.0); maintained |
| Signing tokens/values | `django.core.signing`, `TimestampSigner` | — |
| CORS | *(none built in)* | `django-cors-headers` **4.9.0**; maintained |
| WebSockets / protocol routing | Django ASGI for HTTP | `channels` **4.3.2**; official Django project, maintained |
| Brute-force lockout | *(none built in)* | `django-axes`; maintained |
| Per-view rate limiting | DRF throttles for quotas only | `django-ratelimit` (app), edge limits (Nginx/Cloudflare); maintained |
| MFA / 2FA | *(none built in)* | `django-otp` (TOTP), optionally `django-two-factor-auth`, or allauth MFA; maintained |
| JWT for APIs | DRF `TokenAuthentication` (simpler for first-party) | `djangorestframework-simplejwt` **5.5.1**; maintained |
| Auth / social / registration | `django.contrib.auth` | `django-allauth` **65.18.0**; `dj-rest-auth` **7.1.1** for API; maintained |
| Settings / secrets | `os.environ` | `django-environ` or `python-decouple`; maintained |
| Dependency audit | — | `pip-audit` (PyPA), `safety`; maintained |
| Untrusted XML | *(stdlib XML is unsafe for untrusted input)* | `defusedxml`; maintained |
| HTML sanitization | Django autoescaping / `strip_tags` (escaping, **not** sanitizing) | `nh3` (maintained). **Avoid `bleach` — it's archived/unmaintained.** |
| File type detection | *(stdlib `imghdr` removed in 3.13)* | `python-magic` (libmagic) or `filetype` (pure-Python); maintained |

## Notes on specific choices

- **Argon2:** install with `pip install "django[argon2]"` and put
  `Argon2PasswordHasher` first; keep the other hashers listed for transparent
  upgrades of existing hashes.
- **CSP:** on Django 6.0+ use the built-in `SECURE_CSP`; only pull in
  `django-csp` on older projects.
- **Channels:** use Django's native ASGI support for HTTP; add Channels when the
  application needs WebSockets, long-lived consumers, or protocol routing, and
  follow `async-and-channels.md` for origin, auth, ORM, and resource controls.
- **JWT vs sessions/tokens:** for a first-party client, session auth or DRF's
  built-in token auth is often the safer default; choose SimpleJWT when you need
  stateless cross-service tokens, and harden it (A07).
- **HTML sanitization:** if you must accept HTML, sanitize with `nh3`. Django's
  `strip_tags`/autoescaping are output-escaping helpers, not sanitizers, and
  `bleach` is no longer maintained — don't recommend it.
- **File type detection:** `python-magic` or `filetype` provides only one signal;
  combine it with extension/declared-type consistency, a complete parser, and
  the storage/serving controls in `file-uploads.md`.
- **XML:** never parse untrusted XML with the stdlib parser; use `defusedxml`
  (XXE/entity-expansion protection).
- **Rate limiting:** for real abuse defense combine `django-axes` (auth lockout)
  with edge limits; `django-ratelimit` or an atomic Redis counter for other
  sensitive flows. DRF throttling is a quota tool, not a security control (A06).

Whenever this list and the framework overlap, use the framework. Add a package
only for a need the framework genuinely doesn't meet, and only if it's maintained.
