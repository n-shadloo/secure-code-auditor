# A02:2025 — Security Misconfiguration

The settings surface: debug/hosts, the SECURE_*/SESSION_*/CSRF_* matrix, CORS,
security headers, and the deploy check. Maps to OWASP API8:2023.

## Contents
- [Principle](#principle)
- [DEBUG and ALLOWED_HOSTS](#debug-and-allowed_hosts)
- [The security settings matrix](#the-security-settings-matrix)
- [CSRF settings and trusted origins](#csrf-settings-and-trusted-origins)
- [CORS](#cors)
- [Content Security Policy](#content-security-policy)
- [check --deploy](#check---deploy)
- [Review checklist](#review-checklist)

## Principle

Most breaches don't need a novel exploit; they need a default left on. The
principle is **ship a hardened, minimal configuration**: turn off debug and
verbose errors in production, expose only what's required, set the security
headers the platform gives you, and keep environments (dev/stage/prod)
configured separately so a dev convenience never reaches prod. Configuration is
code — review it like code, and verify it with an automated check rather than by
memory.

## DEBUG and ALLOWED_HOSTS

- `DEBUG = False` in production. `DEBUG = True` renders stack traces, settings,
  SQL, and local variables to anyone who triggers an error — treat any prod path
  that can reach it as Critical.
- With `DEBUG = False`, `ALLOWED_HOSTS` must be set and must **not** be `["*"]`.
  It's the defense against Host-header poisoning (which can forge password-reset
  links pointing at an attacker domain).
- Load both from the environment; never hardcode a production `SECRET_KEY`
  (see A04) or commit one with the `django-insecure-` prefix.

## The security settings matrix

For a TLS-served production backend:

```python
# HTTPS / transport
SECURE_SSL_REDIRECT = True          # unless the proxy/Cloudflare already redirects
SECURE_HSTS_SECONDS = 31536000      # start small (e.g. 3600) to test; HSTS is sticky
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True          # only if you truly control all subdomains
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")  # only behind a trusted proxy

# Content / framing
SECURE_CONTENT_TYPE_NOSNIFF = True  # default True in modern Django; keep it
X_FRAME_OPTIONS = "DENY"            # clickjacking; needs XFrameOptionsMiddleware
SECURE_REFERRER_POLICY = "same-origin"

# Session cookie
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True      # default; keep JS from reading the session
SESSION_COOKIE_SAMESITE = "Lax"     # "Strict" if no cross-site flows

# CSRF cookie
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Lax"
```

Notes and gotchas:

- `SECURE_PROXY_SSL_HEADER` must name a header your proxy sets
  **unconditionally**; if a client can supply it, HTTPS detection is spoofable.
  See the deployment file for the Nginx/Cloudflare specifics.
- `SESSION_COOKIE_HTTPONLY` should stay `True`. `CSRF_COOKIE_HTTPONLY` is
  low-value and must be `False` if your JS reads the CSRF token from the cookie.
- Do **not** recommend `SECURE_BROWSER_XSS_FILTER` / `X-XSS-Protection`; the
  header is deprecated and ignored by modern browsers.
- `XFrameOptionsMiddleware` must be enabled for `X_FRAME_OPTIONS` to take effect.

## CSRF settings and trusted origins

- `CSRF_TRUSTED_ORIGINS` must include the scheme, e.g.
  `["https://app.example.com"]`. It's required to avoid 403s on cross-origin
  form/login POSTs and for correct Origin checking on modern Django.
- Under HTTPS, CSRF also checks the Referer is same-origin; a reverse proxy that
  strips Referer or rewrites Host can break this — fix the proxy, don't disable
  the check.
- `@csrf_exempt` is a red flag on any state-changing view; confirm the endpoint
  is genuinely token-authenticated and not cookie-authenticated. See the DRF file
  for how CSRF interacts with `SessionAuthentication`.

## CORS

Use `django-cors-headers` with an explicit allowlist:

```python
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
# CorsMiddleware must sit high in MIDDLEWARE, above CommonMiddleware.
```

**Package decision (17 Jul 2026):** `django-cors-headers==4.9.0` passes the
maintained-package gate and supports Django 6.0. Keep origins explicit; package
installation does not justify wildcard origins or credentialed reflection. See
`security-hardening-libraries.md` for the recorded vetting fields.

The dangerous combination is:

```python
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True     # with credentials + wildcard, any site can read
```

Reflecting the request Origin while allowing credentials is the same bug in
disguise: it lets an attacker's page make authenticated cross-origin reads.
CORS is not CSRF protection and vice versa — they solve different problems; don't
substitute one for the other.

## Content Security Policy

Django **6.0+** has built-in CSP via `SECURE_CSP` / `SECURE_CSP_REPORT_ONLY` and
helpers in `django.utils.csp`:

```python
from django.utils.csp import CSP
SECURE_CSP = {
    "default-src": [CSP.SELF],
    "script-src": [CSP.SELF, CSP.NONCE],
    "img-src": [CSP.SELF, "https:"],
}
```

On pre-6.0 projects the equivalent is the `django-csp` package. CSP is mainly an
XSS mitigation for server-rendered HTML; for pure JSON APIs it matters less, but
it's cheap defense in depth.

**Package decision (17 Jul 2026):** prefer Django 6's built-in CSP support.
`django-csp==4.0` is a conditional choice only for supported pre-6.0 projects
through Django 5.2; re-check compatibility before a framework upgrade.

## check --deploy

`python manage.py check --deploy` runs Django's own production audit
(security.W* warnings for the settings above). Gate it in CI:

```
python manage.py check --deploy --fail-level WARNING
```

A clean run means Django's baseline is satisfied; it does not replace code
review.

## Review checklist

- [ ] `DEBUG = False` and `ALLOWED_HOSTS` set (not `*`) in production settings.
- [ ] HSTS, SSL redirect, nosniff, `X-Frame-Options`, secure session/CSRF cookies set.
- [ ] `SECURE_PROXY_SSL_HEADER` matches the actual proxy and isn't client-spoofable.
- [ ] `CSRF_TRUSTED_ORIGINS` set with scheme; no stray `@csrf_exempt`.
- [ ] CORS uses an allowlist; no `CORS_ALLOW_ALL_ORIGINS = True` with credentials.
- [ ] `check --deploy` runs clean (and is enforced in CI).
