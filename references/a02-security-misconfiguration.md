# A02:2025 — Security Misconfiguration

This file owns the settings surface. That surface holds debug and hosts, the
SECURE_*/SESSION_*/CSRF_* matrix, CORS, and the security headers. It also
holds the DNS records that authenticate your mail and constrain certificate
issuance, and the deploy check. This file maps to OWASP API8:2023.

This file and `deployment-and-runtime.md` split the configuration surface by
where the setting lives, not by topic. This file owns what a settings module
or a DNS zone **declares**. The deployment file owns what the proxy, the
process, and the image **do** with a request after it arrives. That includes
forwarded-header trust. It also includes the client IP that every rate limit
and audit record depends on.

Mail authentication here asks if an attacker can impersonate your domain.
`a06-insecure-design.md` asks if an attacker can drive your mailer. The secret
*values* these settings name belong to `service-identity-and-secrets.md`.
`a10-exceptional-conditions.md` owns what a `DEBUG` error view discloses when
a request fails.

## Contents
- [Principle](#principle)
- [DEBUG and ALLOWED_HOSTS](#debug-and-allowed_hosts)
- [The security settings matrix](#the-security-settings-matrix)
- [Cookie prefixes and the subdomain boundary](#cookie-prefixes-and-the-subdomain-boundary)
- [Signed cookies and the legacy salt fallback](#signed-cookies-and-the-legacy-salt-fallback)
- [CSRF settings and trusted origins](#csrf-settings-and-trusted-origins)
- [Wildcard entries in a host or origin allowlist](#wildcard-entries-in-a-host-or-origin-allowlist)
- [Fetch Metadata as a second wall](#fetch-metadata-as-a-second-wall)
- [CORS](#cors)
- [Compression and BREACH](#compression-and-breach)
- [Content Security Policy](#content-security-policy)
- [Mail authentication: SPF, DKIM, and DMARC](#mail-authentication-spf-dkim-and-dmarc)
- [Certificate issuance and dangling DNS](#certificate-issuance-and-dangling-dns)
- [security.txt](#securitytxt)
- [check --deploy](#check---deploy)
- [Writing a deployment guardrail check](#writing-a-deployment-guardrail-check)
- [Configuration drift and the expiring exception](#configuration-drift-and-the-expiring-exception)
- [Review checklist](#review-checklist)

## Principle

Most breaches do not need a new exploit. They need a default left on. The
principle is **ship a hardened, minimal configuration**. Turn off debug and
verbose errors in production. Expose only what the deployment requires. Set
the security headers the platform gives you.

Configure each environment (dev/stage/prod) separately, so that a development
convenience never reaches production. Configuration is code. Review
configuration as you review code. Verify configuration with an automated
check, not from memory.

## DEBUG and ALLOWED_HOSTS

- Set `DEBUG = False` in production. `DEBUG = True` renders stack traces,
  settings, SQL, and local variables to any person who triggers an error. Rate
  any production path that can reach it as Critical.
- With `DEBUG = False`, `ALLOWED_HOSTS` must be set and must **not** be
  `["*"]`. It is the defense against Host-header poisoning. Host-header
  poisoning can forge a password-reset link that points at an attacker domain.
- Load both from the environment. Never hardcode a production `SECRET_KEY`
  (see A04). Never commit a key with the `django-insecure-` prefix.
- **An environment variable is a string, and every string that is not empty is
  true.** `DEBUG = os.getenv("DEBUG", "False")` gives `DEBUG` the value
  `"False"`, and Django reads that value as true. `"false"`, `"0"`, and `"no"`
  behave the same way. Parse the value into a `bool`. The same trap changes the
  *shape* of `ALLOWED_HOSTS`. `os.getenv("ALLOWED_HOSTS", "").split(",")`
  returns `[""]`, which rejects every host. A bare string makes each character
  a host pattern, because `validate_host()` iterates the value it receives.

```python
# Wrong: each value keeps the shape the environment gave it. DEBUG is a
# string that is not empty, so it is true. ALLOWED_HOSTS holds one empty entry.
DEBUG = os.getenv("DEBUG", "False")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "").split(",")
```

```python
# Correct: parse each value into the type the setting needs, and drop the
# empty entries that the split produces.
DEBUG = os.getenv("DEBUG", "").lower() in {"1", "true", "yes"}
ALLOWED_HOSTS = [h for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h]
```

The two halves reach the deploy gate differently. `check --deploy` reports
`security.W018` for a `DEBUG` value of any type that is true. The gate catches
that half wherever it runs on the module and the environment production uses.
The check reports `security.W020` only for an empty `ALLOWED_HOSTS`, so `[""]`
passes it. Verified against the Django 6.1
`django/core/checks/security/base.py` on 27 Aug 2026.

### Commonly mistaken for a finding

All three items below are the same mistake, and this file is the most exposed
to it. A settings *file* is not a settings *module in force*. The split layout
is the common case in Django projects: `settings/base.py`, `settings/dev.py`,
`settings/test.py`, and `settings/production.py`, selected by
`DJANGO_SETTINGS_MODULE`. Therefore the deciding question for each item is
which import chain the production entry point follows. Establish that chain
once, and establish it for every process that production runs. `wsgi.py`,
`asgi.py`, and `manage.py` are the first three. A Celery or an RQ worker, a
scheduler, and a command that cron starts each name a settings module of their
own. Each one of them is a production process. That chain then answers all
three items.

- **`DEBUG = True` in a module only the development or test path imports.**
  The line is Critical where production reaches it, and inert where production
  does not reach it. The line looks identical in both cases.
- **`ALLOWED_HOSTS = ["*"]` in a test settings module.** The test client sends
  `testserver` as the host. The wildcard makes the suite run. It does not
  weaken anything a request reaches.
- **A `SECRET_KEY` literal in a module used only by CI or the test suite.** A
  committed test key signs nothing a user holds. The finding is a production
  key in history. That is a different claim, and it belongs to
  `service-identity-and-secrets.md`, "Responding to a leaked secret".

Where the production chain does reach one of these items, none of this note
applies. The severity is then the severity that the section above states.

**Write-time.** When you generate a settings module that carries a development
or test convenience, put that convenience in a module the production entry
point never imports. Do not put it behind a branch inside a single file. The
import chain is the only evidence a reviewer can follow to tell a convenience
from a defect. A one-file layout leaves the reviewer nothing to follow.

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
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"   # default since Django 4.0; keep it

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
  **unconditionally**. If a client can supply that header, an attacker can
  spoof the HTTPS detection. See the deployment file for the Nginx and
  Cloudflare specifics.
- Keep `SESSION_COOKIE_HTTPONLY` at `True`. `CSRF_COOKIE_HTTPONLY` has low
  value. It must be `False` if your JavaScript reads the CSRF token from the
  cookie.
- Do **not** recommend `SECURE_BROWSER_XSS_FILTER` or `X-XSS-Protection`. The
  header is deprecated, and modern browsers ignore it.
- You must enable `XFrameOptionsMiddleware` before `X_FRAME_OPTIONS` takes
  effect.
- `SecurityMiddleware` serves `Cross-Origin-Opener-Policy` since Django 4.0.
  The default `"same-origin"` denies a cross-origin window a scriptable handle
  to this one. `None` and `"unsafe-none"` are the weakened values. OAuth and
  payment popup flows that call `window.opener.postMessage` break under
  `same-origin`. The correct relaxation is `"same-origin-allow-popups"`, not
  `None` and not `"unsafe-none"`. The setting is one value for the whole site,
  so a relaxation for one popup flow weakens every other page. Scope it to the
  flow instead. `SecurityMiddleware` writes the header with
  `response.setdefault()`, so a response that already carries the header keeps
  its own value. Set the relaxed value on the response that opens the popup,
  and leave the setting at `"same-origin"`. Verified against the Django 6.1
  and 6.0.7 `django/middleware/security.py` on 27 Aug 2026.

**Write-time.** When you generate or extend a settings module, read every
secret and per-environment value from the environment. Fail at startup when
one value is missing. A default left in the settings file is the value
production runs on.

Add the HTTPS redirect, HSTS, and the two secure cookie flags in that same
edit. Do not leave them for a later hardening pass. Those four settings are
off by default, and they are what `check --deploy` warns about. Nobody opens a
merged settings module again without a reason.

## Cookie prefixes and the subdomain boundary

### Principle layer

A cookie's *name* can carry a constraint that the browser enforces. It is the
one cookie property that an attacker on a sibling subdomain cannot avoid.

- **`__Host-`** requires `Secure`, requires **no** `Domain` attribute, and
  requires `Path=/`. The cookie is then locked to exactly the host that set
  it. No subdomain can write it, and no subdomain receives it.
- **`__Secure-`** requires only `Secure`, and says nothing about which host
  set the cookie. It is the weaker of the two by a wide margin.

A browser ignores a `Set-Cookie` whose name carries a prefix that the
attributes do not satisfy. The browser gives no error and no warning, and it
never stores the cookie. Thus a wrong prefix shows as "login stopped working",
and not as a security failure.

The attack that `__Host-` closes is **cookie tossing**. The browser scopes a
cookie by domain rather than by origin. Therefore any host under `example.com`
may set a cookie with `Domain=example.com`. The parent then receives its own
cookie and the sibling's cookie under one name, and the ordering rules decide
which one the server reads first.

A compromised marketing site is enough to shadow a session or CSRF cookie on
the main application. A dangling subdomain that an attacker took over, or an
untrusted customer subdomain, is also enough. A cookie that carries a `Domain`
attribute cannot carry the `__Host-` name, which removes the attack rather
than detects it.

Two results follow. A cookie domain set to the parent gives the cookie to
**every** subdomain, present and future. Each subdomain then joins the trust
boundary of whatever that cookie authenticates. That is most of the reason for
the rating of a dangling CNAME in "Certificate issuance and dangling DNS"
below. `Path` is not a security boundary. Same-origin script reads across
paths freely, so `Path=/admin` scopes what the browser sends and isolates
nothing.

### Django & DRF implementation layer

Django emits the name it receives. `SessionMiddleware` and
`CsrfViewMiddleware` pass the `SESSION_COOKIE_*` and `CSRF_COOKIE_*` values
directly into `set_cookie()`. `set_cookie()` performs no prefix validation.
Thus the name and the settings can disagree, and only a dropped cookie shows
the disagreement.

`HttpResponse.delete_cookie()` *does* know about prefixes: it forces
`secure=True` when the name starts with one, so deletion still works. A reader
easily mistakes that behavior for validation at set time. Read off the Django
6.0.7 source on 14 Aug 2026.

```python
# Wrong: the name claims __Host-, the cookie carries a Domain, and Secure is
# off. Every browser drops it, so nobody can log in and nothing says why.
SESSION_COOKIE_NAME = "__Host-sessionid"
SESSION_COOKIE_DOMAIN = ".example.com"
SESSION_COOKIE_SECURE = False
```

```python
# Correct: four settings per cookie saying what the name says. The domain
# must be None -- not "" and not the site's own host.
SESSION_COOKIE_NAME = "__Host-sessionid"
SESSION_COOKIE_DOMAIN = None
SESSION_COOKIE_PATH = "/"
SESSION_COOKIE_SECURE = True

CSRF_COOKIE_NAME = "__Host-csrftoken"
CSRF_COOKIE_DOMAIN = None
CSRF_COOKIE_PATH = "/"
CSRF_COOKIE_SECURE = True
```

What that forbids, and what it costs:

- **A session shared across subdomains becomes impossible**, which is the
  purpose rather than a side effect. A project that authenticates
  `app.example.com` and `admin.example.com` from one cookie chooses
  `SESSION_COOKIE_DOMAIN` over the prefix. That choice puts every subdomain
  inside the session's trust boundary. Prefer a separate cookie for each host.
- **Any code that reads the CSRF cookie by name** reads the new name. The
  usual call is `getCookie("csrftoken")` in front-end code. A change to
  `CSRF_COOKIE_NAME` without a change to the reader breaks every unsafe
  request. `CSRF_USE_SESSIONS = True` avoids the question: it moves the CSRF
  secret into the session and emits no CSRF cookie at all.
- **Cookies already set under the old names are orphaned rather than
  migrated.** They stay in browsers until they expire, and the application
  ignores them. Do not add a reader that accepts the old name beside the new
  one. Backward compatibility is the correct instinct almost everywhere, and
  here it restores the subdomain-writable cookie that the prefix removed.

`LANGUAGE_COOKIE_*` is the remaining set, and its defaults are weaker than the
session's defaults. `LANGUAGE_COOKIE_SECURE` and `LANGUAGE_COOKIE_HTTPONLY`
are both `False`, and `LANGUAGE_COOKIE_SAMESITE` is `None`. The session cookie
uses `True`, `True`, and `"Lax"`. The language cookie carries no credential,
so the finding is not the cookie itself.

The finding is that the application reads a non-`Secure`, subdomain-writable
value on every request, and everything downstream that trusts it inherits
that. Set the three flags. Give the cookie a `__Host-` name wherever nothing
needs it across subdomains.

**Write-time.** When you generate a settings module for a single-host HTTPS
project, write the session and CSRF cookie names with the `__Host-` prefix.
Set the matching domain, path, and secure values in the same edit. The prefix
becomes a rename once the cookie is in production. A reader only ever reads
the four settings together at the moment you write them.

Where the request genuinely calls for a session shared across subdomains,
write `SESSION_COOKIE_DOMAIN` without a prefix. Then say in one line that
every subdomain now sits inside that session's trust boundary. Set
`LANGUAGE_COOKIE_SECURE`, `LANGUAGE_COOKIE_HTTPONLY`, and
`LANGUAGE_COOKIE_SAMESITE` beside the session flags. Do not leave them at
defaults nobody chose.

## Signed cookies and the legacy salt fallback

`HttpRequest.get_signed_cookie()` derived its signing salt from the cookie
name and the `salt` argument, joined together. Where two different
name-and-salt pairs joined to the same string, Django could accept a cookie
signed in one context in a different context. That is CVE-2026-6873, disclosed
3 June 2026 and rated low under Django's security policy. Signed cookies now
use an unambiguous derivation. `a04-cryptographic-failures.md`, "Signing and
salt discipline", describes this domain-separation failure. Django's own
helper reaches it here, rather than a hand-rolled signer.

Two things follow for a settings module.

- **The floor is 5.2.15 or 6.0.6**, both released 3 June 2026. Below either
  version, the project still derives salts ambiguously. The finding is then
  the upgrade, not a setting.
- **`SIGNED_COOKIE_LEGACY_SALT_FALLBACK` decides whether Django still honors
  the old cookies, and its default depends on the line the project runs.**
  Django added it in 5.2.15 and 6.0.6 with a default of `True`. A patched
  project on either of those lines therefore still accepts cookies signed
  under the historical `key + salt` derivation. Django 6.1, released 5 Aug
  2026, changed that default to `False`, which completes the remediation
  rather than extends it. On 6.1, Django rejects the ambiguous derivation
  unless you write the setting back. Django keeps the setting until 7.0, which
  removes it outright. Read the default off the installed line before you call
  an unset value safe or unsafe. On 5.2 and 6.0 an absent setting means Django
  still accepts the old cookies, and on 6.1 it means Django does not.
- **The 6.1 change has a migration consequence. State it before the upgrade,
  not after.** A cookie minted by a pre-June-2026 Django stops validating the
  moment the project moves to 6.1. Django drops a session, preference, or
  consent cookie still in circulation silently, rather than rejects it loudly.
  A project can defer that effect and enable the fallback again. That is the
  wrong instinct in any project whose own calls can collide. The ambiguous
  derivation stays a valid way to present a cookie until the fallback is off.
  Let the old cookies expire, or invalidate them deliberately. Do not restore
  the acceptance path.

The audit is closer to a grep than to a review. Collect every
`set_signed_cookie()` and `get_signed_cookie()` call. Join each cookie name
with the `salt` it passes, and find two pairs that produce the same string. A
cookie named `session` salted `_token` and one named `session_` salted `token`
both derive from `session_token`. Where no pair collides, the setting is
hygiene with no behavioral risk. Where one pair does collide, the setting is
the fix, and you should rename the pair as well.

The audit reads literal values, and it can read nothing else. A `salt` that
the code computes from a user, a path, or a request supplies no pair to
collect. The audit cannot answer the question for that call. Read a
computed `salt` as a collision you cannot rule out. Make it a literal
constant, and then run the audit.

**Write-time.** When you generate a `set_signed_cookie()` or
`get_signed_cookie()` call, pass an explicit `salt` that names the purpose the
cookie serves. Write that `salt` as a literal constant. Do not compute it, and
do not repeat the cookie name. The value is then domain-separated on the same
principle every other signed artifact in the project follows.

On a new project that targets 5.2 or 6.0, write
`SIGNED_COOKIE_LEGACY_SALT_FALLBACK = False` into the same settings module you
generate. Nothing signed under the old derivation is in circulation, so the
default only preserves an acceptance path this project never needed. It is far
easier to set now than to schedule later.

On 6.1 that is already the default, so write nothing. When you generate the
settings change for a 6.1 upgrade, do not add the setting back at `True` to
rescue cookies the upgrade invalidated. That reopens the collision the release
just closed, for every cookie the project signs.

## CSRF settings and trusted origins

- `CSRF_TRUSTED_ORIGINS` must include the scheme, for example
  `["https://app.example.com"]`. That value is an origin literal this setting
  requires, not a hyperlink. It is the one standing exemption from the rule
  that these files carry no links. Django requires it to prevent a 403 on a
  cross-origin form POST or login POST. Django also requires it for correct
  Origin checking on a modern release.
- Under HTTPS, CSRF also checks that the Referer is same-origin. A reverse
  proxy that removes the Referer or rewrites the Host can break this check.
  Correct the proxy. Do not disable the check.
- Examine `@csrf_exempt` on every state-changing view. Confirm that the
  endpoint is genuinely token-authenticated and not cookie-authenticated. See
  the DRF file for the interaction between CSRF and `SessionAuthentication`.

## Wildcard entries in a host or origin allowlist

**The signal is a leading dot, or a `*`, inside an entry of `ALLOWED_HOSTS` or
`CSRF_TRUSTED_ORIGINS`.** `ALLOWED_HOSTS = [".example.com"]` matches
`example.com` and every subdomain of it, present and future.
`CSRF_TRUSTED_ORIGINS = ["https://*.example.com"]` matches that same set in
Django's Origin check. Verified against the Django 6.1 `django/utils/http.py`
and `django/middleware/csrf.py` on 27 Aug 2026.

Each entry therefore admits a name the team does not control. The dangling
CNAME in "Certificate issuance and dangling DNS" below is one such name. A
compromised marketing site and an untrusted customer subdomain are two more.
The attacker sends that host, `ALLOWED_HOSTS` accepts it, and
`request.get_host()` returns it. Every absolute URL the project builds from
the request host then points at a name the attacker serves. The password-reset
link is the one that matters, because it arrives under your own domain.

That same name also passes the CSRF Origin check through the wildcard origin.
A parent-domain CSRF cookie then hands it the token. That is the second reason
"Cookie prefixes and the subdomain boundary" above asks for a `__Host-` name
or for `CSRF_USE_SESSIONS`.

Enumerate the exact hosts instead. A deployment can genuinely serve one
subdomain for each tenant. Record that wildcard in the exception register
below. Give it the owner, the reason, and the expiry date that every other
suppression carries. Build a mail or a reset URL from a configured base URL
rather than from the request host.

`check --deploy` accepts every one of these entries, because it tests that the
setting holds a value rather than what the value permits. The assertion is
therefore a project check. The same holds for each blind spot under
"check --deploy" below that a settings value alone can decide.

**Write-time.** When you generate `ALLOWED_HOSTS` or `CSRF_TRUSTED_ORIGINS`,
write one entry for each host the deployment serves. Never write a leading
dot, and never write a `*`. A wildcard costs almost nothing to write, and it
admits every subdomain the organization creates after you.

## Fetch Metadata as a second wall

A modern browser attaches `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and
`Sec-Fetch-Dest` to a request. Every major browser has this support since
March 2023. A resource-isolation policy in one small middleware rejects a
request whose `Sec-Fetch-Site` is `cross-site`. The policy permits the request
when it is a top-level navigation GET. The policy blocks cross-site request
forgery, cross-site inclusion, and some XS-Leaks probes before view code runs.

- This policy sits beside Django's CSRF protection, never instead of it. A
  non-browser client sends no `Sec-Fetch-*` header, so treat an absent header
  as allowed.
- **The policy rejects `cross-site` and permits `same-site`.** A request from a
  sibling subdomain carries `same-site`. Therefore this wall does not see the
  attacker that "Cookie prefixes and the subdomain boundary" above calls the
  likely one. Django's Origin check is the control that carries a same-site
  request. Do not report the wall as coverage for that case.
- Exempt the documented cross-site entry points: OAuth callbacks, webhook
  receivers, embedded widgets. **Exempt on the resolved route, and never on a
  raw path prefix.** A test of `startswith("/oauth")` also matches
  `/oauth-legacy`, and a percent-encoded or a double-slash form of one path
  reaches the same view. Middleware that runs before `get_response()` reads
  `request.resolver_match` as `None`, because Django resolves the route after
  that point. Read the route after the view resolves, and match it against a
  list of exact names. Verified against the Django 6.1
  `django/core/handlers/base.py` on 27 Aug 2026.

**Write-time.** Add the middleware only when the project asks for
defense-in-depth hardening. Log each rejection with the three header values, so
one grep finds a broken integration.

## CORS

Use `django-cors-headers` with an explicit allowlist. The origin below is a
required configuration value rather than a hyperlink. It carries the same
exemption as the CSRF literal above:

```python
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
# CorsMiddleware must sit high in MIDDLEWARE, above CommonMiddleware.
```

**Package decision (9 Aug 2026):** `django-cors-headers==4.9.0` passes the
maintained-package gate and supports Django 6.0. Keep the origins explicit.
The installation of the package does not justify a wildcard origin or
credentialed reflection. See `security-hardening-libraries.md` for the
recorded vetting fields.

The dangerous combination is:

```python
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True     # with credentials + wildcard, any site can read
```

A server that reflects the request Origin and allows credentials has the same
defect. It lets an attacker's page make authenticated cross-origin reads. CORS
is not CSRF protection, and CSRF protection is not CORS. They solve different
problems. Do not substitute one for the other.

`CORS_ALLOWED_ORIGIN_REGEXES` is the third setting to read, and its name hides
it. A reviewer sees the word allowlist and stops. The package matches each
pattern with `re.match()`, which anchors the start of the origin and not the
end. Therefore a pattern that carries no `$` also matches a longer name.
`r"^https://\w+\.example\.com"` matches
`https://app.example.com.attacker.example`, which is a domain the attacker
registers. Anchor both ends of every pattern. An anchored subdomain pattern
still admits every subdomain, so the rule in "Wildcard entries in a host or
origin allowlist" above governs it as well. Verified against
`django-cors-headers==4.9.0` `corsheaders/middleware.py` on 27 Aug 2026.

### Commonly mistaken for a finding

**`CORS_ALLOW_ALL_ORIGINS = True` with no `CORS_ALLOW_CREDENTIALS`.** Do not
drop this one, because it is still a finding. Reviewers routinely report it at
the severity of the credentialed pair above it, and the two are different
defects. A wildcard with credentials lets any page read authenticated
responses as the logged-in user. A wildcard without credentials lets any page
read what an anonymous client could already have fetched from the server
directly. That is a deliberately widened surface rather than a data leak.

The deciding question is whether `CORS_ALLOW_CREDENTIALS` is set anywhere in
the module in force. A reviewer who confuses the two answers reports a Medium
as a High.

## Compression and BREACH

HTTP compression leaks a secret by size. When a compressed response reflects
attacker-controlled input beside a secret, the compressed length measures how
much of a guess matches the secret. That is BREACH. Django masks the CSRF
token it renders, and the mask changes on each call, which breaks the classic
target. `GZipMiddleware` adds a maximum of 100 random bytes to each compressed
response since Django 4.2, which is the Heal The Breach mitigation. The
mitigation narrows the channel, and it does not remove the channel.

- `GZipMiddleware` on a response that carries a bearer token, a session
  identifier, or another reflected secret beside user input is a finding. Rate
  it by what the response carries. A JSON API that echoes a search string
  beside an API key is the serious case.
- Compress static assets at the proxy instead. A static file carries no
  per-user secret.
- **An absent `GZipMiddleware` is not evidence that the response arrived
  uncompressed.** A proxy compresses a dynamic response under most default
  configurations, which rebuilds this channel outside Django. Confirm which
  content types the proxy compresses before you close the item.
  `deployment-and-runtime.md` owns the proxy rule.

**Write-time.** Do not add `GZipMiddleware` by default. Compress static content
at the proxy. Leave a dynamic response uncompressed unless measurement demands
compression. Then exclude every response that carries a secret.

## Content Security Policy

Django **6.0+** has built-in CSP through `SECURE_CSP` and
`SECURE_CSP_REPORT_ONLY`, with helpers in `django.utils.csp`:

```python
from django.utils.csp import CSP
SECURE_CSP = {
    "default-src": [CSP.SELF],
    "script-src": [CSP.SELF, CSP.NONCE],
    "img-src": [CSP.SELF],
    "base-uri": [CSP.NONE],
    "object-src": [CSP.NONE],
    "form-action": [CSP.SELF],
    "frame-ancestors": [CSP.NONE],
}
```

`base-uri` is the directive a policy omits most often, and its absence undoes
the rest. One injected `<base href>` element rebases every relative URL on the
page. A `<script src="app.js">` element that already carries the nonce then
loads from the attacker, because a nonce authorizes the element rather than
the host. `frame-ancestors` does in the policy what `X_FRAME_OPTIONS` above
does in a header, and a browser that reads both obeys `frame-ancestors`.
`form-action` keeps an injected form from posting the fields a user fills to
another host.

Name the hosts that serve your images. A source expression as wide as `https:`
permits every host on the internet. An injection that the policy stops from
running a script can still send data out in the URL of an image.

Both settings stay inert until you add the dedicated middleware,
`django.middleware.csp.ContentSecurityPolicyMiddleware`, to `MIDDLEWARE`. As
with `X_FRAME_OPTIONS` above, the setting alone emits no header. That
middleware also supplies `request.csp_nonce`. On a pre-6.0 project, the
`django-csp` package is the equivalent. CSP is mainly an XSS mitigation for
server-rendered HTML. It matters less for a pure JSON API, but it is cheap
defense in depth.

A nonce needs a second piece of configuration, and Django 6.1 adds a check for
it. `CSP.NONCE` in the policy emits the source expression. The template
reaches the value through the `django.template.context_processors.csp` context
processor. Without that processor the header promises a nonce that no element
carries, so the browser blocks every inline script the policy was written for.
That is a second way a policy goes inert, after the missing middleware above.
The new `security.W027` check reports it.

Django 6.1 also adds the `csp_nonce_attr` template tag for external `<script
src>` and `<link rel="stylesheet">` elements. The same tag applies the nonce
to a `Media` object's assets.

A policy that starts enforced breaks the inline scripts the team forgot. Deploy
a new policy in report-only mode first. Set `SECURE_CSP_REPORT_ONLY`. Read the
violation reports against real pages. Then move the policy to `SECURE_CSP`.
Keep the report-only channel for the next policy change.

**Package decision (9 Aug 2026):** prefer Django 6's built-in CSP support.
`django-csp==4.0` is a conditional choice only for a supported pre-6.0 project
through Django 5.2. Check the compatibility again before a framework upgrade.

## Mail authentication: SPF, DKIM, and DMARC

### Principle layer

Three DNS-published records decide whether a stranger can send mail that
appears to come from your domain. SPF names the hosts allowed to send for a
domain. DKIM attaches a signature that a receiver verifies against a key
published in the domain's DNS. DMARC ties both to the domain a recipient
actually sees in the `From:` header, through *alignment*. DMARC also tells the
receiver what to do when neither record aligns.

Alignment is the central idea. SPF authenticates the envelope sender, and DKIM
authenticates the domain that signed. Neither one is, on its own, the address
the reader sees. DMARC passes only when at least one of them both passes *and*
matches the visible `From:` domain. That is why a provider dashboard can show
SPF as a pass while an attacker can still forge the domain.

This is a configuration control the team publishes and therefore owns. The
mechanism lives in DNS rather than in code. It is a different question from
*abuse for volume*, which `a06-insecure-design.md`, "Email and notification
abuse", owns. That file asks whether an attacker can drive your sender. This
file asks whether an attacker can impersonate you without any contact with
your sender.

The rollout is monitor first, always:

1. Publish `p=none` with a `rua=` address. That record reports only, and
   enforces nothing. Read the aggregate reports. Make an inventory of every
   system that legitimately sends as you.
2. Fix the alignment for each of those senders. Continue until the reports
   show every legitimate message as a pass.
3. Publish `p=quarantine`. Then publish `p=reject`.

The failure mode is enforcement before that inventory is complete. The policy
then rejects *your own* mail. Password resets, receipts, and alerts are the
first streams to disappear, and the receiver drops them silently. One week
longer in monitor mode is cheaper than that loss.

The opposite failure is far more common, and a reviewer misses it more easily:
**a domain sitting at `p=none` indefinitely has no spoofing protection
whatsoever.** `p=none` is instrumentation, not a policy. Report it as a
finding, not as partial credit.

### Django & DRF implementation layer

**DMARC's specification changed in May 2026.** RFC 9989 is the core document,
RFC 9990 covers aggregate reporting, and RFC 9991 covers failure reporting.
Together they obsolete RFC 7489 and RFC 9091. They also move DMARC from
Informational to Standards Track. The record version identifier is still
`v=DMARC1`. Two changes alter what a correct record contains:

- **`pct` is gone.** It was the percentage-rollout tag. The specification
  removed it, because operational experience showed that receivers rarely
  applied it accurately at any value other than 0 or 100. Its replacement is
  `t` (test mode). `t` defaults to `n`, and it is binary. `t=y` applies a
  policy one level *below* the one stated in `p`, so `p=reject; t=y` behaves
  as quarantine while you watch. A rollout plan written around `pct=25`
  follows a tag that no longer exists.
- **`np` is new**, and it is the cheapest improvement available in the record.
  `sp` sets the policy for subdomains that exist. `np` sets the policy for
  subdomains that do not exist, which is the open path an attacker takes when
  they invent `no-reply.billing.example.com`. Absent `np`, the receiver
  applies `sp`, and then `p`. Publish `np=reject` unless a system genuinely
  sends from names you have not created.

RFC 9989 also replaces the Public Suffix List with a **DNS Tree Walk** that
finds the Organizational Domain, capped at eight queries. The consequence for
a reviewer is practical. A receiver that follows RFC 9989 may resolve a
different Organizational Domain than a legacy receiver resolves. Therefore
**publish an explicit DMARC record at every subdomain you actually send
from**. Do not depend on inheritance.

```
# Wrong: monitor-only indefinitely, no subdomain policy, and a percentage tag
# that RFC 9989 removed. This record reports; it prevents nothing.
v=DMARC1; p=none; pct=50; rua=mailto:dmarc@example.com
```

```
# Correct: enforced, with existing and non-existent subdomains both covered.
# While t=y is present, failing mail is quarantined rather than rejected.
# Record t=y in the exception register with an expiry date, and then drop it.
v=DMARC1; p=reject; sp=reject; np=reject; t=y; rua=mailto:dmarc@example.com
```

`adkim` and `aspf` both default to relaxed (`r`), which accepts alignment
anywhere within the Organizational Domain. Strict (`s`) demands an exact
match. Relaxed is the right default for most projects. Choose strict
deliberately, and only after every sender signs with the exact domain.

**A new transactional provider is what breaks this**, and it breaks the two
paths differently:

- **SPF allows at most 10 DNS-querying mechanisms**, with a recommended cap of
  two void lookups. RFC 7208 requires a `permerror` result once a record
  exceeds the first limit, and DMARC reads `permerror` as an SPF failure.
  Every provider `include:` consumes lookups, and some expand into several.
  Thus the fourth or fifth provider quietly moves the record past the limit.
  Nothing announces this condition, and it appears only in a report.
  Consolidate the record. Remove `include:` entries for providers no longer in
  use. Replace stable ranges with `ip4:` or `ip6:`. Or move a heavy sender
  onto its own subdomain with its own record.
- **SPF alignment breaks even while SPF passes.** A provider sets its own
  envelope sender, so that it can process bounces. SPF then authenticates the
  *provider's* domain, and it does not align with your `From:`. The fix is a
  custom return path under your own domain. The provider normally supplies
  that path as a CNAME.
- **DKIM is the durable answer.** Make each provider sign with a key published
  under your domain. Every serious provider offers a custom-DKIM selector for
  this. `d=` is then your domain, and DKIM aligns. DMARC passes on *either*
  aligned SPF or aligned DKIM, so this also survives forwarding, which breaks
  SPF outright. Use 2048-bit RSA. RFC 8301 requires at least 1024 bits,
  recommends 2048, and requires a verifier to reject anything below 1024.
- **A published selector is a live key. Rotation is therefore the deletion of a
  DNS record, and not only the creation of one.** A private key that leaks
  keeps producing DKIM-passing, DMARC-aligned mail for as long as its selector
  stays in the zone. No receiver can tell that mail from yours. Publish the new
  selector, move the sender onto it, and then delete the retired selector's TXT
  record. Give every selector in the zone an owner, because a selector nobody
  owns is a selector nobody retires.

```
# Wrong: five includes, each costing at least one lookup and several expanding
# into more. Past ten this returns permerror, which DMARC reads as a fail.
# Shown wrapped for width; a published record is a single string.
v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org
  include:servers.mcsv.net include:spf.protection.outlook.com ~all
```

```
# Correct: only the senders still in use, with the marketing platform moved to
# its own subdomain and record, and custom DKIM carrying alignment for both.
v=spf1 include:_spf.google.com include:sendgrid.net -all
```

The Django side is small, but it is worth a check. `DEFAULT_FROM_EMAIL` and
`SERVER_EMAIL` decide the `From:` domain that the receiver evaluates alignment
against. A project that sends as one domain while it publishes DMARC for
another domain fails every check. DNS inspection alone never reveals that
reason.

Error mail sent as `SERVER_EMAIL` and application mail sent through the
provider in `EMAIL_HOST` frequently take different paths. Confirm that both
align. Do not assume that one result covers the other.

Review technique: resolve the records. Do not read the deployment
documentation instead. Query the TXT record at `_dmarc.<domain>` for DMARC, at
the domain itself for SPF, and at `<selector>._domainkey.<domain>` for each
DKIM selector. Count the SPF lookups rather than estimate them from the line.
Compare the sender inventory in the aggregate reports against the systems the
team believes are sending. The gap between those two lists is usually the
finding.

Count the records as well as read them. A receiver discards every DMARC record
at a name where it finds more than one, per RFC 9989. A domain that publishes
more than one SPF record returns `permerror`, per RFC 7208. Thus a zone edit
that leaves the old record beside the new one removes the policy. A lookup
that reports the first record still shows a correct one. Resolve from
outside the deployment's own network, because an internal resolver can hold a
different answer than the one the rest of the world receives.

CWE-290 (Authentication Bypass by Spoofing), CWE-345 (Insufficient
Verification of Data Authenticity); A02:2025. Severity: high for any
public-facing domain. The reachable consequence is credential phishing and
business email compromise carried by your own brand.

SPF, DKIM, and DMARC authenticate the message. Transport is a separate gap.
SMTP sends in cleartext when STARTTLS fails, and an attacker on the network can
force that failure. MTA-STS (RFC 8461) closes that gap in one direction only,
and a reader reverses the direction easily. **The policy you publish declares
that your domain can receive over TLS. It protects the mail that other systems
send to you.** Publish a policy at
`https://mta-sts.<domain>/.well-known/mta-sts.txt` with `mode: enforce` and the
domain's MX hosts. Publish a `_mta-sts.<domain>` TXT record whose `id` changes
on every policy change.

Your own outbound mail depends on the MTA that sends it. That MTA has to read
the recipient's MTA-STS policy, or the recipient's DANE record, and then
refuse a delivery that fails validation. A password-reset message leaves you
on that path. Confirm the behavior with the provider that `EMAIL_HOST` names,
because a DNS query against your own domain never shows it.

TLS-RPT (RFC 8460) adds a `_smtp._tls.<domain>` TXT record with `rua=`, so a
receiver reports each TLS delivery failure to you. Start in `mode: testing`
with TLS-RPT enabled. Then change the mode to `enforce`. For a domain that
receives mail, rate an absent MTA-STS policy LOW.

Django 6.1 moves the sending configuration into one setting. `MAILERS` maps an
alias to a `BACKEND` and an `OPTIONS` dictionary. It uses the shape that
`DATABASES`, `CACHES`, `STORAGES`, and `TASKS` already use. Django deprecates
the `EMAIL_BACKEND`, `EMAIL_HOST`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`,
`EMAIL_PORT`, `EMAIL_USE_TLS`, `EMAIL_USE_SSL`, `EMAIL_SSL_CERTFILE`,
`EMAIL_SSL_KEYFILE`, `EMAIL_FILE_PATH`, and `EMAIL_TIMEOUT` settings, and
Django 7.0 removes them.

Review each alias on its own, because `use_tls` and the credentials are
per-alias now. One mailer can hold TLS while a second sends in cleartext, and
neither setting contradicts the other.

Two system checks arrive with it. `mail.E001` runs only under `--deploy` and
rejects a development-only backend in the `default` alias. `mail.W001` reports
a `MAILERS` value that declares no `default` alias, which Django says will make
sending fail. An empty `MAILERS` dictionary disables sending outright and
raises `MailerDoesNotExist`.

## Certificate issuance and dangling DNS

Two further DNS-published controls sit inside the backend's configuration
surface.

**CAA restricts who may issue certificates for your domain.** By default, any
publicly trusted CA may issue for any name. Thus one CA that validates
incorrectly, or one compromised CA, is enough to produce a valid certificate
for your domain. A CAA record names the CAs permitted to issue. Public CAs
must honor it since September 2017, and RFC 8659 specifies it. Add an `iodef`
address, so that a rejected attempt reaches a person.

```
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 issuewild ";"
example.com. CAA 0 iodef "mailto:security@example.com"
```

`issuewild ";"` forbids wildcard issuance outright, which is the right default
for a project that does not use one. Severity: medium. The record costs
nothing, and the failure it prevents is a valid certificate nobody asked for.

**CAA constrains the issuer, and it does not constrain the requester.**
Whoever controls a name passes an HTTP-01 challenge for that name at any CA
the record permits. The subdomain takeover in the next part therefore defeats
CAA for the name it took. The attacker then holds a publicly trusted
certificate under your own domain. RFC 8657 adds the `accounturi` and the
`validationmethods` parameters to the `issue` and `issuewild` properties.
`accounturi` binds issuance to your own ACME account.
`validationmethods=dns-01` demands control of the zone rather than control of
the host, and a takeover gives the attacker the host alone. Publish both on
the names that matter, and only where your own issuance already validates
through DNS.

**Dangling DNS is subdomain takeover.** A CNAME can still point at a
deprovisioned third-party resource: an object-storage bucket, a former hosting
app, or a documentation or status-page service. Whoever re-creates a resource
under that name at the provider reclaims the CNAME. That person then serves
content from a name your users and your own systems trust. The position is
worth more than it first looks. The name can receive cookies scoped to the
parent domain, satisfy a CSP or CORS allowlist written as `*.example.com`, and
match an OAuth redirect allowlist.

Detection is a three-step loop. Schedule the loop rather than run it once.
Enumerate the subdomains that exist, resolve each CNAME chain to its target,
and flag any target that returns a provider's unclaimed-resource fingerprint
instead of content. The zone is the complete enumeration source, because it
holds the names that no certificate ever covered. Certificate-transparency
logs add the names another team created without telling you. Read both.
Confirm each candidate by hand before you report it. A provider error page is
not always a claimable name.

State one limit of this loop. A fingerprint appears only while the resource
stays unclaimed. Whoever claims it first serves ordinary content, and the next
scan then finds nothing to flag. Therefore watch for a new CNAME that points
at a third party. Do not watch only for a fingerprint at the end of one. Give
priority to the names this file already depends on. Those names are
`mta-sts.<domain>`, each `<selector>._domainkey.<domain>`, and every host in
an OAuth redirect allowlist.

Teams reverse the decommission order, and that order is the whole control.
**Remove the DNS record first, wait for the TTL to expire, and only then
delete the cloud resource.** A team that deletes the resource first opens the
exact window this section is about.

No CWE maps cleanly. Scanners often attach CWE-16 (Configuration), but that
identifier is a category, and CWE's own mapping guidance prohibits a category
in a finding. CWE-672 (Operation on a Resource After Expiration or Release) is
the closest mappable weakness, because the record operates on a resource that
was released. A02:2025 carries the classification either way. Severity: high
where the subdomain shares cookies, an OAuth redirect allowlist, or a CSP or
CORS entry with the application.

## security.txt

RFC 9116 defines `/.well-known/security.txt`. The file tells a security
reporter where to send a vulnerability report. Serve it over HTTPS with a
`Contact:` field and an `Expires:` field. An expired file is the common
failure, so generate the `Expires:` date automatically. Add a `Canonical:`
field that names the file's own URI. RFC 9116 says a reader should not trust
the contents where the URI that retrieved the file is absent from that field.
That field separates your file from a copy on a host somebody else controls.
This is disclosure support, not a control. Rate an absent file INFO.

## check --deploy

`python manage.py check --deploy` runs Django's own production audit
(security.W* warnings for the settings above). Gate it in CI:

```
python manage.py check --deploy --fail-level WARNING
```

A clean run means that the project satisfies Django's baseline. It does not
replace code review.

The more useful list is what the check structurally *cannot* catch, because
readers routinely read a clean run as coverage it never provided:

- **It reads settings, and only settings.** The check cannot see the
  Dockerfile, the proxy configuration, or DNS. Thus a passing run covers
  nothing in `deployment-and-runtime.md`, and nothing in the two sections
  above.
- **It cannot tell a safe `SECURE_PROXY_SSL_HEADER` from a spoofable one.** It
  confirms that the setting has a value. A settings check cannot see whether
  the proxy actually overwrites that header. Thus the dangerous configuration
  passes silently.
- **It does not inspect CSP content.** The check does not lint `SECURE_CSP`,
  so `'unsafe-inline'` or a wildcard source passes. It does not read CORS at
  all, so it cannot see `CORS_ALLOW_ALL_ORIGINS = True` alongside credentials.
- **It does not know what is installed.** `debug_toolbar` or `silk` in
  `INSTALLED_APPS` raises nothing.
- **`ALLOWED_HOSTS = ["*"]` passes.** The check tests that the list is
  non-empty, not that it is restrictive.
- **A team can silence it.** `SILENCED_SYSTEM_CHECKS` removes a warning
  permanently, and without `--fail-level` the command exits zero regardless.
  Read that list as part of the review. Each entry is a decision somebody made
  once, and nobody has examined it again.
- **It reports the posture of the module and the environment that ran it.** The
  pipeline supplies `DJANGO_SETTINGS_MODULE`, and it supplies every value the
  settings module reads. The rule to fail at startup on a missing value then
  obliges the pipeline to invent a value for each variable. Thus a run in CI
  proves that the configuration has the correct shape, and it proves nothing
  about the values production holds. Print `settings.SETTINGS_MODULE` in the
  gate, so that the log names the module the run covered. Keep each check that
  compares a value for the deploy step, which runs inside the target
  environment.

One property of the command itself changed. `run_checks()` in Django 6.1
defaults `databases` to every configured alias when `--database` names none,
where Django 6.0 left it `None`. Checks tagged `database` stay skipped without
an explicit alias, so Django's own deploy checks still read settings alone. A
custom or third-party check that accepts `databases` now receives every alias,
and it can open a connection. Confirm that the pipeline step has a database it
may reach, and that the alias it reaches is not production.

Verified against the 6.1 and 6.0 `django/core/checks/registry.py` on 20 Aug
2026.

Treat the check as the floor in CI. Then audit separately what it cannot
introspect. The portable form: a configuration linter cannot see
infrastructure, so a clean linter is never evidence of deployment posture.

## Writing a deployment guardrail check

The section above lists what Django's check cannot see. You can close part of
that list inside the project, because the framework is silent for generality
rather than for difficulty. It cannot know which variable this deployment
requires, which of its own defaults this project treats as fail-closed, or
which bucket is the production one. A custom system check states one of those,
and the deploy gate then enforces it on every pipeline run.

An absent guardrail is rarely a finding by itself. Rate it as the
defense-in-depth gap behind whatever it would have caught.

### Principle layer

A configuration assertion earns its place where three conditions hold at once.
The property decides whether the deployment is safe. Configuration alone gives
the answer. No generic linter can know it. Four such properties recur in
almost every project, and no framework check can express any of them.

- **A required variable is absent, or still carries a development default.**
  Nobody notices a deployment that uses the default silently, because a
  default produces a running process rather than an error.
- **A secret matches a known placeholder.** Examples are the value from the
  example environment file, the key out of a getting-started guide, and
  `changeme`. Each one is a real value that is also a public one. A length
  test or an entropy test passes straight over that case.
- **A permission, authentication, or visibility default is not the fail-closed
  one.** The framework has no opinion about which of its defaults your project
  considers safe. Only the project knows that the permissive one is a defect
  here.
- **A storage bucket, queue, broker, or callback target names a non-production
  resource while the debug flag is off.** The combination is the assertion.
  Either half alone is ordinary. Write the assertion as the set of values this
  deployment permits. A set of the development values you can remember is a
  denylist, and a denylist passes every value nobody thought of.

Two boundaries hold for every assertion of this kind. **It reads configuration
and nothing else.** A check that opens a connection makes the gate depend on
network reachability and on a credential. That dependency turns a
deterministic assertion into an intermittent one, and it gives the pipeline a
reason to disable the check.

**It reports the property, never the value.** Check output lands in a build
log that is retained, searchable, and readable by more people than the secret
store is. A message that quotes the secret it objects to has published that
secret. `CheckMessage.__str__()` renders `obj` and `hint` beside the message
text. A value passed in either argument is published as surely as one written
into the text. Verified against the Django 6.1
`django/core/checks/messages.py` on 27 Aug 2026.

### Django & DRF implementation layer

Verified against the Django 6.0.7 and 5.2.15 source on 14 August 2026. The
check framework is the same in both releases.

`django.core.checks` exports `register`, the tag constants `Tags`, and the
message classes `Debug`, `Info`, `Warning`, `Error`, and `Critical`. A message
takes its text plus the optional `hint`, `obj`, and `id` arguments. A check is
a callable that must accept `**kwargs`, and it must return a list. The
registry raises `TypeError` at registration time when the callable does not
accept `**kwargs`.

```python
# myproject/guardrails/checks.py
from django.conf import settings
from django.core.checks import Error, Tags, register

PRODUCTION_BUCKETS = {"acme-uploads"}

# Wrong: no deploy=True, so the deploy gate never runs it; a network call
# inside a configuration assertion; a Django identifier reused as its own;
# and the secret written into the build log.
@register(Tags.security)
def check_upload_bucket(app_configs, **kwargs):
    if not vault.get(settings.UPLOAD_TOKEN):
        return [Error(f"bad token {settings.UPLOAD_TOKEN}",
                      id="security.E001")]
    return []

# Correct: deploy-only, project-prefixed identifier, settings alone, an
# allowlist of the values this deployment permits, and the setting named
# rather than its value printed.
@register(Tags.security, deploy=True)
def check_upload_bucket_is_production(app_configs, **kwargs):
    if settings.UPLOAD_BUCKET not in PRODUCTION_BUCKETS:
        return [
            Error(
                "UPLOAD_BUCKET is not a bucket this deployment may use.",
                hint="Set UPLOAD_BUCKET from this environment's config.",
                id="acme.E001",
            )
        ]
    return []
```

A check registers only when Python imports its module, so the conventional
wiring is `myapp/checks.py` imported from that app's `AppConfig.ready()`. A
guardrail nobody imports never runs, and its failure looks exactly like a
passing gate. The `--tag` rule below is what catches that.

**`deploy=True` decides whether it runs at all.** `register` files the
function in a separate deployment set. `run_checks` includes that set only
when `include_deployment_checks` is true, and the `check` command sets that
value from `--deploy`. A pipeline that runs `manage.py check` without the flag
executes every other check, executes none of these, and reports success.

**`--fail-level` decides whether a message stops the build**, and its default
is `ERROR`. A check that returns `Warning` therefore prints its message and
exits zero under that default. The flag sets one floor for the whole run
rather than one floor per check. Thus the level a project can afford is the
level of its noisiest message. Where one message forces that level down,
silence that one identifier through the register below. Do not lower the
floor. A floor at `ERROR` stops every `security.W*` message from gating, and
the noisy message is one of many. A guardrail meant to block a deploy returns
`Error`, and it fails the run even at the default. An advisory message has to
sit at `Info` or below, so that it does not dictate the floor.

Django's own deploy family reports every *absent* hardening setting as a
`security.W*` warning. The three `Error` messages in that set report an
invalid value or an unsafe environment override instead. That is why the gate
this file recommends is `--fail-level WARNING`.

**Prefix every identifier with the project.** Django matches
`SILENCED_SYSTEM_CHECKS` against the message `id`, so any entry aimed at a
Django identifier also silences an identifier that collides with it. A
silenced message disappears from the output *and* from the fail decision, so
the guardrail disappears, the build passes, and nothing reports the collision.
`acme.E001` cannot collide, and `security.E001` can. Give every message an
`id`. A message left at `None` can never be silenced, but nobody can cite it
or find it either.

`--tag` narrows a run to the checks that carry a tag. `Tags.security` is a
constant rather than a constraint. Any string works, so a project can carry
its own tag. A tag that no registered check declares raises `CommandError`, so
a typo in the pipeline fails loudly rather than passes an empty run.

That property is also the answer to the guardrail nobody imports. Give every
project check one project tag, and name that tag in the gate. Removal of the
app from `INSTALLED_APPS`, a rename of the module, and an exception inside an
earlier `ready()` then fail the run. None of them passes an empty one.

**Write-time.** A wrong value in some settings is a security failure rather
than an outage. A bucket name, a permission default, the source of a signing
key, and a callback host are the examples. When you generate such a setting,
write the deploy check that asserts it in the same edit. A reviewer reads the
setting exactly once. The check reads it on every deploy after that.

## Configuration drift and the expiring exception

Two failures have one root: a posture that was true the last time somebody
looked. Drift is the movement of the deployment away from the reviewed
baseline. An expiring exception is an exemption written into that baseline
that outlives the reason it was granted. A review that reads files cannot see
either failure. Therefore both belong beside the check that runs on every
deploy.

### Principle layer

**Detect drift on effective values, not on files.** A settings module is code.
The value in force is whatever the imports, the environment reads, and the
platform's own injection produce at startup. A diff of two modules sees none
of the three. The comparison that means something runs inside the target
environment. It resolves the settings that process actually loaded, and holds
them against the baseline the review was written against. Anything weaker
compares two descriptions of a deployment rather than the deployment.

**Every suppression is a decision that decays with time.** A normal Python
project has five kinds, and they behave identically. They are a silenced system
check, a scanner's ignore list, and a dependency advisory recorded as accepted.
The fourth is an inline suppression comment on a line of code. The fifth is a
state that a rollout was supposed to leave behind: `SECURE_CSP_REPORT_ONLY` in
place of `SECURE_CSP`, DMARC `t=y`, MTA-STS `mode: testing`, and a short
`SECURE_HSTS_SECONDS` chosen to test. Each of those enforces less than the
setting beside it appears to promise, and no attack is needed to keep it.
Each one was defensible the day somebody wrote it. None of them expires. None
of them names who decided. A reader usually reconstructs the reason years
later out of a commit message.

The control has one shape in all five places. An exception carries an
**owner**, a **reason**, and an **expiry date**. A rollout state carries the
same three fields, and its identifier is the setting rather than a check id.
Executable code then fails once that date passes. The executable half is what
makes it a control. A register that holds the same three fields with no
enforcement is a description of a policy rather than the policy. A policy that
cannot fail a build is advice.

That is the whole of policy as code, and the vendor-neutral form is the one
worth holding. Write the required posture as an assertion the pipeline runs,
and keep it in the project's own repository. A change of scanner or platform
then re-implements the gate rather than deletes it.

### Django & DRF implementation layer

**Establish which module the process loads before you compare anything.** The
entry points call `os.environ.setdefault("DJANGO_SETTINGS_MODULE", ...)`, and
`setdefault` does not overwrite. Thus a value the platform supplies wins, and
the module named in `manage.py` is the fallback rather than the value in
force. Read the deployment's environment alongside the file. The same trap has
a review-side form: a settings file is not a settings module in force. The
"Commonly mistaken for a finding" note under "DEBUG and ALLOWED_HOSTS" above
states that form.

`diffsettings` is the instrument for the comparison, and a reader misses its
two useful properties easily. It reads the configured settings object rather
than a file, so it reports what the process resolved, environment reads
included. `--default` takes another settings module to compare against,
instead of Django's defaults.

```
python manage.py diffsettings --default config.settings.reviewed \
    --output unified
```

It reads the running process, so it says nothing about an environment where
nobody runs it. To learn what production loaded, run it in production. Run it
on a schedule as well. The comparison holds for the moment it ran, and an edit
in a platform console needs no deploy.

**Its output is secret material.** It renders every upper-case setting through
`repr()` with no redaction of any kind. Thus `SECRET_KEY`, database passwords,
and every API key the module holds appear in full. Verified against the Django
6.0.7 and 5.2.15 source on 14 August 2026. Never write it to a CI artifact, a
ticket, or a shared log. Compare it in place, and emit the **names** of the
settings that differ.

`--default` names a module, and `diffsettings` imports it. Two results follow.
The baseline runs as code inside the environment where the drift job runs, so
it must declare values and do nothing else. No environment read, no import of
the live settings, and no side effect belongs in it. And a change to the
baseline moves the line the comparison measures against. Read a diff of that
module as a security-relevant settings change. Verified against the Django 6.1
`django/core/management/commands/diffsettings.py` on 27 Aug 2026.

`settings_scan.py` answers the other half, and only the other half. It parses
the settings modules without an import, so it reads what the files declare
across a whole package. By construction it cannot see a value the environment
supplies. It also reads only a name that a module assigns in the plain form. A
module that builds names with `globals().update()`, with `exec`, or in a loop
over the environment declares nothing the parser can see. The scan then
under-reports rather than reports nothing, which is the more dangerous of the
two results. Treat such a module as a module with no readable declaration. Use
the static scan for the declaration. Use `diffsettings` in the environment for
the effective value.

The expiry record is a project file, and the assertion over it is one more
deploy check:

```python
# myproject/guardrails/exceptions.py
from datetime import date

# check id -> (owner, reason, expires)
EXCEPTIONS = {
    "security.W004": (
        "platform-team",
        "HSTS is issued at the edge, not by Django.",
        date(2026, 11, 1),
    ),
}
```

```python
# myproject/guardrails/checks.py
@register(Tags.security, deploy=True)
def check_silenced_checks_are_current(app_configs, **kwargs):
    errors = []
    for check_id in settings.SILENCED_SYSTEM_CHECKS:
        entry = EXCEPTIONS.get(check_id)
        if entry is None:
            errors.append(Error(
                f"{check_id} is silenced with no recorded exception.",
                id="acme.E010",
            ))
            continue
        owner, reason, expires = entry
        if expires < date.today():
            errors.append(Error(
                f"The exception for {check_id} expired on {expires}.",
                hint=f"Owner: {owner}. Reason: {reason}.",
                id="acme.E011",
            ))
    return errors
```

State one limit rather than let a reader discover it. An entry of `acme.E010`
in `SILENCED_SYSTEM_CHECKS` silences the message that would have reported it,
so the register cannot police its own entry. Read the diff on
`SILENCED_SYSTEM_CHECKS` as a security-relevant settings change, which catches
that line. The rest of this file's settings already get that treatment.

In review, read `SILENCED_SYSTEM_CHECKS` as a list of decisions rather than as
configuration. Each entry is a security check somebody disabled. The finding
is the entry with no owner, no reason, and no date. Treat a silenced security
check as a finding until a record explains it. The dependency side of the same
discipline belongs to `a03-software-supply-chain.md`, "SBOM, scan gate, and
provenance". That section owns what a pipeline does with a scanner result.

**Write-time.** A suppression is a silenced check, a scanner ignore entry, or
an inline comment that disables a rule. A rollout state that enforces less
than the setting beside it promises is the fifth kind. When you generate a
suppression of any kind, write the owner, the reason, and the expiry date in
the same edit. Put the entry somewhere an assertion can read it, rather than
in a comment beside the line. The next reader finds the comment. The assertion
is the only part of it that can still object.

## Review checklist

- [ ] `DEBUG = False` and `ALLOWED_HOSTS` set (not `*`) in production settings.
      Each one is parsed out of its environment string into the type the
      setting needs, rather than assigned as the string itself.
- [ ] Secrets and per-environment values are read from the environment and
      validated at startup, rather than carrying a default in the settings
      module.
- [ ] HSTS, SSL redirect, nosniff, `X-Frame-Options`, secure session/CSRF cookies set.
- [ ] `SECURE_CROSS_ORIGIN_OPENER_POLICY` is left at `"same-origin"`, and a
      documented popup flow carries `"same-origin-allow-popups"` on its own
      response rather than for the whole site. It is never `None` and never
      `"unsafe-none"`.
- [ ] `SECURE_PROXY_SSL_HEADER` matches the actual proxy and isn't client-spoofable.
- [ ] Session and CSRF cookie names carry the `__Host-` prefix, with domain
      `None`, path `/`, and `Secure` set to agree with it. Or the team chose a
      parent-domain cookie deliberately, and accepted every subdomain into the
      trust boundary that follows.
- [ ] `LANGUAGE_COOKIE_SECURE`, `LANGUAGE_COOKIE_HTTPONLY`, and
      `LANGUAGE_COOKIE_SAMESITE` are set rather than left at their weaker
      defaults.
- [ ] Django is at 5.2.15 or 6.0.6 and later.
      `SIGNED_COOKIE_LEGACY_SALT_FALLBACK` is `False` wherever two
      `get_signed_cookie()` name-and-salt pairs could join to the same string.
      Read the effective value rather than the written one, since 5.2 and 6.0
      default it to `True` and 6.1 defaults it to `False`.
- [ ] `CSRF_TRUSTED_ORIGINS` set with scheme; no stray `@csrf_exempt`.
- [ ] No entry of `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, or
      `CORS_ALLOWED_ORIGIN_REGEXES` matches a subdomain by pattern, and every
      regex origin is anchored at both ends.
- [ ] CORS uses an allowlist; no `CORS_ALLOW_ALL_ORIGINS = True` with credentials.
- [ ] `GZipMiddleware` is absent from any response that reflects user input
      beside a bearer token, a session identifier, or another secret, and the
      proxy compresses static content only.
- [ ] The CSP names `base-uri`, `object-src`, `form-action`, and
      `frame-ancestors`, and no source expression is as wide as `https:`.
- [ ] DMARC is at `p=quarantine` or `p=reject` rather than parked at `p=none`.
      `sp` and `np` are set, and any rollout uses `t=y` rather than the
      removed `pct` tag.
- [ ] SPF stays within 10 DNS-querying mechanisms, and every third-party sender
      signs with custom DKIM under your own domain at 2048-bit RSA. Exactly one
      SPF record and one DMARC record resolve, and the zone holds no retired
      DKIM selector.
- [ ] An MTA-STS policy is published at `mode: enforce` with a matching
      `_mta-sts` TXT record, and TLS-RPT reports delivery-TLS failures. That
      policy protects inbound mail, and the sending MTA protects outbound.
- [ ] A restrictive CAA record is published, with an `iodef` contact. It binds
      the issuer, so a name an attacker holds still passes HTTP-01 at a
      permitted CA.
- [ ] Every CNAME resolves to a resource you still own, and the decommission
      procedure removes the DNS record before the resource.
- [ ] `check --deploy` runs clean (and is enforced in CI), with
      `SILENCED_SYSTEM_CHECKS` reviewed rather than assumed empty. The run
      names the settings module it loaded, and each value assertion runs where
      the production values exist.
- [ ] Project checks assert the properties no framework check can know: a
      required variable, a placeholder secret, a fail-closed default, and a
      non-production target. Those checks are registered `deploy=True`,
      identified under a project prefix, and return `Error` where they are
      meant to stop a deploy. Each one asserts the values the deployment
      permits rather than the values it forbids, and the gate names the
      project's own tag.
- [ ] Drift is established from the settings the deployed process resolved, and
      compared against the reviewed baseline. It is not a diff of two settings
      modules. The comparison output is treated as secret.
- [ ] Every suppression carries an owner, a reason, and an expiry date that
      executable code enforces. A suppression is a silenced check, a scanner
      ignore entry, an accepted advisory, an inline comment, or a rollout state
      such as a report-only CSP, DMARC `t=y`, or MTA-STS `mode: testing`.
