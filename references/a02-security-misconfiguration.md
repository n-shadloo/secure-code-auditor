# A02:2025 — Security Misconfiguration

The settings surface: debug/hosts, the SECURE_*/SESSION_*/CSRF_* matrix, CORS,
security headers, the DNS records that authenticate your mail and constrain
certificate issuance, and the deploy check. Maps to OWASP API8:2023.

This file and `deployment-and-runtime.md` split the configuration surface by
where the setting lives rather than by topic. This file owns what a settings
module or a DNS zone **declares**. The deployment file owns what the proxy, the
process, and the image **do** with a request once it arrives, including
forwarded-header trust and the client IP that every rate limit and audit record
depends on. Mail authentication here asks whether your domain can be
impersonated; `a06-insecure-design.md` asks whether your mailer can be driven.
The secret *values* these settings name belong to
`service-identity-and-secrets.md`, and `a10-exceptional-conditions.md` owns
what a `DEBUG` error view discloses when a request fails.

## Contents
- [Principle](#principle)
- [DEBUG and ALLOWED_HOSTS](#debug-and-allowed_hosts)
- [The security settings matrix](#the-security-settings-matrix)
- [Cookie prefixes and the subdomain boundary](#cookie-prefixes-and-the-subdomain-boundary)
- [Signed cookies and the legacy salt fallback](#signed-cookies-and-the-legacy-salt-fallback)
- [CSRF settings and trusted origins](#csrf-settings-and-trusted-origins)
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

### Commonly mistaken for a finding

All three below are the same mistake, and it is the one this file is most
exposed to: a settings *file* is not a settings *module in force*. The split
layout — `settings/base.py`, `settings/dev.py`, `settings/test.py`,
`settings/production.py`, selected by `DJANGO_SETTINGS_MODULE` — is the common
case in Django projects, so the deciding question for every one of them is
which import chain the production entry point actually follows. Establish that
chain once, from `wsgi.py`, `asgi.py`, and `manage.py`, and all three answer
themselves.

- **`DEBUG = True` in a module only the development or test path imports.**
  The line is Critical where production reaches it and inert where it does
  not, and the line itself looks identical in both cases.
- **`ALLOWED_HOSTS = ["*"]` in a test settings module.** The test client
  sends `testserver` as the host, so the wildcard is there to make the suite
  run rather than to weaken anything a request reaches.
- **A `SECRET_KEY` literal in a module used only by CI or the test suite.**
  Committed test keys sign nothing a user holds. The finding is a production
  key in history, which is a different claim and belongs to
  `service-identity-and-secrets.md`, "Responding to a leaked secret".

Where the production chain does reach one of these, none of it applies and the
severity is what the section above says it is.

**Write-time.** When generating a settings module that carries a development
or test convenience, put it in a module the production entry point never
imports rather than behind a branch inside a single file, because the import
chain is the only thing a reviewer can follow to tell a convenience from a
defect, and a one-file layout leaves them nothing to follow.

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
  **unconditionally**; if a client can supply it, HTTPS detection is spoofable.
  See the deployment file for the Nginx/Cloudflare specifics.
- `SESSION_COOKIE_HTTPONLY` should stay `True`. `CSRF_COOKIE_HTTPONLY` is
  low-value and must be `False` if your JS reads the CSRF token from the cookie.
- Do **not** recommend `SECURE_BROWSER_XSS_FILTER` / `X-XSS-Protection`; the
  header is deprecated and ignored by modern browsers.
- `XFrameOptionsMiddleware` must be enabled for `X_FRAME_OPTIONS` to take effect.
- `SecurityMiddleware` serves `Cross-Origin-Opener-Policy` since Django 4.0.
  The default `"same-origin"` denies a cross-origin window a scriptable handle
  to this one. `None` and `"unsafe-none"` are the weakened values. OAuth and
  payment popup flows that call `window.opener.postMessage` break under
  `same-origin`. The correct relaxation is `"same-origin-allow-popups"`, not
  `None` and not `"unsafe-none"`.

**Write-time.** When generating or extending a settings module, read every
secret and per-environment value from the environment and fail at startup when
one is missing, because a default left in the settings file is the value
production quietly runs on. Add the HTTPS redirect, HSTS, and the two secure
cookie flags in that same edit rather than leaving them for a later hardening
pass: those four are off by default, they are precisely what `check --deploy`
warns about, and a settings module that has already been merged is one nobody
re-opens without a reason to.

## Cookie prefixes and the subdomain boundary

### Principle layer

A cookie's *name* can carry a constraint the browser enforces, which makes it
the one cookie property an attacker positioned on a sibling subdomain cannot
work around.

- **`__Host-`** requires `Secure`, requires **no** `Domain` attribute, and
  requires `Path=/`. The cookie is then locked to exactly the host that set
  it: no subdomain can write it and no subdomain receives it.
- **`__Secure-`** requires only `Secure`, and says nothing about which host
  set the cookie. It is the weaker of the two by a wide margin.

A browser silently ignores a `Set-Cookie` whose name carries a prefix the
attributes do not satisfy. There is no error and no warning — the cookie is
simply never stored — so a mis-set prefix presents as "login stopped working"
rather than as anything security-shaped.

The attack `__Host-` closes is **cookie tossing**. Cookies are scoped by
domain rather than by origin, so any host under `example.com` may set a
cookie with `Domain=example.com`, and the parent then receives its own cookie
and the sibling's under one name, with the ordering rules deciding which the
server reads first. A compromised marketing site, a taken-over dangling
subdomain, or an untrusted customer subdomain is enough to shadow a session
or CSRF cookie on the main application. A cookie carrying a `Domain`
attribute cannot carry the `__Host-` name, which is what removes the attack
rather than detecting it.

Two corollaries. Setting a cookie's domain to the parent hands it to **every**
subdomain, present and future, so each one joins the trust boundary of
whatever that cookie authenticates — which is most of why a dangling CNAME is
rated as it is in "Certificate issuance and dangling DNS" below. And `Path`
is not a security boundary: same-origin script reads across paths freely, so
`Path=/admin` scopes what the browser sends and isolates nothing.

### Django & DRF implementation layer

Django emits whatever name it is handed. `SessionMiddleware` and
`CsrfViewMiddleware` pass the `SESSION_COOKIE_*` and `CSRF_COOKIE_*` values
straight into `set_cookie()`, and `set_cookie()` performs no prefix
validation, so the name and the settings can disagree with nothing but a
dropped cookie to show for it. `HttpResponse.delete_cookie()` *does* know
about prefixes — it forces `secure=True` when the name starts with one, so
deletion still works — which is easy to mistake for validation at set time.
Read off the Django 6.0.7 source on 14 Aug 2026.

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
  point rather than a side effect. A project authenticating
  `app.example.com` and `admin.example.com` from one cookie is choosing
  `SESSION_COOKIE_DOMAIN` over the prefix, and with it every subdomain inside
  the session's trust boundary. Prefer a separate cookie per host.
- **Anything reading the CSRF cookie by name** — the usual
  `getCookie("csrftoken")` in front-end code — reads the new name, so
  changing `CSRF_COOKIE_NAME` without changing the reader breaks every unsafe
  request. `CSRF_USE_SESSIONS = True` sidesteps the question by moving the
  CSRF secret into the session and emitting no CSRF cookie at all.
- **Cookies already set under the old names are orphaned rather than
  migrated.** They sit in browsers until they expire and are ignored.

`LANGUAGE_COOKIE_*` is the set left behind, and its defaults are weaker than
the session's: `LANGUAGE_COOKIE_SECURE` and `LANGUAGE_COOKIE_HTTPONLY` are
both `False` and `LANGUAGE_COOKIE_SAMESITE` is `None`, against `True`,
`True`, and `"Lax"` for the session cookie. It carries no credential, so the
finding is not the cookie — it is that a non-`Secure`, subdomain-writable
value is read by the application on every request, and anything downstream
that trusts it inherits that. Set the three flags, and give it a `__Host-`
name wherever nothing needs it cross-subdomain.

**Write-time.** When generating a settings module for a project served over
HTTPS from a single host, write the session and CSRF cookie names with the
`__Host-` prefix and set the matching domain, path, and secure values in the
same edit, because the prefix is a rename once the cookie is in production
and the four settings are only ever read together at the moment they are
written. Where the request genuinely calls for a session shared across
subdomains, write `SESSION_COOKIE_DOMAIN` without a prefix and say in one
line that every subdomain now sits inside that session's trust boundary. Set
`LANGUAGE_COOKIE_SECURE`, `LANGUAGE_COOKIE_HTTPONLY`, and
`LANGUAGE_COOKIE_SAMESITE` alongside the session flags rather than leaving
them at defaults nobody chose.

## Signed cookies and the legacy salt fallback

`HttpRequest.get_signed_cookie()` derived its signing salt by concatenating
the cookie name and the `salt` argument. Where two distinct name-and-salt
pairs concatenated to the same string, a cookie signed in one context could be
accepted in another — CVE-2026-6873, disclosed 3 June 2026 and rated low under
Django's security policy. Signed cookies now use an unambiguous derivation.
This is the domain-separation failure `a04-cryptographic-failures.md`,
"Signing and salt discipline", describes, reached through Django's own helper
rather than through a hand-rolled signer.

Two things follow for a settings module.

- **The floor is 5.2.15 or 6.0.6**, both released 3 June 2026. Below either,
  the project still derives salts ambiguously and the finding is the upgrade,
  not a setting.
- **`SIGNED_COOKIE_LEGACY_SALT_FALLBACK` decides whether the old cookies are
  still honored, and its default depends on the line the project runs.** It
  was added in 5.2.15 and 6.0.6 defaulting to `True`, so a patched project on
  either of those lines goes on accepting cookies signed under the historical
  `key + salt` derivation. Django 6.1, released 5 Aug 2026, flipped that
  default to `False`, which completes the remediation rather than extending
  it: on 6.1 the ambiguous derivation is rejected unless the setting is
  written back. Django keeps the setting until 7.0, where it is removed
  outright. Read the default off the installed line before calling an unset
  value safe or unsafe — on 5.2 and 6.0 an absent setting means the old
  cookies are still accepted, and on 6.1 it means they are not.
- **The 6.1 flip has a migration consequence worth stating before the
  upgrade, not after.** Cookies minted by a pre-June-2026 Django stop
  validating the moment the project moves to 6.1, so a session, preference,
  or consent cookie still in circulation is silently dropped rather than
  rejected loudly. Re-enabling the fallback is a way to defer that, and it is
  the wrong instinct in any project whose own calls can collide, because
  until it is off the ambiguous derivation remains a valid way to present a
  cookie. Prefer letting the old cookies expire, or invalidating them
  deliberately, over restoring the acceptance path.

Auditing it is closer to a grep than a review. Collect every
`set_signed_cookie()` and `get_signed_cookie()` call, concatenate each cookie
name with the `salt` it passes, and look for two pairs that produce the same
string: a cookie named `session` salted `_token` and one named `session_`
salted `token` both derive from `session_token`. Where no pair collides, the
setting is hygiene with no behavioral risk. Where one does, it is the fix,
and the pair should be renamed as well.

**Write-time.** When generating a `set_signed_cookie()` or
`get_signed_cookie()` call, pass an explicit `salt` naming the purpose the
cookie serves rather than repeating its name, so the value is domain-separated
on the same principle every other signed artifact in the project follows. On a
new project targeting 5.2 or 6.0, write
`SIGNED_COOKIE_LEGACY_SALT_FALLBACK = False` into the same settings module you
generate: nothing signed under the old derivation is in circulation, so the
default only preserves an acceptance path this project never needed, and it is
far easier to set now than to schedule later. On 6.1 that is already the
default, so write nothing — and when generating the settings change for a 6.1
upgrade, do not add the setting back at `True` to rescue cookies the upgrade
invalidated, because that reopens the collision the release just closed for
every cookie the project signs.

## CSRF settings and trusted origins

- `CSRF_TRUSTED_ORIGINS` must include the scheme, e.g.
  `["https://app.example.com"]` — an origin literal this setting requires, not
  a hyperlink, and the one standing exemption from the rule that these files
  carry no links. It's required to avoid 403s on cross-origin form/login POSTs
  and for correct Origin checking on modern Django.
- Under HTTPS, CSRF also checks the Referer is same-origin; a reverse proxy that
  strips Referer or rewrites Host can break this — fix the proxy, don't disable
  the check.
- `@csrf_exempt` is a red flag on any state-changing view; confirm the endpoint
  is genuinely token-authenticated and not cookie-authenticated. See the DRF file
  for how CSRF interacts with `SessionAuthentication`.

## Fetch Metadata as a second wall

A modern browser attaches `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and
`Sec-Fetch-Dest` to a request. Every major browser has this support since March
2023. A resource-isolation policy in one small middleware rejects a request
whose `Sec-Fetch-Site` is `cross-site`, unless the request is a top-level
navigation GET. The policy blocks cross-site request forgery, cross-site
inclusion, and some XS-Leaks probes before view code runs.

- This sits beside Django's CSRF protection, never instead of it. A non-browser
  client sends no `Sec-Fetch-*` header, so treat an absent header as allowed.
- Exempt the documented cross-site entry points by path: OAuth callbacks,
  webhook receivers, embedded widgets.

**Write-time.** Add the middleware only when the project asks for
defense-in-depth hardening. Log each rejection with the three header values, so
one grep finds a broken integration.

## CORS

Use `django-cors-headers` with an explicit allowlist. The origin below is a
required config value rather than a hyperlink, and carries the same exemption
as the CSRF literal above:

```python
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
# CorsMiddleware must sit high in MIDDLEWARE, above CommonMiddleware.
```

**Package decision (9 Aug 2026):** `django-cors-headers==4.9.0` passes the
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

### Commonly mistaken for a finding

**`CORS_ALLOW_ALL_ORIGINS = True` with no `CORS_ALLOW_CREDENTIALS`.** This one
is not dropped — it is still a finding — but it is routinely reported at the
severity of the credentialed pair above it, and the two are different bugs. A
wildcard with credentials lets any page read authenticated responses as the
logged-in user. A wildcard without them lets any page read what an anonymous
client could already have fetched from the server directly, which is a
deliberately widened surface rather than a data leak. The deciding question is
whether `CORS_ALLOW_CREDENTIALS` is set anywhere in the module in force, and
conflating the two answers is how a Medium gets reported as a High.

## Compression and BREACH

HTTP compression leaks a secret by size. When a compressed response reflects
attacker-controlled input beside a secret, the compressed length measures how
much of a guess matches the secret. That is BREACH. Django masks the CSRF token
it renders, and the mask changes on each call, which breaks the classic target.
`GZipMiddleware` adds up to 100 random bytes to each compressed response since
Django 4.2, which is the Heal The Breach mitigation. The mitigation narrows the
channel; it does not remove it.

- `GZipMiddleware` on a response that carries a bearer token, a session
  identifier, or another reflected secret beside user input is a finding. Rate
  it by what the response carries. A JSON API that echoes a search string
  beside an API key is the serious case.
- Compress static assets at the proxy instead. A static file carries no
  per-user secret.

**Write-time.** Do not add `GZipMiddleware` by default. Compress static content
at the proxy. Leave a dynamic response uncompressed unless measurement demands
compression. Then exclude every response that carries a secret.

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

Both settings are inert until the dedicated middleware,
`django.middleware.csp.ContentSecurityPolicyMiddleware`, is added to
`MIDDLEWARE` — like `X_FRAME_OPTIONS` above, the setting alone emits no
header, and `request.csp_nonce` is also supplied by that middleware. On
pre-6.0 projects the equivalent is the `django-csp` package. CSP is mainly an
XSS mitigation for server-rendered HTML; for pure JSON APIs it matters less, but
it's cheap defense in depth.

A nonce needs a second piece of configuration, and Django 6.1 adds a check for
it. `CSP.NONCE` in the policy emits the source expression, but the template
reaches the value through the `django.template.context_processors.csp` context
processor. Without that processor the header promises a nonce that no element
carries, so every inline script the policy was written for is blocked. That is
a second way a policy goes inert, after the missing middleware above, and the
new `security.W027` check reports it. Django 6.1 also adds the
`csp_nonce_attr` template tag for external `<script src>` and
`<link rel="stylesheet">` elements. The same tag applies the nonce to a
`Media` object's assets.

A policy that starts enforced breaks the inline scripts the team forgot. Deploy
a new policy in report-only mode first. Set `SECURE_CSP_REPORT_ONLY`. Read the
violation reports against real pages. Then move the policy to `SECURE_CSP`.
Keep the report-only channel for the next policy change.

**Package decision (9 Aug 2026):** prefer Django 6's built-in CSP support.
`django-csp==4.0` is a conditional choice only for supported pre-6.0 projects
through Django 5.2; re-check compatibility before a framework upgrade.

## Mail authentication: SPF, DKIM, and DMARC

### Principle layer

Three DNS-published records decide whether anyone at all can send mail that
appears to come from your domain. SPF names the hosts allowed to send for a
domain; DKIM attaches a signature verifiable against a key published in the
domain's DNS; DMARC ties both to the domain a recipient actually sees in the
`From:` header through *alignment*, and tells receivers what to do when neither
aligns.

Alignment is the load-bearing idea. SPF authenticates the envelope sender and
DKIM authenticates whichever domain signed — neither is, on its own, the address
the reader sees. DMARC passes only when at least one of them both passes *and*
matches the visible `From:` domain. That is why a provider dashboard can show
SPF passing while the domain remains forgeable.

This is a configuration control the team publishes and therefore owns, even
though the mechanism lives in DNS rather than in code. It is a different
question from whether your mailer can be *abused for volume*, which is
`a06-insecure-design.md`, "Email and notification abuse": that file asks whether
an attacker can drive your sender, this one asks whether they can impersonate
you without touching it at all.

The rollout is monitor first, always:

1. `p=none` with a `rua=` address — reporting only, no enforcement. Read the
   aggregate reports and inventory every system that legitimately sends as you.
2. Fix alignment for each of those senders until the reports show all
   legitimate mail passing.
3. `p=quarantine`, then `p=reject`.

Enforcing before that inventory is complete is the failure mode, and the mail it
rejects is *your own* — password resets, receipts, and alerts are the streams
that go missing first, silently, at the receiver. A week longer in monitor mode
is cheaper than that.

The opposite failure is far more common and easier to miss: **a domain sitting
at `p=none` indefinitely has no spoofing protection whatsoever.** `p=none` is
instrumentation, not a policy. Finding one is a finding, not partial credit.

### Django & DRF implementation layer

**DMARC's specification changed in May 2026.** RFC 9989 (core), with RFC 9990
for aggregate reporting and RFC 9991 for failure reporting, obsoletes RFC 7489
and RFC 9091 and moves DMARC from Informational to Standards Track. The record
version identifier is still `v=DMARC1`, but two changes alter what a correct
record looks like:

- **`pct` is gone.** It was the percentage-rollout tag, removed because
  operational experience showed it was rarely applied accurately at any value
  other than 0 or 100. Its replacement is `t` (test mode), which defaults to
  `n` and is binary: `t=y` applies a policy one level *below* the one stated in
  `p`, so `p=reject; t=y` behaves as quarantine while you watch. A rollout plan
  written around `pct=25` is following a tag that no longer exists.
- **`np` is new**, and it is the cheapest win available in the record. `sp`
  sets policy for subdomains that exist; `np` sets it for subdomains that do
  not, which is the wide-open path an attacker takes when they invent
  `no-reply.billing.example.com`. Absent `np`, the policy falls back to `sp`
  and then to `p`. Publish `np=reject` unless something genuinely sends from
  names you have not created.

RFC 9989 also replaces the Public Suffix List with a **DNS Tree Walk**, capped
at eight queries, for locating the Organizational Domain. The consequence for a
reviewer is practical: a receiver following RFC 9989 may resolve a different
Organizational Domain than a legacy one, so **publish an explicit DMARC record
at every subdomain you actually send from** rather than relying on inheritance.

```
# Wrong: monitor-only indefinitely, no subdomain policy, and a percentage tag
# that RFC 9989 removed. This record reports; it prevents nothing.
v=DMARC1; p=none; pct=50; rua=mailto:dmarc@example.com
```

```
# Correct: enforced, with existing and non-existent subdomains both covered.
# Drop t=y once the aggregate reports are clean; while it is present, failing
# mail is quarantined rather than rejected.
v=DMARC1; p=reject; sp=reject; np=reject; t=y; rua=mailto:dmarc@example.com
```

`adkim` and `aspf` both default to relaxed (`r`), which accepts alignment
anywhere within the Organizational Domain. Strict (`s`) demands an exact match.
Relaxed is the right default for most projects; choose strict deliberately, and
only once every sender signs with the exact domain.

**Adding a transactional provider is what breaks this**, and it breaks the two
paths differently:

- **SPF allows at most 10 DNS-querying mechanisms**, with a recommended cap of
  two void lookups; RFC 7208 requires a `permerror` result once the first limit
  is exceeded, and DMARC reads `permerror` as an SPF failure. Every provider
  `include:` consumes lookups and some expand into several, so the fourth or
  fifth provider quietly pushes the record over. Nothing announces this —
  it surfaces only in a report. Consolidate, drop `include:` entries for
  providers no longer in use, replace stable ranges with `ip4:`/`ip6:`, or move
  a heavy sender onto its own subdomain with its own record.
- **SPF alignment breaks even while SPF passes.** A provider sets its own
  envelope sender so it can process bounces, so SPF authenticates the
  *provider's* domain and does not align with your `From:`. The fix is a custom
  return path under your own domain, normally a CNAME the provider supplies.
- **DKIM is the durable answer.** Have each provider sign with a key published
  under your domain — the custom-DKIM selector every serious provider offers —
  so `d=` is your domain and DKIM aligns. Because DMARC passes on *either*
  aligned SPF or aligned DKIM, this also survives forwarding, which breaks SPF
  outright. Use 2048-bit RSA: RFC 8301 requires at least 1024 bits, recommends
  2048, and requires verifiers to reject anything below 1024.

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

The Django side is small but worth checking. `DEFAULT_FROM_EMAIL` and
`SERVER_EMAIL` decide the `From:` domain that alignment is evaluated against, so
a project sending as one domain while publishing DMARC for another fails every
check for a reason no amount of DNS inspection will reveal. Error mail sent as
`SERVER_EMAIL` and application mail sent through the provider in `EMAIL_HOST`
frequently take different paths, so confirm both align rather than assuming one
result covers the other.

Review technique: resolve the records rather than reading the deployment
documentation. Query the TXT record at `_dmarc.<domain>` for DMARC, at the
domain itself for SPF, and at `<selector>._domainkey.<domain>` for each DKIM
selector. Count the SPF lookups rather than eyeballing the line, and compare the
sender inventory in the aggregate reports against the systems the team believes
are sending — the gap between those two lists is usually the finding.

CWE-290 (Authentication Bypass by Spoofing), CWE-345 (Insufficient Verification
of Data Authenticity); A02:2025. Severity: high for any public-facing domain,
because the reachable consequence is credential phishing and business email
compromise carried by your own brand.

SPF, DKIM, and DMARC authenticate the message. Transport is a separate gap.
SMTP sends in cleartext when STARTTLS fails, and an attacker on the network can
force that failure. MTA-STS (RFC 8461) closes that gap. Publish a policy at
`https://mta-sts.<domain>/.well-known/mta-sts.txt` with `mode: enforce` and the
domain's MX hosts. Publish a `_mta-sts.<domain>` TXT record whose `id` changes
on every policy change.

TLS-RPT (RFC 8460) adds a `_smtp._tls.<domain>` TXT record with `rua=`, so a
receiver reports each TLS delivery failure to you. Start in `mode: testing`
with TLS-RPT enabled. Then change the mode to `enforce`. For a domain that
sends password-reset mail, rate an absent MTA-STS policy LOW.

Django 6.1 moves the sending configuration into one setting. `MAILERS` maps an
alias to a `BACKEND` and an `OPTIONS` dictionary, in the shape `DATABASES`,
`CACHES`, `STORAGES`, and `TASKS` already use. The `EMAIL_BACKEND`,
`EMAIL_HOST`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_PORT`,
`EMAIL_USE_TLS`, `EMAIL_USE_SSL`, `EMAIL_SSL_CERTFILE`, `EMAIL_SSL_KEYFILE`,
`EMAIL_FILE_PATH`, and `EMAIL_TIMEOUT` settings are deprecated, and Django 7.0
removes them. Review each alias on its own, because `use_tls` and the
credentials are per-alias now. One mailer can hold TLS while a second sends in
cleartext, and neither setting contradicts the other.

Two system checks arrive with it. `mail.E001` runs only under `--deploy` and
rejects a development-only backend in the `default` alias. `mail.W001` reports
a `MAILERS` value that declares no `default` alias, which Django says will make
sending fail. An empty `MAILERS` dictionary disables sending outright and
raises `MailerDoesNotExist`.

## Certificate issuance and dangling DNS

Two further DNS-published controls sit inside the backend's configuration
surface.

**CAA restricts who may issue certificates for your domain.** By default any
publicly trusted CA may issue for any name, so one mis-validating or compromised
CA anywhere in the ecosystem is enough to produce a valid certificate for your
domain. A CAA record names the CAs permitted to issue; public CAs have been
required to honor it since September 2017, and it is specified in RFC 8659. Add
an `iodef` address so a rejected attempt reaches somebody.

```
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 issuewild ";"
example.com. CAA 0 iodef "mailto:security@example.com"
```

`issuewild ";"` forbids wildcard issuance outright, which is the right default
for a project that does not use one. Severity: medium — the record costs
nothing and the failure it prevents is a valid certificate nobody asked for.

**Dangling DNS is subdomain takeover.** A CNAME still pointing at a
deprovisioned third-party resource — an object-storage bucket, a former hosting
app, a documentation or status-page service — can be reclaimed by whoever
re-creates a resource under that name at the provider. They then serve content
from a name your users and your own systems trust, which is worth more than it
first looks: it can receive cookies scoped to the parent domain, satisfy a CSP
or CORS allowlist written as `*.example.com`, and match an OAuth redirect
allowlist.

Detection is a three-step loop worth scheduling rather than doing once:
enumerate the subdomains that exist, resolve each CNAME chain to its target, and
flag any target returning a provider's unclaimed-resource fingerprint instead of
content. Certificate-transparency logs are the most complete enumeration source,
since every issued certificate is published. Confirm by hand before reporting —
a provider error page is not always a claimable name.

Decommissioning order is what teams get backwards, and it is the whole control:
**remove the DNS record first, wait out the TTL, and only then delete the cloud
resource.** Deleting the resource first opens the exact window this section is
about.

No CWE maps cleanly: CWE-16 (Configuration) is the identifier scanners often
attach, but it is a category, which CWE's own mapping guidance prohibits citing
in a finding. CWE-672 (Operation on a Resource After Expiration or Release) is
the closest mappable weakness — the record operates on a resource that was
released — and A02:2025 carries the classification either way. Severity: high
where the subdomain shares cookies, an OAuth redirect allowlist, or a CSP or
CORS entry with the application.

## security.txt

RFC 9116 defines `/.well-known/security.txt`. The file tells a security
reporter where to send a vulnerability report. Serve it over HTTPS with a
`Contact:` field and an `Expires:` field. An expired file is the common
failure, so generate the `Expires:` date automatically. This is disclosure
support, not a control. Rate an absent file INFO.

## check --deploy

`python manage.py check --deploy` runs Django's own production audit
(security.W* warnings for the settings above). Gate it in CI:

```
python manage.py check --deploy --fail-level WARNING
```

A clean run means Django's baseline is satisfied; it does not replace code
review.

What it structurally *cannot* catch is the more useful list, because a clean run
is routinely read as coverage it never provided:

- **It reads settings, and only settings.** The Dockerfile, the proxy
  configuration, and DNS are all invisible to it, so nothing in
  `deployment-and-runtime.md` and nothing in the two sections above is covered
  by a passing run.
- **It cannot tell a safe `SECURE_PROXY_SSL_HEADER` from a spoofable one.** It
  confirms the setting has a value; whether the proxy actually overwrites that
  header is not something a settings check can see, so the dangerous
  configuration passes silently.
- **It does not inspect CSP content.** `SECURE_CSP` is not linted, so
  `'unsafe-inline'` or a wildcard source passes. It does not look at CORS at
  all, so `CORS_ALLOW_ALL_ORIGINS = True` alongside credentials is invisible.
- **It does not know what is installed.** `debug_toolbar` or `silk` in
  `INSTALLED_APPS` raises nothing.
- **`ALLOWED_HOSTS = ["*"]` passes.** The check tests that the list is
  non-empty, not that it is restrictive.
- **It can be silenced.** `SILENCED_SYSTEM_CHECKS` removes a warning
  permanently, and without `--fail-level` the command exits zero regardless.
  Read that list as part of the review; an entry in it is a decision somebody
  made once and nobody has revisited.

One thing about the command itself changed. Django 6.1's `run_checks()`
defaults `databases` to every configured alias when `--database` names none,
where Django 6.0 left it `None`. Checks tagged `database` stay skipped without an explicit alias,
so Django's own deploy checks still read settings alone. A custom or
third-party check that accepts `databases` now receives every alias and can
open a connection. Confirm the pipeline step has a database it may reach, and
that the alias it reaches is not production. Verified against the 6.1 and 6.0
`django/core/checks/registry.py` on 20 Aug 2026.

Treat the check as the floor in CI, then audit what it cannot introspect
separately. The portable form: a configuration linter cannot see infrastructure,
so a clean linter is never evidence of deployment posture.

## Writing a deployment guardrail check

The section above lists what Django's check cannot see. Part of that list is
closable inside the project, because the framework's silence is about
generality rather than difficulty: it cannot know which variable this
deployment requires, which of its own defaults this project treats as
fail-closed, or which bucket is the production one. A custom system check
states one of those, and the deploy gate then enforces it on every pipeline
run. An absent guardrail is rarely a finding by itself — it is rated as the
defense-in-depth gap behind whatever it would have caught.

### Principle layer

A configuration assertion earns its place where three things hold at once:
the property decides whether the deployment is safe, it is knowable from
configuration alone, and no generic linter can know it. Four recur in almost
every project, and none of them is expressible as a framework check.

- **A required variable is absent, or still carries a development default.**
  A deployment that falls back silently is the one nobody notices, because a
  fallback produces a running process rather than an error.
- **A secret matches a known placeholder.** The value from the example
  environment file, the key out of a getting-started guide, `changeme` — a
  real value that is also a public one, which is the case a length or
  entropy test passes straight over.
- **A permission, authentication, or visibility default is not the
  fail-closed one.** The framework has no opinion about which of its
  defaults your project considers safe; only the project knows that the
  permissive one is a defect here.
- **A storage bucket, queue, broker, or callback target names a
  non-production resource while the debug flag is off.** The combination is
  the assertion — either half alone is ordinary.

Two boundaries hold for every assertion of this kind. **It reads
configuration and nothing else**: a check that opens a connection makes the
gate depend on network reachability and on a credential, which turns a
deterministic assertion into an intermittent one and hands the pipeline a
reason to switch it off. And **it reports the property, never the value**:
check output lands in a build log that is retained, searchable, and readable
by more people than the secret store is, so a message quoting the secret it
objects to has published it.

### Django & DRF implementation layer

Verified against the Django 6.0.7 and 5.2.15 source on 14 August 2026; the
check framework is the same in both.

`django.core.checks` exports `register`, the tag constants `Tags`, and the
message classes `Debug`, `Info`, `Warning`, `Error`, and `Critical`. A
message takes its text plus optional `hint`, `obj`, and `id`. A check is a
callable that must accept `**kwargs` — the registry raises `TypeError` at
registration time otherwise — and must return a list.

```python
# myproject/guardrails/checks.py
from django.conf import settings
from django.core.checks import Error, Tags, register

DEV_BUCKETS = {"acme-uploads-dev", "acme-uploads-local"}

# Wrong: no deploy=True, so the deploy gate never runs it; a network call
# inside a configuration assertion; a Django identifier reused as its own;
# and the secret written into the build log.
@register(Tags.security)
def check_upload_bucket(app_configs, **kwargs):
    if not vault.get(settings.UPLOAD_TOKEN):
        return [Error(f"bad token {settings.UPLOAD_TOKEN}",
                      id="security.E001")]
    return []

# Correct: deploy-only, project-prefixed identifier, settings alone, and the
# setting named rather than its value printed.
@register(Tags.security, deploy=True)
def check_upload_bucket_is_production(app_configs, **kwargs):
    if settings.UPLOAD_BUCKET in DEV_BUCKETS:
        return [
            Error(
                "UPLOAD_BUCKET names a development bucket.",
                hint="Set UPLOAD_BUCKET from this environment's config.",
                id="acme.E001",
            )
        ]
    return []
```

A check registers only when its module is imported, so the conventional
wiring is `myapp/checks.py` imported from that app's `AppConfig.ready()`. A
guardrail nobody imports never runs, and it fails in exactly the shape a
passing gate has.

**`deploy=True` decides whether it runs at all.** `register` files the
function in a separate deployment set that `run_checks` includes only when
`include_deployment_checks` is true, which the `check` command sets from
`--deploy`. A pipeline running `manage.py check` without the flag executes
every other check, none of these, and reports success.

**`--fail-level` decides whether a message stops the build**, and its
default is `ERROR`. A check returning `Warning` therefore prints and exits
zero under that default. The flag sets one floor for the whole run rather
than per check, so the level a project can afford is the level of its
noisiest message: a guardrail meant to block a deploy returns `Error` and
fails even at the default, while an advisory message has to sit at `Info` or
below to avoid dictating the floor. Django's own deploy family reports every
*absent* hardening setting as a `security.W*` warning — the three `Error`
messages in that set report an invalid value or an unsafe environment
override instead — which is why the gate this file recommends is
`--fail-level WARNING`.

**Prefix every identifier with the project.** `SILENCED_SYSTEM_CHECKS` is
matched against the message `id`, so an identifier colliding with Django's
is silenced by any entry aimed at Django's, and a silenced message is
dropped from the output *and* from the fail decision: the guardrail
disappears, the build passes, and nothing reports the collision. `acme.E001`
cannot collide; `security.E001` can. Give every message an `id` — one left
at `None` can never be silenced, but can never be cited or looked up either.

`--tag` narrows a run to the checks carrying a tag, and `Tags.security` is a
constant rather than a constraint: any string works, so a project can carry
its own. A tag no registered check declares raises `CommandError`, so a typo
in the pipeline fails loudly rather than passing an empty run.

**Write-time.** When generating a setting whose wrong value is a security
failure rather than an outage — a bucket name, a permission default, the
source of a signing key, a callback host — write the deploy check that
asserts it in the same edit, because the setting gets a reviewer looking at
it exactly once and the check is what looks at it on every deploy after
that.

## Configuration drift and the expiring exception

Two failures with one root: a posture that was true the last time somebody
looked. Drift is the deployment moving away from the reviewed baseline; an
expiring exception is an exemption written into that baseline outliving the
reason it was granted. Both are invisible to a review that reads files,
which is why they belong beside the check that runs on every deploy.

### Principle layer

**Detect drift on effective values, not on files.** A settings module is
code: the value in force is whatever the imports, the environment reads, and
the platform's own injection produce at startup, and a diff of two modules
sees none of the three. The comparison that means something runs inside the
target environment, resolves the settings that process actually loaded, and
holds them against the baseline the review was written against. Anything
weaker compares two descriptions of a deployment rather than the deployment.

**Every suppression is a decision with a half-life.** A normal Python
project has four kinds and they behave identically: a silenced system check,
a scanner's ignore list, a dependency advisory recorded as accepted, and an
inline suppression comment on a line of code. Each was defensible the day it
was written. None of them expires, none names who decided, and the reason is
usually reconstructed years later out of a commit message.

The control has one shape in all four places: an exception carries an
**owner**, a **reason**, and an **expiry date**, and something executable
fails once that date passes. The executable half is what makes it a control.
A register holding the same three fields with nothing enforcing them is a
description of a policy rather than the policy, and a policy that cannot
fail a build is advice.

That is the whole of policy as code, and the vendor-neutral form is the one
worth holding: the required posture is written as an assertion the pipeline
runs, kept in the project's own repository, so changing scanner or platform
re-implements the gate rather than deleting it.

### Django & DRF implementation layer

**Establish which module the process loads before comparing anything.** The
entry points call `os.environ.setdefault("DJANGO_SETTINGS_MODULE", ...)`,
and `setdefault` does not overwrite, so a value the platform supplies wins
and the module named in `manage.py` is the fallback rather than the value in
force. Read the deployment's environment alongside the file. The review-side
form of the same trap — a settings file is not a settings module in force —
is the "Commonly mistaken for a finding" note under "DEBUG and ALLOWED_HOSTS"
above.

`diffsettings` is the instrument for the comparison, and its two useful
properties are easy to miss. It reads the configured settings object rather
than a file, so it reports what the process resolved, environment reads
included; and `--default` takes another settings module to compare against
instead of Django's defaults.

```
python manage.py diffsettings --default config.settings.reviewed \
    --output unified
```

Because it reads the running process, it says nothing about an environment
it is not run in: to learn what production loaded, it has to run there.

**Its output is secret material.** Every upper-case setting is rendered
through `repr()` with no redaction of any kind, so `SECRET_KEY`, database
passwords, and every API key the module holds appear in full — verified
against the Django 6.0.7 and 5.2.15 source on 14 August 2026. Never write it
to a CI artifact, a ticket, or a shared log. Compare it in place and emit
the **names** of the settings that differ.

`settings_scan.py` answers the other half and only the other half: it parses
the settings modules without importing them, so it reads what the files
declare across a whole package and by construction cannot see a value the
environment supplies. Static scan for the declaration, `diffsettings` in the
environment for the effective value.

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

One limit is worth naming rather than discovering: adding `acme.E010` to
`SILENCED_SYSTEM_CHECKS` silences the message that would have reported it,
so the register cannot police its own entry. That line is caught by reading
the diff on `SILENCED_SYSTEM_CHECKS` as a security-relevant settings change,
which is the treatment the rest of this file's settings already get.

In review, read `SILENCED_SYSTEM_CHECKS` as a list of decisions rather than
as configuration. Each entry is a security check somebody turned off, and
the finding is the entry with no owner, no reason, and no date: treat a
silenced security check as a finding until a record explains it. The
dependency side of the same discipline belongs to
`a03-software-supply-chain.md`, "SBOM, scan gate, and provenance", which
owns what a pipeline does with a scanner result.

**Write-time.** When generating a suppression of any kind — a silenced
check, a scanner ignore entry, an inline comment that turns a rule off —
write the owner, the reason, and the expiry date in the same edit, and put
the entry somewhere an assertion can read it rather than in a comment beside
the line, because the comment is what the next reader finds and the
assertion is the only part of it that can still object.

## Review checklist

- [ ] `DEBUG = False` and `ALLOWED_HOSTS` set (not `*`) in production settings.
- [ ] Secrets and per-environment values are read from the environment and
      validated at startup, rather than carrying a default in the settings
      module.
- [ ] HSTS, SSL redirect, nosniff, `X-Frame-Options`, secure session/CSRF cookies set.
- [ ] `SECURE_CROSS_ORIGIN_OPENER_POLICY` is left at `"same-origin"`, or
      relaxed to `"same-origin-allow-popups"` for a documented popup flow,
      rather than to `None` or `"unsafe-none"`.
- [ ] `SECURE_PROXY_SSL_HEADER` matches the actual proxy and isn't client-spoofable.
- [ ] Session and CSRF cookie names carry the `__Host-` prefix with domain
      `None`, path `/`, and `Secure` set to agree with it — or a
      parent-domain cookie was chosen deliberately, with every subdomain
      accepted into the trust boundary that follows.
- [ ] `LANGUAGE_COOKIE_SECURE`, `LANGUAGE_COOKIE_HTTPONLY`, and
      `LANGUAGE_COOKIE_SAMESITE` are set rather than left at their weaker
      defaults.
- [ ] Django is at 5.2.15 or 6.0.6 and later, and
      `SIGNED_COOKIE_LEGACY_SALT_FALLBACK` is `False` wherever two
      `get_signed_cookie()` name-and-salt pairs could concatenate alike —
      read as the effective value rather than the written one, since 5.2 and
      6.0 default it to `True` and 6.1 defaults it to `False`.
- [ ] `CSRF_TRUSTED_ORIGINS` set with scheme; no stray `@csrf_exempt`.
- [ ] CORS uses an allowlist; no `CORS_ALLOW_ALL_ORIGINS = True` with credentials.
- [ ] `GZipMiddleware` is absent from any response that reflects user input
      beside a bearer token, a session identifier, or another secret.
- [ ] DMARC is at `p=quarantine` or `p=reject` rather than parked at `p=none`,
      with `sp` and `np` set and any rollout ramped via `t=y` rather than the
      removed `pct` tag.
- [ ] SPF stays within 10 DNS-querying mechanisms, and every third-party sender
      signs with custom DKIM under your own domain at 2048-bit RSA.
- [ ] An MTA-STS policy is published at `mode: enforce` with a matching
      `_mta-sts` TXT record, and TLS-RPT reports delivery-TLS failures.
- [ ] A restrictive CAA record is published, with an `iodef` contact.
- [ ] Every CNAME resolves to a resource you still own, and decommissioning
      removes the DNS record before the resource.
- [ ] `check --deploy` runs clean (and is enforced in CI), with
      `SILENCED_SYSTEM_CHECKS` reviewed rather than assumed empty.
- [ ] The properties no framework check can know — a required variable, a
      placeholder secret, a fail-closed default, a non-production target —
      are asserted by project checks registered `deploy=True`, identified
      under a project prefix, and returning `Error` where they are meant to
      stop a deploy.
- [ ] Drift is established by comparing the settings the deployed process
      resolved against the reviewed baseline, rather than by diffing two
      settings modules, and the comparison output is treated as secret.
- [ ] Every suppression — a silenced check, a scanner ignore entry, an
      accepted advisory, an inline comment — carries an owner, a reason, and
      an expiry date that something executable enforces.
