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
- [Signed cookies and the legacy salt fallback](#signed-cookies-and-the-legacy-salt-fallback)
- [CSRF settings and trusted origins](#csrf-settings-and-trusted-origins)
- [CORS](#cors)
- [Content Security Policy](#content-security-policy)
- [Mail authentication: SPF, DKIM, and DMARC](#mail-authentication-spf-dkim-and-dmarc)
- [Certificate issuance and dangling DNS](#certificate-issuance-and-dangling-dns)
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

**Write-time.** When generating or extending a settings module, read every
secret and per-environment value from the environment and fail at startup when
one is missing, because a default left in the settings file is the value
production quietly runs on. Add the HTTPS redirect, HSTS, and the two secure
cookie flags in that same edit rather than leaving them for a later hardening
pass: those four are off by default, they are precisely what `check --deploy`
warns about, and a settings module that has already been merged is one nobody
re-opens without a reason to.

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
  still honoured.** It was added in 5.2.15 and defaults to `True`, so a
  patched project goes on accepting cookies signed under the historical
  `key + salt` derivation. Django accepts them until 7.0, where the
  transitional setting is removed. Set it to `False` once cookies signed
  before the upgrade have expired — and immediately, rather than on a
  schedule, in any project whose own calls can collide, because until then
  the ambiguous derivation remains a valid way to present a cookie.

Auditing it is closer to a grep than a review. Collect every
`set_signed_cookie()` and `get_signed_cookie()` call, concatenate each cookie
name with the `salt` it passes, and look for two pairs that produce the same
string: a cookie named `session` salted `_token` and one named `session_`
salted `token` both derive from `session_token`. Where no pair collides, the
setting is hygiene with no behavioural risk. Where one does, it is the fix,
and the pair should be renamed as well.

**Write-time.** When generating a `set_signed_cookie()` or
`get_signed_cookie()` call, pass an explicit `salt` naming the purpose the
cookie serves rather than repeating its name, so the value is domain-separated
on the same principle every other signed artifact in the project follows. On a
new project set `SIGNED_COOKIE_LEGACY_SALT_FALLBACK = False` in the same
settings module you generate: nothing signed under the old derivation is in
circulation, so the default only preserves an acceptance path this project
never needed, and it is far easier to set now than to schedule later.

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

## CORS

Use `django-cors-headers` with an explicit allowlist. The origin below is a
required config value rather than a hyperlink, and carries the same exemption
as the CSRF literal above:

```python
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
# CorsMiddleware must sit high in MIDDLEWARE, above CommonMiddleware.
```

**Package decision (8 Aug 2026):** `django-cors-headers==4.9.0` passes the
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

**Package decision (8 Aug 2026):** prefer Django 6's built-in CSP support.
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

## Certificate issuance and dangling DNS

Two further DNS-published controls sit inside the backend's configuration
surface.

**CAA restricts who may issue certificates for your domain.** By default any
publicly trusted CA may issue for any name, so one mis-validating or compromised
CA anywhere in the ecosystem is enough to produce a valid certificate for your
domain. A CAA record names the CAs permitted to issue; public CAs have been
required to honour it since September 2017, and it is specified in RFC 8659. Add
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

CWE-16 (Configuration) is the clean mapping; A02:2025. Severity: high where the
subdomain shares cookies, an OAuth redirect allowlist, or a CSP or CORS entry
with the application.

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

Treat the check as the floor in CI, then audit what it cannot introspect
separately. The portable form: a configuration linter cannot see infrastructure,
so a clean linter is never evidence of deployment posture.

## Review checklist

- [ ] `DEBUG = False` and `ALLOWED_HOSTS` set (not `*`) in production settings.
- [ ] Secrets and per-environment values are read from the environment and
      validated at startup, rather than carrying a default in the settings
      module.
- [ ] HSTS, SSL redirect, nosniff, `X-Frame-Options`, secure session/CSRF cookies set.
- [ ] `SECURE_PROXY_SSL_HEADER` matches the actual proxy and isn't client-spoofable.
- [ ] Django is at 5.2.15 or 6.0.6 and later, and
      `SIGNED_COOKIE_LEGACY_SALT_FALLBACK` is `False` wherever two
      `get_signed_cookie()` name-and-salt pairs could concatenate alike.
- [ ] `CSRF_TRUSTED_ORIGINS` set with scheme; no stray `@csrf_exempt`.
- [ ] CORS uses an allowlist; no `CORS_ALLOW_ALL_ORIGINS = True` with credentials.
- [ ] DMARC is at `p=quarantine` or `p=reject` rather than parked at `p=none`,
      with `sp` and `np` set and any rollout ramped via `t=y` rather than the
      removed `pct` tag.
- [ ] SPF stays within 10 DNS-querying mechanisms, and every third-party sender
      signs with custom DKIM under your own domain at 2048-bit RSA.
- [ ] A restrictive CAA record is published, with an `iodef` contact.
- [ ] Every CNAME resolves to a resource you still own, and decommissioning
      removes the DNS record before the resource.
- [ ] `check --deploy` runs clean (and is enforced in CI), with
      `SILENCED_SYSTEM_CHECKS` reviewed rather than assumed empty.
