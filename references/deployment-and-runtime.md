# Deployment and Runtime

This file covers the layer the backend owns in production. That layer is TLS
and headers, the reverse proxy and forwarded-header trust, operational endpoint
exposure, and Gunicorn and systemd hardening. It also covers the container
image as a build artifact, static and media serving, the database connection,
and cache and queue exposure. The stack is Nginx, Gunicorn, and systemd,
optionally containerized, and optionally behind Cloudflare.

This file and `a02-security-misconfiguration.md` split the configuration
surface by where the setting lives rather than by topic. This file owns what
the proxy, the process, and the image **do** with a request once it arrives.
That scope is TLS termination, and which layer owns each header. It covers
forwarded-header trust and the client IP that every rate limit and audit record
depends on. It also covers operational endpoints left reachable in production,
and the Gunicorn or systemd unit that runs the code. A02 owns what a settings
module or a DNS zone declares.

On the container this file stops at the artifact the repository produces: the
base image, `USER`, `.dockerignore`, and secrets baked into layers. It names
orchestrator enforcement as a cross-team recommendation rather than a
repository finding. `service-identity-and-secrets.md` owns where a secret comes
from at run time.

## Contents
- [Principle](#principle)
- [TLS and HSTS](#tls-and-hsts)
- [Reverse proxy and forwarded headers](#reverse-proxy-and-forwarded-headers)
- [Security headers at the edge](#security-headers-at-the-edge)
- [Operational and development endpoints](#operational-and-development-endpoints)
- [Gunicorn hardening](#gunicorn-hardening)
- [systemd hardening](#systemd-hardening)
- [Container images](#container-images)
- [Static and media](#static-and-media)
- [Database and secrets](#database-and-secrets)
- [Caching security](#caching-security)
- [Queue and broker exposure](#queue-and-broker-exposure)
- [Review checklist](#review-checklist)

## Principle

The app can be perfect, and how it runs can still expose it. The exposures are
plaintext transport, and a proxy that lets clients forge their apparent IP or
scheme. They are also a worker that runs as root, and user uploads that the
server delivers as executable code. The principle is **least privilege and
least exposure at runtime**. Encrypt transport, trust only what the proxy
actually sets, drop privileges, and serve untrusted content inertly.

## TLS and HSTS

- Terminate TLS with modern protocols and ciphers, and redirect HTTP→HTTPS. If
  Cloudflare or the proxy already redirects, set `SECURE_SSL_REDIRECT = False`
  in Django. That setting prevents a redirect loop.
- Set HSTS (see A02). Deploy it with a short max-age first, because it is hard
  to undo.

### Hybrid post-quantum key exchange

Hybrid key exchange is the one post-quantum change that is already deployed
rather than pending. It answers the harvest-now-decrypt-later exposure that
`a04-cryptographic-failures.md`, "Post-quantum posture", tells you to
inventory. It runs X25519 and ML-KEM-768 together, and derives the session key
from both. A recorded handshake therefore stays secret unless *both* halves
fall. An adoption of it costs nothing in confidence, and it is not a bet on the
newer primitive.

The state of it as of 8 Aug 2026:

- **OpenSSL 3.5.0, April 2025, is the line that turns it on**, and it turned it
  on by default in the same release that added it. The default supported-groups
  list changed to include and prefer hybrid PQC KEM groups. The default
  keyshares offered became `X25519MLKEM768` and `X25519`. An edge linked
  against 3.5 or later negotiates the hybrid with no configuration at all.
- **The client side is already there.** Chrome 131 and Firefox 132 each enabled
  ML-KEM hybrid key exchange by default. A current browser that reaches a
  current OpenSSL therefore negotiates `X25519MLKEM768` today, whether or not
  anyone decided that it should.
- **The group name is settled; the specification is not finished.** The TLS
  hybrid document is an IESG-approved Internet-Draft in the RFC Editor queue,
  not yet an RFC. Its IANA codepoint is permanent: 4588 for `X25519MLKEM768`,
  now marked Recommended. The pre-standard `X25519Kyber768Draft00` at 25497 is
  obsolete. A config that still pins the Kyber draft group is therefore stale,
  and a report that calls the hybrid a finished standard overclaims.

Nginx expresses the group list through `ssl_ecdh_curve`. Despite the name, that
directive sets every key-exchange group the server offers, not only ECDH
curves. It has accepted a colon-separated list since 1.11.0, and it defaults to
`auto`, which means OpenSSL's own built-in list:

```nginx
# `auto` on OpenSSL 3.5 already prefers the hybrid, so pin the order only when
# you need to. Whatever you write, the hybrid group has to be in it.
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;
```

Two placement rules travel with that line. Set it in the `http` context or on
the `default_server`. Nginx ticket #2542 records that under TLS 1.3 the
directive is silently ignored in a non-default `server` block that shares an
address and port. A value written into one virtual host therefore does nothing,
and reports nothing. Write a single colon-separated list. Nginx rejects
OpenSSL's space-separated multi-tier prioritization syntax as an invalid
argument count.

**The finding is a group list that excludes the hybrid, not its absence.** A
modern edge already negotiates it, so this is rarely a change anyone has to
make. It is a change someone made years ago and never revisited. A hardening
snippet copied from a pre-2025 guide pins
`ssl_ecdh_curve X25519:prime256v1:secp384r1;`. On an OpenSSL that would
otherwise have offered ML-KEM, that line turns the default off. The config then
looks more secure than the default it replaced, and is less secure.

Confirm what the deployed host actually negotiates, rather than read the file.
The effective list depends on which OpenSSL the edge links against, and, per
the ticket above, on which server block holds the value.

**Write-time.** When you generate an nginx TLS block, leave `ssl_ecdh_curve`
out entirely and let `auto` stand, or write a list with `X25519MLKEM768` first.
Never write a curve list carried over from an older hardening template. On
OpenSSL 3.5 that line is a downgrade, and the config reads as an improvement.
Put it in the `http` context in the same edit, so that the virtual-host rule
above does not silently drop the value.

CWE-327 (broken or risky cryptographic algorithm) is the mapping when a pinned
list excludes what the platform would have offered. Severity: low today, and
rising with the retention period of whatever the connection carries.

## Reverse proxy and forwarded headers

This is the subtle one. Behind Nginx/Cloudflare:

- Set `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")` **only** if
  the proxy sets that header unconditionally and strips any client-supplied copy.
  Otherwise a client can claim HTTPS.
- Trust `X-Forwarded-For` and `X-Forwarded-Proto` **only** from your proxy. The
  client IP that lockout and rate limiting use must come from a trusted hop, or
  attackers spoof it. This applies to `django-axes` and to allauth, which now
  distrusts `X-Forwarded-For` by default. Configure the proxy count or the
  trusted header explicitly.
- Nginx: `underscores_in_headers off;` (default). The Django 6.0.4
  underscore-header spoofing CVE is a reminder not to enable it. Validate
  `Host`, and consider a default server that returns 444 for unknown hosts, as
  a complement to `ALLOWED_HOSTS`.
- A header that carries a *verified client certificate* obeys the same rule at
  a higher penalty. That header is `X-Forwarded-Client-Cert`, or RFC 9440's
  `Client-Cert`. A spoof of it is an authentication bypass, not a client-IP
  trust problem. The proxy must strip or overwrite any inbound copy, and the
  application must not be reachable except through it.
  `service-identity-and-secrets.md`, "Client-certificate identity behind a
  proxy" owns the application side.
- `USE_X_FORWARDED_HOST = True` moves host trust to the proxy. It is safe only
  when the proxy sets `X-Forwarded-Host` on every request and strips the
  client's copy. Every absolute URL Django builds from `get_host()` trusts that
  value. Without `django.contrib.sites`, a password-reset link is one of them.
  `ALLOWED_HOSTS` still validates the forwarded host. The trust rule is the
  same as `SECURE_PROXY_SSL_HEADER` above.
- A CDN in front of the origin adds a hop, and it does not hide the origin. An
  attacker finds the origin address in a certificate-transparency log, in an
  old DNS record, or on a subdomain that points straight at it. A request sent
  to the origin then carries whatever forwarded headers the caller wrote, and
  it skips every rule the CDN applies. Restrict the origin to the CDN's
  published address ranges, and count the CDN as one of the hops below. Where
  the CDN sets its own single-value client-IP header, that header is
  trustworthy only after the origin refuses every other source.

Example Nginx snippet:

```nginx
server_tokens off;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Real-IP $remote_addr;
# An empty value removes the header, so this line deletes an inbound copy.
proxy_set_header Forwarded "";
proxy_set_header Client-Cert "";
# Empty while the client presents no certificate, so one line serves both a
# deployment with mutual TLS and a deployment that must never accept the value.
proxy_set_header X-Forwarded-Client-Cert $ssl_client_escaped_cert;
client_max_body_size 10m;   # cap uploads at the edge
```

Every line after `Host` overwrites an inbound copy the client can send. The
rules above demand each one, and a snippet that sets only `Host`,
`X-Forwarded-Proto`, and `X-Forwarded-For` passes the rest through untouched.
`X-Forwarded-Host` reaches `get_host()` under `USE_X_FORWARDED_HOST`, and a
poisoned password-reset link follows. A forged client certificate is an
authentication bypass. The client IP still comes from the hop count below,
never from `X-Real-IP`.

**Warning: one `proxy_set_header` inside a `location` block removes every
inherited one.** Nginx does not merge these directives across levels. It uses
the set declared at the innermost level that declares any. A `location` that
adds one unrelated header therefore forwards the client's own
`X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` unchanged. Nginx
reports no error, and the response looks correct. `add_header` obeys the same
rule, so a `location` that adds one header drops every inherited security
header.

Put the `proxy_set_header` lines above in one file, and include that file in
every `location` that declares a `proxy_set_header` or an `add_header` of its
own. The audit signal is a `proxy_set_header` or an `add_header` inside a
`location`. For each one, confirm that the same block restores the full set.

### Reading the client IP

`X-Forwarded-For` is `client, proxy1, proxy2`, read left to right. Each hop
appends the address it received the connection from. The snippet above uses
`$proxy_add_x_forwarded_for`, which **appends** to whatever the caller sent
rather than replaces it. The left of that list is therefore attacker-supplied,
in exactly the way a request body is. Only the entries your own infrastructure
appended are trustworthy, and those are on the right.

The rule: **count the proxies you actually operate and take the address that
many hops in from the right.** Never the leftmost entry, and never the raw
header.

```python
# Wrong: the leftmost entry is whatever the caller put in the header, so a
# request carrying "X-Forwarded-For: 198.51.100.9" is throttled, locked out,
# and audited as that address. Every IP-keyed control becomes opt-out. Any
# read of the first comma-separated value is this bug, however it is spelled.
leftmost, _, _ = request.META["HTTP_X_FORWARDED_FOR"].partition(",")
client_ip = leftmost.strip()
```

```python
# Correct: with one proxy in front of Django the trustworthy entry is the last
# one, because that is the address the proxy itself observed. The hop count is
# deployment configuration rather than a default -- it changes the moment a CDN
# or a second load balancer is put in front, and a stale value silently
# reintroduces the bug above. A count alone cannot detect that, so the
# addresses are checked as well.
from ipaddress import ip_address, ip_network

from django.conf import settings
from django.core.exceptions import SuspiciousOperation

TRUSTED_PROXY_HOPS = 1
# The networks your own proxies answer from, including the CDN egress ranges
# where a CDN fronts the origin. Deployment configuration, exactly like the hop
# count above, and an empty list is not a safe default.
TRUSTED_PROXY_NETWORKS = [
    ip_network(cidr) for cidr in settings.TRUSTED_PROXY_CIDRS
]


def is_own_proxy(value):
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in TRUSTED_PROXY_NETWORKS)


def client_ip(request):
    if not TRUSTED_PROXY_HOPS:
        # Nothing trustworthy in front: the header is pure client input, so the
        # peer address is the only honest answer. A zero hop count also cannot
        # be handled by the indexing below, because negating zero still selects
        # the leftmost and attacker-supplied entry.
        return request.META["REMOTE_ADDR"]
    peer = request.META.get("REMOTE_ADDR", "")
    if peer and not is_own_proxy(peer):
        # The connection did not arrive from a proxy you operate, so no
        # forwarded header on it is evidence of anything. A unix socket reports
        # no peer address at all; there the socket permissions carry this
        # guarantee instead, and "Gunicorn hardening" states them.
        raise SuspiciousOperation("forwarded header from an untrusted peer")
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    hops = [value.strip() for value in forwarded.split(",") if value.strip()]
    if len(hops) < TRUSTED_PROXY_HOPS:
        # Fewer entries than the topology guarantees means the request did not
        # traverse the expected chain. Fail closed rather than fall back to a
        # value the caller controls.
        raise SuspiciousOperation("unexpected forwarded-header depth")
    # Your own chain appended everything to the right of the answer. A hop
    # count larger than the real chain selects an entry the caller wrote, and
    # the depth check above still passes, because the caller pads the header to
    # any length. This check is the one that sees it.
    selected, *appended_by_your_chain = hops[-TRUSTED_PROXY_HOPS:]
    if not all(is_own_proxy(hop) for hop in appended_by_your_chain):
        raise SuspiciousOperation("forwarded-header chain is not yours")
    return selected
```

The depth check alone is one-directional. Too few entries fail loudly, and too
many fail silently to an address the caller chose. Only the address check
closes the second direction, and it also refuses a request that reached the
application without the proxy.

Warning: this function fails closed, so keep it off a path an internal probe
reaches. A liveness or readiness probe sent straight to the application port
carries no forwarded header, and its peer is not a proxy. Both checks reject
it. Route the probe through the proxy, or exempt the probe path. Otherwise the
probe fails and the platform restarts a healthy process.

A wrong client IP is not one finding. It voids rate limiting, login lockout, IP
allowlists, and the attribution in every audit record at once. Each of those
failures looks exactly like the control at work. DRF's throttle classes have
their own setting for this; see `api-drf-specific.md`, "Throttling as quota,
not security (API4)". Do not use a client-IP package. The logic is the code
above, and the maintained-package gate rejects the usual candidate in
`security-hardening-libraries.md`.

A related trap is a duplicated `proxy_set_header X-Forwarded-Proto`, typically
an ingress-controller default with a hand-written snippet. It yields
`http,https` rather than a loud failure. Set each forwarded header exactly
once.

CWE-348 (Use of Less Trusted Source), CWE-290 (Authentication Bypass by
Spoofing), CWE-807 (Reliance on Untrusted Inputs in a Security Decision).
Severity: high.

### Request smuggling and the parser chain

Request smuggling is not a defect in application code, and no Django line
causes or prevents it. It exists when two components in front of the same
request disagree about where that request ends. An edge proxy can honor
`Content-Length` where the origin honors `Transfer-Encoding`. Either one can
accept a malformed framing header that the other rejects. Bytes the first
treats as the tail of one request the second treats as the head of the next.

The consequence lands on the application anyway. A smuggled prefix is
attributed to the owner of the connection it was appended to. That forges
authentication, and poisons any cache in the path.

Treat it the way this file treats orchestrator enforcement: **record it as a
recommendation to whoever operates the proxy chain, not as a repository
finding.** From the tree, a review can say which components are in the chain
and what versions they are pinned to. The question addressed outward is whether
every hop parses framing identically. It also asks whether each hop rejects a
request that carries both framing headers, rather than chooses between them. A
repository that holds no proxy configuration cannot answer that. An assertion
either way is the phase 0 error in `01-audit-workflow.md`, "Phase 0 — scope,
mode, and what the repository cannot tell you". `01-audit-workflow.md`,
"Mapping to the OWASP Testing Guide" declares the corresponding WSTG test a
non-goal on the same reasoning.

One half of it does resolve to a repository finding, and most reviews skip that
half because the exposure above is not one. That half is the pinned version of
the application server and of its worker dependencies, which sit in the
requirements file the tree does hold. Gunicorn validated `Transfer-Encoding`
loosely enough to permit TE.CL smuggling twice over. CVE-2024-1135 was fixed in
**22.0.0**. CVE-2024-6827 was disclosed in January 2025 against 22.0.0 itself,
and fixed in **23.0.0**. So 22.0.0 closes the first advisory and remains
vulnerable to the second, and a floor that quotes both CVEs has to sit at
23.0.0.

The two bodies that scored the first agree rather than diverge, which is worth
a statement because divergence is the usual case. The GitHub Advisory Database
rates CVE-2024-1135 7.5 HIGH on `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`,
and IBM X-Force publishes the identical vector and score. Treat 23.0.0 as the
floor and the 2026 line as the target. That line refuses a request that carries
both `Transfer-Encoding` and `Content-Length` rather than chooses between them.
It rejects empty transfer codings, and it tightened chunk-extension parsing to
reject a bare CR per RFC 9112, alongside its keepalive and PROXY-protocol
handling.

The async workers carry their own floors, and a dependency review misses those.
A worker arrives through a `-k` flag on the command line, rather than as a
package anybody chose for its security properties. The floors are
`eventlet>=0.40.3` for CVE-2025-58068, `gevent>=23.9.0` for CVE-2023-41419, and
`tornado>=6.5.0` for CVE-2025-47287. Read the worker class the deployment
actually names, and check the floor that belongs to that one rather than all
three.

For uvicorn and Daphne this file records **no advisory found**. That is not the
same claim as none existing. The search behind that phrase was not exhaustive.
A report of an absence as a clean result is the error
`a02-security-misconfiguration.md`, "check --deploy" describes in its own
domain. Report the pinned version, and say what the search covered and what it
did not.

CWE-444 (Inconsistent Interpretation of HTTP Requests). Severity: not rated as
a repository finding. Where whoever operates the chain confirms it vulnerable,
the impact is authentication bypass and cache poisoning together. The version
floors above are ordinary A03 findings, and they are rated there.

**Write-time.** When you generate or edit a proxy configuration this repository
actually holds, keep the chain to one edge parser in front of the application
server. Do not introduce a third component that re-parses the request body. Two
parsers that disagree create the vulnerability, and not one parser that is
wrong on its own. A desync reaches a second client only where the proxy reuses
one upstream connection for both. Nginx opens a new upstream connection for
each request until an `upstream` block declares `keepalive`. Where you add that
directive, add `proxy_set_header Connection "";` in the same edit. In the same
edit, pin the application server at or above its floor: `gunicorn>=23.0.0`, and
the floor for whichever async worker the command line selects. One file
selects the worker for throughput, and nobody revisits the requirements file
where its version is actually decided.

## Security headers at the edge

Set HSTS, `X-Frame-Options` or frame-ancestors,
`X-Content-Type-Options: nosniff`, `Referrer-Policy`, and CSP. Set them either
in Django (A02; CSP built-in on 6.0+) or at Nginx. Define them in one place, to
prevent conflicting or duplicated headers. Hide version banners with
`server_tokens off`, and do not advertise Gunicorn's.

Ownership is the part that goes wrong. Split it by what each layer can actually
compute:

- **Django owns anything that varies per request or per view.** A nonce-based
  CSP is the clear case. The nonce has to be minted for the response that
  carries it, and a proxy cannot mint one. A CSP with `CSP.NONCE` must
  therefore come from Django, where `a02-security-misconfiguration.md` owns the
  setting that declares it. Cookie flags, `X-Frame-Options` where it differs by
  view, and `Referrer-Policy` belong here for the same reason.
- **The edge owns what is uniform across the site and what has to happen before
  Django sees the request.** The important one is to strip and re-set inbound
  `X-Forwarded-*`. It is the precondition for everything in the previous
  section, and Django cannot do it. By the time Django runs, a forged header is
  indistinguishable from a real one.
- **HSTS belongs wherever TLS terminates** — one place, not both.

A header set in two places is a real failure, not untidiness. For CSP, the
browser takes the *intersection* of the two policies. For a duplicated
`X-Frame-Options`, it may ignore both. Pick one owner per header, and assert
the response headers in a test, so that the test catches a second owner when
someone adds one.

Two nginx rules decide whether an edge-owned header arrives at all. The
inheritance rule under "Reverse proxy and forwarded headers" is the first, and
it governs `add_header` exactly as it governs `proxy_set_header`. The second is
the `always` keyword. Write it on every `add_header` that carries a security
header. Without it nginx adds the header to a 2xx or a 3xx response only, and
an attacker picks when to receive a 4xx.

The split of ownership has a matching gap. Django sets a header on a response
Django generated. A `/static/` or a `/media/` path that nginx serves never
reaches Django, so it carries no Django-set header at all. Public user content
sits on those paths. Give every serving location the edge header set, and
assert the headers on a static path and on a 404 as well as on a 200.

CWE-693 (Protection Mechanism Failure). Severity: medium.

## Operational and development endpoints

Anything that renders internal state is an exposure surface, unless it is
authenticated or genuinely unreachable from outside. Such a surface is a
profiler, metrics, or a health check that echoes versions and dependency
status. The admin is one, and above all so is development tooling that was
never meant to leave a laptop.

The severe cases are development tools reachable in production. The Django
Debug Toolbar renders SQL, settings, and request internals. CVE-2021-30459 —
CVSS 9.8, fixed in 1.11.1, 2.2.1, and 3.2.1 — allowed an attacker to execute
SQL through the SQL panel's own form. An exposed toolbar therefore sits closer
to remote code execution than to information disclosure. `django-silk`
publishes a request and SQL profiling UI. `runserver_plus`, from
`django-extensions`, carries the Werkzeug interactive debugger, which is
arbitrary code execution by design.

The durable rule is not "patch the toolbar". It is that development tooling must
not be *importable* in production:

```python
# Wrong: installed unconditionally. A DEBUG=False deployment still ships the
# code, still routes the panel if the URLconf includes it, and is one settings
# mistake away from serving a SQL console.
INSTALLED_APPS = [..., "debug_toolbar", "silk"]
```

```python
# Correct: development tooling is added only under DEBUG and, better, is absent
# from the production requirements file -- so an accidental DEBUG=True in
# production raises ImportError instead of publishing the panel.
if DEBUG:
    INSTALLED_APPS += ["debug_toolbar", "silk"]
    MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")
```

Review technique, from outside and from the repository:

- Request the well-known paths against the deployed host, and record what
  answers rather than what should. Those paths are `/admin/`, `/__debug__/`,
  `/silk/`, `/flower/`, `/metrics`, `/health`, `/api/schema`, `/swagger/`,
  `/redoc/`, `/.env`, and `/.git/config`.
- Trigger a deliberate 500 and confirm no traceback renders.
- Grep `INSTALLED_APPS`, `MIDDLEWARE`, and the URLconf for `debug_toolbar`,
  `silk`, and `django_extensions`. Confirm that `DEBUG` guards each one, and
  that each is missing from the production dependency set.
- Read what a health endpoint actually returns. One that reports dependency
  versions and database reachability is a reconnaissance aid. Keep the detailed
  variant authenticated, and leave a bare liveness endpoint public.

Metrics deserve their own line. `django-prometheus` and its equivalents publish
per-endpoint request counts and latencies, which disclose the URL inventory and
the traffic shape. The endpoint is a Django view on the same listener that
serves the site, so no bind address separates it, and advice to move it to an
internal interface is not a change anyone can make in the application. Two
mechanisms do exist. Require authentication on the view, or deny the path at
the edge for every source outside the monitoring network. An unguessable path
is not a control. `api-drf-specific.md`, "Schema and browsable-API exposure"
owns schema and browsable-API exposure, and A02 owns the `DEBUG` error page
itself.

CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-489
(Active Debug Code), and CWE-287 (Improper Authentication) for an operational
endpoint that requires none. Severity: critical for a reachable Werkzeug
console or Debug Toolbar, medium for metrics and health disclosure.

## Gunicorn hardening

- Run as a dedicated non-root user. Bind to a local socket or loopback, not to
  a public interface. Let Nginx face the internet.
- Warning: a local socket is not private by default. Gunicorn creates the
  socket under the mask that `--umask` sets, and that option defaults to `0`.
  The socket mode is then `srwxrwxrwx`, and every local account can connect to
  it. Such a caller reaches the application without the proxy, so it supplies
  its own forwarded headers and meets no edge limit. Set `--umask 007`. Own the
  socket directory with the application's group, and put the proxy's user in
  that group. The same reasoning applies to a sidecar or a second container
  that shares the network namespace.
- Set a sensible `--timeout`, worker count, and
  `--max-requests`/`--max-requests-jitter` to recycle workers. Do not run
  Gunicorn with `--reload` or Django's `runserver` in production.
- `forwarded_allow_ips` decides whether Gunicorn honors `X-Forwarded-*` at all,
  and it defaults to `127.0.0.1,::1`. In a container the proxy is a different
  host, so that default ignores the headers. The fix copied from most
  deployment guides is `--forwarded-allow-ips="*"`, which accepts the forwarded
  headers of *any* client that can open a connection. Gunicorn's own
  documentation is explicit that the front-end proxy must ensure these headers
  cannot be passed directly from the client. Name the proxy's address. Use `*`
  only where the port is unreachable except through the proxy, as a network
  guarantee rather than an assumption.
- `secure_scheme_headers` by default treats `X-Forwarded-Proto: https`,
  `X-Forwarded-Protocol: ssl`, and `X-Forwarded-Ssl: on` as proof of TLS, and
  it sets `wsgi.url_scheme` before Django runs. A permissive
  `forwarded_allow_ips` therefore makes `request.is_secure()`
  client-controlled, whatever `SECURE_PROXY_SSL_HEADER` says. That setting is
  not the only thing that decides the answer.
- `--proxy-protocol` makes Gunicorn read a PROXY header and set `REMOTE_ADDR`
  from it. `--proxy-allow-from` decides which peer may send that header, and it
  defaults to `127.0.0.1,::1`. A permissive value lets any caller name the
  address that every IP-keyed control then reports. The client-IP code above
  never inspects that layer, so neither the hop count nor the depth check sees
  it. Enable the option only where the load balancer requires it, and name the
  load balancer's address in `--proxy-allow-from`.
- The ASGI servers carry the same switch under other names, and a project that
  moves to Channels or to uvicorn keeps the habit it learned on Gunicorn.
  uvicorn honors the forwarded headers under `--proxy-headers`, and
  `--forwarded-allow-ips` names the peers it trusts. The value `*` makes
  uvicorn take the **leftmost** `X-Forwarded-For` entry, which is the caller's
  own value rather than an observed one. Daphne has `--proxy-headers` and no
  allow-list at all. It always takes the leftmost entry, and it trusts any peer
  that connects. On Daphne the network guarantee is therefore the only control,
  and the socket or the port must be unreachable except through the proxy.
- The request-size limits are an edge control the application cannot apply for
  itself. `--limit-request-line` (default 4094), `--limit-request-fields`
  (default 100), and `--limit-request-field-size` (default 8190) bound the
  request line and headers before any Django code runs.

This file owns the finding on whether a setting or a runtime posture is unsafe.
Deploy sequencing, process supervision, and rollback behavior are outside its
scope.

## systemd hardening

Restrict the service unit:

```ini
[Service]
User=appuser
Group=appuser
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/app/run /var/app/media
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
```

Grant write access only to the paths the app genuinely needs.

Warning: `Environment=` and `EnvironmentFile=` do not protect a secret. systemd
publishes a unit's environment to unprivileged clients over D-Bus, and its own
documentation states that environment variables do not suit secrets. Any local
account therefore reads the database password with `systemctl show`. Deliver a
secret with `LoadCredential=` or `LoadCredentialEncrypted=` instead. Those
directives expose the value to the service alone.

## Container images

### Principle layer

An image is a build artifact with a security posture of its own. The split of
responsibility keeps the findings actionable: **the backend owns everything
reproducible from the repository; the platform owns everything enforced by the
orchestrator.** A missing `USER` line is a defect in a file the reader can
edit. A missing `runAsNonRoot` is a recommendation to another team. Audit the
first, and record the second as a cross-team note. Without that split, the
review fills with findings nobody who reads it can fix.

Backend-owned, and all of it visible in the Dockerfile:

- A pinned, minimal, currently maintained base image — a digest or a specific
  slim or distroless tag, never a floating `latest`.
- A non-root `USER`. The default is root, so without that line the application
  runs as root inside the container. That turns a container-escape weakness in
  the runtime below into a host-root problem rather than an unprivileged one.
- A multi-stage build, so compilers, package caches, and any build-time
  credential stay out of the shipped stage.
- A `.dockerignore` that excludes `.env`, `.git`, `*.pem`, `*.key`, local
  settings, and fixtures, with `COPY` scoped rather than `COPY . .`.
- The *ability* to run on a read-only root filesystem: the process writes only
  to `/tmp` or an explicitly mounted volume. This is the backend's half of a
  control the platform switches on.

Name these platform-owned items once, rather than audit them: `runAsNonRoot`,
`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, dropped
capabilities, seccomp profiles, resource limits, and egress policy. A non-root
`USER` is necessary but not sufficient, because the platform is what enforces
it.

CWE-250 (Execution with Unnecessary Privileges). Severity: medium on its own,
high in combination with a runtime escape. runc's CVE-2024-21626 is the
reference case. It is a working-directory and leaked-descriptor breakout, fixed
in runc 1.1.12. Against it, a non-root container with capabilities dropped is
the difference between an escape and a contained one.

### Django & DRF implementation layer

```dockerfile
# Wrong: runs as root, ships the build toolchain and the pip cache, floats on a
# tag that changes underneath you, and sweeps the working tree -- including any
# .env and the .git directory -- into the image.
FROM python:latest
COPY . /app
RUN pip install -r /app/requirements.txt
CMD ["gunicorn", "app.wsgi"]
```

```dockerfile
# Correct: build tooling stays in the first stage, the runtime stage runs as a
# numeric non-root UID, and nothing outside /tmp is written at run time, so the
# platform can add a read-only root filesystem without breaking the app.
FROM python:3.13-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
RUN useradd --system --uid 10001 appuser
COPY --from=build /install /usr/local
WORKDIR /app
# Named paths only. `COPY . /app` sweeps whatever the build context holds, and
# `.dockerignore` stops only the entries somebody remembered to list.
COPY --chown=appuser:appuser manage.py ./
COPY --chown=appuser:appuser app/ ./app/
USER 10001
ENV PYTHONDONTWRITEBYTECODE=1
# `0.0.0.0` binds inside the container's network namespace, and that is the
# boundary. A published port removes it, and the application then answers
# without the proxy. Publish the proxy's port, never this one.
CMD ["gunicorn", "app.wsgi", "--bind", "0.0.0.0:8000"]
```

The numeric `USER` is deliberate. `runAsNonRoot` compares a UID, and it cannot
determine whether a user *name* resolves to zero. `collectstatic` output and
any writable cache directory belong in a build stage or a mounted volume. They
do not belong in a path the running process has to create for itself.

**Write-time.** When you generate a Dockerfile, write the pinned base image,
the multi-stage split, the numeric non-root `USER`, and a `.dockerignore` with
a scoped `COPY`. Write them as the first version of the file, not as a later
hardening pass. A layer is immutable and additive. An image that once carried
`.env`, `.git`, or a build credential still carries it after the line that
copied it is gone. In that same edit, keep the running process writing only to
`/tmp` or a mounted volume. The platform can then switch on a read-only root
filesystem, and nobody has to rewrite the application for it.

### Secrets in image layers

Layers are immutable and additive. A file written in one layer stays in that
layer's archive, even when a later layer deletes it. `RUN rm` removes it from
the merged filesystem the container sees, not from the image. `docker history`,
`docker save`, and anyone who can pull the image still reach it. Build
arguments are worse still, because the image metadata records `ARG` values
outright.

Four ways a secret arrives:

- `ENV` or `ARG` carrying a token, recorded in the metadata.
- `COPY . .` sweeping in a `.env`, a `.git` directory, or a local settings file
  because `.dockerignore` did not exclude it.
- `COPY` of a key followed by `RUN rm` of that key, which removes nothing.
- A credential fetched and written during a `RUN` step with no secret mount.

```dockerfile
# Wrong: the token is recorded in the build metadata, and deleting the key in a
# later layer leaves it fully readable in the layer that added it.
ARG PIP_INDEX_TOKEN
COPY deploy_key.pem /root/.ssh/id_rsa
RUN pip install -r requirements.txt && rm /root/.ssh/id_rsa
```

```dockerfile
# Correct: a BuildKit secret mount exposes the value to one RUN step and writes
# it into no layer at all.
RUN --mount=type=secret,id=pip_token \
    PIP_INDEX_URL="$(cat /run/secrets/pip_token)" \
    pip install --no-cache-dir -r requirements.txt
```

The audit technique matters as much as the rule. **A scan of the running
container passes while the secret sits in a lower layer in the registry.** Scan
the image and its layers, not a container started from it:

```bash
docker history --no-trunc IMAGE
docker image inspect IMAGE --format '{{range .Config.Env}}{{println .}}{{end}}'
docker save IMAGE -o image.tar   # then scan each layer archive inside
```

`service-identity-and-secrets.md`, "Where secrets live and how they reach the
process" owns where secrets come from at run time. It also owns why an
environment variable is the floor rather than the target. This section covers
only the image as a leak vector. Treat a secret found in a published layer as
disclosed. Rotate first, then fix the build. CWE-522 (Insufficiently Protected
Credentials), CWE-540 (Inclusion of Sensitive Information in Source Code), and
A03:2025 where the value is a registry or build credential. Severity: high to
critical by blast radius.

### Scanning the built image

A scan of the image answers a question the Dockerfile cannot. It reports what
is actually present in the layers that shipped, not what the build was
instructed to assemble. Trivy (v0.73.0, 3 Aug 2026) scans OS packages and
language dependencies for known advisories, and it also covers IaC
misconfiguration, secrets, and licenses. Grype (v0.116.1, 28 July 2026) matches
OS and language packages against its own vulnerability database, and it reads
an SBOM in place of the image. Syft (v1.50.0, 28 July 2026) generates the SBOM
those tools consume, in CycloneDX, SPDX, or its own format.

All three are Apache-2.0, and all three ship as single Go binaries rather than
as Python packages. This file therefore documents them as CI patterns, and they
hold no row in `security-hardening-libraries.md`. That index gates
pip-installable dependencies, and a binary a workflow invokes is not one.

Four questions belong to the pipeline rather than to the image. They are where
those scanners run, what their exit codes gate, which file the SBOM comes from,
and what provenance the build carries. `a03-software-supply-chain.md`, "SBOM,
scan gate, and provenance" owns them. It also gives the reason to pin a
scanner's own action to a commit SHA rather than to a tag. This file stops at
the artifact. That is what the image contains, who it runs as, and what a layer
still holds after a later layer deleted it.

## Static and media

- Keep user uploads outside application and static roots, or in object storage,
  with no execute behavior and no write path into deployed code. Public user
  content should use an isolated origin. Private media must not have a
  permanent, directly browsable URL. `file-uploads.md` owns full validation,
  SVG, image and archive handling, generated names, and download authorization.
  A CDN in front of private objects must either not cache them, or include the
  signing parameters in its cache key. The same file carries that rule and the
  internal-redirect pattern that pairs with it.
- Serve static assets from the proxy or from WhiteNoise, never through Django
  in production. When Nginx serves them, end both the `location` prefix and the
  `alias` value with `/`: `location /static/ { alias /srv/app/static/; }`. A
  prefix with no trailing slash (`location /static`) also matches `/static../`.
  Nginx joins the remainder onto the `alias` path, so
  `GET /static../config/settings.py` reads one directory above the static root.
  `root` inside a prefix `location` does not have this trap. Prefer `root`
  where the URL prefix mirrors the directory name.
- Put a hard request-body limit at Nginx (`client_max_body_size`) or the
  gateway, so an oversized upload stops before Django buffers it. Then apply
  endpoint-specific file, count, processing, and quota limits in the
  application (A06 and `file-uploads.md`). Django's upload memory settings are
  not hard file-size caps.

**Write-time.** When you generate an Nginx static block, write the trailing
slash on both sides in the same edit. The pair is the control, and a `location`
prefix that is correct alone still exposes the parent directory.

## Database and secrets

- Enforce TLS on the DB connection. Do not expose the DB port publicly, and
  firewall it to the app hosts. "Enforced" means *verified*:
  `sslmode=verify-full` with a pinned root certificate, not `require`.
  `data-layer-and-database.md` owns the application-side data layer: migration
  versus runtime roles, row-level security, pool sizing, and statement
  timeouts.
- Load secrets with `os.environ` from an injected environment, or through the
  official, maintained SDK for the deployment's secrets manager. Keep `.env`
  out of the repository and out of the production artifact.
  `service-identity-and-secrets.md`, "Where secrets live and how they reach the
  process" owns which delivery mechanism suits which runtime. It also owns why
  an environment variable is the floor rather than the target for a production
  credential. Do not add a generic helper merely to parse environment
  variables. `python-decouple` does not pass the current maintenance gate, and
  existing use needs a re-vet. Validate required settings and types at startup,
  and fail closed without a print of secret values.

## Caching security

- Treat reverse proxies, CDNs, Django's site and per-view cache, and shared
  Redis or Memcached as data-serving infrastructure. Keep cache services
  authenticated, private, least-privileged, and separated by environment. Do
  not expose cache ports publicly.
- Never shared-cache authenticated or personalized responses by default. Audit
  `cache_page`, `UpdateCacheMiddleware`, proxy/CDN rules, `Vary`, `Set-Cookie`,
  and `Cache-Control` together, and test with two users and two tenants.
- Keep Django at the current patch level in the supported line: 6.1, 6.0.8, or
  5.2.17 as of 9 Aug 2026. The 2026 cache fixes themselves landed in 6.0.7 and
  5.2.16. See A01 for audience-safe keys, authorization order, invalidation,
  and private-response policy. Infrastructure configuration cannot repair a key
  that omits security context.

### Cache deception at the edge

Cache deception is the opposite case to the leak A01 owns. There, an
application key omits an authorization dimension, and one principal receives
another's cached bytes. Here the application key is irrelevant, because the
edge decided on its own that the response was static. The URL ends in something
that looks like a file extension, or it sits under a prefix a CDN rule marks
cacheable. The edge then stored a personalized response under a path any
anonymous caller can request.

Two things have to be true at once, which is why it splits across two teams.
The edge caches by what the URL looks like rather than by what the origin said.
The application answers a decorated URL with the same personalized response it
gives the undecorated one.

The second half is the one this repository can act on, and it is a routing
question rather than a caching one. Three things make the decorated URL reach
the authenticated view at all. They are a route that ends in a catch-all
segment, a loose `re_path`, and a resolver that tolerates a trailing suffix. A
route that matches exactly returns 404, and there is nothing to cache.

The first half is a recommendation to whoever operates the edge, in the same
register as orchestrator enforcement above. That half is which paths and
extensions the CDN treats as static, and whether it honors the origin's
`Cache-Control`. The question to send them is whether any cache rule can
override a `private` or `no-store` response.

CWE-524 (Use of Cache Containing Sensitive Information). Severity: rated on
what the cached response holds, per A01's cache section rather than separately
here.

**Write-time.** When you generate a route that serves authenticated or
personalized content, match the path exactly rather than with a trailing
catch-all. Put `never_cache` or an explicit `Cache-Control: private, no-store`
on the response in the same edit. An edge rule keyed on what a URL looks like
caches anything the origin did not mark private, and the attacker chooses the
decorated URL.

## Queue and broker exposure

- Redis and RabbitMQ brokers must be authenticated and firewalled, and never
  internet-reachable. A public broker with a pickle serializer is Critical RCE
  (A08). Do not put secrets in task arguments or results (A09).
- Encrypt the broker link, and replace the packaged default account. The broker
  URL in the settings module is the signal a review reads: `redis://` and
  `amqp://` are plaintext, and `rediss://` and `amqps://` are not. A plaintext
  link puts the broker password and every task argument on the wire. A broker
  that still answers to its packaged default account is unauthenticated in the
  way that matters, although a password exists. Separate the broker by
  environment, as the cache rule above requires for a cache.
- Treat a reachable, unauthenticated Redis as Critical on its own, not merely
  as a broker-hygiene issue. The rating does not rest on a CVE, and a team that
  reads it that way under-reacts on a patched instance. `dir` and `dbfilename`
  are writable at run time through `CONFIG SET`, so a caller who reaches an
  unauthenticated instance chooses the path and the content of the next
  persistence file. Replication hands the same caller the contents of the
  instance. Both are features, and a fully patched Redis keeps both. The CVEs
  raise the ceiling rather than set it. CVE-2025-49844 is a use-after-free in
  the embedded Lua interpreter. It lets a caller who can run a script escape
  the sandbox and execute code. CVE-2022-0543 was an equivalent sandbox escape
  that Debian and Ubuntu packaging introduced. Patch, require an ACL user with
  a password, keep `protected-mode` on, and keep the instance off any routable
  network. Deny the `admin` and `dangerous` ACL categories to the application's
  own user, because a cache client and a broker client need neither.
  `data-layer-and-database.md` owns application-side use of Redis and other
  key-value stores.

## Review checklist

- [ ] TLS enforced; HSTS set; no redirect loop with the proxy.
- [ ] Any pinned key-exchange group list includes `X25519MLKEM768`. It does not
      override a current OpenSSL's hybrid default with a classical-only list
      inherited from an older hardening template.
- [ ] Forwarded headers trusted only from the proxy; client IP for lockout is
      correct; `SECURE_PROXY_SSL_HEADER` not client-spoofable. The proxy
      overwrites every trust-bearing header it does not set, including
      `X-Forwarded-Host` and any forwarded client-certificate identity. The
      application port cannot be reached without a traversal of the proxy, and
      a CDN-fronted origin accepts the CDN's ranges only.
- [ ] No `location` block declares a `proxy_set_header` or an `add_header`
      without restoring the full inherited set. Nginx drops the rest silently.
- [ ] The code reads the client IP a known number of hops from the right of
      `X-Forwarded-For`, never the leftmost entry. It confirms that the peer
      and the hops to the right of the answer are proxies the project operates,
      because the depth check cannot detect a hop count set too high.
- [ ] Security headers defined once; server/version banners hidden. Each
      edge `add_header` carries `always`, and the proxy-served static and media
      locations get the header set that Django cannot reach.
- [ ] No development tooling is reachable or importable in production, and a
      deliberate 500 renders no traceback. Metrics and detailed health
      endpoints are authenticated or internal-only.
- [ ] Gunicorn non-root on a local socket; systemd unit hardened;
      `forwarded_allow_ips` names the proxy rather than `*`. The socket is not
      world-connectable (`--umask 007`). PROXY-protocol acceptance names the
      load balancer. An ASGI deployment restricts `--forwarded-allow-ips`, and
      a Daphne deployment relies on the network guarantee alone.
- [ ] The application server is pinned at or above `23.0.0` for Gunicorn.
      Whichever async worker the command line selects is pinned at its own
      floor. The review sends the smuggling exposure itself outward as a
      question about the proxy chain, rather than a repository finding.
- [ ] The image pins a maintained base, declares a numeric non-root `USER`,
      builds in stages, and writes nothing outside `/tmp` or a mounted volume.
- [ ] `.dockerignore` excludes `.env`, `.git`, keys, and local settings, and no
      secret appears in `docker history`, image metadata, or any saved layer.
- [ ] Uploads use inert/origin-isolated serving; hard edge limits and
      application file/count/processing/quotas are enforced.
- [ ] DB over TLS with certificate verification, and firewalled; secrets from
      env, not in image/VCS. A systemd unit carries no secret in
      `Environment=` or `EnvironmentFile=`.
- [ ] No shared-cache caching of authenticated responses; cache and broker
      services are authenticated, private, and environment-separated. The
      broker URL names a TLS scheme, and no service keeps its packaged default
      account.
