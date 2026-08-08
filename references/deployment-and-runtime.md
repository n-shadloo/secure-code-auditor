# Deployment and Runtime

The layer the backend owns in production: TLS/headers, reverse proxy and
forwarded-header trust, operational endpoint exposure, Gunicorn/systemd
hardening, the container image as a build artifact, static/media serving, the
database connection, and caching/queue exposure. Nginx + Gunicorn + systemd,
optionally containerised, optionally behind Cloudflare.

This file and `a02-security-misconfiguration.md` split the configuration
surface by where the setting lives rather than by topic. This file owns what
the proxy, the process, and the image **do** with a request once it arrives:
TLS termination and which layer owns each header, forwarded-header trust and
the client IP that every rate limit and audit record depends on, operational
endpoints left reachable in production, and the Gunicorn or systemd unit that
runs the code. A02 owns what a settings module or a DNS zone declares. On the
container this file stops at the artifact the repository produces — base
image, `USER`, `.dockerignore`, and secrets baked into layers — with
orchestrator enforcement named as a cross-team recommendation rather than a
repository finding, and `service-identity-and-secrets.md` owning where a
secret comes from at run time.

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

The app can be perfect and still be exposed by how it runs: plaintext transport,
a proxy that lets clients forge their apparent IP or scheme, a worker running as
root, or user uploads served as executable code. The principle is **least
privilege and least exposure at runtime**: encrypt transport, trust only what the
proxy actually sets, drop privileges, and serve untrusted content inertly.

## TLS and HSTS

- Terminate TLS with modern protocols/ciphers; redirect HTTP→HTTPS. If Cloudflare
  or the proxy already redirects, set `SECURE_SSL_REDIRECT = False` in Django to
  avoid redirect loops.
- Set HSTS (see A02). Roll it out with a short max-age first; it's hard to undo.

## Reverse proxy and forwarded headers

This is the subtle one. Behind Nginx/Cloudflare:

- Set `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")` **only** if
  the proxy sets that header unconditionally and strips any client-supplied copy.
  Otherwise a client can claim HTTPS.
- Trust `X-Forwarded-For`/`X-Forwarded-Proto` **only** from your proxy. Client-IP
  used for lockout/rate limiting must come from a trusted hop, or attackers spoof
  it (relevant to `django-axes` and allauth, which now distrusts `X-Forwarded-For`
  by default). Configure the proxy count / trusted header explicitly.
- Nginx: `underscores_in_headers off;` (default) — the Django 6.0.4
  underscore-header spoofing CVE is a reminder not to enable it. Validate `Host`
  and consider a default server returning 444 for unknown hosts, complementing
  `ALLOWED_HOSTS`.
- A header carrying a *verified client certificate* — `X-Forwarded-Client-Cert`,
  or RFC 9440's `Client-Cert` — obeys the same rule at a higher penalty:
  spoofing it is an authentication bypass, not a client-IP trust problem. The
  proxy must strip or overwrite any inbound copy, and the application must not
  be reachable except through it. The application side is in
  `service-identity-and-secrets.md`, "Client-certificate identity behind a
  proxy".

Example Nginx snippet:

```nginx
server_tokens off;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
client_max_body_size 10m;   # cap uploads at the edge
```

### Reading the client IP

`X-Forwarded-For` is `client, proxy1, proxy2` read left to right: each hop
appends the address it received the connection from. The snippet above uses
`$proxy_add_x_forwarded_for`, which **appends** to whatever the caller sent
rather than replacing it, so the left of that list is attacker-supplied in
exactly the way a request body is. Only the entries your own infrastructure
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
# reintroduces the bug above.
from django.core.exceptions import SuspiciousOperation

TRUSTED_PROXY_HOPS = 1


def client_ip(request):
    if not TRUSTED_PROXY_HOPS:
        # Nothing trustworthy in front: the header is pure client input, so the
        # peer address is the only honest answer. A zero hop count also cannot
        # be handled by the indexing below, because negating zero still selects
        # the leftmost and attacker-supplied entry.
        return request.META["REMOTE_ADDR"]
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    hops = [value.strip() for value in forwarded.split(",") if value.strip()]
    if len(hops) < TRUSTED_PROXY_HOPS:
        # Fewer entries than the topology guarantees means the request did not
        # traverse the expected chain. Fail closed rather than fall back to a
        # value the caller controls.
        raise SuspiciousOperation("unexpected forwarded-header depth")
    return hops[-TRUSTED_PROXY_HOPS]
```

A wrong client IP is not one finding. It voids rate limiting, login lockout, IP
allowlists, and the attribution in every audit record at once, and each of those
failures looks exactly like the control working. DRF's throttle classes have
their own setting for this; see `api-drf-specific.md`, "Throttling as quota, not
security (API4)". Do not reach for a client-IP package — the logic is the few
lines above, and the maintained-package gate rejects the usual candidate in
`security-hardening-libraries.md`.

A related trap: a duplicated `proxy_set_header X-Forwarded-Proto`, typically an
ingress-controller default plus a hand-written snippet, yields `http,https`
rather than failing loudly. Set each forwarded header exactly once.

CWE-348 (Use of Less Trusted Source), CWE-290 (Authentication Bypass by
Spoofing), CWE-807 (Reliance on Untrusted Inputs in a Security Decision).
Severity: high.

## Security headers at the edge

Set HSTS, `X-Frame-Options`/frame-ancestors, `X-Content-Type-Options: nosniff`,
`Referrer-Policy`, and CSP either in Django (A02; CSP built-in on 6.0+) or at
Nginx — but define them in one place to avoid conflicting/duplicated headers.
Hide version banners (`server_tokens off`, and don't advertise Gunicorn's).

Ownership is the part that goes wrong. Split it by what each layer can actually
compute:

- **Django owns anything that varies per request or per view.** A nonce-based
  CSP is the clear case — the nonce has to be minted for the response that
  carries it, and a proxy cannot mint one, so a CSP with `CSP.NONCE` must come
  from Django, where `a02-security-misconfiguration.md` owns the setting that
  declares it. Cookie flags, `X-Frame-Options` where it differs by view, and
  `Referrer-Policy` belong here for the same reason.
- **The edge owns what is uniform across the site and what has to happen before
  Django sees the request.** Stripping and re-setting inbound `X-Forwarded-*` is
  the important one: it is the precondition for everything in the previous
  section, and Django cannot do it, because by the time Django runs, a forged
  header is indistinguishable from a real one.
- **HSTS belongs wherever TLS terminates** — one place, not both.

A header set in two places is a real failure, not untidiness: duplicated
`X-Frame-Options` and two `Content-Security-Policy` headers are resolved by the
browser taking the *intersection* of the policies for CSP and, for
`X-Frame-Options`, potentially ignoring both. Pick one owner per header, and
assert the response headers in a test so the second owner is caught when someone
adds it. CWE-693 (Protection Mechanism Failure). Severity: medium.

## Operational and development endpoints

Anything that renders internal state is an exposure surface unless it is
authenticated or genuinely unreachable from outside: profilers, metrics, health
checks that echo versions and dependency status, the admin, and above all
development tooling that was never meant to leave a laptop.

The severe cases are development tools reachable in production. The Django Debug
Toolbar renders SQL, settings, and request internals, and CVE-2021-30459 — CVSS
9.8, fixed in 1.11.1, 2.2.1, and 3.2.1 — allowed an attacker to execute SQL
through the SQL panel's own form, so an exposed toolbar sits closer to remote
code execution than to information disclosure. `django-silk` publishes a request
and SQL profiling UI. `runserver_plus`, from `django-extensions`, carries the
Werkzeug interactive debugger, which is arbitrary code execution by design.

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

- Request the well-known paths against the deployed host and record what
  answers rather than what should: `/admin/`, `/__debug__/`, `/silk/`,
  `/metrics`, `/health`, `/api/schema`, `/swagger/`, `/redoc/`, `/.env`,
  `/.git/config`.
- Trigger a deliberate 500 and confirm no traceback renders.
- Grep `INSTALLED_APPS`, `MIDDLEWARE`, and the URLconf for `debug_toolbar`,
  `silk`, and `django_extensions`, and confirm each is both guarded by `DEBUG`
  and missing from the production dependency set.
- Read what a health endpoint actually returns. One that reports dependency
  versions and database reachability is a reconnaissance aid; keep the detailed
  variant authenticated and leave a bare liveness endpoint public.

Metrics deserve their own line: `django-prometheus` and its equivalents publish
per-endpoint request counts and latencies, which disclose the URL inventory and
the traffic shape. Bind them to an internal interface or require
authentication; an unguessable path is not a control. Schema and browsable-API
exposure is owned by `api-drf-specific.md`, "Schema and browsable-API
exposure", and the `DEBUG` error page itself by A02.

CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-489
(Active Debug Code), CWE-200 (Exposure of Sensitive Information). Severity:
critical for a reachable Werkzeug console or Debug Toolbar, medium for metrics
and health disclosure.

## Gunicorn hardening

- Run as a dedicated non-root user. Bind to a local socket/loopback, not a public
  interface; let Nginx face the internet.
- Set sensible `--timeout`, worker count, and `--max-requests`/`--max-requests-jitter`
  to recycle workers. Don't run Gunicorn with `--reload` or Django's `runserver`
  in production.
- `forwarded_allow_ips` decides whether Gunicorn honours `X-Forwarded-*` at all,
  and it defaults to `127.0.0.1,::1`. In a container the proxy is a different
  host, so that default ignores the headers — and the fix copied from most
  deployment guides is `--forwarded-allow-ips="*"`, which accepts the forwarded
  headers of *any* client that can open a connection. Gunicorn's own
  documentation is explicit that the front-end proxy must ensure these headers
  cannot be passed directly from the client. Name the proxy's address, and use
  `*` only where the port is unreachable except through the proxy as a network
  guarantee rather than an assumption.
- `secure_scheme_headers` defaults to treating `X-Forwarded-Proto: https`,
  `X-Forwarded-Protocol: ssl`, and `X-Forwarded-Ssl: on` as proof of TLS, and it
  sets `wsgi.url_scheme` before Django runs. A permissive `forwarded_allow_ips`
  therefore makes `request.is_secure()` client-controlled no matter what
  `SECURE_PROXY_SSL_HEADER` says — the setting is not the only thing deciding
  that answer.
- The request-size limits are an edge control the application cannot apply for
  itself: `--limit-request-line` (default 4094), `--limit-request-fields`
  (default 100), and `--limit-request-field-size` (default 8190) bound the
  request line and headers before any Django code runs.

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

## Container images

### Principle layer

An image is a build artifact with a security posture of its own, and the split
of responsibility is what keeps the findings actionable: **the backend owns
everything reproducible from the repository; the platform owns everything
enforced by the orchestrator.** A missing `USER` line is a defect in a file the
reader can edit. A missing `runAsNonRoot` is a recommendation to another team.
Audit the first and record the second as a cross-team note, or the review fills
with findings nobody reading it can fix.

Backend-owned, and all of it visible in the Dockerfile:

- A pinned, minimal, currently maintained base image — a digest or a specific
  slim or distroless tag, never a floating `latest`.
- A non-root `USER`. The default is root, so without that line the application
  runs as root inside the container, which is what turns a container-escape
  weakness in the runtime below into a host-root problem rather than an
  unprivileged one.
- A multi-stage build, so compilers, package caches, and any build-time
  credential stay out of the shipped stage.
- A `.dockerignore` that excludes `.env`, `.git`, `*.pem`, `*.key`, local
  settings, and fixtures, with `COPY` scoped rather than `COPY . .`.
- The *ability* to run on a read-only root filesystem: the process writes only
  to `/tmp` or an explicitly mounted volume. This is the backend's half of a
  control the platform switches on.

Platform-owned, and worth naming once rather than auditing: `runAsNonRoot`,
`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, dropped
capabilities, seccomp profiles, resource limits, and egress policy. A non-root
`USER` is necessary but not sufficient — the platform is what enforces it.

CWE-250 (Execution with Unnecessary Privileges), CWE-16 (Configuration).
Severity: medium on its own, high in combination with a runtime escape. runc's
CVE-2024-21626 is the reference case, a working-directory and leaked-descriptor
breakout fixed in runc 1.1.12, against which a non-root container with
capabilities dropped is the difference between an escape and a contained one.

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
COPY --chown=appuser:appuser . /app
WORKDIR /app
USER 10001
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["gunicorn", "app.wsgi", "--bind", "0.0.0.0:8000"]
```

The numeric `USER` is deliberate: `runAsNonRoot` compares a UID, and it cannot
tell whether a user *name* resolves to zero. `collectstatic` output and any
writable cache directory belong in a build stage or a mounted volume, not in a
path the running process has to create for itself.

**Write-time.** When generating a Dockerfile, write the pinned base image, the
multi-stage split, the numeric non-root `USER`, and a `.dockerignore` with a
scoped `COPY` as the first version of the file rather than as a later
hardening pass, because a layer is immutable and additive: an image that once
carried `.env`, `.git`, or a build credential still carries it after the line
that copied it is gone. Keep the running process writing only to `/tmp` or a
mounted volume in that same edit, so the platform can switch on a read-only
root filesystem without the application having to be rewritten for it.

### Secrets in image layers

Layers are immutable and additive. A file written in one layer stays in that
layer's archive even when a later layer deletes it — `RUN rm` removes it from
the merged filesystem the container sees, not from the image. `docker history`,
`docker save`, and anyone who can pull the image still reach it. Build
arguments are worse still: `ARG` values are recorded in image metadata outright.

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

The audit technique matters as much as the rule, because **a scan of the running
container passes while the secret sits in a lower layer in the registry.** Scan
the image and its layers, not a container started from it:

```bash
docker history --no-trunc IMAGE
docker image inspect IMAGE --format '{{range .Config.Env}}{{println .}}{{end}}'
docker save IMAGE -o image.tar   # then scan each layer archive inside
```

Where secrets should come from at run time, and why an environment variable is
the floor rather than the target, is in `service-identity-and-secrets.md`,
"Where secrets live and how they reach the process"; this section covers only
the image as a leak vector. Treat a secret found in a published layer as
disclosed — rotate first, then fix the build. CWE-522 (Insufficiently Protected
Credentials), CWE-540 (Inclusion of Sensitive Information in Source Code), and
A03:2025 where the value is a registry or build credential. Severity: high to
critical by blast radius.

## Static and media

- Keep user uploads outside application/static roots or in object storage, with
  no execute behavior and no write path into deployed code. Public user content
  should use an isolated origin; private media must not have a permanent,
  directly browsable URL. Full validation, SVG/image/archive handling, generated
  names, and download authorization are in `file-uploads.md`. A CDN placed in
  front of private objects must either not cache them or include the signing
  parameters in its cache key; the same file carries that rule and the
  internal-redirect pattern that pairs with it.
- Serve static via Nginx or WhiteNoise. Put a hard request-body limit at Nginx
  (`client_max_body_size`) or the gateway, then apply endpoint-specific file,
  count, processing, and quota limits in the application (A06 and
  `file-uploads.md`). Django's upload memory settings are not hard file-size
  caps.

## Database and secrets

- Enforce TLS on the DB connection; don't expose the DB port publicly; firewall
  it to the app hosts. "Enforced" means *verified* — `sslmode=verify-full` with
  a pinned root certificate, not `require`. The application-side data layer —
  migration versus runtime roles, row-level security, pool sizing, statement
  timeouts — is in `data-layer-and-database.md`.
- Load secrets with `os.environ` from an injected environment or through the
  official, maintained SDK for the deployment's secrets manager; keep `.env` out
  of the repository and production artifact. Which delivery mechanism suits
  which runtime, and why an environment variable is the floor rather than the
  target for a production credential, are in
  `service-identity-and-secrets.md`, "Where secrets live and how they reach the
  process". Do not add a generic helper merely
  to parse environment variables. `python-decouple` does not pass the current
  maintenance gate; existing use should be re-vetted. Validate required settings
  and types at startup and fail closed without printing secret values.

## Caching security

- Treat reverse proxies, CDNs, Django's site/per-view cache, and shared Redis or
  Memcached as data-serving infrastructure. Keep cache services authenticated,
  private, least-privileged, and separated by environment; do not expose cache
  ports publicly.
- Never shared-cache authenticated or personalized responses by default. Audit
  `cache_page`, `UpdateCacheMiddleware`, proxy/CDN rules, `Vary`, `Set-Cookie`,
  and `Cache-Control` together, and test with two users and two tenants.
- Keep Django at 6.0.7 or 5.2.16 or later in the supported line for the 2026
  cache fixes. See A01 for audience-safe keys, authorization ordering,
  invalidation, and private-response policy; infrastructure configuration cannot
  repair a key that omits security context.

## Queue and broker exposure

- Redis/RabbitMQ brokers must be authenticated and firewalled, never
  internet-reachable. A public broker plus a pickle serializer is critical RCE
  (A08). Don't put secrets in task args/results (A09).
- Treat a reachable, unauthenticated Redis as Critical on its own, not merely as
  a broker-hygiene issue. CVE-2025-49844 is a use-after-free in the embedded Lua
  interpreter that lets a caller able to run a script escape the sandbox and
  execute code, and CVE-2022-0543 was an equivalent sandbox escape introduced by
  Debian/Ubuntu packaging. Patch, require authentication, and keep the instance
  off any routable network. Application-side use of Redis and other key-value
  stores is in `data-layer-and-database.md`.

## Review checklist

- [ ] TLS enforced; HSTS set; no redirect loop with the proxy.
- [ ] Forwarded headers trusted only from the proxy; client IP for lockout is
      correct; `SECURE_PROXY_SSL_HEADER` not client-spoofable; any forwarded
      client-certificate identity is stripped inbound and the application port
      cannot be reached without traversing the proxy.
- [ ] Client IP is read a known number of hops from the right of
      `X-Forwarded-For`, never the leftmost entry, and the hop count matches the
      deployed topology.
- [ ] Security headers defined once; server/version banners hidden.
- [ ] No development tooling is reachable or importable in production; a
      deliberate 500 renders no traceback; metrics and detailed health
      endpoints are authenticated or internal-only.
- [ ] Gunicorn non-root on a local socket; systemd unit hardened;
      `forwarded_allow_ips` names the proxy rather than `*`.
- [ ] The image pins a maintained base, declares a numeric non-root `USER`,
      builds in stages, and writes nothing outside `/tmp` or a mounted volume.
- [ ] `.dockerignore` excludes `.env`, `.git`, keys, and local settings, and no
      secret appears in `docker history`, image metadata, or any saved layer.
- [ ] Uploads use inert/origin-isolated serving; hard edge limits and
      application file/count/processing/quotas are enforced.
- [ ] DB over TLS with certificate verification, and firewalled; secrets from
      env, not in image/VCS.
- [ ] No shared-cache caching of authenticated responses; cache and broker
      services are authenticated, private, and environment-separated.
