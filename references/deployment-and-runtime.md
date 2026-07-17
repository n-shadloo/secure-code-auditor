# Deployment and Runtime

The layer the backend owns in production: TLS/headers, reverse proxy and
forwarded-header trust, Gunicorn/systemd hardening, static/media serving, the
database connection, and caching/queue exposure. Nginx + Gunicorn + systemd,
optionally behind Cloudflare.

## Contents
- [Principle](#principle)
- [TLS and HSTS](#tls-and-hsts)
- [Reverse proxy and forwarded headers](#reverse-proxy-and-forwarded-headers)
- [Security headers at the edge](#security-headers-at-the-edge)
- [Gunicorn hardening](#gunicorn-hardening)
- [systemd hardening](#systemd-hardening)
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

Example Nginx snippet:

```nginx
server_tokens off;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
client_max_body_size 10m;   # cap uploads at the edge
```

## Security headers at the edge

Set HSTS, `X-Frame-Options`/frame-ancestors, `X-Content-Type-Options: nosniff`,
`Referrer-Policy`, and CSP either in Django (A02; CSP built-in on 6.0+) or at
Nginx — but define them in one place to avoid conflicting/duplicated headers.
Hide version banners (`server_tokens off`, and don't advertise Gunicorn's).

## Gunicorn hardening

- Run as a dedicated non-root user. Bind to a local socket/loopback, not a public
  interface; let Nginx face the internet.
- Set sensible `--timeout`, worker count, and `--max-requests`/`--max-requests-jitter`
  to recycle workers. Don't run Gunicorn with `--reload` or Django's `runserver`
  in production.

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

## Static and media

- Keep user uploads outside application/static roots or in object storage, with
  no execute behavior and no write path into deployed code. Public user content
  should use an isolated origin; private media must not have a permanent,
  directly browsable URL. Full validation, SVG/image/archive handling, generated
  names, and download authorization are in `file-uploads.md`.
- Serve static via Nginx or WhiteNoise. Put a hard request-body limit at Nginx
  (`client_max_body_size`) or the gateway, then apply endpoint-specific file,
  count, processing, and quota limits in the application (A06 and
  `file-uploads.md`). Django's upload memory settings are not hard file-size
  caps.

## Database and secrets

- Enforce TLS on the DB connection; don't expose the DB port publicly; firewall
  it to the app hosts.
- Load secrets from the environment or a secrets manager; keep `.env` out of the
  image and out of VCS (`django-environ`/`python-decouple`). No secrets baked into
  Docker layers.

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

## Review checklist

- [ ] TLS enforced; HSTS set; no redirect loop with the proxy.
- [ ] Forwarded headers trusted only from the proxy; client IP for lockout is
      correct; `SECURE_PROXY_SSL_HEADER` not client-spoofable.
- [ ] Security headers defined once; server/version banners hidden.
- [ ] Gunicorn non-root on a local socket; systemd unit hardened.
- [ ] Uploads use inert/origin-isolated serving; hard edge limits and
      application file/count/processing/quotas are enforced.
- [ ] DB over TLS and firewalled; secrets from env, not in image/VCS.
- [ ] No shared-cache caching of authenticated responses; cache and broker
      services are authenticated, private, and environment-separated.
