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

- Serve user-uploaded media so it can never be executed: store outside the web
  root or on object storage/CDN, and don't let the server interpret uploaded
  files as code. Validate uploads (extension + content-type + magic bytes),
  sanitize filenames, and set restrictive permissions (`FILE_UPLOAD_PERMISSIONS = 0o644`).
- Serve static via Nginx or WhiteNoise; keep `MEDIA_ROOT` and any private files
  off directly browsable paths. Enforce upload size at both Nginx
  (`client_max_body_size`) and Django (A06) — the app-level limit alone has been
  bypassable.

## Database and secrets

- Enforce TLS on the DB connection; don't expose the DB port publicly; firewall
  it to the app hosts.
- Load secrets from the environment or a secrets manager; keep `.env` out of the
  image and out of VCS (`django-environ`/`python-decouple`). No secrets baked into
  Docker layers.

## Caching security

- Never cache authenticated/personalized responses in a shared cache. Django's
  2026 cache CVEs are concrete precedents: responses setting `Set-Cookie` or
  bearing an `Authorization` header, or with mishandled `Vary`, were stored in the
  shared cache — leaking one user's data to another. Audit `cache_page` /
  `UpdateCacheMiddleware` on any view that varies by user.
- Vary cached responses correctly; keep Django patched for the cache fixes; don't
  cache `private`/`no-store` responses.

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
- [ ] Uploads validated and served inertly; size capped at edge and app.
- [ ] DB over TLS and firewalled; secrets from env, not in image/VCS.
- [ ] No shared-cache caching of authenticated responses; broker authenticated
      and private.
