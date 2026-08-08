# scripts

Two read-only triage helpers used by the secure-code-auditor skill. They read
files and print indicators; confirm everything they surface by reading the code.

## Invariants

These hold for both scripts and are not negotiable:

- **Read-only.** Neither writes, moves, or deletes anything.
- **Standard library only, Python 3.9+.** No third-party dependency, no
  vendored code.
- **No network.** Nothing here opens a connection.
- **Neither imports or executes the audited project.** `settings_scan.py` is
  AST-based; `dangerous_patterns.py` is a text scanner.
- **Exit code is always 0.** Findings are output, never exit codes; these are
  aids, not gates.
- **Findings are indicators to verify, not confirmed vulnerabilities.** Each
  one names the reference file that owns the follow-up.

Values computed at runtime (`env("DEBUG")`, `os.environ[...]`, a call that
builds a dict) are reported as dynamic and left for manual verification rather
than guessed at, so a hit is a hit and not an inference.

## settings_scan.py

Static, AST-based posture check for a single Django settings file.

```
python scripts/settings_scan.py path/to/settings.py
```

### Checks, by owning reference

**`a02-security-misconfiguration.md`** — what the settings module declares:

- `DEBUG` is `True`.
- `ALLOWED_HOSTS` is empty or contains `*`.
- `SECRET_KEY` is a hardcoded string literal, or carries the
  `django-insecure-` prefix `startproject` writes. Where the key should live
  and how it rotates is `service-identity-and-secrets.md`.
- `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`,
  `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_CONTENT_TYPE_NOSNIFF`,
  `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and
  `CSRF_COOKIE_SECURE` are unset or not `True`.
- `X_FRAME_OPTIONS` is set to something other than `DENY`.
- `CORS_ALLOW_ALL_ORIGINS` is `True`, raised in severity when
  `CORS_ALLOW_CREDENTIALS` is `True` alongside it.
- `CSRF_TRUSTED_ORIGINS` is absent from this file.

**`a02-security-misconfiguration.md` and `deployment-and-runtime.md`**:

- `SECURE_PROXY_SSL_HEADER` is set. Informational: no settings check can tell a
  safe proxy header from a spoofable one, so the answer is at the proxy.

**`deployment-and-runtime.md`**:

- `INSTALLED_APPS` installs `debug_toolbar`, `silk`, or `django_extensions`
  unconditionally. An `if DEBUG:` append is not a module-level assignment and
  is deliberately not reported.

**`data-layer-and-database.md`** — per `DATABASES` alias:

- A PostgreSQL alias whose `OPTIONS` do not set `sslmode` to `verify-ca` or
  `verify-full`. `require` encrypts without validating the server that
  answered.
- `OPTIONS["pool"]` set while `CONN_MAX_AGE` is not `0`, which Django rejects
  at startup with `ImproperlyConfigured`.

**`a10-exceptional-conditions.md`**:

- `ATOMIC_REQUESTS` is `True`, at module level or on a `DATABASES` alias.
  Informational: it holds a connection and an open transaction for the whole of
  every view, so long-running, streaming, and external-call views need
  excluding.

**`a04-cryptographic-failures.md`**:

- `PASSWORD_HASHERS` is unset — Django's shipped order puts PBKDF2 first and
  Argon2 third, so installing `argon2-cffi` changes nothing and the absence is
  the finding — or its first entry is not an Argon2 hasher.

**`a08-integrity-and-deserialization.md`**:

- `SESSION_SERIALIZER` names a pickle serializer. Django removed the built-in
  one in 5.0, so any hit here is a custom or third-party one, and it turns
  `SECRET_KEY` disclosure into code execution.

## dangerous_patterns.py

Line-oriented regex scan across the `.py` files in a tree. Every hit is a lead
to verify, not a confirmed finding; patterns are exact strings chosen for a low
false-positive rate, and anything needing data-flow reasoning is out of scope
by design.

```
python scripts/dangerous_patterns.py path/to/project
python scripts/dangerous_patterns.py .
```

### Indicators, by owning reference

**`a05-injection.md`** — SQL, the shell, and server-side output:

- `.raw(`, `.extra(`, `RawSQL(`, and `cursor.execute()` built with an f-string,
  `%` formatting, or `.format()`.
- `order_by(request...)`, `filter(**request...)`, and `annotate(**...)`, where
  the identifier rather than the value comes from the client.
- `mark_safe(`, the `|safe` filter, `format_html()` given an f-string, and
  `autoescape=False`.
- `shell=True`, `os.system(`, `eval(`, and `exec(`.

**`a08-integrity-and-deserialization.md`**:

- `pickle.load` / `pickle.loads`.
- `yaml.load(` without `SafeLoader` or `safe_load` on the same line.
- `CELERY_TASK_SERIALIZER = "pickle"`.
- An `accept_content` line admitting `pickle` — the setting that decides what
  a worker will execute, whatever the producers are configured to send.

**`a04-cryptographic-failures.md`**:

- `verify=False`, which disables TLS certificate verification on an outbound
  call.
- `random.random(`, `random.randint(`, and `random.choice(`. The default
  generator is a Mersenne Twister and is reconstructible from its output, so
  each hit needs confirming as not a secret, token, or identifier.
  `random.SystemRandom()` and `secrets` do not match.

**`service-identity-and-secrets.md`**:

- A `SECRET_KEY`, `SIGNING_KEY`, `API_KEY`, `PASSWORD`, or `TOKEN` assigned a
  string literal. Heuristic: assignments from `os.environ`, `env()`,
  `config()`, `getenv`, or `get_secret` are skipped.

**`a02-security-misconfiguration.md`**:

- `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, `CORS_ALLOW_ALL_ORIGINS = True`, and
  `@csrf_exempt`.

**`api-drf-specific.md`**:

- `fields = "__all__"` on a serializer.

**`graphql-and-alternative-api-surfaces.md`**:

- `bypass_get_queryset`, the graphene-django decorator that makes traversal
  skip `get_queryset` entirely, so the resolver opts out of every scope its
  type declares.
