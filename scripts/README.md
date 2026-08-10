# scripts

Two read-only triage helpers used by the secure-code-auditor skill. They read
files and print indicators; confirm everything they surface by reading the code.

## Invariants

These hold for both scripts and are not negotiable:

- **Read-only.** Neither writes, moves, or deletes anything.
- **Standard library only, Python 3.9+.** No third-party dependency, no
  vendored code.
- **No network.** Nothing here opens a connection.
- **Neither imports or executes the audited project.** Both parse with the
  `ast` module; neither runs a line of the code it reads.
- **Exit code is always 0.** Findings are output, never exit codes; these are
  aids, not gates.
- **Findings are indicators to verify, not confirmed vulnerabilities.** Each
  one names the reference file that owns the follow-up.
- **A file that cannot be parsed is reported, never skipped in silence.** A
  silent skip is a false negative wearing the clothes of a clean result.

Values computed at runtime (`env("DEBUG")`, `os.environ[...]`, a call that
builds a dict) are reported as dynamic and left for manual verification rather
than guessed at, so a hit is a hit and not an inference.

Because both scanners parse rather than match text, they can tell a string
literal from an expression, a call carrying a parameter sequence from one that
does not, a local rebinding from a module constant, and a real call from the
same characters inside a docstring.

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

Static, AST-based scan across the `.py` files in a tree. Every hit is a lead to
verify, not a confirmed finding.

```
python scripts/dangerous_patterns.py path/to/project
python scripts/dangerous_patterns.py .
python scripts/dangerous_patterns.py . --min-severity MEDIUM
python scripts/dangerous_patterns.py . --json
python scripts/dangerous_patterns.py --selftest
```

### What the AST basis buys

Every rule decides on structure. That is what separates this scanner from a
line matcher, and the separation is the point rather than a refinement:

- **A literal is distinguishable from an expression.** `cursor.execute("SELECT
  * FROM app_user WHERE id = %s", [user_id])` is the correct form and is not
  reported, whatever the string contains. A line matcher cannot tell the DB-API
  placeholder from the string-formatting operator, so it reports the safest
  possible code as its most severe indicator and teaches the reader to discount
  the tool.
- **A call's other arguments are visible.** `yaml.load` is decided by reading
  its `Loader` keyword, not by a lookahead on the rest of the line;
  `subprocess` is decided by the `shell` keyword together with whether the
  command is constant.
- **An identifier's binding is visible.** A query passed as a name is resolved
  against the enclosing function and then the module. Resolving to a literal
  clears it; resolving to an f-string convicts it even though the interpolation
  is on a different line; resolving to nothing is reported at reduced severity
  as an unresolved query source rather than passed in silence.
- **A docstring is not code.** Text inside a string literal is never a hit.
  This file's own fixtures are full of `os.system` and `eval`, and the scanner
  reports nothing when run against this repository.
- **An attribute is not a builtin.** `eval` is flagged only as a bare-name
  call, so `model.eval()` and `expression.eval()` never match.

### The contract for adding a rule

**A rule is added only when it can be decided structurally.** Breadth is not
the goal. A check that needs to guess — because the answer lives in a template
file, in another module, or in a runtime value — is left out rather than
carried at a lower severity, because a hit an agent learns to skip costs more
than the hit is worth. Two deliberate consequences:

- The `|safe` template filter is not checked. It lives in template files, and
  matching it inside a Python string would be text matching again.
- Nothing is reported for `filter(**kwargs)` in a helper whose mapping is a
  parameter. Only mappings the scanner can tie to request data are flagged.

### Rule identifiers

Every rule carries a stable identifier: a short category prefix and a number,
chosen once and never reused for a different rule, so a hit can be referred to
across runs and across releases. `SQL` for SQL text, `IDN` for ORM identifier
positions, `CMD` for shell and code execution, `DES` for deserialization, `TPL`
for template and output, `NET` for transport, `RND` for randomness, `CFG` for
DRF and configuration, `SEC` for hardcoded secrets.

A rule's severity may vary with what the code does — `CMD001` is HIGH on an
interpolated command and LOW on a constant one — while the identifier stays
fixed. Severity is a property of the hit; the identifier is a property of the
rule.

### Output

Default output is human-readable and grouped by file:

```
  app/views.py:15:9: [HIGH] SQL001 (sql) execute(): SQL text is built by string
      interpolation - pass values as parameters instead (a05-injection.md)
      | cursor.execute("SELECT * FROM item WHERE name LIKE '%%%s%%'" % term)
```

`--min-severity {LOW,MEDIUM,HIGH}` suppresses hits below the given level. It
never suppresses an unparsed file.

`--json` emits JSON Lines — one object per record, one record per line, so a
large tree can be streamed. A `kind` field discriminates the two shapes:

| field | `kind: "hit"` | `kind: "unparsed"` |
| --- | --- | --- |
| `file` | path as given on the command line | same |
| `line` | 1-based line | 1-based line of the syntax error, `0` if unknown |
| `column` | 1-based column | column reported by the parser |
| `rule` | stable rule identifier | absent |
| `severity` | `HIGH`, `MEDIUM`, or `LOW` | absent |
| `category` | `sql`, `command`, `deser`, `xss`, `tls`, `crypto`, `drf`, `config`, `csrf`, `graphql`, `secret` | absent |
| `message` | what the rule decided | absent |
| `reference` | the reference file that owns the rule | absent |
| `snippet` | the source line, stripped, capped at 160 characters | absent |
| `error` | absent | the parser's message |

The owning reference is a field of its own in JSON and is appended to the
message in the default output, so an agent can route from a hit to the rules
for it without guessing and a human reading the terminal sees the same routing.

A file that fails to parse — or that cannot be read — is reported as unparsed
in both modes and counted separately in the summary. It is never skipped in
silence.

### --selftest

```
python scripts/dangerous_patterns.py --selftest
```

Runs alone, takes no path, and exercises source fixtures embedded in the module
— nothing is read from or written to disk. It prints the rule identifiers
expected and the ones produced for each fixture, reports which rules have no
positive fixture, and reports failures explicitly. It exits 0 whether or not
the fixtures pass, like every other mode.

There is one positive fixture per rule. The negative fixtures are correct code
that must produce **no** hit: parameterized `cursor.execute` with `%s` and a
params sequence, `Manager.raw` with params, a fully literal `shell=True`
command, `mark_safe` on a constant, `yaml.load` with `SafeLoader`, a secret
assigned from `os.environ`, a literal dict expanded into `filter`, a
module-level SQL constant, `eval` as an attribute alongside `SystemRandom` and
`secrets`, and a docstring full of dangerous-looking text. Run it after
changing a rule; a negative fixture that starts producing a hit is a
regression on correct code, which is the failure this scanner exists to avoid.

### Indicators, by owning reference

**`a05-injection.md`** — SQL, ORM identifier positions, the shell, and
server-side output:

- `SQL001` — SQL text built by interpolation: an f-string, a `%` operation, a
  `.format()` call, or a concatenation with anything that is not a literal,
  reaching `cursor.execute`, `executemany`, `callproc`, `Manager.raw`,
  `QuerySet.extra`, or `RawSQL`. Resolved through a local or module-level name.
- `SQL002` — the same sinks reached by SQL text the scanner cannot resolve to a
  literal. Reduced severity: unresolved is not the same as wrong. On `.execute`
  alone this is reported only when the receiver names a cursor or a connection,
  since `.execute` is a common method name on objects that are not databases.
- `IDN001` — a mapping expanded with `**` into `annotate`, `aggregate`,
  `alias`, `values`, `values_list`, `filter`, `exclude`, `Q`, or `order_by`,
  where the mapping derives from request data. The ORM parameterizes values,
  not identifiers. Expanding a name bound to a literal dict is not reported.
- `IDN002` — a positional argument to `order_by`, `values`, or `values_list`
  that derives from request data. Only those three: a positional argument to
  `filter` or `Q` is an expression, so `filter(user=request.user)` is correct
  code and is deliberately not reported.
- `CMD001` — `os.system` or `os.popen`. HIGH when any argument is not
  constant; LOW as a hygiene note when the command is entirely literal, because
  the argument list form never reaches a shell at all.
- `CMD002` — a call passing `shell=True` with a command that is not constant. A
  fully literal shell command is not reported: a fixed pipeline is what the
  flag is for.
- `CMD003` — `eval`, `exec`, or `compile` as bare-name calls. HIGH when any
  argument is not constant, LOW when they all are.
- `TPL001` — `mark_safe` on a value that is not a constant. `mark_safe` on a
  constant is not reported.
- `TPL002` — `format_html` whose first argument is an f-string, which
  interpolates before it escapes.
- `TPL003` — `Template(...)` or `Engine.from_string(...)` on a non-constant.
- `TPL004` — `autoescape=False`.

**`a08-integrity-and-deserialization.md`**:

- `DES001` — `pickle.load` / `pickle.loads`, resolved through `import ... as`
  and `from ... import`.
- `DES002` — `yaml.load` whose `Loader` is absent or is not a `SafeLoader`,
  decided from the keyword or the second positional argument.
- `DES003` — `marshal.load` / `marshal.loads`.
- `DES004` — `jsonpickle.decode` / `jsonpickle.loads`.
- `DES005` — a Celery task or result serializer set to `"pickle"`.
- `DES006` — an `accept_content` list admitting `pickle` or
  `application/x-python-serialize` — the setting that decides what a worker
  will execute, whatever the producers are configured to send.

**`a04-cryptographic-failures.md`**:

- `NET001` — `verify=False`, which disables TLS certificate verification on an
  outbound call.
- `RND001` — `random.random`, `randint`, `choice`, `shuffle`, `sample`, and
  `random.Random`. LOW: the default generator is a Mersenne Twister and is
  reconstructible from its output, so each hit turns on whether the value is a
  secret, a token, or an identifier. `random.SystemRandom` and `secrets` do not
  match.

**`service-identity-and-secrets.md`**:

- `SEC001` — a name ending in `SECRET`, `SECRET_KEY`, `SIGNING_KEY`,
  `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`, `PASSWORD`, or `TOKEN` assigned a
  string literal of eight characters or more. Heuristic, so confirm the value
  is not a placeholder. Any assignment whose value is a call is structurally
  excluded, which covers `os.environ`, `env()`, `config()`, and every other
  loader without naming them.

**`a02-security-misconfiguration.md`**:

- `CFG002` — `CORS_ALLOW_ALL_ORIGINS = True`.
- `CFG003` — `DEBUG = True`.
- `CFG004` — `ALLOWED_HOSTS` containing `*`.
- `CFG005` — `@csrf_exempt`.

**`api-drf-specific.md`**:

- `CFG001` — `fields = "__all__"` on a serializer.

**`graphql-and-alternative-api-surfaces.md`**:

- `CFG006` — graphene `bypass_get_queryset`, as a decorator, a keyword, or an
  assignment. It makes traversal skip `get_queryset` entirely, so the resolver
  opts out of every scope its type declares.
