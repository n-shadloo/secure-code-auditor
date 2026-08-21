# scripts

These are three read-only triage helpers for the secure-code-auditor skill.
They read files and print what they find. Confirm everything they surface by a
read of the code.

- `entrypoint_inventory.py` answers **where does execution begin**, which is
  the question the audit workflow's first phase runs on.
- `settings_scan.py` answers **what does the settings surface declare**.
- `dangerous_patterns.py` answers **which call sites are worth reading first**.

## Invariants

These hold for all three scripts and are not negotiable:

- **Read-only.** None of them writes, moves, or deletes anything.
- **Standard library only, Python 3.9+.** No third-party dependency, no
  vendored code.
- **No network.** Nothing here opens a connection.
- **None of them imports or executes the audited project.** All three parse
  with the `ast` module; none runs a line of the code it reads.
- **Exit code is always 0, with one exception.** Output is the product, never
  the exit code; these are aids, not gates. The exception is
  `dangerous_patterns.py --selftest`, which returns 1 when a check fails,
  because there the scanner itself is what is under test.
- **Output is indicators to verify, not confirmed vulnerabilities.** Each row
  names the reference file that owns the follow-up.
- **A file that cannot be parsed is reported, never skipped in silence.** A
  silent skip is a false negative with the appearance of a clean result. A
  directory that cannot be read is reported the same way and counted as a
  traversal error.
- **A `--json` stream always ends with one `kind: "summary"` record.** An empty
  stream never occurs. A run that finds nothing still writes the summary, so a
  reader can tell a clean tree from a run that stopped. A path that is not a
  file or a directory writes one `kind: "error"` record and the summary, and
  still exits 0.
- **`--json` is the mode intended for agent use.** It is JSON Lines in all
  three: one object per record, one record per line. A large tree therefore
  streams, and a partial read is still parseable. The default output is for a
  human at a terminal.

The scripts report a value computed at runtime as dynamic, and leave it for
manual verification rather than a guess. Such a value is `env("DEBUG")`,
`os.environ[...]`, or a call that builds a dict. A hit is therefore a hit and
not an inference.

All three parse rather than match text. They can therefore separate a string
literal from an expression, and a call that carries a parameter sequence from
one that does not. They can also separate a local rebinding from a module
constant, and a real call from the same characters inside a docstring.

None of them can see a declaration that is not written down. A parser cannot
see a route registered in a loop, or a viewset assembled by a factory. It
cannot see a task registered at import time from a table. Each one stays a
residual gap that a read closes.

## entrypoint_inventory.py

This is a static, AST-based inventory of every declared way execution enters
application code. It is the instrument for `01-audit-workflow.md`, "Phase 1 —
entry-point inventory". Everything after that phase derives from it.

```
python scripts/entrypoint_inventory.py path/to/project
python scripts/entrypoint_inventory.py . --settings config/settings
python scripts/entrypoint_inventory.py . --kind url,drf,action
python scripts/entrypoint_inventory.py . --json
```

`--settings` takes a settings module or a settings package, and supplies the
context the tree alone does not carry. That context is `ROOT_URLCONF`,
`MIDDLEWARE` in declared order, and the DRF `DEFAULT_PERMISSION_CLASSES` a
viewset that declares nothing falls back on. `--kind` restricts the run to
named families, comma-separated and repeatable.

It reports what is declared and stops there. It never prints a verdict, and it
does not decide whether a surface is adequately protected. Each family names
the reference file that answers that.

### Families collected, by owning reference

| Family | What it reports | Rules |
| --- | --- | --- |
| `url` | `path()`, `re_path()`, and legacy `url()` entries at their full prefix, with the view and the route name, following `include()` through the chain | `authorization-architecture.md` |
| `drf` | router constructions, `register()` calls with prefix, viewset and basename, and viewset/generic-view/`APIView` classes with their declared `permission_classes`, `authentication_classes`, `throttle_classes`, `queryset` and `serializer_class`, and which of `get_queryset`, `get_object`, `get_serializer_class`, `perform_create` and `check_object_permissions` are overridden | `api-drf-specific.md` |
| `action` | `@action` methods with `detail`, `methods`, and any `permission_classes` on the decorator | `api-drf-specific.md` |
| `ninja` | `NinjaAPI(...)` and `Router(...)` constructions with the presence or absence of `auth=`, and operation decorators with their own `auth=` | `graphql-and-alternative-api-surfaces.md` |
| `graphql` | schema constructions, `Query`/`Mutation` type definitions, and resolver methods | `graphql-and-alternative-api-surfaces.md` |
| `grpc` | classes deriving from a generated `Servicer` base, with their method names | `graphql-and-alternative-api-surfaces.md` |
| `channels` | `ProtocolTypeRouter` and `URLRouter` entries and consumer classes | `async-and-channels.md` |
| `celery` | functions decorated with `shared_task` or an app `task` attribute, and literal beat-schedule entries. A bare `@task` resolved to `django.tasks` is reported with `system: django-tasks`, because its default backend executes the task inline in the caller's transaction; `a08-integrity-and-deserialization.md`, "Django's built-in tasks framework", owns the difference | `a08-integrity-and-deserialization.md` |
| `command` | modules under a `management/commands/` path with a `Command` class | `a05-injection.md` |
| `signal` | `@receiver` decorators and `.connect()` calls, with the signal and the sender where literal | `a09-logging-and-alerting.md` |
| `admin` | `@admin.register`, `admin.site.register`, `ModelAdmin` subclasses, and their declared `actions` | `authorization-architecture.md` |
| `middleware` | `MIDDLEWARE` in declared order, only when `--settings` is supplied | `authorization-architecture.md` |

### The include chain

The script reports a route at the concatenation of every prefix an `include()`
chain contributed. The leaf module is the one file that cannot tell you what
the route is. Three consequences are worth a note before you read the output:

- **A second mount appears as a second row.** An `include()` left under an
  older prefix serves the same view twice, and only the resolved form lists
  both.
- **`include(router.urls)` is followed.** Router registrations carry the full
  mounted prefix rather than the fragment passed to `register()`. One that no
  URLconf root reaches says so, rather than appears as though it were mounted.
- **An include target that cannot be resolved statically is reported as an
  unresolved edge, not dropped.** So is an include chain that returns to a
  module already on it.

Roots are the modules that define `urlpatterns` and that no other module
includes. `--settings` adds the declared `ROOT_URLCONF` to that set. Without it
the script walks every unincluded URLconf, which is wider rather than narrower.

### The authorization column

Every HTTP-reachable row carries one of exactly three states, and the
difference between the last two is the whole value of the column:

- **`declared`** — this site declares it, and the value is printed beside the
  row.
- **`inherited`** — this site declares nothing and something upstream supplies
  it: a base class, `DEFAULT_PERMISSION_CLASSES`, a router-level `auth=`, an
  admin permission check. **Not visible from here**, which is a different fact
  from its absence.
- **`absent`** — this site declares nothing, and the construct has no default
  that would supply one. Such a construct is a Ninja API, router, or operation
  with no `auth=`. It is also a gRPC servicer, or a plain Django view with no
  decorator and no mixin. Middleware or a check inside the body may still
  apply. This column looks for neither, so `absent` is a statement about
  declarations and never a finding.

The mixins that count as a declaration are `LoginRequiredMixin`,
`PermissionRequiredMixin`, and `UserPassesTestMixin`. `AccessMixin` is not one
of them. It configures the failure behavior — `login_url`, `raise_exception`,
`handle_no_permission` — and enforces nothing on its own. A class that carries
only `AccessMixin` reads as `inherited`.

A `ProtocolTypeRouter` row is always `absent`. `AuthMiddlewareStack` supplies
the identity and not the authorization. It puts a user in the scope, and admits
every consumer it wraps. The stack stays in the row's `stack` detail, where it
answers the different question of whether a consumer can see a user at all.
Each consumer carries its own state.

A collapse of `inherited` and `absent` into "missing" would rebuild exactly the
false positive this script exists to avoid.

### Output

Default output groups by family, with a count per family and the owning
reference in the heading. It then writes two lines per row. The first is the
label with its authorization state, and the second is the location with the
family-specific fields.

It closes with a coverage line — the families found, the families looked for
and not found, and the families not examined at all. An empty family is
information. It says that surface is absent rather than unexamined.
`01-audit-workflow.md`, "Phase 6 — the coverage ledger" is built on that
distinction.

`--json` emits JSON Lines. A `kind` field discriminates the two shapes, as in
`dangerous_patterns.py`:

| field | `kind: "entry"` | `kind: "unparsed"` |
| --- | --- | --- |
| `file` | path as walked from the command-line root | same |
| `line` | 1-based line | 1-based line of the syntax error, `0` if unknown |
| `column` | 1-based column | column reported by the parser |
| `family` | one of the families above | absent |
| `label` | the entry's identity: a resolved route, a class name, a task name | absent |
| `authorization` | `declared`, `inherited`, `absent`, or `null` where the family has no such concept | absent |
| `reference` | the reference file that owns the family | absent |
| `detail` | an object of family-specific fields, empty values omitted | absent |
| `error` | absent | the parser's message |

Two more shapes close the stream. A `kind: "error"` record names a path that is
not a file or a directory, or a `--kind` value that names no family. A
`kind: "summary"` record is always the last line, and it carries `path`,
`files_discovered`, `files_scanned`, `files_unparsed`, `entries`, and
`walk_errors`. A directory the walk cannot read is reported as `unparsed` and
counted in `walk_errors`. The default output ends with the same counts on one
line.

### Limits

- It finds **declarations**. A route registered at runtime, a viewset built by
  a factory, and a task registered from a loop are not written down as
  constructs. None of them appears here. That is a residual gap the phase
  closes by a read, not a bug to avoid.
- Two families the workflow's inventory lists are not families here, because
  neither is a distinct construct. An inbound **webhook receiver** is an
  ordinary route that authenticates nothing. An **MCP tool** is whatever the
  integration package's registration decorator makes it. Find them in the `url`
  and `drf` rows.
- A view name that resolves to more than one class in the tree, or to none, is
  reported as `inherited` rather than guessed at.
- `re_path` patterns are concatenated verbatim, so an anchored child pattern
  appears with its anchor inside the resolved route.

## settings_scan.py

This is a static, AST-based posture check for a Django settings module, or for
a settings package and the import chain behind it.

```
python scripts/settings_scan.py path/to/settings.py
python scripts/settings_scan.py path/to/settings/
python scripts/settings_scan.py path/to/settings/ --json
```

### Settings packages

The dominant Django layout is a package rather than a file: a base module and
per-environment modules that star-import it. Against `settings/production.py`
alone, a single-file scan reports most of its checks as unset. That is the same
output a genuinely empty module produces. Such a scan looks clean because it
could not see anything.

- Given a **file**, the script resolves the module and everything it imports.
- Given a **directory**, the script resolves every module directly inside it. A
  module that another module in the package imports joins that importer's
  chain, rather than gets a scan of its own. `config/settings/` therefore
  reports the environment modules with `base` merged in, rather than reports
  `base` several times. A module that assigns nothing is named rather than
  scanned. That module is the usual empty `__init__.py`, and the checks against
  it would print a page of "not set".
- `from .base import *`, `from .base import NAME`, and the equivalent absolute
  forms are followed. Assignments merge **later-wins** along the chain, and
  every reported value carries the module it came from. A setting that is safe
  in `base.py` and overridden in `production.py` is therefore visible as
  exactly that.
- The script resolves an import only inside the **package root** the module
  belongs to, which is the nearest ancestor directory without an `__init__.py`.
  It never opens anything outside it, it imports nothing, and it executes
  nothing.
- An unresolvable import is reported and the scan continues. An import **cycle**
  is reported and stopped rather than recursed.
- A setting assigned inside an `if` is reported as **conditional**, with the
  module it appears in, rather than read as a literal. The scan reads the
  assignment and not the condition. An `INSTALLED_APPS +=` append is reported
  as an augmentation for the same reason. The scan still declines to judge it,
  as before, and now says so explicitly.

`--json` emits JSON Lines with five record shapes. A `setting` record carries
`file`, `origin`, `line`, `setting`, `severity`, `message`, `reference`, and
`conditional`. `origin` is the module the effective value came from, and it is
`null` when unset. A `note` record covers a cycle, an unresolvable import, a
module named rather than scanned, or a directory that could not be read. An
`unparsed` record covers a module that could not be read. An `error` record
covers a path that is not a file or a directory. A `summary` record is always
the last line, and it carries `path`, `files_discovered`, `files_scanned`,
`files_unparsed`, `findings`, and `walk_errors`.

The default output ends with the same counts on one line.

### Checks, by owning reference

**`a02-security-misconfiguration.md`** — what the settings module declares:

- `DEBUG` is `True`.
- `ALLOWED_HOSTS` is empty or contains `*`.
- `SECRET_KEY` is a hardcoded string literal, or carries the
  `django-insecure-` prefix `startproject` writes. A dynamic `SECRET_KEY` is
  reported as INFO to confirm by hand, like every other dynamic value. Where
  the key should live and how it rotates is `service-identity-and-secrets.md`.
- `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, and
  `CSRF_COOKIE_SECURE` are unset or not `True`. Django's default for each is
  the unsafe value, so the absence is the finding.
- `SECURE_CONTENT_TYPE_NOSNIFF` and `SESSION_COOKIE_HTTPONLY` are set to
  something other than `True`. Their absence is reported as INFO and names the
  default, because Django already defaults each to `True`.
- `SECURE_HSTS_INCLUDE_SUBDOMAINS` is not `True`, judged **only** when
  `SECURE_HSTS_SECONDS` is positive or dynamic. An HSTS companion setting does
  nothing while HSTS is off, so reporting it there would be noise.
- `MIDDLEWARE`, judged only when it is a literal list with no later `+=`. The
  checks are `CsrfViewMiddleware` absent (HIGH), `SecurityMiddleware` absent
  (MEDIUM), and `XFrameOptionsMiddleware` absent (LOW). One more is
  `SECURE_CSP` / `SECURE_CSP_REPORT_ONLY` present with no CSP middleware
  installed (MEDIUM), because the settings are inert without it. An augmented
  or dynamic list is reported as exactly that rather than judged.
- `SESSION_COOKIE_SAMESITE` / `CSRF_COOKIE_SAMESITE` weakened. Python `None`
  removes the attribute. The string `"None"` opts into cross-site sending, and
  is reported higher when the matching `*_SECURE` flag is not `True`.
- `SECURE_CROSS_ORIGIN_OPENER_POLICY` set to `None` or `"unsafe-none"`.
- `X_FRAME_OPTIONS` is set to something other than `DENY`.
- `CORS_ALLOW_ALL_ORIGINS` is `True`, raised in severity when
  `CORS_ALLOW_CREDENTIALS` is `True` alongside it.
- `CSRF_TRUSTED_ORIGINS` is absent from the module and everything it imports.

**`a02-security-misconfiguration.md` and `deployment-and-runtime.md`**:

- `SECURE_PROXY_SSL_HEADER` is set. Informational: no settings check can tell a
  safe proxy header from a spoofable one, so the answer is at the proxy.

**`a07-authentication-failures.md`**:

- `SESSION_ENGINE` names `signed_cookies` — no server-side record exists, so no
  single session can be revoked.

**`api-drf-specific.md`**:

- A `REST_FRAMEWORK` literal with no `DEFAULT_PERMISSION_CLASSES`, or with
  `AllowAny` in it — DRF's own default is `AllowAny`, so a view that declares
  nothing is public. A block with no `DEFAULT_AUTHENTICATION_CLASSES` is
  reported as INFO.

**`deployment-and-runtime.md`**:

- `USE_X_FORWARDED_HOST` is `True`. Informational, same reasoning as
  `SECURE_PROXY_SSL_HEADER`: only the proxy can make it safe.
- `INSTALLED_APPS` installs `debug_toolbar`, `silk`, or `django_extensions`
  unconditionally. An `if DEBUG:` append is still not judged as an
  unconditional install. It is reported as an augmentation that names the
  module it lives in, so the reader knows the branch exists and has to read it.

**`data-layer-and-database.md`** — per `DATABASES` alias:

- A PostgreSQL alias whose `OPTIONS` do not set `sslmode` to `verify-ca` or
  `verify-full`. `require` encrypts without validating the server that
  answered. PostGIS aliases are included: the engine
  `django.contrib.gis.db.backends.postgis` carries the same libpq options and
  does not contain the substring `postgresql`.
- A MySQL/MariaDB alias whose `OPTIONS` carry no `ssl` — the server is dialed,
  not verified.
- `OPTIONS["pool"]` **truthy or dynamic** while `CONN_MAX_AGE` is not `0`,
  which Django rejects at startup with `ImproperlyConfigured`. Django reads the
  value for truth, so a literal `"pool": False` is not a pool and is not
  reported.

**`a10-exceptional-conditions.md`**:

- `ATOMIC_REQUESTS` is `True`, at module level or on a `DATABASES` alias.
  Informational: it holds a connection and an open transaction for the whole of
  every view, so long-running, streaming, and external-call views need
  excluding.

**`a04-cryptographic-failures.md`**:

- `PASSWORD_HASHERS` is unset, or its first entry is not an Argon2 hasher.
  Django's shipped order puts PBKDF2 first and Argon2 third, so an install of
  `argon2-cffi` changes nothing, and the absence is the finding.

**`a08-integrity-and-deserialization.md`**:

- `SESSION_SERIALIZER` names a pickle serializer. Django removed the built-in
  one in 5.0, so any hit here is a custom or third-party one, and it turns
  `SECRET_KEY` disclosure into code execution.

## dangerous_patterns.py

This is a static, AST-based scan across the `.py` files in a tree. Every hit is
a lead to verify, not a confirmed finding.

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
    reported, whatever the string contains. A line matcher cannot separate the
    DB-API placeholder from the string-formatting operator. It therefore
    reports the safest possible code as its most severe indicator, and teaches
    the reader to discount the tool.
- **A call's other arguments are visible.** The scanner decides `yaml.load` by
  a read of its `Loader` keyword, not by a lookahead on the rest of the line.
  It decides `subprocess` by the `shell` keyword, together with whether the
  command is constant.
- **An identifier's binding is visible.** A query passed as a name is resolved
  against the enclosing function and then the module. A resolution to a literal
  clears it. A resolution to an f-string convicts it, even though the
  interpolation is on a different line. A resolution to nothing is reported at
  reduced severity as an unresolved query source, rather than passed in
  silence.
- **A docstring is not code.** Text inside a string literal is never a hit.
  This file's own fixtures are full of `os.system` and `eval`, and the scanner
  reports nothing when it runs against this repository.
- **An attribute is not a builtin.** `eval` is flagged only as a bare-name
  call, so `model.eval()` and `expression.eval()` never match.

### The contract for adding a rule

**A rule is added only when it can be decided structurally.** Breadth is not
the goal. A check that needs to guess is left out, rather than carried at a
lower severity. Such a check guesses because the answer lives in a template
file, in another module, or in a runtime value. A hit an agent learns to skip
costs more than the hit is worth. Two deliberate consequences follow:

- The `|safe` template filter is not checked. It lives in template files, and
  matching it inside a Python string would be text matching again.
- Nothing is reported for `filter(**kwargs)` in a helper whose mapping is a
  parameter. Only mappings the scanner can tie to request data are flagged.

### Rule identifiers

Every rule carries a stable identifier: a short category prefix and a number.
The identifier is chosen once and never reused for a different rule, so a
reader can refer to a hit across runs and across releases. The prefixes are
`SQL` for SQL text, `IDN` for ORM identifier positions, `CMD` for shell and
code execution, and `DES` for deserialization. They are also `TPL` for template
and output, `NET` for transport, `RND` for randomness, `CFG` for DRF and
configuration, and `SEC` for hardcoded secrets.

A rule's severity may vary with what the code does, while the identifier stays
fixed. `CMD001` is HIGH on an interpolated command and LOW on a constant one.
Severity is a property of the hit, and the identifier is a property of the
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
| `category` | `sql`, `command`, `deser`, `xss`, `tls`, `ssrf`, `crypto`, `drf`, `config`, `csrf`, `graphql`, `secret` | absent |
| `message` | what the rule decided | absent |
| `reference` | the reference file that owns the rule | absent |
| `snippet` | the source line, stripped, capped at 160 characters, with ANSI escapes and control bytes removed; a `SEC001` snippet is the fixed text `<redacted: secret-shaped literal>`, so a report never prints the secret back | absent |
| `error` | absent | the parser's message |

The owning reference is a field of its own in JSON, and the default output
appends it to the message. An agent can therefore route from a hit to the rules
for it without a guess. A human at the terminal sees the same routing.

A file that fails to parse, or that cannot be read, is reported as unparsed in
both modes. The summary counts it separately. It is never skipped in silence. A
directory the walk cannot read is reported the same way.

Two more shapes close the stream. A `kind: "error"` record names a path that is
not a file or a directory. A `kind: "summary"` record is always the last line,
and it carries `path`, `files_discovered`, `files_scanned`, `files_unparsed`,
`hits` (after `--min-severity` filtering), and `walk_errors`.

### --selftest

```
python scripts/dangerous_patterns.py --selftest
```

It runs alone, takes no path, and exercises source fixtures embedded in the
module. It reads nothing from disk and writes nothing to disk. It prints the
rule identifiers expected and the ones produced for each fixture, reports which
rules have no positive fixture, and reports failures explicitly. It returns
**1** when any check fails and 0 when they all pass. It is the one mode whose
exit code carries a verdict, because there the scanner itself is under test.
Run it in CI and read `$?`.

It also proves the `SEC001` redaction: it scans an assignment of a known canary
string and asserts the canary reaches no snippet.

There is one positive fixture per rule. The negative fixtures are correct code
that must produce **no** hit. They are parameterized `cursor.execute` with `%s`
and a params sequence, `Manager.raw` with params, a fully literal `shell=True`
command, and `mark_safe` on a constant. They are also `yaml.load` with
`SafeLoader`, a secret assigned from `os.environ`, a literal dict expanded into
`filter`, and a module-level SQL constant.

The rest are `eval` as an attribute alongside `SystemRandom` and `secrets`, a
docstring full of dangerous-looking text, and `string.Template` from a bare
`from string import Template`. The last three start with `format_html`, with a
placeholder template and a separate value argument. The others are `jwt.decode`
with the signature verified, and a fetch of an operator-configured URL.

Run it after you change a rule. A negative fixture that starts to produce a hit
is a regression on correct code, which is the failure this scanner exists to
avoid.

### Indicators, by owning reference

**`a05-injection.md`** — SQL, ORM identifier positions, the shell, and
server-side output:

- `SQL001` — SQL text built by interpolation, which reaches `cursor.execute`,
  `executemany`, `callproc`, `Manager.raw`, `QuerySet.extra`, or `RawSQL`. The
  interpolation is an f-string, a `%` operation, a `.format()` call, or a
  concatenation with anything that is not a literal. Resolved through a local
  or module-level name.
- `SQL002` — the same sinks reached by SQL text the scanner cannot resolve to a
  literal. Reduced severity: unresolved is not the same as wrong. On `.execute`
  alone this is reported only when the receiver names a cursor or a connection.
  `.execute` is a common method name on objects that are not databases.
- `IDN001` — a mapping expanded with `**` into `annotate`, `aggregate`,
  `alias`, `values`, `values_list`, `filter`, `exclude`, `Q`, or `order_by`,
  where the mapping derives from request data. The ORM parameterizes values,
  not identifiers. Expanding a name bound to a literal dict is not reported.
- `IDN002` — a positional argument to `order_by`, `values`, or `values_list`
  that derives from request data. Only those three: a positional argument to
  `filter` or `Q` is an expression, so `filter(user=request.user)` is correct
  code and is deliberately not reported.
- `CMD001` — `os.system` or `os.popen`. HIGH when any argument is not constant.
  LOW as a hygiene note when the command is entirely literal, because the
  argument list form never reaches a shell at all.
- `CMD002` — a call passing `shell=True` with a command that is not constant. A
  fully literal shell command is not reported: a fixed pipeline is what the
  flag is for.
- `CMD003` — `eval`, `exec`, or `compile` as bare-name calls. HIGH when any
  argument is not constant, LOW when they all are.
- `TPL001` — `mark_safe` on a value that is not a constant. `mark_safe` on a
  constant is not reported.
- `TPL002` — `format_html` whose first argument is already interpolated: an
  f-string, a `%` operation, or a `.format()` call. The values went in before
  escaping ran. `format_html("{}", value)` is the correct form and is not
  reported.
- `TPL003` — `Template(...)` or `Engine.from_string(...)` on a non-constant.
  `string.Template` is exempt in both spellings — the attribute form and
  `from string import Template` — because it is the stdlib substitution class
  and not a template engine.
- `TPL004` — `autoescape=False`.

**`a08-integrity-and-deserialization.md`**:

- `DES001` — `pickle.load` / `pickle.loads` and the libraries that carry the
  same protocol: `cPickle`, `_pickle`, `dill`, `cloudpickle`, and
  `joblib.load`. Resolved through `import ... as` and `from ... import`.
- `DES002` — the unsafe `yaml` loaders. The first are `yaml.load` and
  `yaml.load_all` whose `Loader` is absent or is not a `SafeLoader`, decided
  from the keyword or the second positional argument. The next are
  `yaml.unsafe_load` and `yaml.unsafe_load_all`, which construct arbitrary
  Python objects. The last are `yaml.full_load` and `yaml.full_load_all` at
  MEDIUM, because the object set is wider than `safe_load` and the wider set
  can be deliberate.
- `DES003` — `marshal.load` / `marshal.loads`.
- `DES004` — `jsonpickle.decode` / `jsonpickle.loads`.
- `DES005` — a Celery task or result serializer set to `"pickle"`.
- `DES006` — an `accept_content` list that admits `pickle` or
  `application/x-python-serialize`. That setting decides what a worker will
  execute, whatever the producers are configured to send.

**`a04-cryptographic-failures.md`**:

- `NET001` — `verify=False`, which disables TLS certificate verification on an
  outbound call.
- `NET002` — `ssl._create_unverified_context()`, `check_hostname = False`, or
  `verify_mode = ssl.CERT_NONE`. The same failure `NET001` catches at the
  `requests` layer, caught where a custom client builds its own context.
- `RND001` — `random.random`, `randint`, `choice`, `shuffle`, `sample`, and
  `random.Random`. LOW: the default generator is a Mersenne Twister and is
  reconstructible from its output. Each hit therefore turns on whether the
  value is a secret, a token, or an identifier. `random.SystemRandom` and
  `secrets` do not match.

**`service-identity-and-secrets.md`**:

- `SEC001` — a name that ends in `SECRET`, `SECRET_KEY`, `SIGNING_KEY`,
  `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`, `PASSWORD`, `PASSWD`, `PASSPHRASE`,
  or `TOKEN`. The name carries a `str` or `bytes` literal of eight characters
  or more. Heuristic, so confirm the value is not a placeholder. Any assignment
  whose value is a call is structurally excluded, which covers `os.environ`,
  `env()`, `config()`, and every other loader without naming them. The snippet
  is redacted: the report names the line and never prints the literal.
- `SEC002` — `jwt.decode` with `verify=False` or an `options` literal carrying
  `verify_signature: False`. The token's contents are then whatever the caller
  wrote.

**`a02-security-misconfiguration.md`**:

- `CFG002` — `CORS_ALLOW_ALL_ORIGINS = True`.
- `CFG003` — `DEBUG = True`.
- `CFG004` — `ALLOWED_HOSTS` containing `*`.

**`api-drf-specific.md`**:

- `CFG001` — `fields = "__all__"` on a serializer or `ModelForm` `Meta`. Every
  model field is exposed or writable, including ones added later.
- `CFG005` — `@csrf_exempt`. Routed here rather than to the settings file,
  because DRF enforces CSRF inside `SessionAuthentication` rather than through
  the middleware. What `authentication_classes` resolves to for the view
  therefore decides whether the decorator removed a check at all.

**`graphql-and-alternative-api-surfaces.md`**:

- `CFG006` — graphene `bypass_get_queryset`, as a decorator, a keyword, or an
  assignment. It makes traversal skip `get_queryset` entirely, so the resolver
  opts out of every scope its type declares.

**`a01-broken-access-control.md`**:

- `NET003` — a `requests`/`httpx` verb or `urllib.request.urlopen` call whose
  URL argument derives from request data. The scanner resolves it through the
  same taint machinery as the ORM identifier rules. A URL from a settings value
  or a module constant is not reported. Who last wrote the value is the SSRF
  question, and this rule only fires when the answer is the request.
