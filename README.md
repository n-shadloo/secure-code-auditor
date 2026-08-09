# secure-code-auditor

A Claude Agent Skill for backend security work. It reviews existing code for
vulnerabilities and applies secure defaults while new code is written. The
deep specialty is Django and Django REST Framework; underneath that sits a
general OWASP layer that applies to any backend stack, so the same skill is
useful whether or not you're on Django.

## Why this exists

Backend security review is repetitive and easy to do inconsistently. The high-
risk areas — access control, injection, auth and tokens, serializer exposure,
secrets, deployment settings — are well understood, but they're spread across a
lot of documentation and they change (Django ships security releases regularly).
This skill packages that knowledge so an agent applies it the same way every
time, and points a reviewer straight at the parts that matter.

It's organized on the OWASP Top 10 (2025) as a spine. Each category has two
layers: a short, stack-agnostic explanation of the vulnerability and its defense,
then a deep Django/DRF section with the actual settings, code, and gotchas.
Findings always carry a CWE and an OWASP mapping; where a project is genuinely
held to OWASP ASVS 5.0, they can carry an ASVS chapter as well. The methodology
file maps all seventeen ASVS chapters onto the reference files, and says plainly
which two are permanent non-goals for a backend skill, where the coverage is
only partial, and where this skill covers ground ASVS scopes out entirely.

Security topics don't sort cleanly into ten boxes, so the router is grouped —
the OWASP spine, then cross-cutting surfaces, then package decisions — and
every topic that more than one file could plausibly own has a single named
owner. Rate limiting, object-level authorization, secrets, SSRF, error
behaviour and the rest are each settled once, in an "Ownership and boundaries"
section under the router, and every other file cross-references the owner
rather than keeping its own copy of the rules. Each reference file restates its
own half of that boundary in its opening paragraph, so an agent that opened the
wrong file first is told where to go.

Every control is written twice, in two grammars: a review form that says what
to flag in code that exists, and a write-time form that says what to write
before it does. Agreeing that views should be authorized and emitting a viewset
with no permission class are different operations, so the second form is not
left to follow from the first. It sits directly under the control it completes,
in the same file, which means opening a reference for a concern also loads the
rule for generating that code.

## What it covers

- Access control: object- and function-level authorization, IDOR/BOLA,
  cache-mediated data leaks, SSRF and the egress control behind it —
  allowlist-by-destination, deny-by-default egress for the workers whose
  destinations are known in advance, and the split between what the platform
  enforces and what the application checks — path traversal as the same
  failure against the filesystem, where `os.path.join` reads like a
  containment function and is not one, `FileResponse` validates nothing, and
  the fix is to let the client name an identifier rather than a path — open
  redirect, multi-tenancy, admin exposure.
- Authorization architecture: the privilege model (RBAC/ABAC/ReBAC), what
  Django's permission layer actually does, the DRF and admin enforcement
  surfaces, default-deny with a URLconf audit test, field-level authorization,
  and authorization test design that isn't false confidence.
- Privileged access: impersonation ("log in as user"), break-glass and
  just-in-time elevation, and the operator audit identity both require.
- File uploads: type/content validation, safe names and storage keys that leak
  nothing, inert storage and serving, the object-store settings a code review
  can see and the platform state it cannot, delegated upload URLs and what
  each unbound constraint hands an attacker, direct-to-storage uploads with a
  quarantine prefix and a verification step that reads size and type back from
  the store, callback and event-notification trust, SVG, image/archive bombs,
  size/count limits, quotas, private downloads, the choice between proxying
  and signing, and CDN cache keys that turn a signed URL into a cross-user
  read.
- Injection: the sink inventory every other reference defers to — every
  interpreter a request can reach, and which file owns each one — with the
  method for tracing a source to it, worked end to end on the stored field
  whose writer and reader sit in different requests; SQL/ORM (including the
  dictionary-expansion column-alias class, and the two GeoDjango positions the
  ORM does not parameterize — a raster band index PostGIS inlines as syntax,
  and a spatial-lookup value read as a raster source to open rather than as a
  value to bind), command and argument injection,
  template injection and server-side output handling, LDAP/directory
  injection, and header/email injection.
- Authentication: sessions, JWT, OAuth2/OIDC and social login, API keys,
  brute-force resistance, MFA, password reset, and enumeration resistance.
- API/DRF: where the framework runs an object check and every route that skips
  it (`@action(detail=True)`, plain `APIView`, overridden `get_object`, bulk),
  function-level authorization on viewset actions, serializer over-exposure and
  mass assignment, pagination/filter/ordering leakage, throttling mechanics that
  decide whether a configured limit is the real one, browsable-API and OpenAPI
  schema exposure, enumerating the live URL map to find shadow endpoints,
  version deprecation that actually ends, default permission classes, CSRF
  interaction, and webhook raw-body handling.
- GraphQL and non-DRF API surfaces: authorization on every resolved edge rather
  than at the query root, all-fields schema types, depth/alias/token/cost limits
  applied before execution, introspection and error-message leakage, mutation
  mass assignment, batching that defeats request throttling, N+1 as resource
  exhaustion, persisted operations, and Django Ninja routes that are public
  because nothing set `auth=`.
- Async/ASGI and Channels: safe ORM boundaries, request-context isolation,
  origin checks, per-connection authentication, authorization, and limits, and
  the subscription as a long-lived query — authorized when it is registered and
  again before every event it publishes.
- Algorithmic resource exhaustion: the design rule that every caller-controlled
  value which multiplies work carries a ceiling the server enforces, the
  paginator, serializer, and recursion mechanics that decide whether one
  exists, and a table naming the surface that owns each bound.
- Agent and LLM-facing interfaces: DRF viewsets republished as MCP tools and
  the controls that silently drop, agent token audience validation and the
  no-passthrough rule, tool scope intersected with the user's own permissions,
  model output and retrieved content as untrusted input, per-agent cost and
  concurrency limits, server-enforced confirmation, and tool-call audit.
- Abuse-resistant notifications: reset/magic-link, invite/share throttling,
  idempotency, anti-enumeration, and SSRF-safe previews.
- Data layer and database: separate migration and runtime roles, row-level
  security and tenant context that survives a connection pool, verified database
  TLS, field-level encryption and blind-index lookups, raw-SQL isolation bypass,
  NoSQL and Redis injection, read-replica staleness in authorization reads,
  transaction isolation and the serialization-failure retry a raised level
  requires rather than merely benefits from, connection exhaustion, and where
  copies of production data may travel.
- Data lifecycle and privacy: deletion completeness and what a soft-delete flag
  does not hide, erasure as a fan-out with a per-target completion ledger,
  files left behind after a row is gone, retention that can be shown to have
  run, anonymization versus pseudonymization, personal-data classification in
  the model layer, and export/subject-access endpoints as an authenticated
  exfiltration path.
- Service identity and secrets: choosing between a static key, an OAuth
  client-credentials token, mutual TLS, and platform workload identity;
  validating an inbound machine token claim by claim; JWKS caching and key
  rotation; proxy-set client-certificate identity; endpoints authenticated only
  by network position; downstream token exchange instead of forwarding; where
  secrets live and how they reach the process; `SECRET_KEY` rotation and what
  it does and does not invalidate; and the ordered response to a leak.
- Configuration: the `SECURE_*`/`SESSION_*`/`CSRF_*` matrix, CORS, headers, the
  DNS records that decide whether your domain can be forged (SPF's ten-lookup
  ceiling, DKIM alignment through a third-party sender, and the DMARC rollout
  under the 2026 specification that removed `pct` and added `np`), CAA and
  dangling-DNS subdomain takeover, and the list of things `check --deploy`
  structurally cannot see.
- Cryptography: choosing a password-hashing family and pinning its cost to the
  hardware that runs it, why a stock Django install is on PBKDF2 no matter what
  is in its requirements file, parameter increases that propagate as users log
  in, randomness and token generation as the failure this category actually
  catches most often, where a constant-time comparison earns its place and
  where it is noise, per-purpose salt discipline so a token minted for one flow
  cannot be replayed against another, the key lifecycle from generation to
  destruction with envelope encryption and resumable re-encryption, and a sober
  post-quantum posture that is an inventory rather than a migration.
- Integrity and cross-system trust: the inbound webhook receiver end to end
  (raw-body capture before any parser, a timestamp inside the signed material,
  constant-time comparison, per-provider signing schemes, and a de-duplication
  store keyed on the provider's event id), outbound delivery that isn't an SSRF
  proxy or a retry amplifier, insecure deserialization including the cache,
  session, and fixture paths Django deserializes without being asked, Celery
  task messages as input from anyone who can reach the broker and the
  confidentiality a signed serializer does not provide, artifact provenance,
  and safe schema/data migrations.
- Logging and lifecycle: secret-safe audit logs, complete lifecycle coverage,
  post-commit side effects, error handling, and alerting.
- Exceptional conditions and concurrency: fail-closed error handling and the
  shapes that fail open instead, race conditions and TOCTOU, when the right
  defence is a database constraint and when it is a row lock, the four ways
  `select_for_update()` silently does nothing, idempotency-key design with a
  request fingerprint so a reused key cannot answer a different request, side
  effects ordered against the commit, state transitions the database arbitrates
  rather than a Python check, and regular-expression denial of service.
- Deployment/runtime: TLS, security headers and which layer owns each one,
  reverse-proxy trust and reading the client IP from the right of
  `X-Forwarded-For` rather than the attacker-supplied left, debug toolbars and
  profilers reachable in production, Gunicorn/systemd, the container image as a
  build artifact of its own (non-root, pinned base, and the secrets that stay
  readable in a layer after a later layer deletes them), origin-isolated media,
  caching, and brokers.
- Supply chain: third-party dependency vetting, maintained-package gates, the
  development-only package that reaches the production requirements file and
  ships a debugger with it, pinning, hashing, advisory scanning, SBOMs, and EOL
  frameworks.

Version baseline is kept current (Django 6.1, 6.0.8, and 5.2.17 LTS; DRF
3.18.0; Channels 4.3.2; django-allauth 65.19.0; dj-rest-auth 7.2.0;
django-oauth-toolkit 3.4.0; social-auth-app-django 6.0.1, as of 8 Aug 2026).
Compatibility is checked per package: SimpleJWT 5.5.1 and several optional
auth/CSP helpers remain conditional on Django 5.2, and projects on end-of-life
Django are flagged. Each area carries the date it was last checked.

| Date checked | Area | Disposition |
|---|---|---|
| 1 Aug 2026 | Authorization and impersonation | django-guardian 3.3.3, django-hijack 3.7.8, rules 3.5, and the external policy engines. |
| 1 Aug 2026 | Agent and MCP integration | django-mcp-server 0.5.7, django-rest-framework-mcp 0.1.0a4, and the admin- and shell-exposing candidates; none recommended. |
| 2 Aug 2026 | Data layer | django-tenants, the official django-mongodb-backend, and PyCA cryptography 50.0.0; every packaged Django field-encryption library rejected as abandoned. |
| 2 Aug 2026 | Data lifecycle | django-simple-history 3.13.0, django-celery-beat 2.9.0, django-cleanup 9.0.0, and Faker 40.36.0; the two soft-delete packages and the dedicated privacy packages not recommended. |
| 2 Aug 2026 | Framework currency | Django 6.0.7, 5.2.16 LTS, and DRF 3.17.1 re-confirmed current on this date. |
| 3 Aug 2026 | Service identity | PyJWT 2.13.0 recommended with a `>=2.13.0` floor; SimpleJWT re-checked and confirmed not to cap PyJWT, while remaining out of scope as a machine-identity mechanism. |
| 4 Aug 2026 | GraphQL and non-DRF | strawberry-graphql 0.323.2 with strawberry-graphql-django 0.86.8 conditional and pinned; django-ninja 1.6.2 conditional; graphene-django 3.2.3 existing-install audit only, declaring no support for Django 5.2 or 6.0 and unreleased since March 2025. |
| 5 Aug 2026 | API surface and schema | drf-spectacular 0.30.0 and django-filter 26.1 recommended, the latter only with explicit field allowlists; django-extensions 4.1 a development-only existing-install disposition; both DRF bulk packages rejected because their bulk paths skip per-object authorization. |
| 7 Aug 2026 | Runtime and proxy trust | django-ipware 7.0.1 rejected for new use, unreleased since April 2024 and declaring no supported Django version at all; django-debug-toolbar 7.0.0 and django-silk 5.5.0 rejected for production as development-only tooling rather than on maintenance grounds. |
| 7 Aug 2026 | Concurrency and idempotency | google-re2 1.1.20251105 and django-fsm-2 4.2.4 conditional; django-fsm 3.0.1 rejected for new use because PyPI classifies it inactive and its own README renames the line to viewflow.fsm; the two idempotency-key packages rejected as stale; Redis distributed-lock packages rejected as a correctness primitive on design grounds. |
| 7 Aug 2026 | Integrity and webhooks | standardwebhooks 1.1.0 conditional and only for signing the webhooks you send; PyYAML 6.0.3 conditional on safe_load at every call site; svix 1.99.1 rejected as a verification dependency because it pulls six packages transitively to compute one HMAC; nothing recommended for verifying an inbound webhook, because the standard library's hmac module already covers it. |
| 7 Aug 2026 | Cryptographic primitives | argon2-cffi 25.1.0 and PyCA cryptography 50.0.0 recommended and now in their own section of the index; django-fernet-encrypted-fields 0.4.0 conditional as the one packaged field-encryption library still maintained, its condition being that it derives its key from SECRET_KEY and a SALT_KEY setting; application-layer post-quantum libraries not adopted this cycle. |
| 7 Aug 2026 | Object storage | `django-storages` 1.14.6 stays rejected as a new recommendation, now recorded with the evidence: its own Django classifiers stop at 5.1, and on an existing install `AWS_S3_CUSTOM_DOMAIN` makes `url()` return an unsigned URL unless a CloudFront signer is configured alongside it, silently overriding `AWS_QUERYSTRING_AUTH`. Provider object-storage SDKs are patterns to audit rather than gate entries, on the same basis as the cloud KMS SDKs. |
| 8 Aug 2026 | LDAP | `django-auth-ldap` 5.3.0 recommended where a directory is the identity source, because it escapes filter arguments by default and declares Django 4.2, 5.2, and 6.0; `python-ldap` carries an explicit `>=3.4.5` floor for CVE-2025-61911 that the integration's own `>=3.1` requirement does not enforce. |
| 8 Aug 2026 | Coordinated re-date | Baseline moved onto Django 6.1, 6.0.8, and 5.2.17 LTS with DRF 3.18.0. Django 6.0.8 and 5.2.17 were the 4 Aug 2026 security releases fixing four issues, the most serious a file-write and request-forgery flaw reachable through spatial lookups; 6.1 followed on 5 Aug 2026, which puts 6.0 on security fixes only through April 2027. |
| 8 Aug 2026 | DRF line | The security fixes are in 3.17.2 rather than in 3.18.0, so 3.17.2 is the minimum safe version, while 3.18.0 is a feature release that drops three end-of-life Django lines and changes the error shape list serializers return. |
| 8 Aug 2026 | OAuth and social login | django-oauth-toolkit 3.4.0, a mandatory floor rather than a preferred one: below it the authorization endpoint carries an unauthenticated open redirect under `prompt=none`, tokens and codes render in cleartext in the admin, client secrets reach debug logs, device-flow user codes are predictable, and redirect-URI matching deviates from RFC 9700 in four ways. django-allauth moved to 65.19.0 and social-auth-app-django to 6.0.1. |
| 8 Aug 2026 | Django 6.1 lag | Most other entries still declare support through Django 6.0 rather than 6.1, which days after a feature release is packaging lag rather than a compatibility finding. |

## Install

The repository is a plain-Markdown Agent Skill. The canonical instructions live
in the root `SKILL.md`, which routes to the files under `references/`. Claude
reads the skill directly. Cursor and OpenAI Codex CLI reuse the same canonical
content through their native discovery mechanisms, while Gemini CLI reads a
`GEMINI.md` context file. Nothing needs to be built; there are no dependencies
beyond `git`.

### Claude

One project:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  .claude/skills/secure-code-auditor
```

All your projects:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  ~/.claude/skills/secure-code-auditor
```

For claude.ai or the API, upload the folder as a custom skill in Settings.

### Codex CLI

Codex CLI discovers Agent Skills from the `.agents/skills/` directory. Cloning
the repository there is the whole mechanism: the clone's own root `SKILL.md` is
the canonical instruction file, and there is no separate pointer skill to
install.

One project:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  .agents/skills/secure-code-auditor
```

All your projects:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  ~/.agents/skills/secure-code-auditor
```

`AGENTS.md` provides project-wide context and points at the same `SKILL.md` and
`references/`.

### Cursor

Cursor natively supports Agent Skills, so the same repository works:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  .cursor/skills/secure-code-auditor
```

The included `.cursor/rules/secure-code-auditor.mdc` file is optional
reinforcement that points back to the canonical `SKILL.md`.

### Gemini CLI

Gemini CLI doesn't read Agent Skills directly; it reads `GEMINI.md`.

- **Per project:** copy `GEMINI.md` into the repository root.
- **All projects:** copy it to `~/.gemini/GEMINI.md`.

`GEMINI.md` points Gemini to the canonical `SKILL.md` and `references/`
instead of duplicating the content.

The only requirement is `git` and a Git repository to run in.

## Use

Two modes, chosen from context.

Review an existing codebase — ask for a security review, or point it at code:

```
Review this Django app for security issues before we ship.
```

You'll get findings ordered by severity, each with a location, a CWE and OWASP
mapping, the concrete problem, the impact, and a fix. For fast triage there are
two read-only helper scripts (no network access, they don't run your project):

```
python scripts/settings_scan.py config/settings/production.py
python scripts/dangerous_patterns.py .
```

Write new code — it applies secure defaults as it goes (parameterized queries,
scoped querysets, explicit serializer fields, correct cookie flags, secrets from
the environment) and closes with a short "Security decisions" note rather than
a findings report: the defaults it applied, anything your request forced along
with the residual risk, and anything left for you to do. Where a secure default
conflicts with what you asked for, it applies the default and says so in one
line naming the risk and the opt-out, so nothing is downgraded or refused
silently.

## Example finding

```
### [High] Object endpoint returns any user's invoice (IDOR)
- Location: billing/views.py:42
- Category: Broken Object Level Authorization | CWE-639 | OWASP A01:2025, API1:2023
- Confidence: High
- Problem: InvoiceDetail uses Invoice.objects.all() and looks up by pk from the
  URL with permission_classes = [IsAuthenticated]. Authentication is checked but
  ownership is not, so any logged-in user can read /invoices/<id>/ for any id.
- Impact: Authenticated horizontal privilege escalation; read access to other
  accounts' billing records by incrementing the id.
- Fix: scope the queryset to the requester.

    def get_queryset(self):
        return Invoice.objects.filter(account=self.request.user.account)
```

## Notes

The scripts need only the Python standard library (3.9+). Findings from the
scripts are indicators to verify, not confirmed vulnerabilities. Security is not
a checklist you finish; treat this as a strong, current baseline, not a guarantee.
The skill version is recorded in SKILL.md frontmatter (`metadata.version`); releases are tagged in git.

## Layout

```text
secure-code-auditor/
├── SKILL.md                            # canonical skill and router
├── AGENTS.md                           # always-on project context
├── GEMINI.md                           # Gemini CLI context
├── .cursor/
│   └── rules/
│       └── secure-code-auditor.mdc     # Cursor reinforcement rule
├── references/
│   ├── 00-methodology-and-severity.md  # methodology and findings format
│   ├── a01-broken-access-control.md
│   ├── a02-security-misconfiguration.md
│   ├── a03-software-supply-chain.md
│   ├── a04-cryptographic-failures.md
│   ├── a05-injection.md
│   ├── a06-insecure-design.md
│   ├── a07-authentication-failures.md
│   ├── a08-integrity-and-deserialization.md
│   ├── a09-logging-and-alerting.md
│   ├── a10-exceptional-conditions.md
│   ├── agent-and-llm-interfaces.md
│   ├── api-drf-specific.md
│   ├── async-and-channels.md
│   ├── authorization-architecture.md
│   ├── data-layer-and-database.md
│   ├── data-lifecycle-and-privacy.md
│   ├── deployment-and-runtime.md
│   ├── file-uploads.md
│   ├── graphql-and-alternative-api-surfaces.md
│   ├── privileged-access-and-impersonation.md
│   ├── security-hardening-libraries.md
│   └── service-identity-and-secrets.md
├── scripts/
│   ├── dangerous_patterns.py           # read-only project scanner
│   ├── settings_scan.py                # read-only Django settings scanner
│   └── README.md
├── README.md
├── LICENSE
└── .gitignore
```

## License

MIT. See `LICENSE`.
