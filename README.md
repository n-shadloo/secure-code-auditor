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

## What it covers

- Access control: object- and function-level authorization, IDOR/BOLA,
  cache-mediated data leaks, SSRF, open redirect, multi-tenancy, admin exposure.
- Authorization architecture: the privilege model (RBAC/ABAC/ReBAC), what
  Django's permission layer actually does, the DRF and admin enforcement
  surfaces, default-deny with a URLconf audit test, field-level authorization,
  and authorization test design that isn't false confidence.
- Privileged access: impersonation ("log in as user"), break-glass and
  just-in-time elevation, and the operator audit identity both require.
- File uploads: type/content validation, safe names and inert storage/serving,
  SVG, image/archive bombs, size/count limits, quotas, private downloads.
- Injection: SQL/ORM (including the recent column-alias class), command,
  template, and header injection; server-side output handling.
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
  origin checks, and per-connection authentication, authorization, and limits.
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
  connection exhaustion, and where copies of production data may travel.
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
- Configuration: the `SECURE_*`/`SESSION_*`/`CSRF_*` matrix, CORS, headers.
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
  task messages as input from anyone who can reach the broker, artifact
  provenance, and safe schema/data migrations.
- Logging and lifecycle: secret-safe audit logs, complete lifecycle coverage,
  post-commit side effects, error handling, and alerting.
- Exceptional conditions and concurrency: fail-closed error handling and the
  shapes that fail open instead, race conditions and TOCTOU, when the right
  defence is a database constraint and when it is a row lock, the four ways
  `select_for_update()` silently does nothing, idempotency-key design with a
  request fingerprint so a reused key cannot answer a different request, side
  effects ordered against the commit, state transitions the database arbitrates
  rather than a Python check, and regular-expression denial of service.
- Deployment/runtime: TLS, headers, reverse-proxy trust, Gunicorn/systemd,
  origin-isolated media, caching, and brokers.
- Supply chain: third-party dependency vetting, maintained-package gates,
  pinning, hashing, advisory scanning, SBOMs, and EOL frameworks.

Version baseline is kept current (Django 6.0.7 / 5.2.16 LTS; DRF 3.17.1;
Channels 4.3.2; django-allauth 65.18.0; dj-rest-auth 7.2.0;
django-oauth-toolkit 3.3.0; social-auth-app-django 6.0.0, as of 17 Jul 2026).
Compatibility is checked per package: SimpleJWT 5.5.1 and several optional
auth/CSP helpers remain conditional on Django 5.2, and projects on end-of-life
Django are flagged. The authorization and impersonation packages
(django-guardian 3.3.3, django-hijack 3.7.8, rules 3.5, and the external policy
engines) and the agent/MCP integration packages (django-mcp-server 0.5.7,
django-rest-framework-mcp 0.1.0a4, and the admin- and shell-exposing
candidates, none of which are recommended) were checked separately on
1 Aug 2026. The data-layer packages (django-tenants, the official
django-mongodb-backend, PyCA cryptography 50.0.0, and the packaged Django
field-encryption libraries, every one of which is rejected as abandoned) were
checked on 2 Aug 2026, as were the data-lifecycle packages
(django-simple-history 3.13.0, django-celery-beat 2.9.0, django-cleanup 9.0.0,
Faker 40.36.0, the two soft-delete packages, and the dedicated privacy
packages, none of which is recommended). Django 6.0.7, 5.2.16 LTS, and DRF
3.17.1 were re-confirmed as current on that date. The service-identity
packages were checked on 3 Aug 2026: PyJWT 2.13.0 is recommended with a
`>=2.13.0` floor, and SimpleJWT was re-checked and confirmed not to cap PyJWT,
while remaining out of scope as a machine-identity mechanism. The GraphQL and
non-DRF packages were checked on 4 Aug 2026: strawberry-graphql 0.323.2 with
strawberry-graphql-django 0.86.8 is conditional and pinned, django-ninja 1.6.2
is conditional, and graphene-django 3.2.3 is existing-install audit only
because it declares no support for Django 5.2 or 6.0 and has not released since
March 2025. The API-surface packages were checked on 5 Aug 2026:
drf-spectacular 0.30.0 and django-filter 26.1 are recommended (the latter only
with explicit field allowlists), django-extensions 4.1 is a development-only
existing-install disposition, and both DRF bulk packages are rejected because
their bulk paths skip per-object authorization. The concurrency and idempotency
packages were checked on 7 Aug 2026: google-re2 1.1.20251105 and django-fsm-2
4.2.4 are conditional, django-fsm 3.0.1 is rejected for new use because PyPI
classifies it inactive and its own README renames the line to viewflow.fsm, the
two idempotency-key packages are rejected as stale, and Redis distributed-lock
packages are rejected as a correctness primitive on design grounds. The
integrity and webhook packages were checked on the same date: standardwebhooks
1.1.0 is conditional and only for signing the webhooks you send, PyYAML 6.0.3 is
conditional on safe_load at every call site, svix 1.99.1 is rejected as a
verification dependency because it pulls six packages transitively to compute
one HMAC, and nothing is recommended for verifying an inbound webhook, because
the standard library's hmac module already covers it. The cryptographic
primitives were re-checked on the same date: argon2-cffi 25.1.0 and PyCA
cryptography 50.0.0 are recommended and now sit in their own section of the
index, django-fernet-encrypted-fields 0.4.0 is conditional as the one packaged
field-encryption library that is still maintained — its condition being that it
derives its key from SECRET_KEY and a SALT_KEY setting — and application-layer
post-quantum libraries are not adopted this cycle. Django 6.0.8 and 5.2.17
LTS were published on 4 Aug 2026, after this baseline was set, fixing
four security issues; the repository baseline is unchanged until the next
coordinated re-date, and any project still on 6.0.7 or 5.2.16 should take the
patch now.

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

Codex CLI discovers Agent Skills from the `.agents/skills/` directory and uses
the bundled pointer skill to load the canonical `SKILL.md`.

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

`AGENTS.md` provides project-wide context, while the pointer skill forwards to
the canonical instructions in the repository root.

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
the environment) and notes the security-relevant choices it made.

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
