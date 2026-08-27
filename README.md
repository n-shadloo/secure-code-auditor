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
only partial, and where this skill covers ground ASVS scopes out entirely. ASVS
has no chapter for agent and MCP tool surfaces, so that file carries a spine of
its own: the OWASP LLM Top 10 2026 and Agentic Top 10, mapped section by section
at entry-token level, with the entries a backend skill declares non-goals named
rather than stretched to fit.

Security topics don't sort cleanly into ten boxes, so the router is grouped —
the OWASP spine, then cross-cutting surfaces, then package decisions — and
every topic that more than one file could plausibly own has a single named
owner. Rate limiting, object-level authorization, secrets, SSRF, error
behavior and the rest are each settled once, in an "Ownership and boundaries"
section under the router, and every other file cross-references the owner
rather than keeping its own copy of the rules. That section is a table of
contested topic, owner, and the distinction that decides a case near the
boundary; three splits — path traversal, configuration against runtime, and
human against machine identity — keep a paragraph because a row would misstate
the axis they turn on. Each reference file restates its own half of that
boundary in its opening paragraph, so an agent that opened the wrong file first
is told where to go.

Knowing all of that still leaves the question of what to open first. A review
is bounded by whatever the reviewer thought to look at, and a route nobody
enumerated is not reviewed by a skill that knows everything about routes. So
the sweep is a procedure of its own, run inventory-first: establish every way
a request, a message, or a schedule reaches application code, work out which
principals arrive there, and derive the reading list from that rather than
from the files that looked interesting. Each phase hands the next one a written
artifact and ends on a property of its coverage rather than on an amount of
reading, because a phase that hands forward an impression makes the next one
re-derive it, and re-derivation is how a review narrows onto whatever it read
most recently. Where the tree is larger than the reading available, the
inventory is still completed over all of it and only the close reading is
rationed — per area rather than spent on the first lead, and with any family
read as a sample recorded as a sample, so that a partial audit is not delivered
in the shape of a complete one. It ends in a coverage ledger that
keeps *examined and clean* separate from *not examined*, because a report that
blurs the two is read as though everything was covered. That same file maps the
sweep onto the OWASP Web Security Testing Guide, section by section, and says
which of the guide's twelve web-application sections this skill covers and
which it declares non-goals: the client-side chapter, the reconnaissance tests,
and everything that needs a proxy or a live target, since this skill reads
source rather than exercising a deployment. The mapping stops at section
granularity because the guide's own referencing guidance says its test
identifiers change between versions — the same reason the ASVS mapping cites
chapters rather than requirement numbers.

Every control is written twice, in two grammars: a review form that says what
to flag in code that exists, and a write-time form that says what to write
before it does. Agreeing that views should be authorized and emitting a viewset
with no permission class are different operations, so the second form is not
left to follow from the first. It sits directly under the control it completes,
in the same file, which means opening a reference for a concern also loads the
rule for generating that code.

## What it covers

- The audit workflow itself: the order the phases run in, an entry-point
  inventory covering URLconf chains resolved to the full prefix, DRF routers
  and `@action` methods, Django Ninja, GraphQL, gRPC, Channels, Celery tasks
  and beat schedules, management commands, signals, admin registrations and
  actions, webhook receivers, MCP tools, and middleware; the principals a
  Django backend actually distinguishes and the boundaries between them;
  pairing sources to sinks; ordering hypotheses by impact against the effort
  to confirm them; the six-item gate a hypothesis has to discharge before it
  is written up at all, with the benign Django and DRF patterns that look
  exactly like defects cataloged beside the controls they qualify; a coverage
  ledger that reports what was examined and found clean separately from what
  was never opened; and the attack chains worth looking for, each rated as one
  finding at the severity of its outcome rather than as three unrelated
  Mediums. Then what holds the fix afterwards: one regression test per closed
  finding that states the attack rather than the patch, proven by
  reintroducing the defect and watching the suite fail, and a pipeline gate
  that reads the bundled scanners' records because their exit code is always
  0 by design.
- Access control: object- and function-level authorization, IDOR/BOLA, the
  generic relation whose target model a client picks by naming a content
  type — where the object permission written for one model does not run for
  another, and a check placed before the pair is resolved checks a type name
  instead of a record — URL resolution as the surface every one of those
  checks assumes, where an endpoint pattern missing its terminating anchor
  matches more than its shape, the first of two matching patterns wins while
  the second is the one carrying the permission, and the review action is to
  group the resolved routes rather than read the route files,
  cache-mediated data leaks, SSRF and the egress control behind it —
  allowlist-by-destination, deny-by-default egress for the workers whose
  destinations are known in advance, and the split between what the platform
  enforces and what the application checks — path traversal as the same
  failure against the filesystem, where `os.path.join` reads like a
  containment function and is not one, `FileResponse` validates nothing, and
  the fix is to let the client name an identifier rather than a path — open
  redirect including the language switch that is one, the locale prefix
  redirect and the cache key that loses the request's language while `Vary`
  still names it, multi-tenancy, admin exposure.
- Authorization architecture: the privilege model (RBAC/ABAC/ReBAC), what
  Django's permission layer actually does, the DRF and admin enforcement
  surfaces, default-deny with a URLconf audit test, field-level authorization,
  authorization test design that isn't false confidence, and the joiner,
  mover, and leaver path — what a disable at the identity provider does not
  reach, and why a locally made grant survives a provider-side removal.
- Privileged access: impersonation ("log in as user"), break-glass and
  just-in-time elevation, and the operator audit identity both require.
- File uploads: type/content validation, safe names and storage keys that leak
  nothing, inert storage and serving, the metadata an object store echoes back
  on serve, the object-store settings a code review can see and the platform
  state it cannot, per-tenant buckets against a shared bucket with prefixes,
  delegated upload URLs and what each unbound constraint hands an attacker
  across S3, GCS, and Azure — which of the three can bind a size at all, and
  what it takes to withdraw a URL early on each — direct-to-storage uploads
  with a quarantine prefix and a verification step that reads size and type
  back from the store, scan verdict caching and content disarm, callback and
  event-notification trust, SVG, image/archive bombs, size/count limits,
  quotas, private downloads, the choice between proxying and signing, and CDN
  cache keys that turn a signed URL into a cross-user read.
- Injection: the sink inventory every other reference defers to — every
  interpreter a request can reach, and which file owns each one — with the
  method for tracing a source to it, worked end to end on the stored field
  whose writer and reader sit in different requests; SQL/ORM (including the
  dictionary-expansion column-alias class, and the two GeoDjango positions the
  ORM does not parameterize — a raster band index PostGIS inlines as syntax,
  and a spatial-lookup value read as a raster source to open rather than as a
  value to bind), command and argument injection,
  template injection and server-side output handling, LDAP/directory
  injection, header/email injection, XML external entity injection and entity
  expansion named at the XML sink, the exported CSV or workbook cell whose
  interpreter is a spreadsheet program on the reader's machine, and the
  duplicated request parameter that a check and a use read differently because
  one calls `getlist` and the other subscripts the `QueryDict`.
- Authentication: password policy stated as the standard actually states it —
  fifteen characters where the password is a single factor, no composition
  rule, no expiry job, and a blocklist that reaches a breach corpus rather
  than the twenty thousand entries Django ships — with the screening validator
  written out because no maintained package currently clears the gate to
  provide it; the user model read as an identity contract, where the
  identifier field, the normalization applied before storage, and the
  collation the database compares under all have to agree before two rows
  are one person, and where `is_active` is a constant `True` on a model that
  never declared it; sessions, with the engine choice that decides whether
  one can be revoked at all and the three calls that rotate one; JWT,
  OAuth2/OIDC and social login including the mix-up attack under the name
  the advisories use, API keys, brute-force resistance, MFA, passkey and
  WebAuthn configuration on a framework that ships no native support for
  either, password reset, and enumeration resistance.
- API/DRF: where the framework runs an object check and every route that skips
  it (`@action(detail=True)`, plain `APIView`, overridden `get_object`, bulk),
  function-level authorization on viewset actions, serializer over-exposure and
  mass assignment including `ModelForm` and formsets, writable relation fields
  scoped to the caller, pagination/filter/ordering leakage, throttling
  mechanics that decide whether a configured limit is the real one and the
  atomic counter to reach for when it has to be, browsable-API and OpenAPI
  schema exposure,
  enumerating the live URL map to find shadow endpoints,
  version deprecation that actually ends, default permission classes, CSRF
  interaction, and webhook raw-body handling.
- GraphQL and non-DRF API surfaces: authorization on every resolved edge rather
  than at the query root, all-fields schema types, depth/alias/token/cost limits
  applied before execution, introspection and error-message leakage, mutation
  mass assignment, batching that defeats request throttling, N+1 as resource
  exhaustion, persisted operations, Django Ninja routes that are public
  because nothing set `auth=`, and gRPC servicers, which answer on a second
  server Django's request cycle never enters — every method public until an
  interceptor is installed, a send-size and a concurrency limit with no default
  at all, `Any` unpacking on the sender's terms, and reflection as the
  introspection analog.
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
  concurrency limits, server-enforced confirmation, tool-call audit, and the
  file's own standards mapping onto the OWASP LLM Top 10 2026 and Agentic
  Top 10.
- Agent-operator security, which is the other side of that boundary: the
  access the reviewing agent itself holds. The credential files it must never
  open and why a `.gitignore` or an ignore-file rule is not the control, the
  name-by-location rule for every finding, report, commit message, and fixture
  it writes and why redaction is a backstop rather than a control, the kind,
  scope, and life of its own repository credential, CI token, and deploy key
  ranked by blast radius, the per-job token permission and the federated cloud
  credential that replace a stored one, revocation at the end of the task,
  instructions arriving through repository content, a ticket, or tool output
  treated as data rather than as authority, the confirmation gate on a
  rotation or a revocation a finding recommends, and the command, change, and
  cloud-action record that a layer the agent cannot edit has to author.
- Money, entitlement, and state-transition flows: how to find every path that
  moves a balance, a price, a credit, a plan, an expiry, or a status before
  reasoning about any of them — from the model fields those values live in,
  then from every writer of one, including the management command, Celery
  task, admin action, signal receiver, data migration, and bulk queryset write
  that never pass through a view, and finally from the external events that
  drive them; the single question that decides each transition, whether its
  invariant is held by the database or only by a Python check that runs on one
  path; amounts, currencies, and discounts resolved from server records keyed
  by an identifier the client supplies; capture, refund, and reversal as design
  questions about what is irreversible, what compensates rather than reverses,
  and what a partial failure between the provider and the local record leaves
  behind; and entitlement grants weighed against the revocation nobody
  demonstrates — the entitlement that survives its subscription, the seat that
  survives its team, the cached permission that outlives the role change, and
  the trial that restarts.
- Abuse-resistant side effects: the general rule that any action which spends a
  budget, notifies a third party, or cannot be undone needs a bound, with
  reset/magic-link, invite/share throttling, idempotency, anti-enumeration, and
  SSRF-safe previews as the worked instance of it.
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
- Configuration: the `SECURE_*`/`SESSION_*`/`CSRF_*` matrix, the `__Host-`
  and `__Secure-` cookie prefixes as the one cookie property a sibling
  subdomain cannot work around, with the four settings each prefix needs to
  agree with and the silent drop that follows when they don't, the
  signed-cookie salt collision Django fixed in June 2026 and the transitional
  setting whose default flipped in 6.1, so whether the old cookies are still
  accepted is a question about the installed line rather than about the
  settings file, CORS, headers, the
  DNS records that decide whether your domain can be forged (SPF's ten-lookup
  ceiling, DKIM alignment through a third-party sender, and the DMARC rollout
  under the 2026 specification that removed `pct` and added `np`), CAA and
  dangling-DNS subdomain takeover, the list of things `check --deploy`
  structurally cannot see, the deploy-only guardrail check a project writes
  for the part of that list it can close — with the identifier prefix that
  keeps an unrelated silencing entry from switching it off — drift measured
  against the settings a deployed process actually resolved rather than
  against two files, and the owner, reason, and expiry that turn a
  suppression into an exception with an end date.
- Cryptography: choosing a password-hashing family and pinning its cost to the
  hardware that runs it, why a stock Django install is on PBKDF2 no matter what
  is in its requirements file, parameter increases that propagate as users log
  in and the wrapped-hasher migration that moves the accounts which never log
  in at all, randomness and token generation as the failure this category
  actually catches most often, where a constant-time comparison earns its place
  and where it is noise, per-purpose salt discipline so a token minted for one
  flow cannot be replayed against another, the key lifecycle from generation to
  destruction with envelope encryption worked against a KMS and resumable
  re-encryption, cryptographic agility as a posture rather than a primitive —
  the algorithm and key identifier stored with the value rather than inferred
  from it, and the four-step migration whose measurement step is the one that
  gets skipped — and a sober post-quantum posture that is an inventory rather
  than a migration.
- Integrity and cross-system trust: the inbound webhook receiver end to end
  (raw-body capture before any parser, a timestamp inside the signed material,
  constant-time comparison, per-provider signing schemes, and a de-duplication
  store keyed on the provider's event id), outbound delivery that isn't an SSRF
  proxy or a retry amplifier, insecure deserialization including the cache,
  session, and fixture paths Django deserializes without being asked, Celery
  task messages as input from anyone who can reach the broker and the
  confidentiality a signed serializer does not provide, Django's own built-in
  tasks framework and the in-request execution its default backend gives an
  enqueue that reads as backgrounded, artifact provenance, and safe
  schema/data migrations.
- Logging and lifecycle: secret-safe audit logs, complete lifecycle coverage,
  post-commit side effects, error handling, and alerting; then whether the
  record survives as evidence — an append-only sink, and a hash chain sold
  with its ceiling attached rather than as proof a record was ever written —
  with decoy records and canary tokens as a detection control that never
  stands in for an access control.
- Exceptional conditions and concurrency: fail-closed error handling and the
  shapes that fail open instead, race conditions and TOCTOU, when the right
  defense is a database constraint and when it is a row lock, the four ways
  `select_for_update()` silently does nothing, idempotency-key design with a
  request fingerprint so a reused key cannot answer a different request, side
  effects ordered against the commit, state transitions the database arbitrates
  rather than a Python check, and regular-expression denial of service.
- Deployment/runtime: TLS including the hybrid post-quantum group a current
  OpenSSL already prefers and the copied hardening snippet that quietly pins it
  back out, security headers and which layer owns each one,
  reverse-proxy trust and reading the client IP from the right of
  `X-Forwarded-For` rather than the attacker-supplied left, debug toolbars and
  profilers reachable in production, Gunicorn/systemd, the container image as a
  build artifact of its own (non-root, pinned base, and the secrets that stay
  readable in a layer after a later layer deletes them), origin-isolated media,
  caching, and brokers — plus the two classes that belong to whoever operates
  the edge rather than to this repository, request smuggling between two
  parsers that frame a request differently and cache deception by a rule that
  decides what is cacheable from what a URL looks like, each recorded as a
  cross-team recommendation with the repository-side half named — for
  smuggling that half is the pinned version of the application server and of
  whichever async worker its command line selects, which is an ordinary
  dependency finding even though the exposure itself is not.
- Supply chain: third-party dependency vetting, maintained-package gates, the
  development-only package that reaches the production requirements file and
  ships a debugger with it, pinning, hashing, advisory scanning, EOL
  frameworks, and the build pipeline read as reviewable configuration — the
  SBOM generated from the lockfile rather than from the finished image, and
  why it is an inventory rather than integrity evidence; a scan step judged by
  what its exit code does rather than by whether it exists; build provenance
  and the consumer-side verification without which an attestation proves
  nothing; SLSA Build levels claimed only at the level the platform's own
  documentation supports; and a hard line between the artifacts a repository
  audit can actually read and the registry, deploy, and runner state it has to
  ask an operator about.

Version baseline is kept current (Django 6.1, 6.0.8, and 5.2.17 LTS; DRF
3.18.0; Channels 4.3.2; django-allauth 65.19.0; dj-rest-auth 7.2.0;
django-oauth-toolkit 3.4.0; social-auth-app-django 6.0.1, as of 9 Aug 2026).
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
| 9 Aug 2026 | Cryptographic currency | `argon2-cffi` 25.1.0 and PyCA `cryptography` 50.0.0 both re-confirmed against PyPI with no release and no advisory after the 7 Aug check, so neither pin moves; Django's hard-coded Argon2 parameters re-read off the 6.0 source and unchanged since 3.2. Cloud KMS SDKs stay patterns rather than gate entries, now with the boto3 envelope calls written out in A04 and the GCP and Azure equivalents named beside them. |
| 9 Aug 2026 | Library index sweep | Every package version and classifier in the index re-checked against PyPI on this date, which is what the index date now means. Six entries moved and none of them were flagged by the research for this sweep: `django-tenants` to 3.14.0, which declares Django 6.1 and is now pinned exactly against four minor versions between 30 Jun and 5 Aug; `strawberry-graphql-django` to 0.87.0; `django-mongodb-backend` to 6.0.4; `mcp-django` to 0.14.0, which changes nothing about a disposition resting on what it exposes; `pganonymize` to 0.13.0, whose two-year gap closed, so that row now rests on fit rather than staleness; and `django-mcp-server`'s recorded date corrected to 10 Oct 2025, turning it into a ten-month gap. No tier changed. The five standing re-vet triggers are restated with what each was on this date rather than left to age. |
| 9 Aug 2026 | Research corrections | Three recorded facts the research for this sweep contradicted were re-checked against primary sources and all three stand as recorded. DRF 3.17.2 (5 Aug 2026) is the security release carrying the AdminRenderer GET-disclosure and `DATA_UPLOAD_MAX_MEMORY_SIZE` fixes and remains the minimum safe version; 3.18.0 (7 Aug 2026) is the feature release. django-allauth 65.19.0 shipped 6 Aug 2026 and declares Django 4.2 through 6.1. django-ipware 7.0.1 is 19 Apr 2024. Dating format ruled on at the same time: one index date governs every version and classifier claim, and a section or entry states its own date only for the behavioral claims it actually re-read. |
| 9 Aug 2026 | Authentication currency | `django-two-factor-auth` 1.18.1 and SimpleJWT 5.5.1 both re-confirmed conditional rather than re-tiered: each shipped artifact declares Django 4.2 through 5.2 and no Django 6 line, whatever the development branch reads. `pwned-passwords-django` 5.2.0 rejected as a new recommendation on the same test, so breached-password screening lands as an owned pattern. `django-smart-ratelimit` 4.12.1 rejected despite being current and declaring Django 6.0, on maintainer concentration and an in-memory default backend that multiplies the limit by the worker count; the category ruling for general-purpose rate limiting is recorded with it so the question stops recurring. |
| 9 Aug 2026 | Supply-chain pipeline | A03 grew a section for the artifacts a hashed lockfile cannot produce on its own — SBOM, scan gate, and provenance — organized around the boundary rather than the tooling. Repository-auditable: the lockfile and whether the install enforces it, the scanner step and what its exit code does, the attestation workflow with its permissions and pins. Confirm-with-platform: registry-side signatures, deploy-time admission enforcement, and the runner isolation any SLSA Build L3 claim rests on. SLSA is stated at claim level and no higher — v1.2 approved November 2025, Build track L0 to L3 with no L4, and GitHub's own documented ceiling of Build Level 2 for attestations alone, Level 3 only with an isolating reusable workflow. Deployment gained an image-scanning paragraph pointing at A03 for the pipeline; A08 gained the reciprocal pointer for the build-artifact case. |
| 9 Aug 2026 | Supply-chain tooling gate | Only two tools in this landscape are pip-installable, so only two face the gate. `cyclonedx-bom` 7.3.1 (23 Jul 2026) enters as **conditional**, not recommend: pip-audit already emits CycloneDX, so a project running it in CI has the artifact without a second dependency. Its row carries the naming trap — the distribution is `cyclonedx-bom`, the command is `cyclonedx-py`, and a `cyclonedx-py` distribution exists on PyPI as an alias at 1.0.1 — and the finding that it records no component hashes at all. `pip-audit` stays at 2.10.1, re-confirmed at 10 Jun 2026, needing no re-date under the index's own dating rule; its row gains its advisory sources, which are PyPI and OSV rather than NVD-derived CPE matching. That distinction is now load-bearing: NIST moved the NVD to risk-based triage on 15 April 2026 and marked every backlogged CVE published before 1 March 2026 not scheduled. Trivy, Grype, Syft and cosign are Go binaries, documented in A03 as CI patterns with their Apache-2.0 licensing stated, and take no index row. |
| 9 Aug 2026 | gRPC and protobuf | The stack enters the index instead of being deferred on. `grpcio` 1.83.0 (23 Jul 2026) and `protobuf` 7.35.1 (11 Jun 2026) are **recommend, pinned**, the protobuf floors being `>=6.33.5` on the 6.x line or `>=5.29.6` on 5.x for the two recursion advisories, both of which the current 7.x line already clears. `grpcio-tools` 1.83.0 is **recommend as a build-time dependency** and does not belong in a production requirements file. The grpcio floor is unusual and is stated as such: neither 2024 C-core advisory that reaches Python has a PyPI-ecosystem record in OSV, so `pip-audit` raises neither against an old wheel and currency is the control rather than a scanner result. `django-socio-grpc` 0.25.0 (24 Sep 2025) moves from a scoping note to **existing-install audit only** — pre-1.0 after five years, no Django classifier at all, `django>=4.2` with no upper bound, `djangorestframework` with no floor, no release in ten months, and authentication, permission, interceptor, server-option and client-auth defaults that are all open. |
| 9 Aug 2026 | gRPC research corrections | Four claims in the research for this release did not survive re-checking against PyPI and the distributions themselves. `django-socio-grpc` is 0.25.0 from 24 Sep 2025, not 0.24.4 from May — two releases missed, and a ten-month gap rather than fifteen. The three grpcio siblings were each reported at a different older version when `grpcio-reflection`, `grpcio-health-checking` and `grpcio-channelz` all ship at 1.83.0 in lockstep with grpcio. The Django and DRF floors the research left unsettled are in the distribution metadata and are the main reason the row is audit-only. And OSV holds no PyPI-ecosystem record for either grpcio CVE, nor any advisory at all for django-socio-grpc, which settles the coverage question the research flagged and is what the grpcio row is now built around. |
| 9 Aug 2026 | Pipeline research corrections | Four claims in the research for this release were wrong or unsettled and were fixed against primary sources. `cyclonedx-py` records no hashes — generating from a `--generate-hashes` requirements file emits components with no `hashes` member in either mode, which the research had left open and which is what lets the guidance say plainly that only `--require-hashes` is integrity evidence. No `setup-trivy` tag was safe in the March 2026 compromise: all seven were force-pushed, so the research's "safe baseline v0.2.6" named the exact reference that was hijacked, and the Docker Hub images were a second wave on 22 March rather than part of the 19 March window. `actions/attest` is the current action rather than `attest-build-provenance`, it needs three permissions rather than one, and a step given `sbom-path` produces an SBOM attestation instead of provenance. cosign is v3.1.3 as of 6 Aug 2026, not v3.1.1. |
| 10 Aug 2026 | Django currency re-check | A currency report for this date was checked against the tree and largely did not survive it: the baseline it called stale was already Django 6.1, 6.0.8, and 5.2.17, and on eight library rows the report was behind the index rather than ahead of it, including DRF, django-allauth, social-auth-app-django, django-hijack and PyCA cryptography. The index date therefore stays at 9 Aug 2026, because nothing in it was re-checked against PyPI on this date and re-dating it would assert a sweep that did not happen. Five findings the tree genuinely lacked did land, all of them application-code patterns rather than version pins. |
| 10 Aug 2026 | Signed-cookie default flip | `SIGNED_COOKIE_LEGACY_SALT_FALLBACK` defaults to `False` from Django 6.1, released 5 Aug 2026, so the default now depends on the installed line: 5.2 and 6.0 still accept the pre-June-2026 derivation and 6.1 does not. The skill previously stated the `True` default without qualification, which made it wrong on the current release. The migration consequence is recorded with it — cookies minted before the fix stop validating on 6.1 — along with the ruling that re-enabling the fallback to rescue them is the wrong response. |
| 10 Aug 2026 | Application-server floors | Request smuggling stays a cross-team recommendation and produces no code finding, unchanged. What was missing is the half that is a repository finding: a Gunicorn floor for CVE-2024-1135 and CVE-2024-6827 (7.5 HIGH by the GitHub Advisory Database and IBM X-Force on the first), plus the async-worker floors that arrive through a `-k` flag rather than as a chosen dependency — `eventlet>=0.40.3`, `gevent>=24.10.1`, and `tornado>=6.5.0`. uvicorn and Daphne are recorded as no advisory found, which is not a clean bill. The floor originally landed as `>=22.0.0`; corrected to `>=23.0.0` on 13 Aug 2026, since CVE-2024-6827 affects 22.0.0 and was fixed in 23.0.0. |
| 10 Aug 2026 | Cryptographic floor | PyCA `cryptography` gains a minimum-safe floor at the 48.x line, which it had never carried: CVE-2026-39892, a buffer overflow on a non-contiguous buffer; CVE-2026-34073, name constraints skipped under a wildcard DNS SAN; and CVE-2026-26007, a private-key leak on the binary elliptic curves whose remediation deprecates the SECT curves and so implies a migration rather than only an upgrade. The recommended pin stays 50.0.0. |
| 13 Aug 2026 | Full-tree audit corrections | A file-by-file audit of every reference and script, with each checkable Django claim re-verified against the 6.0.7 and 5.2.15 source rather than recalled. Version claims were left alone — no PyPI sweep ran, so the index date does not move. Five errors corrected: the Gunicorn floor above (22.0.0 left CVE-2024-6827 open; the floor is 23.0.0); `django-mcp-server`'s date in the agent file, which still read 10 Mar 2026 after the index corrected it to 10 Oct 2025; the hijack staff opt-in, named by its v2 setting when v3 moved it to `HIJACK_PERMISSION_CHECK`; the workflow's gRPC grep hint `_Servicer_to_server`, which cannot match the generated `add_XServicer_to_server` helpers; and the claim that `LocMemCache.incr` is not thread-safe — it holds the backend's lock, and the real failure stays per-process multiplication. Three prohibited-for-mapping CWE categories (16, 320) were replaced with mappable weaknesses, A01's cache-fix summary was disambiguated from CVE-2026-35192, the A04 wrapped-hasher migration now routes through `schema_editor.connection.alias` as A03 requires, and two false-positive guards were added: Django 6's CSP settings are inert without `django.middleware.csp.ContentSecurityPolicyMiddleware`, and Django's own Jinja2 backend autoescapes by default, so the finding there is an explicit opt-out, not a missing option. |
| 14 Aug 2026 | v1.43.0 capability batch | Fifteen new sections across nine references, each behavioral claim read off Django 6.0.7 and 5.2.15 source on this date and the majority executed rather than inferred. Identity and session lifecycle: the user model as an identity contract, the session engine choice that decides whether a session can be revoked at all, cookie prefixes and the subdomain boundary, and the joiner/mover/leaver event a provider-side disable does not finish. Configuration: writing a project's own deploy-only guardrail check, and drift measured against what a deployed process resolved. Reference authorization: the generic relation whose target model the client picks, URL resolution as the surface every check assumes, and locale redirects with the cache key that loses the request's language. Detection and evidence: export formula injection as a sink whose interpreter runs on the reader's machine, forensic readiness with a hash chain sold with its ceiling attached, and decoy records. Cryptography and tasks: algorithm agility as a posture, and Django's built-in tasks framework, whose default `ImmediateBackend` runs the task inline in the caller's transaction. The library index date does not move: no PyPI sweep ran. Django 6.1 was not installed and was not checked, so the tasks material is scoped to the 6.0 line in prose. |
| 20 Aug 2026 | v1.44.0 scanner repair | The three bundled scanners become complete, honest about coverage, and precise. Every change ships with a fixture, and the self-test now holds 49 of them. `dangerous_patterns.py` gains `SEC002` for a `jwt.decode` that does not verify, `NET002` for TLS verification switched off at the `ssl` layer, and `NET003` for an outbound URL that derives from request data. `DES002` now reads the whole unsafe `yaml` family, `DES001` reads the pickle-protocol libraries, `TPL002` reads `%` and `.format` beside the f-string, and `SEC001` reads `PASSWD`, `PASSPHRASE`, and `bytes`. A `SEC001` snippet is redacted, and every snippet drops its ANSI escapes and control bytes, so a report never prints a secret back. `TPL003` stops reporting `from string import Template`. `settings_scan.py` gains middleware membership, `SESSION_ENGINE`, SameSite, `SECURE_CROSS_ORIGIN_OPENER_POLICY`, `USE_X_FORWARDED_HOST`, `REST_FRAMEWORK`, and MySQL transport checks. It judges a PostGIS alias, reads `OPTIONS['pool']` for truth rather than for the key, and stops reporting an HSTS companion while HSTS is off. Each Django default was read off 6.0.7 source on this date, and an absence whose default is already safe is reported as INFO with the default named. `entrypoint_inventory.py` drops `AccessMixin` from the mixins that count as a declaration, stops reading `AuthMiddlewareStack` as an authorization declaration, and marks a bare `@task` that resolves to `django.tasks` with `system: django-tasks`. Every `--json` stream in all three now ends with one `kind: "summary"` record, so an empty stream never occurs, and a directory that cannot be read is counted rather than skipped. `--selftest` returns 1 when a check fails: the one mode whose exit code carries a verdict. CI runs the self-test and the summary smoke check. This entry also covers the two commits released here for the first time: the SKILL.md frontmatter validation, and the reference link, orphan, fence, and size check. |
| 20 Aug 2026 | v1.45.0 reference corrections | Every verified factual error and defective example in the reference corpus is corrected, each against its primary source. `authorization-architecture.md`: stock `DjangoObjectPermissions` maps `GET`, `HEAD`, and `OPTIONS` to an empty permission list, read off DRF 3.17.1 source, so a safe request checks nothing and the documented 404 row never fired on the stock class -- the response matrix is now scoped to a subclassed `perms_map`, which the section supplies. `data-layer-and-database.md`: `pg_dump` sets `row_security` to off and a restricted role gets an error rather than a partial dump, with `--enable-row-security` as the opt-in that filters; a `USING`-only `ALL` or `UPDATE` policy reuses `USING` as its check, so the real trap is a `FOR SELECT` policy beside a permissive write policy; `REPEATABLE READ` permits write skew and only `SERIALIZABLE` detects it; and the alias on `atomic()` does not route the ORM. `a07-authentication-failures.md`: `AUTH_PASSWORD_VALIDATORS` run only where `validate_password()` is called, which the auth forms do and `set_password()` and `create_user()` do not; the HIBP `Add-Padding` header varies the entry count in a band rather than making responses byte-uniform; the outbound read is capped. `api-drf-specific.md`: the correct serializer carried an `extra_kwargs` entry bound to a field its `fields` list omitted, and now accepts the secret write-only and validates it; two new controls land -- a writable relation defaults to the related model's whole table, and `ModelForm` and formset mass assignment, which `CFG001` already scanned with no documented owner. `a08-integrity-and-deserialization.md`: the webhook example acknowledged an event it could then lose, and now stores a `RECEIVED` record and enqueues in `transaction.on_commit`; Django's YAML serializer loads with `SafeLoader`, so a YAML fixture is not the `yaml.load` finding; `result_accept_content` is named. `async-and-channels.md`: the membership transfer authorized only the source tenant. Also corrected: the at-least-once scope and the idempotency fingerprint (A10), the error-report scrub scope and `extra=` rendering (A09), `SECRET_KEY` rotation on a rolling fleet, the RFC 8693 subject token, the `PyJWT[crypto]` extra, the Django 6.2 `listurls` tense, the `MultiFernet` batch overwrite, and the nested-router mixin and lexical `safe_join` containment (A01). |
| 20 Aug 2026 | v1.46.0 perimeter hardening | The missing perimeter controls now have owners. Every new claim is verified against its primary source. `deployment-and-runtime.md` gains the Nginx off-by-slash traversal. A `location` prefix with no trailing slash also matches `/static../`. Nginx joins the remainder onto the `alias` path, so `GET /static../config/settings.py` reads one directory above the static root. `root` inside a prefix `location` does not have this trap. The same file gains `USE_X_FORWARDED_HOST`, which moves host trust to the proxy. `ALLOWED_HOSTS` still validates the forwarded host. `file-uploads.md` gains the tar extraction filters. `TarFile.extractall()` without a filter obeys the archive's own metadata. Python 3.12 adds the filters. The backports are 3.9.17, 3.10.12, and 3.11.4, each read off that version's own documentation. Python 3.12 warns when the caller gives no filter, and Python 3.14 makes `"data"` the default; both were executed locally on 3.12.10 and 3.14.4. `a02-security-misconfiguration.md` gains four controls. `SecurityMiddleware` has served the `"same-origin"` default of `SECURE_CROSS_ORIGIN_OPENER_POLICY` since Django 4.0, and the correct relaxation for a popup flow is `"same-origin-allow-popups"` rather than `None` or `"unsafe-none"`. A CSP policy rolls out through `SECURE_CSP_REPORT_ONLY` before `SECURE_CSP`. `GZipMiddleware` adds up to 100 random bytes to each compressed response since Django 4.2, which narrows the BREACH channel rather than removing it. Fetch Metadata sits beside Django's CSRF protection, never instead of it. The same file gains `security.txt` (RFC 9116), rated INFO, and mail transport security: MTA-STS (RFC 8461) and TLS-RPT (RFC 8460), rated LOW for a domain that sends password-reset mail. `a03-software-supply-chain.md` gains index resolution and dependency confusion, where `--extra-index-url` lets a public index win the version race. `service-identity-and-secrets.md` gains "Stopping the commit": a pre-commit scan, host push protection, and a scheduled history scan, with a hit in history treated as a leak rather than as a lint. `.gitignore` gains `__MACOSX/` and `._*`. The README records that a release archive comes from `git archive` rather than from a zip of the working directory. Three review checklists and the three cascade files are updated to match. One correction to the change brief: a password-reset link trusts the forwarded host only where `django.contrib.sites` is absent, because `get_current_site()` otherwise returns the `Site` row. |
| 20 Aug 2026 | v1.47.0 identity and admin surface | The missing identity, recovery, admin, sanitizer, and erasure-restore controls now have owners, and `bleach` gets a disposition. Every claim is verified against Django 6.0.7 source or against PyPI on this date, and three of them by execution. `a07-authentication-failures.md` gains three controls. `RemoteUserMiddleware` reads `request.META["REMOTE_USER"]`, which under WSGI the server's own authentication module sets; a client-sent `Remote-User` header maps to the different key `HTTP_REMOTE_USER`, so the trap is a subclass whose `header` names an `HTTP_` key. `RemoteUserBackend.create_unknown_user` defaults to `True`, and `PersistentRemoteUserMiddleware` sets `force_logout_if_no_header = False`. The email address is the recovery root, so a change of address re-authenticates, completes on confirmation at the new address, and notifies the old one. One correction to the change brief: `default_token_generator._make_hash_value()` hashes five values and not three -- the primary key, the password hash, `last_login`, the token time, and the email address -- so a change of address already invalidates every outstanding reset token, proved by execution rather than assumed, and only a custom generator or a stored token row needs that invalidation written. Purpose-bound tokens get their own `key_salt` and their own `_make_hash_value()`. The device-cookie pattern answers the per-account lockout's denial-of-service edge. `a04-cryptographic-failures.md` gains peppering as a wrapping hasher, rated as available hardening rather than as a finding. `authorization-architecture.md` gains custom admin views: an unwrapped view returned from `get_urls()` answered an anonymous request in full on Django 6.0.7, and `admin_site.admin_view()` adds the `is_active`/`is_staff` check plus `never_cache` and `csrf_protect`, with `cacheable=True` dropping the cache decorator only. A second correction to the brief: the action POST path does re-check, because `response_action()` re-resolves through `get_actions()` -- the real gap is that `_filter_actions_by_permissions()` keeps an action that declares no `permissions` for any staff user, also proved by execution. `a05-injection.md` gains Markdown as an output context, with a sink row: `markdown-it-py` sets `html` to `True` in the `commonmark` preset its constructor selects and in both `gfm-like` presets, and `mistune.create_markdown()` escapes by default while the module-level `mistune.html` renderer carries `escape=False`. `data-lifecycle-and-privacy.md` gains the restore as a resurrection path, with the replay step and its fixture-subject test. `security-hardening-libraries.md` gains `bleach==6.4.0`, rejected for new use: the release carries the `Development Status :: 7 - Inactive` classifier and `mozilla/bleach` is archived, both on 5 Jun 2026, with `nh3` the successor. The index date does not move. Four review checklists and the `.cursor` rule are updated to match. |
| 20 Aug 2026 | v1.48.0 Django 6.1 delta | Django 6.1, released 5 Aug 2026, read end to end on this date, and every item below verified against the 6.1 documentation or the tagged source rather than against the change brief. `a04-cryptographic-failures.md` carries the new PBKDF2 default: 1,500,000 iterations on 6.1 against 1,200,000 on 6.0 and 1,000,000 on 5.2, read off `django/contrib/auth/hashers.py` at each tag. Argon2, Scrypt, and the shipped `PASSWORD_HASHERS` order are unchanged on 6.1, so the rest of that table re-scopes as it stands. `salted_hmac()` and `django.core.signing.base64_hmac()` now deprecate the implicit `algorithm` default ahead of the 7.0 change to `"sha256"`. `a07-authentication-failures.md` carries the `RemoteUserMiddleware` change, which is subtler than the release note states: 6.1's `get_username()` adds the `HTTP_` prefix under ASGI only when `header` is still the default `REMOTE_USER`, so a custom header is read verbatim and has to be written as `HTTP_AUTHUSER`. Django 5.2 and 6.0 prefixed it on the async path unconditionally, so one subclass resolved two different keys. The upgrade fails closed under `RemoteUserMiddleware` and fails open under `PersistentRemoteUserMiddleware`, whose `force_logout_if_no_header = False` makes it return without reading the header at all. Django 6.1 also removed the 6.0 shim that ran a `process_request()` override through `sync_to_async`, so such an override is now skipped under ASGI while the base class still authenticates. `a01-broken-access-control.md` gains `RedirectView.preserve_request`, new in 6.1; the `preserve_request` argument on `HttpResponseRedirect` and `redirect()` is 5.2 and is scoped as such. The 16384-character redirect bound is not new -- 6.0 hard-codes it -- but 6.1's `max_length` argument makes it overridable and `max_length=None` removes it. `a02-security-misconfiguration.md` gains the CSP nonce path: `security.W027` reports `CSP.NONCE` in a policy without the `csp()` context processor, which is a second way a policy goes inert after the missing middleware the bundled scanner already flags, and `csp_nonce_attr` renders the attribute on external `<script>` and `<link>` elements and on a `Media` object. It also gains `MAILERS`, which moves the backend, the credentials, and the TLS posture per alias and deprecates eleven `EMAIL_*` settings, with the `mail.E001` and `mail.W001` checks; and the `check` command change, which is narrower than the release note reads -- 6.1's `run_checks()` defaults `databases` to every configured alias while still skipping `database`-tagged checks without an explicit `--database`, so a third-party check that accepts `databases` can now open a connection in CI. `a09-logging-and-alerting.md` carries the delete-signal half of `DB_CASCADE`: `SKIP_COLLECTION` in 6.1's `django/db/models/deletion.py` holds all three `DB_*` constants, so an audit hook on a delete signal records nothing for the far side of that relation. The erasure half was already correct in `data-lifecycle-and-privacy.md` and is left alone. `file-uploads.md` gains `HttpRequest.multipart_parser_class` and the strict Base64 validation in `MultiPartParser`, `BinaryField`, and `DatabaseCache`; request-body parsing is this file's, and `api-drf-specific.md` keeps DRF parser configuration only. `authorization-architecture.md` gains the admin action `location` argument, which puts an action on the change form and so gives an action declaring no `permissions` a second unguarded entry point, together with the deprecated `get_actions()` signature the file's own mitigation depends on, and the 6.1 `Permission` rename-on-migration and `user_perm_str`. `a08-integrity-and-deserialization.md` gains the XML deserializer's `SuspiciousOperation` and the picklability of `Task` and `TaskResult`, whose reconstruction resolves `module_path` through `import_string`. Dropped after checking each: `delete_confirmation_max_display`, which the 6.1 documentation calls purely a display setting that does not change what is retrieved; the admin login redirect to `next`, which resolves through `LoginView.get_redirect_url()` and its `url_has_allowed_host_and_scheme` check; the systematic quoting of SQL `SELECT` aliases, which A05's alias section already generalizes across versions while keeping the durable fix; `SessionBase.__bool__`; the `File` truthiness change, whose upload subclasses keep the old behavior; fetch modes and the `select_related()` deprecation, which are query-count and plan work; the dropped PostgreSQL, MySQL, MariaDB, and SQLite floors, a support matter with no home here; and the `task()` decorator's `**kwargs`, which is extensibility rather than behavior. The signed-cookie item needed no edit: A02 already carries CVE-2026-6873, the 5.2.15 and 6.0.6 floor, the 6.1 flip of `SIGNED_COOKIE_LEGACY_SALT_FALLBACK` to `False`, and the 7.0 removal. The library-index date does not move. `a04-cryptographic-failures.md` is now 1119 lines, still over the 1100 convention that change set 04 deferred to the final checkpoint. |
| 20 Aug 2026 | v1.49.0 final checkpoint | One deterministic sweep of the whole repository, with every failure fixed in session. Ledger reconciliation passes on both sides: all thirty accepted items are present, and every rejected item is still absent, including the exit-code contract, the labelled wrong-versus-correct pairs, and the twenty-four reference files. Corrections, each re-verified against a primary source fetched on this date. `deployment-and-runtime.md`: the gevent floor for CVE-2023-41419 moves from 24.10.1 to **23.9.0**, which is the first patched version in GHSA-x7m3-jprg-wc5g and in the upstream issue; the eventlet and tornado floors beside it re-verified as correct. `data-layer-and-database.md`: the claim that a pool's maximum size bounds total backends "regardless of how many workers exist" was false -- Django holds `_connection_pools` as a class attribute, so each process builds its own pool, and the sizing bullet now multiplies by hosts as well. `a07-authentication-failures.md`: `PersistentRemoteUserMiddleware` does read the header -- `process_request()` calls `get_username()` and catches `KeyError` -- so `force_logout_if_no_header = False` means the missing header logs nobody out, rather than that the header is never read. `a02-security-misconfiguration.md`: the 6.1 `check` change is attributed correctly to `run_checks()`, which defaults `databases` to every alias, and not to the command, which still passes `None`. `file-uploads.md`: the tar filter backport list gains **3.8.17**, which carries the same CPython entry. `a08-integrity-and-deserialization.md`: the "6.1 was not available to check" caveat contradicted the section's own 6.1 items and is narrowed. Nine controls added at sentence scale from the attack pass, each in its owning file: SSRF pinning against DNS rebinding (A01), a closed exemption set for the default-deny URLconf test, the `authtoken` `Token` model's plaintext key at rest (A07), a correlation identifier replaced at the edge (A09), the `btree_gist` dependency on `ExclusionConstraint` (A10), `DATA_UPLOAD_MAX_MEMORY_SIZE` named where a webhook reads `request.body`, a single-use WebSocket ticket, and a `versionId` or generation match at upload promotion. Six attack-pass items passed and are recorded as passes; the KDF-input ceiling was one of them, because Django reverted its 4096-byte cap in 1.5.5 and OWASP declines a general maximum, so the bcrypt 72-byte and 64-character floors the corpus already carries are the correct ones. Sibling non-absorption: `a03-software-supply-chain.md` carried migration operation mechanics with no handoff, and is cut to the security invariant -- the access rule holds at every batch boundary -- plus a handoff to migration operations and lock behavior. Twenty-six sentences this build added are re-worded to the ASD-STE100 length and one-instruction rules, and five uppercase MUST/NEVER uses are lowered to the corpus register, which carries none. `a04-cryptographic-failures.md` goes from 1119 to 1112 lines: a mechanical duplication pass, internal and cross-file, found the disk-versus-column distinction, the encrypted-column query cost, and the `os.environ` rule already owned by `data-layer-and-database.md` and `service-identity-and-secrets.md`, and those are now pointers. The rest of the file is controls rather than duplication, so it stays over the 1100 convention deliberately and this row closes that deferral rather than carrying it again. The `SKILL.md` A02 router row now names MTA-STS, TLS-RPT, and `security.txt`, which the `.cursor` rule already carried. Every Django 6.1 claim, the CVE-2026-6873 record, and all eighty-one identifiers this build introduced were re-verified; none failed. The description is untouched at 1013 characters. The library-index date does not move. Community health files are added in a separate commit and carry no version. |
| 21 Aug 2026 | v1.50.0 language pass | The whole reference corpus is converted to ASD-STE100 Simplified Technical English, in three waves released here as one version. Wave 1 took the method and access-control family, wave 2 the attack-class family, and wave 3 the data, runtime, and interface family together with `scripts/README.md`, the `SKILL.md` prose, and the `AGENTS.md`, `GEMINI.md`, and `.cursor` cascade. The rules applied are the standard's: short sentences, the active voice, the imperative mood for an instruction, one instruction to a sentence, the present tense for a fact, no gerund or participle as a noun or a verb, noun clusters of three words or fewer, articles kept, approved phrasal verbs only, one term for one thing, a warning before the instruction it applies to, and no slang, metaphor, or rhetorical question. The meaning is unchanged, and the change is language only: no control, example, or caveat is added, removed, or reordered. Every heading is byte-identical, so every anchor still resolves -- the docs-integrity check passes with 24 reference files, no orphan, balanced fences, and 297 anchored links across 33 markdown files. Every fenced code block, table, cross-reference, identifier, severity word, threshold, date, and version claim was diffed per file against its previous state and is unchanged. The frontmatter `description` is byte-identical at 1013 characters, and `SKILL.md` is 33860 of the 40960 bytes the workflow allows. The documented script contract does not move: the exit-code statement, the `kind: "summary"` output shape, and the `--selftest` CI wording are byte-identical, all 29 rule identifiers still match between `scripts/README.md` and `dangerous_patterns.py`, `--selftest` passes 49 fixtures with 29 of 29 rules covered, and all three scanners report zero findings against this repository. On sentence length, the eleven wave-3 files carry no prose sentence over 25 words, against 562 before the wave. Waves 1 and 2 left 82 such sentences between them across the fourteen files they touched; those are fixed here, so the whole of `references/` now carries exactly one, the verbatim SP 800-63B-4 blocklist requirement in `a07-authentication-failures.md`, kept intact because a split would falsify a quoted normative SHALL. The precise control verbs stay apart throughout -- log, redact, retain, erase, restore, promote, quarantine, scan, throttle, lock, commit, and roll back each still name what they named before, and delete and erase are still two words. This row also releases the boundary scrub that has been unreleased since v1.49.0: three passages that named a repository which is not public were rewritten by capability rather than deleted, so the seam and its direction survive without the name; two seams the final checkpoint reported as unmarked gained a boundary sentence each, in `deployment-and-runtime.md` and `graphql-and-alternative-api-surfaces.md`; and two historical changelog rows lost the two names they carried, with no date, number, claim, or verdict moved. The library-index date does not move. |
| 27 Aug 2026 | v1.52.0 audit closure and router rebuild | Two change sets land in one version. The first is the full-corpus audit closure: twenty-two commits, one per reference family, that repair the defects a file-by-file audit found, at 3,992 insertions across twenty-three files. Defective examples are corrected — the canonical A01 `CommentCreateView` gains the object permission its own `check_object_permissions` call had nothing to run, the A04 wrapped-hasher migration gains the survey that stops on a row it cannot wrap, and the graphene `UserType` scope returns the set a caller may read rather than the one row the caller is. Decision rules that let real findings through are closed — the duplicate-route dismissal now compares the queryset scope and the serializer, the route artifact carries the `request.urlconf` caveat, the SSRF allowlist states how a host matches, and a model `validators` argument no longer closes a sink finding. Verified mechanics land across every file: the env-string `DEBUG`/`ALLOWED_HOSTS` parsing trap with `security.W018`/`security.W020`, wildcard host and origin allowlists as their own A02 section, `BasicAuthentication` in DRF's default list, the `@action` keyword arguments that replace every viewset list, gRPC metadata read as a multimap, the negative page argument in a GraphQL cost rule, `AXES_COOLOFF_TIME = None` as a permanent lock, the IPv6 /64 lockout key, the `SECURITY DEFINER` `search_path` pin, partition and view policies under row-level security, the `${filename}` key condition on a presigned POST, tenant binding on webhook events, the five suppression kinds, and the impersonation episode record as the authority middleware re-reads. Each claim carries the source it was read from, most against Django 6.0.7 or 6.1 source on 27 Aug 2026. The second set is the router rebuild. The audit closure had added 74 prose sentences over the 25-word ceiling the v1.50.0 language pass set; each is split back under it, and the verbatim SP 800-63B-4 blocklist requirement stays the one standing exception. `SKILL.md` is rewritten to the same ASD-STE100 standard: the router rows become keyword lists, the ownership table keeps every row and the three prose splits, and the byte count falls from 39,065 to 32,436 of the 40,960 the workflow allows. The stale twenty-two-references count becomes a count-free statement, and the methodology file drops its own twenty-three-file count. `AGENTS.md`, `GEMINI.md`, and the `.cursor` rule become the thin pointers they always claimed to be, so the router has one home and the pointers cannot drift from it. The frontmatter `description` is byte-identical at 1013 characters. Every file-and-heading cross-reference was re-verified across the corpus — 366 pairs resolve — and the docs-integrity and validate-skill checks pass on the finished tree with 25 reference files, no orphan, and the `dangerous_patterns.py` self-test at 49 fixtures. The library-index date does not move: no PyPI sweep ran. |
| 27 Aug 2026 | v1.51.0 agent-operator security | The twenty-fifth reference lands: `references/agent-operator-security.md`, which owns the access the reviewing agent itself holds rather than the surface of the backend it audits. That surface does not exist until an agent runs the review unsupervised, which is why a skill written for a supervised one had no reason to carry it. The file owns six controls. The credential files the agent must never open -- `.env` and each variant, `*.pem`, `*.key`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`, a service-account key, and a decrypted secrets file -- with the counter-instinct half stated outright: a `.gitignore`, a tool-specific ignore file, and an instruction in a project memory file are defaults rather than walls, because a shell command the agent composes itself opens the file with no ignore rule between the two, and the published defect reports that record exactly that path are cited (anthropics/claude-code issues #4160, #12102, and #24185; The Register, 28 Jan 2026, against v2.1.12). The Django half of the same rule is that a settings module is executable, so an import of a production one resolves the production `SECRET_KEY`, the database password, and every API key it names -- which is why `settings_scan.py` parses a settings package with the `ast` module and never imports the target project. The name-by-location rule for every finding, report, commit message, and fixture the agent writes, with redaction placed where it belongs: a masking layer matches a literal string, so base64, a split, URL encoding, or the value inside JSON, XML, or YAML each defeat it, and GitHub's own Actions hardening guidance says both that its redaction rests on an exact match and that automatic redaction is not guaranteed. The kind, scope, and life of the agent's own repository credential, ranked by blast radius in one table -- a classic personal access token reaches every repository the account can see and carries no expiration requirement, a fine-grained one is bounded by an organization maximum between 1 and 366 days (GitHub Changelog, 18 Oct 2024), a deploy key reaches exactly one repository with no account behind it, and an installation token expires in an hour -- plus the per-job token permission that resolves an omitted scope to none, the federated cloud credential that replaces a stored one and leaves the control-plane record a stored one cannot, and revocation at the end of the task. Instructions arriving through repository content, a ticket, a comment, a web page, or tool output as data rather than authority, with four incidents against coding agents specifically: the Amazon Q Developer extension for VS Code (CVE-2025-8217, AWS advisory AWS-2025-015, 1.84.0 on 17 Jul 2025 and the clean 1.85.0 on 24 Jul 2025, with AWS recording that the malicious code failed on a syntax error), three agents driven from pull-request titles and issue bodies with one made to post its own API key as a public comment (Google VRP #1609699), a token exfiltration that defeated the host's own secret scanning by base64 (Orca Security, disclosed 2026), and a backdoor header inserted from a helpful-looking issue (Trail of Bits, 6 Aug 2025). The confirmation gate on an action a finding recommends, enforced in the execution path rather than in the prompt, because the July 2025 production-database deletion happened during a declared freeze that lived only in the instructions and the agent then misreported the restore as impossible. And the command, change, and cloud-action record a layer the agent cannot edit has to author, including the source identity a session holder cannot change against the session name it can. The boundary with `agent-and-llm-interfaces.md` is drawn in both files with one line each: that file keeps the serving side, this one the agent's own access. `SKILL.md` gains the router row, the ownership row, and three sections it never carried -- what proof is in this domain and the exact commands that produce it, the stop conditions with the five handoff fields instantiated, and a freshness statement. The evidence definition is the one the methodology and workflow files already imply, stated where it can be enforced: a finding without confirmed evidence is a hypothesis and is labelled as one, the not-examined list is part of the deliverable, and the exact commands are the three scripts under `scripts/`. The stop conditions extend the existing refusal rather than duplicate it -- read-only review and the three write-time changes that need explicit confirmation stand, and three more are added for the skill's own actions: escalate at once on a live credential exposure, never execute a rotation, a revocation, a disable, or a delete, and refuse a read of credential material. Three anti-gaming lines land beside them: never lower a severity to shorten a report, never mark a not-examined surface as examined, never close a finding without the test that holds it closed. One ground-truth read rule lands in the verification section, where the sweep first needs a local fact that the repository cannot supply. Drops from the research input, each for a stated reason: the GitLab and Bitbucket token models, unverified in the source pass; the `github-actions[bot]` email format, de-facto and undocumented; the `git.addAICoAuthor` default, unstable across 2026; the full OpenTelemetry attribute enumeration, which is restated documentation rather than a rule; the unverified Copilot and Cursor CVE identifiers; and the M365 Copilot zero-click case, which is not the operator surface. Two deletions from the new file under the deletion pass, both justified as long justifications for a rule rather than the rule: the pair of sentences explaining why the suite lacked this file, and the sentence apologising for the cost of asking a human for a value. No claim, control, or example is removed anywhere else. The register ruling holds: the corpus carries zero uppercase MUST/NEVER, so the absolutes here are sentence-initial and unhedged, matching the other twenty-four files. Verified on the finished tree -- docs-integrity passes with 25 reference files, no orphan, balanced fences, 306 anchored links across 34 markdown files, and `SKILL.md` at 39065 of 40960 bytes; validate-skill passes with the description byte-identical at 1013 characters, the `dangerous_patterns.py` self-test at 49 fixtures and 29 of 29 rules, and all three scanners exiting 0 with a `kind: "summary"` record. The new file carries no prose sentence over 25 words and no prose line over 79 characters. The library-index date does not move. |

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
mapping, the concrete problem, the shortest source-to-sink path the finding was
actually confirmed on together with the protection that failed, the impact, and
a fix — and at the end an explicit account of what was examined and what was
not, so a quiet report is distinguishable from a clean one. Nothing reaches
that list until it has discharged the verification gate, so a keyword that
turned out to be the framework working correctly is dropped rather than
reported with a hedge. For fast triage there are
three read-only helper scripts (no network access, they don't run your project);
all three take `--json`, which is JSON Lines in each — one object per line,
consumed a record at a time rather than parsed as one document:

```
python scripts/entrypoint_inventory.py . --settings config/settings --json
python scripts/settings_scan.py config/settings/ --json
python scripts/dangerous_patterns.py .
python scripts/dangerous_patterns.py . --json --min-severity MEDIUM
```

The first answers where execution begins: every declared route at the full
prefix its `include()` chain resolves to, routers and viewset actions, Ninja,
GraphQL, gRPC, Channels, Celery, management commands, signals, admin, and
middleware in declared order — each HTTP-reachable row marked as declaring its
authorization, inheriting it from somewhere the row cannot show you, or having
none. The second reads a whole settings package rather than one file, follows
the star-imports, and names the module each effective value came from, so a
setting that is safe in `base.py` and overridden in `production.py` is visible
as exactly that.

All three parse with the `ast` module rather than grepping lines, so a hit is a
structural match: parameterized SQL and anything inside a docstring are not
reported, every row names the reference file that owns it, a
`dangerous_patterns.py` hit additionally carries a stable rule identifier, and
a file that fails to parse is reported as unparsed rather than skipped in
silence. Every `--json` stream ends with one `kind: "summary"` record, so an
empty stream never occurs and a clean tree is distinguishable from a run that
stopped. `python scripts/dangerous_patterns.py --selftest` checks the scanner
against its own fixtures before you trust a quiet result, and returns 1 when a
check fails.

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
- Evidence: GET /invoices/<pk>/ -> InvoiceDetail -> Invoice.objects.all().get(
  pk=pk), with pk taken straight from the URL kwarg. The protection that failed
  is queryset scoping: no get_queryset() override and no object permission.
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
The skill version is recorded in SKILL.md frontmatter (`metadata.version`);
releases are tagged in git.

GitHub builds each tag download with `git archive`, so a release archive holds
no editor, OS, or bytecode file. Never zip the working directory, because that
is how `__pycache__/`, `.DS_Store`, and `__MACOSX/` entries reach a reviewer.
When you attach an archive by hand, build it the same way:
`git archive --format=zip -o secure-code-auditor.zip HEAD`.

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
│   ├── 01-audit-workflow.md            # how a codebase is swept
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
│   ├── agent-operator-security.md
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
│   ├── dangerous_patterns.py           # read-only AST project scanner
│   ├── entrypoint_inventory.py         # read-only AST entry-point inventory
│   ├── settings_scan.py                # read-only AST Django settings scanner
│   └── README.md
├── README.md
├── LICENSE
└── .gitignore
```

## Contributing

Issues yes, pull requests no. Pull request creation is restricted to
collaborators, so open an issue and I implement the change myself. See
[CONTRIBUTING.md](CONTRIBUTING.md) for what a good report contains,
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for conduct, and
[SECURITY.md](SECURITY.md) for reporting a vulnerability in the scanners.

## License

MIT. See `LICENSE`.
