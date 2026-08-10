---
name: secure-code-auditor
description: >-
  Backend security auditor for Django and DRF on an OWASP Top 10 (2025),
  API Security Top 10 (2023), and ASVS 5.0 foundation. Use when backend
  code is written or reviewed and touches authentication, sessions, JWT,
  OAuth2/OIDC, API keys, passkeys, password hashing, permissions, access
  control, SSRF, path traversal, impersonation, SQL/command/template
  injection, LDAP, row-level security, encrypted columns, NoSQL,
  Redis, file uploads, S3, serializers, API endpoints, pagination, rate
  limiting, CSRF/CORS, OpenAPI schema, GraphQL, Django Ninja, AI agents,
  MCP tools, secrets, payments, webhooks, Celery, race conditions,
  caching, deserialization, async/ASGI, WebSockets, audit logging,
  erasure, retention, personal data, migrations, JWKS, mutual TLS, key
  rotation, SECRET_KEY, Dockerfile, SBOM, X-Forwarded-For, SPF/DKIM/DMARC,
  or deployment config, even if "security" is never used.
  Review-time returns prioritized findings with fixes; write-time
  applies secure defaults. Django/DRF-first; general layer suits any
  stack.
license: MIT
allowed-tools: Read, Grep, Glob, Bash
metadata:
  author: n-shadloo
  version: 1.33.0
---

# secure-code-auditor

A backend security skill. It reviews and hardens server-side code, with
Django/DRF as the deep specialty and a general OWASP layer that applies to any
stack. Scope is the backend: server-side code, data handling, configuration,
and the deployment/runtime the backend owns. It does not cover browser/frontend
concerns except where the server controls output (encoding, headers, cookies).
Its canonical content is reused by other agents (Codex, Cursor, Gemini CLI) via
`AGENTS.md`, with Claude as the primary integration.

## How the reference material is organized

Everything is arranged on the **OWASP Top 10:2025 spine**. Category files and
cross-cutting topic references have two layers:

1. **Principle** — the vulnerability, why it matters, and the defense, stated
   stack-agnostically so it's useful in any backend language.
2. **Django & DRF implementation** — the specific settings, code patterns,
   correct/incorrect examples, gotchas, and hardening steps. This is where the
   depth lives.

The same split names the two halves of a sub-topic checklist,
`#### Stack-neutral` and `#### Django & DRF`. A file's final
`## Review checklist` may stay unsplit; about half of them do, and neither form
is a defect.

Every control is stated in both grammars — a review form saying what to flag,
and a write-time form saying what to write — and the second is a paragraph
opening `**Write-time.**` directly under the control it completes, never
collected into a list of its own. All twenty-two references that own a control
carry at least one. The two that do not are the methodology file, which indexes
them by generation moment, and the library index, which owns package
dispositions rather than controls.

Load only the file(s) relevant to the concern in front of you. The tables below
group on that spine, so the choice is two steps rather than one: pick the group,
then the row. Where two rows could both match, the ownership rules underneath
decide which file is authoritative.

### Start here

| Concern | Reference file |
|---|---|
| How a codebase is swept before anything is judged: the phase order, the entry-point inventory across URLconf chains, routers and actions, Django Ninja, GraphQL, gRPC, Channels, Celery and beat, management commands, signals, admin, webhooks, MCP tools, and middleware, the principals and trust boundaries a Django backend actually distinguishes, source-to-sink pairing, hypothesis ordering by impact against effort to confirm, what verification has to discharge before a hypothesis is a finding, the coverage ledger that keeps examined-and-clean apart from not-examined, and the attack chains worth searching for with the file that owns each hop | `references/01-audit-workflow.md` |
| Method & severity model including how a race and a privacy failure are rated, report format, the ASVS 5.0 chapter mapping with the chapters this skill treats as non-goals, mode selection, the write-time secure-default contract and the index of which file holds each generation moment's rule, what to do when a secure default conflicts with the request, the security-decisions note write-time returns instead of a findings report, and the two-mode convention every control follows | `references/00-methodology-and-severity.md` |

### The OWASP Top 10:2025 spine

| Concern | Reference file |
|---|---|
| **A01** Access control, IDOR/BOLA, object- & function-level authz, cache-mediated data leaks, SSRF and egress control, path traversal on a file read the request names, open redirect, multi-tenancy, admin access | `references/a01-broken-access-control.md` |
| **A02** DEBUG/ALLOWED_HOSTS, SECURE_*/SESSION_*/CSRF_* matrix, signed cookies and the legacy salt fallback, CORS, headers, mail authentication (SPF/DKIM/DMARC alignment and rollout), CAA and dangling-DNS/subdomain takeover, `check --deploy` and what it cannot see | `references/a02-security-misconfiguration.md` |
| **A03** Dependencies, third-party vetting/maintained-package gate, a development-only package reaching the production requirements file, pinning/hashing, `pip-audit`, EOL frameworks, migrations/data integrity, the SBOM generated from the lockfile rather than the built image and what it does not prove, the CI scan gate read as configuration rather than as a step that exists, build provenance and the consumer-side verification that makes an attestation mean anything, SLSA Build levels at claim level, and the line between what a repository audit can verify and what is confirm-with-platform | `references/a03-software-supply-chain.md` |
| **A04** Password-hashing family and parameters, upgrade-on-login and the wrapped-hasher migration that reaches the dormant accounts it cannot, randomness and token generation, constant-time comparison, signing and per-purpose salt discipline, TLS-in-transit, data at rest, key lifecycle and envelope encryption worked against a KMS, post-quantum posture | `references/a04-cryptographic-failures.md` |
| **A05** The sink inventory every other reference defers to and the method for tracing a source to it, including the stored-then-used path worked end to end, SQL/ORM injection, dictionary-expansion column aliases, GeoDjango raster band indexes and spatial-lookup raster sources, command and argument injection, template injection and XSS from server-rendered output, LDAP/directory injection, header/email injection | `references/a05-injection.md` |
| **A06** Which flows need a rate limit or anti-automation in the first place, algorithmic resource exhaustion and the bound every caller-controlled input needs, business-logic and email/notification abuse, missing limits, insecure defaults | `references/a06-insecure-design.md` |
| **A07** Human authentication: password policy from the length floor to the breached-corpus screening no built-in validator provides, sessions, JWT/SimpleJWT, OAuth2/OIDC/social login, API keys, brute force, MFA, passkey and WebAuthn configuration, password reset, allauth/dj-rest-auth/OAuth Toolkit, enumeration | `references/a07-authentication-failures.md` |
| **A08** Insecure deserialization (pickle/yaml), the cache/session/fixture paths Django deserializes without being asked, Celery task-message trust and serializers, signed data, inbound webhook signature/timestamp/replay and event de-duplication, outbound webhook delivery controls, artifact provenance | `references/a08-integrity-and-deserialization.md` |
| **A09** Sensitive-data leakage in logs, audit logging, lifecycle hooks/signals, alerting, log injection | `references/a09-logging-and-alerting.md` |
| **A10** Fail-open vs fail-closed checks, error views and stack-trace leakage, race conditions/TOCTOU, locking vs database constraints, idempotency-key design, transaction side-effect ordering, state-transition enforcement, ReDoS | `references/a10-exceptional-conditions.md` |

### Cross-cutting surfaces

These span several categories, so they are grouped by the surface in front of
you rather than by OWASP number.

| Concern | Reference file |
|---|---|
| Privilege model (RBAC/ABAC/ReBAC), `ModelBackend`/DRF/admin permission behavior, default-deny + URLconf audit test, field-level authz (BOPLA), search-index and denormalised-copy leakage, authz test design, permission decay | `references/authorization-architecture.md` |
| Impersonation / "log in as user", django-hijack, break-glass & JIT elevation, operator audit identity | `references/privileged-access-and-impersonation.md` |
| Where DRF runs the object check and the routes that skip it, `@action` and function-level authz (BFLA), serializer over-exposure/mass assignment, pagination/filter/ordering leakage, throttling mechanics and the owned atomic counter a limit that must hold needs instead, schema and browsable-API exposure, endpoint inventory and shadow routes, versioning and deprecation, bulk endpoints, unsafe DRF defaults, DRF+CSRF | `references/api-drf-specific.md` |
| GraphQL endpoints and schemas, resolver-level authorization and nested traversal, all-fields types, query depth/alias/token/cost limits, introspection and error masking, mutation inputs and nested writes, batching, persisted queries, N+1 as resource exhaustion, Strawberry and graphene-django defaults, Django Ninja routes with no `auth=`, gRPC servicers serving every method until an interceptor is installed, protobuf message-size and recursion limits, `Any` and unknown-field handling, reflection and channelz as debug surfaces | `references/graphql-and-alternative-api-surfaces.md` |
| Async/ASGI boundaries, sync ORM access, task/request context, WebSocket/Channels origin, authentication, authorization, and limits, subscriptions on the subscribe and publish paths | `references/async-and-channels.md` |
| File uploads, type/content validation, safe names and storage-key design, object-storage configuration and bucket exposure, per-tenant bucket vs shared prefix, delegated upload URLs across S3 presigned POST, GCS V4 signed URLs, and Azure SAS — what each binds, what caps its size, and what it takes to withdraw one, quarantine and promotion, scan verdict caching and CDR, callback trust, SVG, image/archive bombs, size/count/quotas, metadata reflected on serve, private downloads, proxy vs signed URL, CDN caching of private objects | `references/file-uploads.md` |
| AI agents and MCP tool surfaces, DRF viewsets republished as tools, agent tokens and audience validation, tool scope vs user permissions, model output and retrieved content as untrusted input, prompt injection reaching a backend sink, per-agent cost/concurrency limits, tool-call confirmation and audit, the entry-token mapping to the OWASP LLM Top 10 2026 and Agentic Top 10 with the entries a backend skill declares non-goals | `references/agent-and-llm-interfaces.md` |
| Database roles and privilege separation, row-level security, tenant context on pooled connections, verified DB TLS, field-level encryption and blind indexes, raw-SQL isolation bypass, NoSQL/Redis injection, read-replica staleness, transaction isolation and the serialization-failure retry a raised level requires, connection exhaustion, backups and production-data copies | `references/data-layer-and-database.md` |
| Deletion completeness and erasure, soft-delete tombstones leaking through related-object/admin/serializer/raw paths, files left after a row is deleted, retention and scheduled purges, anonymization vs pseudonymization, personal-data inventory and model-layer classification, data export/DSAR endpoints, copies in indexes, caches, history tables, and lower environments | `references/data-lifecycle-and-privacy.md` |
| Service-to-service identity, machine-token validation (algorithm pinning, `iss`/`aud`, required claims), JWKS caching and key rotation, OAuth client credentials, mutual TLS and certificate-bound tokens, proxy-set client-certificate identity, platform workload identity, network-position-as-authentication on internal endpoints, downstream token exchange, secret storage/delivery/rotation, `SECRET_KEY` rotation, leaked-secret response | `references/service-identity-and-secrets.md` |
| TLS/HSTS and hybrid post-quantum key exchange at the edge, Nginx, reverse-proxy & `X-Forwarded-*` trust, reading the client IP behind proxies, header ownership edge-vs-Django, debug/profiling and metrics endpoints reachable in production, Gunicorn/systemd hardening, container image posture and secrets baked into layers, static/media, cache & queue exposure | `references/deployment-and-runtime.md` |

### Package decisions

| Concern | Reference file |
|---|---|
| Vetted security-library choices, compatibility, minimum-safe versions, conditional/existing-install-only/rejected candidates (current as of 9 Aug 2026) | `references/security-hardening-libraries.md` |

## Ownership and boundaries

Overlap between these files is designed. Each contested topic below has exactly
one owner; every other file names the topic and points at the owner instead of
restating its rules. Each reference file repeats its own half of the rule in
its opening paragraph, so the decision holds whichever file you opened first.

**Workflow versus methodology.** `references/01-audit-workflow.md` owns how a
codebase is swept; `references/00-methodology-and-severity.md` owns how a
finding is scored and written. The split is procedural against evaluative. The
first decides what gets opened and in what order, and carries the entry-point
inventory, the principal and trust-boundary model, hypothesis ordering, the
coverage ledger, and the rule that a chain is one finding at the severity of
its outcome. The second keeps the severity rubric, the confidence scale, the
finding schema, the ASVS mapping, the report structure, and the standing
write-time contract. The handoff runs one way at write-up: the ledger's
not-examined lines become the report's limitations section, whose shape the
methodology file owns.

**Authorization.** A01 owns the per-request failure and how to recognize it.
`references/authorization-architecture.md` owns the privilege model that
produces it, the field-level model, and the table of which DRF paths invoke the
object hook. `references/api-drf-specific.md` owns the call sites — the routes,
actions, and defaults where a correct model still fails to run.
`references/privileged-access-and-impersonation.md` owns operator privilege.
The bypass-path table lives only in
`references/authorization-architecture.md`; everything else cross-references it.

**Rate limiting.** A06 owns which flows need a limit in the first place.
`references/api-drf-specific.md` owns the throttling mechanics every other file
defers to, including the reasons a configured rate is not the effective one.
A07 owns login lockout, `references/agent-and-llm-interfaces.md` owns per-agent
cost and concurrency limits, and A10 owns the race and idempotency mechanics
that decide whether a limit holds under concurrent requests.

**Algorithmic resource exhaustion.** A06, which owns the design question —
which caller-controlled inputs multiply work and therefore need a bound the
server enforces — and the table naming the surface that enforces each one. The
mechanics stay where they already are: `references/file-uploads.md` for size,
count, and expansion, `references/api-drf-specific.md` for pagination,
`references/graphql-and-alternative-api-surfaces.md` for document cost,
`references/async-and-channels.md` for the long-lived connection,
`references/data-layer-and-database.md` for connections and query time, and A10
for the regular expression alone.

**Injection sinks.** A05 is the inventory for the whole skill, and it is meant
to be exhaustive so that no other file keeps a partial copy. It owns SQL, the
shell, and server-side output outright, and with SQL it owns the GeoDjango
positions the ORM does not parameterize — the raster band index and the
spatial-lookup value that is read as a raster source rather than as a value.
Its other rows point outward: `references/data-layer-and-database.md` for raw
paths and document-store shape validation, A01 for SSRF and for the filesystem
path a request names, `references/file-uploads.md` for the storage key an
upload lands under, A08 for deserialization, and A09 for the log line.

**SSRF.** A01, which absorbed it in the 2025 list.
`references/file-uploads.md`, `references/agent-and-llm-interfaces.md`,
`references/service-identity-and-secrets.md`, and
`references/a08-integrity-and-deserialization.md` each reach it and all defer
here, as does the cloud metadata endpoint a leaked workload credential is
reached through.

**Path traversal.** A01, on the same reasoning as SSRF: a request reaching a
resource it should not, with nothing in the code that looks like an
authorization decision. The split against `references/file-uploads.md` is by
direction rather than by file type. A01 owns the read whose path the request
named — the report download, the export, the artifact or log viewer, flows
with no upload in them at all — along with what Django does and does not
protect there. `references/file-uploads.md` owns the name an upload brings,
the key it lands under, and the private download of a file the application
stored. A05's inventory row for the filesystem path points at A01 and names
`references/file-uploads.md` for the storage-key half.

**Secrets and keys.** A04 owns the choice of primitive and its parameters, and
the life of a key from generation to destruction.
`references/service-identity-and-secrets.md` owns where a secret lives, how it
reaches the process, and how it rotates, `SECRET_KEY` included. A02 owns the
settings module that names it, and `references/deployment-and-runtime.md` owns
how the environment is injected.

**Configuration versus runtime.** Split by where the setting lives rather than
by topic. A02 owns what a settings module or a DNS zone declares.
`references/deployment-and-runtime.md` owns what the proxy, the process, and
the image do with a request once it arrives, including forwarded-header trust
and the client IP that every rate limit and audit record depends on. Mail
authentication is A02 — whether your domain can be forged — while whether your
mailer can be driven is A06.

**Failure behavior.** A10 owns what happens when the expected sequence does
not hold: the concurrency mechanics, idempotency-key design, and fail-closed
error handling. A09 owns what must be recorded and what must never be. A06
catalogs the flows worth attacking, A08's event de-duplication is the same
design as A10's idempotency key, and `references/api-drf-specific.md`,
`references/a03-software-supply-chain.md`, and
`references/data-lifecycle-and-privacy.md` carry one-line uses that name A10
rather than restating it.

**Human versus machine identity.** A07 owns the human principal and every
credential issued to one, including the API-key discipline a static service key
still has to meet. `references/service-identity-and-secrets.md` owns the
machine principal — mechanism choice, inbound machine-token validation, JWKS
caching and rotation, proxy-set certificate identity, and downstream token
exchange. `references/agent-and-llm-interfaces.md` owns the tool-call threat
model and the passthrough prohibition itself, and A04 owns the primitives all
of it is built on.

**Cross-system trust.** A08 owns the receiving end: the inbound webhook end to
end, every path that turns bytes back into live objects including the ones the
framework runs without being asked, and the task message a worker will execute
for anyone who can reach the broker. A01 keeps the SSRF mechanics an outbound
delivery worker has to satisfy, `references/deployment-and-runtime.md` keeps
broker and cache exposure, `references/service-identity-and-secrets.md` keeps
where signing secrets live, and A03 keeps dependency vetting while A08 keeps
only the integrity of what the project itself produces and consumes.

**Uploads and object storage.** `references/file-uploads.md` owns the file from
the request to the reader, including the architecture where the bytes never
reach the application at all: what a delegated upload URL binds, the quarantine
prefix an object waits in until the server has verified it against the store
rather than against the uploader's claims, and the choice between proxying a
private download and signing a URL for it. A08 keeps the signature, timestamp,
and replay rules a callback has to satisfy. A01 keeps import-from-URL SSRF, the
cache-mediated leak that a CDN cache key dropping its signing parameters is
one case of, and the traversal question on a read whose path the request named.
`references/data-lifecycle-and-privacy.md` keeps whether the bytes
are gone, while `references/file-uploads.md` keeps only the fact that an
already-issued signed URL is beyond the reach of any erasure — and the
per-provider qualification of that fact, since an Azure SAS is the one form
that can be withdrawn without rotating the credential that signed it.

**The database as a boundary.** `references/data-layer-and-database.md` owns
roles, row-level security, connection verification, encrypted columns, the
isolation level the connection runs at, and pooling. It keeps the
serialization-failure retry that a raised level requires, while A10 keeps the
constraint-versus-lock choice that usually makes raising it unnecessary.
It defers to A05 for injection mechanics, A04 for the cryptographic
principle, `references/authorization-architecture.md` for the tenant model
those mechanisms enforce, and `references/deployment-and-runtime.md` for the
network, cache, broker, and secrets operations around them.

**The record over time.** `references/data-lifecycle-and-privacy.md` owns
deletion completeness, what a soft-delete flag fails to hide, retention,
anonymization, and every copy an erasure has to reach.
`references/authorization-architecture.md` owns who may read a denormalised
copy while `references/data-lifecycle-and-privacy.md` owns whether that copy
still exists once the source row is gone. A09 owns what must be logged while
`references/data-lifecycle-and-privacy.md` owns the log and the history table
as retained copies of personal data. `references/data-layer-and-database.md`
keeps backups, replicas, and the encryption substrate that crypto-shredding
depends on, and `references/file-uploads.md` keeps storage and delivery of the
files whose deletion `references/data-lifecycle-and-privacy.md` owns.

**Client-composed requests.** `references/graphql-and-alternative-api-surfaces.md`
owns the surface where the client composes the request — resolver-edge
authorization, document cost limits, schema exposure — and the defaults of the
non-DRF frameworks and transports, from a Django Ninja route to a gRPC
servicer. It defers to A01 for the access-control failure itself,
`references/authorization-architecture.md` for the field-level model,
`references/api-drf-specific.md` for the serializer and throttling patterns it
generalizes, `references/file-uploads.md` and `references/async-and-channels.md`
for uploads and subscriptions, and A03 for the stale-library finding a
graphene-django install raises.

**Agent and MCP surfaces.** `references/agent-and-llm-interfaces.md` owns the
tool-call threat model and the MCP-specific controls, and defers to the files
above for the authorization mechanics, token rules, injection sinks, and audit
machinery it reuses rather than restating them.

**The container image.** `references/deployment-and-runtime.md` stops at the
artifact the repository produces — base image, `USER`, `.dockerignore`, and
secrets baked into layers. Orchestrator enforcement is named as a cross-team
recommendation rather than a repository finding, and where a secret comes from
at run time belongs to `references/service-identity-and-secrets.md`.

## Mode selection

**Review-time.** Trigger when the user asks to review, audit, scan, or "check"
existing code; pastes code and asks whether it's safe; or has just finished a
feature and wants it looked at. Behavior:

- Load `references/01-audit-workflow.md` first, before any topic file. It owns
  the sweep — the phase order, the entry-point inventory, the principals and
  boundaries, the coverage ledger — and the topic files answer the questions
  that sweep generates. Opening a topic file first means reviewing whatever
  the codebase made obvious.
- Treat the codebase as **read-only**. Do not edit, refactor, or "fix in place"
  unless the user explicitly asks you to apply fixes afterward.
- Optionally run the bundled scripts for fast triage (see below), then read the
  code yourself. Scripts surface indicators; they do not replace judgment.
- Investigate before flagging. Confirm the data flow and the reachability of a
  sink. Do not pattern-match a keyword into a finding.
- Produce a findings report in the exact format in
  `references/00-methodology-and-severity.md`: ordered by severity, each with
  location, CWE, OWASP mapping, and a concrete fix. End with what you did *not*
  review.

**Write-time.** Trigger when you're generating or modifying backend code for a
feature. Behavior:

- Apply the secure defaults from the relevant category file(s) as you write —
  parameterized queries, scoped querysets, explicit serializer fields, correct
  cookie/security flags, safe deserializers, secrets from the environment. The
  standing contract behind those, and the index of which file carries the rule
  for each generation moment, are in
  `references/00-methodology-and-severity.md`.
- Prefer built-in framework mechanisms over add-ons (see the libraries file).
- Where a secure default conflicts with what was asked for, apply the default
  and say so in one line naming the risk and the exact opt-out. Never downgrade
  silently, and never refuse silently.
- Close with a short **Security decisions** note: the defaults applied,
  anything the request forced along with its residual risk, and anything left
  for the caller to do. Write-time does not produce a findings report.

**If it's ambiguous,** default to write-time guardrails while coding and offer to
run a review afterward.

## Using the scripts

Both scripts are read-only, stdlib-only, and make no network calls. Run them for
triage; always confirm what they surface by reading the code.

- Settings posture (AST-based; never imports the project):
  `python scripts/settings_scan.py path/to/settings.py`
- Risky-pattern indicators across a tree:
  `python scripts/dangerous_patterns.py path/to/project`

Their output is a starting point for investigation, not a final report. Map each
real issue to a category file, verify it, and write it up per the methodology.

## Severity, in one line each

- **Critical** — trivially exploitable; RCE, full auth bypass, mass data
  exposure, or financial/payment manipulation.
- **High** — directly exploitable under realistic conditions; account takeover,
  privilege escalation, significant data exposure.
- **Medium** — exploitable given specific conditions, or a meaningful
  defense-in-depth gap.
- **Low** — hardening / defense-in-depth with limited direct impact.

A race is rated on how reliably its window can be won and what the collision
costs, rather than filed as Medium for being a race, and a failure that leaves
personal data alive past a promised deletion is rated on that promise as well
as on attacker value.

Report findings you're ≥80% confident are real and reachable. Full rubric, the
ASVS 5.0 chapter mapping and when to cite one, and the report template:
`references/00-methodology-and-severity.md`.
