---
name: secure-code-auditor
description: >-
  Backend security auditor for Django and DRF on an OWASP Top 10 (2025)
  and API Security Top 10 (2023) foundation. Use when backend code is
  written or reviewed and touches authentication, sessions, JWT,
  OAuth2/OIDC, API keys, password hashing, permissions, access control,
  impersonation, the ORM, raw SQL, SQL/command/template injection, XSS,
  LDAP, row-level security, encrypted columns, NoSQL, Redis, file
  uploads, object storage, S3, buckets, presigned URLs, serializers, API
  endpoints, OpenAPI schema, GraphQL, Django Ninja, AI agents, MCP
  tools, secrets, payments, webhooks, HMAC, notifications, Celery, race
  conditions, caching, CDN, deserialization, async/ASGI, WebSockets,
  erasure, retention, personal data, migrations,
  JWKS, mutual TLS, key rotation, SECRET_KEY, Dockerfile,
  X-Forwarded-For, SPF/DKIM/DMARC, or deployment config, even if
  "security" is never used.
  Review-time returns prioritized findings with fixes; write-time
  applies secure defaults. Django/DRF-first; general layer suits any
  stack.
license: MIT
allowed-tools: Read, Grep, Glob, Bash
metadata:
  author: n-shadloo
  version: 1.16.0
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

Load only the file(s) relevant to the concern in front of you.

| Concern | Reference file |
|---|---|
| Method & severity model, report format, mode selection | `references/00-methodology-and-severity.md` |
| Access control, IDOR/BOLA, object- & function-level authz, cache-mediated data leaks, SSRF, open redirect, multi-tenancy, admin access | `references/a01-broken-access-control.md` |
| DEBUG/ALLOWED_HOSTS, SECURE_*/SESSION_*/CSRF_* matrix, CORS, headers, mail authentication (SPF/DKIM/DMARC alignment and rollout), CAA and dangling-DNS/subdomain takeover, `check --deploy` and what it cannot see | `references/a02-security-misconfiguration.md` |
| Dependencies, third-party vetting/maintained-package gate, pinning/hashing, `pip-audit`, EOL frameworks, migrations/data integrity, SBOM | `references/a03-software-supply-chain.md` |
| Password-hashing family and parameters, upgrade-on-login, randomness and token generation, constant-time comparison, signing and per-purpose salt discipline, TLS-in-transit, data at rest, key lifecycle and envelope encryption, post-quantum posture, secrets | `references/a04-cryptographic-failures.md` |
| The sink inventory every other reference defers to and the method for tracing a source to it, SQL/ORM injection, dictionary-expansion column aliases, command and argument injection, template injection and XSS from server-rendered output, LDAP/directory injection, header/email injection | `references/a05-injection.md` |
| Rate limiting/anti-automation, business-logic and email/notification abuse, missing limits, insecure defaults | `references/a06-insecure-design.md` |
| Sessions, JWT/SimpleJWT, OAuth2/OIDC/social login, API keys, brute force, MFA, password reset, allauth/dj-rest-auth/OAuth Toolkit, enumeration | `references/a07-authentication-failures.md` |
| Insecure deserialization (pickle/yaml), the cache/session/fixture paths Django deserializes without being asked, Celery task-message trust and serializers, signed data, inbound webhook signature/timestamp/replay and event de-duplication, outbound webhook delivery controls, artifact provenance | `references/a08-integrity-and-deserialization.md` |
| Sensitive-data leakage in logs, audit logging, lifecycle hooks/signals, alerting, log injection | `references/a09-logging-and-alerting.md` |
| DEBUG/error views, stack-trace leakage, fail-open vs fail-closed checks, race conditions/TOCTOU, locking vs database constraints, idempotency-key design, transaction side-effect ordering, state-transition enforcement, ReDoS | `references/a10-exceptional-conditions.md` |
| Privilege model (RBAC/ABAC/ReBAC), `ModelBackend`/DRF/admin permission behavior, default-deny + URLconf audit test, field-level authz (BOPLA), search-index and denormalised-copy leakage, authz test design, permission decay | `references/authorization-architecture.md` |
| Impersonation / "log in as user", django-hijack, break-glass & JIT elevation, operator audit identity | `references/privileged-access-and-impersonation.md` |
| Where DRF runs the object check and the routes that skip it, `@action` and function-level authz (BFLA), serializer over-exposure/mass assignment, pagination/filter/ordering leakage, throttling mechanics, schema and browsable-API exposure, endpoint inventory and shadow routes, versioning and deprecation, bulk endpoints, unsafe DRF defaults, DRF+CSRF | `references/api-drf-specific.md` |
| GraphQL endpoints and schemas, resolver-level authorization and nested traversal, all-fields types, query depth/alias/token/cost limits, introspection and error masking, mutation inputs and nested writes, batching, persisted queries, N+1 as resource exhaustion, Strawberry and graphene-django defaults, Django Ninja routes with no `auth=` | `references/graphql-and-alternative-api-surfaces.md` |
| Async/ASGI boundaries, sync ORM access, task/request context, WebSocket/Channels origin, authentication, authorization, and limits | `references/async-and-channels.md` |
| File uploads, type/content validation, safe names and storage-key design, object-storage configuration and bucket exposure, presigned URLs and direct-to-storage uploads, quarantine and promotion, callback trust, SVG, image/archive bombs, size/count/quotas, private downloads, proxy vs signed URL, CDN caching of private objects | `references/file-uploads.md` |
| AI agents and MCP tool surfaces, DRF viewsets republished as tools, agent tokens and audience validation, tool scope vs user permissions, model output and retrieved content as untrusted input, prompt injection reaching a backend sink, per-agent cost/concurrency limits, tool-call confirmation and audit | `references/agent-and-llm-interfaces.md` |
| Database roles and privilege separation, row-level security, tenant context on pooled connections, verified DB TLS, field-level encryption and blind indexes, raw-SQL isolation bypass, NoSQL/Redis injection, read-replica staleness, connection exhaustion, backups and production-data copies | `references/data-layer-and-database.md` |
| Deletion completeness and erasure, soft-delete tombstones leaking through related-object/admin/serializer/raw paths, files left after a row is deleted, retention and scheduled purges, anonymization vs pseudonymization, personal-data inventory and model-layer classification, data export/DSAR endpoints, copies in indexes, caches, history tables, and lower environments | `references/data-lifecycle-and-privacy.md` |
| Service-to-service identity, machine-token validation (algorithm pinning, `iss`/`aud`, required claims), JWKS caching and key rotation, OAuth client credentials, mutual TLS and certificate-bound tokens, proxy-set client-certificate identity, platform workload identity, network-position-as-authentication on internal endpoints, downstream token exchange, secret storage/delivery/rotation, `SECRET_KEY` rotation, leaked-secret response | `references/service-identity-and-secrets.md` |
| TLS/HSTS, Nginx, reverse-proxy & `X-Forwarded-*` trust, reading the client IP behind proxies, header ownership edge-vs-Django, debug/profiling and metrics endpoints reachable in production, Gunicorn/systemd hardening, container image posture and secrets baked into layers, static/media, cache & queue exposure | `references/deployment-and-runtime.md` |
| Vetted security-library choices, compatibility, minimum-safe versions, conditional/existing-install-only/rejected candidates (current as of 17 Jul 2026) | `references/security-hardening-libraries.md` |

Cross-references between files are intentional: authz appears in A01 as
per-request failures, in the authorization-architecture file as the model that
produces them, and again API-shaped in the DRF file; rate limiting spans A06,
A07, uploads, and async connections, with the DRF file owning the throttling
mechanics the others defer to; deployment covers the infrastructure side of
cache and media controls whose application rules live in A01 and the upload
reference. The agent reference owns the tool-call threat
model and the MCP-specific controls, and defers to those files for the
authorization mechanics, token rules, injection sinks, and audit machinery it
reuses rather than restating them. The data-layer reference owns the database as
a boundary of its own — roles, row-level security, connection verification,
encrypted columns, and pooling — and defers to A05 for injection mechanics, A04
for the cryptographic principle, the authorization-architecture file for the
tenant model those mechanisms enforce, and the deployment file for the network,
cache, broker, and secrets operations around them. The data-lifecycle reference
owns the record over time — deletion completeness, what a soft-delete flag
fails to hide, retention, anonymization, and every copy an erasure has to reach
— and draws deliberate lines against the files it overlaps: the
authorization-architecture file owns who may read a denormalised copy while the
data-lifecycle file owns whether that copy still exists after the source row is
gone; A09 owns what must be logged while the data-lifecycle file owns the log
and the history table as retained copies of personal data; the data-layer file
keeps backups, replicas, and the encryption substrate that the crypto-shredding
route depends on; and the upload reference keeps storage and delivery of files
whose deletion the data-lifecycle file owns. The service-identity reference
owns the machine principal and the credential material behind it — mechanism
choice, inbound machine-token validation, JWKS rotation, proxy-set certificate
identity, secret delivery, and key rotation — and stays clear of its
neighbours: A07 keeps human authentication and the API-key discipline any
static service key still has to meet, the agent reference keeps the tool-call
threat model and the passthrough prohibition itself, the deployment file keeps
proxy configuration and how the environment is injected, A04 keeps the
cryptographic primitives the signing is built on, and A01 keeps SSRF and the
metadata endpoint that a leaked workload credential is reached through. The
GraphQL reference owns the surface where the client composes the request —
resolver-edge authorization, document cost limits, schema exposure, and the
non-DRF framework defaults — and defers to A01 for the access-control failure
itself, the authorization-architecture file for the field-level model, the DRF
file for the serializer and throttling patterns it generalises, the upload and
async references for uploads and subscriptions, and A03 for the stale-library
finding a graphene-django install raises. A10 owns what happens when the
expected sequence does not hold — the concurrency mechanics, the idempotency-key
design, and fail-closed error handling — and is the single home for each: A06
keeps the catalogue of business flows worth attacking and defers to A10 for the
race and idempotency mechanics that enforce them, A08 keeps webhook signature
and replay verification while its event de-duplication is the same design, A09
keeps the lifecycle ordering and the transactional outbox that the side-effect
section points back at, and the DRF, migration, and data-lifecycle files carry
one-line uses that name A10 rather than restating the design. A08 owns the
receiving end of cross-system trust — the inbound webhook receiver end to end,
every path that turns bytes back into live objects including the ones the
framework runs without being asked, and the task message a worker will execute
for anyone who can reach the broker — and holds its boundaries against four
neighbours: A01 keeps the SSRF mechanics an outbound delivery worker has to
satisfy, the deployment file keeps broker and cache-service exposure, the
service-identity file keeps where signing secrets live and how they rotate, and
A03 keeps dependency vetting while A08 keeps only the integrity of the artifacts
and data the project itself produces and consumes. A04 owns the choice of
primitive and its parameters, and the life of a key from generation to
destruction — the password-hashing family and its cost settings, the source and
size of every random token, when a comparison has to be constant-time and when
that is noise, per-purpose salt discipline on signed values, envelope
encryption and versioned rotation, and the post-quantum inventory — while the
files that consume those choices keep the mechanism: the data-layer file owns
the encrypted column and the blind index, the service-identity file owns where
the key lives and how `SECRET_KEY` rotates, the deployment file owns TLS at the
edge, A08 owns the webhook receiver that the constant-time rule is applied
inside, and A07 owns password policy and the API-key lifecycle whose tokens A04
only says how to generate. A02 and the deployment file split the configuration
surface by where the setting lives rather than by topic: A02 owns what a
settings module or a DNS zone declares — the security matrix, CORS, CSP, and
the SPF, DKIM, DMARC, and CAA records that decide whether the domain can be
forged or a certificate issued for it — while the deployment file owns what the
proxy, the process, and the image do with a request once it arrives, including
forwarded-header trust and the client IP that every rate limit and audit record
depends on. Mail authentication is deliberately separate from A06's notification
abuse: one asks whether your domain can be impersonated, the other whether your
mailer can be driven. The container material stops at the artifact the
repository produces — base image, `USER`, `.dockerignore`, and secrets baked
into layers — and names orchestrator enforcement as a cross-team recommendation
rather than a repository finding, while the service-identity file keeps where a
secret comes from at run time. The upload reference owns the file from the
request to the reader, and now owns the architecture where the bytes never
reach the application at all: what a delegated upload URL binds and what each
unbound constraint buys an attacker, the quarantine prefix an object waits in
until the server has verified it against the store rather than against the
uploader's claims, the object-store settings a code review can actually see
and the platform state it cannot, and the choice between proxying a private
download and signing a URL for it. Its boundaries run three ways: A08 keeps
the signature, timestamp, and replay rules an upload callback has to satisfy;
A01 keeps the SSRF mechanics of an import-from-URL path and the general
cache-mediated leak that a CDN cache key dropping the signing parameters is
one case of; and the data-lifecycle file keeps whether the bytes are gone,
while the upload reference keeps only the fact that an already-issued signed
URL is beyond the reach of any erasure. A05 is the sink inventory for the whole
skill: it enumerates every interpreter a request can reach — SQL and its
identifier positions, the shell and a program's own option parser, the template
compiler, the directory, headers, log lines, paths, outbound HTTP,
deserializers, XML — so that a reference deferring to it can rely on the list
being complete rather than restating a partial copy, and it carries the
source-to-sink tracing method the other files apply. Its rows point outward
where another file owns the rules: the data-layer file for the raw-path
enumeration and document-store shape validation, the upload reference for
storage keys, A01 for SSRF, A08 for deserialization, and A09 for the log line.
The three sinks it owns outright and no other file duplicates are SQL, the
shell, and server-side output.

## Mode selection

**Review-time.** Trigger when the user asks to review, audit, scan, or "check"
existing code; pastes code and asks whether it's safe; or has just finished a
feature and wants it looked at. Behavior:

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
  cookie/security flags, safe deserializers, secrets from the environment.
- Prefer built-in framework mechanisms over add-ons (see the libraries file).
- Briefly note the security-relevant choices you made. If a requirement forces a
  risky pattern, say so and describe the residual risk rather than hiding it.

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

Report findings you're ≥80% confident are real and reachable. Full rubric and
report template: `references/00-methodology-and-severity.md`.
