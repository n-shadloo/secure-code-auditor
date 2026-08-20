---
name: secure-code-auditor
description: >-
  Backend security auditor for Django and DRF on an OWASP Top 10 (2025), API
  Security Top 10 (2023), and ASVS 5.0 foundation. Use when backend code is
  written or reviewed and touches authentication, sessions, cookies, JWT,
  OAuth2/OIDC, API keys, password hashing, permissions, access control,
  IDOR, SSRF, path traversal, open redirect, impersonation,
  SQL/command/template injection, LDAP, row-level security, encrypted
  columns, NoSQL, Redis, file uploads, S3, serializers, rate limiting,
  CSRF/CORS, OpenAPI schema, GraphQL, Django Ninja, gRPC, AI agents, MCP
  tools, secrets, payments, webhooks, Celery, Django tasks, race conditions,
  ReDoS, caching, deserialization, async/ASGI, WebSockets, audit logging,
  erasure, retention, personal data, migrations, JWKS, mutual TLS,
  SECRET_KEY, SBOM, X-Forwarded-For, SPF/DKIM/DMARC, or deployment config,
  even if "security" is never used. Review-time returns prioritized findings
  with fixes; write-time applies secure defaults. Django/DRF-first; general
  layer suits any stack.
license: MIT
allowed-tools: Read, Grep, Glob, Bash
metadata:
  author: n-shadloo
  version: 1.45.0
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
| How a codebase is swept before anything is judged: the phase order together with the artifact each phase hands the next and the coverage property that closes it, the entry-point inventory across URLconf chains, routers and actions, Django Ninja, GraphQL, gRPC, Channels, Celery and beat, management commands, signals, admin, webhooks, MCP tools, and middleware, the principals and trust boundaries a Django backend actually distinguishes, source-to-sink pairing with the intervening functions retrieved rather than the path inferred from its two ends, hypothesis ordering by impact against effort to confirm, the budget rule for a tree too large to read closely — enumerate exhaustively, read selectively, and record a sampled family as sampled — the six-item gate every hypothesis discharges before it is written as a finding, each discharge resting on retrieved text rather than remembered behavior, and the disposition rule for one that fails an item, the Django and DRF patterns commonly mistaken for findings together with the question that decides each, the coverage ledger that keeps examined-and-clean apart from not-examined and is read back at each phase boundary rather than recalled, the attack chains worth searching for with the file that owns each hop, the regression harness that holds a finding closed — one test per finding stating the attack rather than the patch, proven by reintroducing the defect, and a pipeline gate that reads the bundled scanners' records because their exit code is always 0 — and the WSTG mapping at section granularity naming which of the testing guide's sections this skill covers, which it declares non-goals, and why any test identifier it cites is version-tagged | `references/01-audit-workflow.md` |
| Method & severity model including how a race and a privacy failure are rated, the baseline-severity table that makes an ordinary finding class reproducible beside the rubric that decides the borderline one, the evidence line every finding carries, report format, the ASVS 5.0 chapter mapping with the chapters this skill treats as non-goals, mode selection, the write-time secure-default contract and the index of which file holds each generation moment's rule, what to do when a secure default conflicts with the request, the security-decisions note write-time returns instead of a findings report, and the two-mode convention every control follows | `references/00-methodology-and-severity.md` |

### The OWASP Top 10:2025 spine

| Concern | Reference file |
|---|---|
| **A01** Access control, IDOR/BOLA, object- & function-level authz, the generic relation whose target model the client picks by naming a content type and the check that therefore runs against nothing, URL resolution as the surface every check assumes — the unanchored pattern that matches more than its shape, the first of two matching patterns winning while the second carries the permission, and the review action of grouping resolved routes rather than reading route files, cache-mediated data leaks, SSRF and egress control, path traversal on a file read the request names, open redirect including the language switch that is one, the locale prefix redirect and the cache key that loses the request's language while `Vary` still names it, multi-tenancy, admin access | `references/a01-broken-access-control.md` |
| **A02** DEBUG/ALLOWED_HOSTS, SECURE_*/SESSION_*/CSRF_* matrix, the `__Host-` and `__Secure-` cookie prefixes with the four settings each needs to agree with and the cookie tossing from a sibling subdomain that the strong one removes, signed cookies and the legacy salt fallback, CORS, headers, mail authentication (SPF/DKIM/DMARC alignment and rollout), CAA and dangling-DNS/subdomain takeover, `check --deploy` and what it cannot see, writing the project's own deploy-only guardrail check for the properties no framework check can know together with the identifier prefix that keeps a silencing entry from disabling it, configuration drift measured against the settings a deployed process resolved rather than against the files, and the owner, reason, and expiry every suppression carries | `references/a02-security-misconfiguration.md` |
| **A03** Dependencies, third-party vetting/maintained-package gate, a development-only package reaching the production requirements file, pinning/hashing, `pip-audit`, EOL frameworks, migrations/data integrity, the SBOM generated from the lockfile rather than the built image and what it does not prove, the CI scan gate read as configuration rather than as a step that exists, build provenance and the consumer-side verification that makes an attestation mean anything, SLSA Build levels at claim level, and the line between what a repository audit can verify and what is confirm-with-platform | `references/a03-software-supply-chain.md` |
| **A04** Password-hashing family and parameters, upgrade-on-login and the wrapped-hasher migration that reaches the dormant accounts it cannot, randomness and token generation, constant-time comparison, signing and per-purpose salt discipline, TLS-in-transit, data at rest, key lifecycle and envelope encryption worked against a KMS, cryptographic agility and the four-step algorithm migration whose measurement step is the one that gets skipped, post-quantum posture | `references/a04-cryptographic-failures.md` |
| **A05** The sink inventory every other reference defers to and the method for tracing a source to it, including the stored-then-used path worked end to end, SQL/ORM injection, dictionary-expansion column aliases, GeoDjango raster band indexes and spatial-lookup raster sources, command and argument injection, template injection and XSS from server-rendered output, LDAP/directory injection, header/email injection, XML external entity injection and entity expansion named at the XML sink, and the exported CSV or workbook cell whose interpreter is a spreadsheet program on the reader's machine | `references/a05-injection.md` |
| **A06** Which flows need a rate limit or anti-automation in the first place, the inventory of every path that moves money, credits, entitlements, or durable status — including the command, task, admin action, signal, migration, and bulk writers that never reach a view — and whether each transition's invariant is held by the database or only by Python, amount and currency binding, capture/refund/reversal as a design question, entitlement grant against revocation, algorithmic resource exhaustion and the bound every caller-controlled input needs, abuse of side-effecting actions with email/notification abuse as its worked instance, missing limits, insecure defaults | `references/a06-insecure-design.md` |
| **A07** Human authentication: password policy from the length floor to the breached-corpus screening no built-in validator provides, the user model as an identity contract — which field is the identifier, the collation that silently decides whether two rows are one person, the one normalization every write path has to share, and what `is_active` reaches against what it leaves standing — sessions, the engine choice that decides whether a session can be revoked at all and the three calls that rotate one, JWT/SimpleJWT, OAuth2/OIDC/social login including the mix-up attack by name, API keys, brute force, MFA, passkey and WebAuthn configuration, password reset, allauth/dj-rest-auth/OAuth Toolkit, enumeration | `references/a07-authentication-failures.md` |
| **A08** Insecure deserialization (pickle/yaml), the cache/session/fixture paths Django deserializes without being asked, Celery task-message trust and serializers, Django's built-in tasks framework and the inline execution its default backend gives an enqueue that reads as backgrounded, signed data, inbound webhook signature/timestamp/replay and event de-duplication, outbound webhook delivery controls, artifact provenance | `references/a08-integrity-and-deserialization.md` |
| **A09** Sensitive-data leakage in logs, audit logging, lifecycle hooks/signals, alerting, log injection, forensic readiness and evidence integrity including append-only sinks and what a hash chain does and does not prove, decoy records and canary tokens as a detection control | `references/a09-logging-and-alerting.md` |
| **A10** Fail-open vs fail-closed checks, error views and stack-trace leakage, race conditions/TOCTOU, locking vs database constraints, idempotency-key design, transaction side-effect ordering, state-transition enforcement, ReDoS | `references/a10-exceptional-conditions.md` |

### Cross-cutting surfaces

These span several categories, so they are grouped by the surface in front of
you rather than by OWASP number.

| Concern | Reference file |
|---|---|
| Privilege model (RBAC/ABAC/ReBAC), `ModelBackend`/DRF/admin permission behavior, default-deny + URLconf audit test, field-level authz (BOPLA), search-index and denormalized-copy leakage, authz test design, permission decay, and the joiner/mover/leaver lifecycle a provider-side disable does not finish | `references/authorization-architecture.md` |
| Impersonation / "log in as user", django-hijack, break-glass & JIT elevation, operator audit identity | `references/privileged-access-and-impersonation.md` |
| Where DRF runs the object check and the routes that skip it, `@action` and function-level authz (BFLA), serializer over-exposure/mass assignment (ModelForm and formset included), pagination/filter/ordering leakage, throttling mechanics and the owned atomic counter a limit that must hold needs instead, schema and browsable-API exposure, endpoint inventory and shadow routes, versioning and deprecation, bulk endpoints, unsafe DRF defaults, DRF+CSRF | `references/api-drf-specific.md` |
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
restating its rules. Each reference file also repeats its own half of the rule
in its opening paragraph, which is why a row can carry the decision here: the
reader who needs it is usually already in one of the two files, and the table
only has to send them to the right one. The three splits below the table turn
on an axis a row would misstate, so they keep their sentence.

| Contested topic | Owner | Deciding distinction |
|---|---|---|
| Sweeping a codebase: phase order, entry-point inventory, principals and boundaries, hypothesis ordering, the budget rule, the coverage ledger, a chain as one finding at the severity of its outcome | `references/01-audit-workflow.md` | Procedural — what gets opened, and in what order |
| Scoring and writing a finding: severity rubric, confidence scale, finding schema, ASVS mapping, report structure, the standing write-time contract | `references/00-methodology-and-severity.md` | Evaluative — what an opened file is worth. The handoff runs one way at write-up: the ledger's not-examined lines become the limitations section, whose shape belongs here |
| The test that holds a closed finding, and the pipeline step that runs it | `references/01-audit-workflow.md` | Procedural, and the sweep's forward half: what runs on every commit once the report is written. `references/authorization-architecture.md` still owns the authorization matrix's design, and A03 the dependency scan gate whose exit code is its own verdict |
| A suppression, an ignore entry, or a silenced check, and the expiry it carries | `references/a02-security-misconfiguration.md` | An exception is a configuration decision wherever it is written, so one file owns the record for all four kinds; A03 keeps what a pipeline does with the scanner result being suppressed |
| The per-request access-control failure | `references/a01-broken-access-control.md` | The request that reached what it should not, and how to recognize it in code |
| The privilege model that produces it, field-level authorization, and which DRF paths invoke the object hook | `references/authorization-architecture.md` | The model rather than the failure. The bypass-path table lives only here; everything else cross-references it |
| The identity's own lifecycle: joiner, mover, leaver, and everything a provider-side disable leaves running | `references/authorization-architecture.md` | The principal and its grants over time. A07 owns each credential's own rules, this file the event that should have ended all of them at once |
| The call sites where a correct model still fails to run | `references/api-drf-specific.md` | DRF routes, actions, and defaults rather than the model behind them |
| Which view a path reaches when two patterns match it | `references/a01-broken-access-control.md` | The request that arrived at the wrong code, so the check on the other route never ran. `references/api-drf-specific.md` owns producing the route inventory; the pass that groups it by resolved path is here |
| Operator privilege | `references/privileged-access-and-impersonation.md` | Impersonation and break-glass, and the accountable operator identity both have to carry |
| Which flows need a rate limit or anti-automation in the first place | `references/a06-insecure-design.md` | The design question, never the mechanism |
| Throttling mechanics, including the reasons a configured rate is not the effective one | `references/api-drf-specific.md` | The mechanism every other file defers to |
| Login lockout | `references/a07-authentication-failures.md` | The limit belonging to a human credential |
| Per-agent cost and concurrency limits | `references/agent-and-llm-interfaces.md` | Budget per caller rather than requests per window |
| Whether a limit holds under concurrent requests | `references/a10-exceptional-conditions.md` | Race and idempotency mechanics |
| Algorithmic resource exhaustion: which caller-controlled inputs multiply work and need a server-enforced bound | `references/a06-insecure-design.md` | Its own table names the surface that enforces each bound and each of those files keeps its mechanics, down to A10 for the regular expression alone |
| The injection-sink inventory for the whole skill | `references/a05-injection.md` | Exhaustive by design, so no other file keeps a partial copy. SQL, the shell, and server-side output are owned outright — with SQL, the GeoDjango raster band index and spatial-lookup raster source the ORM does not parameterize — and every other row points outward |
| SSRF, including the cloud metadata endpoint a leaked workload credential is reached through | `references/a01-broken-access-control.md` | Absorbed into A01 in the 2025 list; every file that reaches it defers here |
| The choice of cryptographic primitive, its parameters, and the life of a key from generation to destruction | `references/a04-cryptographic-failures.md` | The primitive, not the place it is consumed |
| Where a secret lives, how it reaches the process, and how it rotates, `SECRET_KEY` included | `references/service-identity-and-secrets.md` | A02 owns the settings module that names it, and `references/deployment-and-runtime.md` how the environment is injected |
| What happens when the expected sequence does not hold: concurrency mechanics, idempotency-key design, fail-closed error handling | `references/a10-exceptional-conditions.md` | The mechanics and the fixes. A06 keeps the inventory of flows worth attacking, and A08's event de-duplication is the same design as the idempotency key here |
| What must be recorded and what must never be, and whether the record survives as evidence | `references/a09-logging-and-alerting.md` | The record, not the failure being recorded. Append-only sinks, sequence integrity, and decoys are here; `references/data-lifecycle-and-privacy.md` keeps the erasure obligation the retained record has to reconcile with |
| The receiving end of cross-system trust: the inbound webhook end to end, the task message a worker will execute for anyone who can reach the broker, both task systems a project may be running and the authorization a task body has no principal to re-derive, every path that turns bytes back into live objects including the ones the framework runs without being asked | `references/a08-integrity-and-deserialization.md` | Only the integrity of what the project itself produces and consumes. A03 keeps dependency vetting, A01 the SSRF an outbound delivery worker has to satisfy, `references/deployment-and-runtime.md` broker and cache exposure, and `references/service-identity-and-secrets.md` where signing secrets live |
| The file from the request to the reader: delegated upload URLs, the quarantine prefix and promotion, proxying a private download against signing a URL for it | `references/file-uploads.md` | A08 keeps the signature, timestamp, and replay rules a callback satisfies; A01 keeps import-from-URL SSRF and the cache-mediated leak a CDN key dropping its signing parameters is one case of; `references/data-lifecycle-and-privacy.md` keeps whether the bytes are gone, leaving here only that an already-issued signed URL outruns any erasure |
| The database as a boundary: roles, row-level security, verified transport, encrypted columns, the isolation level, pooling | `references/data-layer-and-database.md` | The serialization-failure retry a raised level requires is here; the constraint-versus-lock choice that usually makes raising it unnecessary is A10's |
| The record over time: deletion completeness, what a soft-delete flag fails to hide, retention, anonymization, every copy an erasure has to reach | `references/data-lifecycle-and-privacy.md` | Existence rather than access. `references/authorization-architecture.md` owns who may read a denormalized copy and A09 what must be logged; this file owns whether the copy still exists, and the log and history table as retained personal data |
| The surface where the client composes the request, and every API surface that is not a DRF route | `references/graphql-and-alternative-api-surfaces.md` | Resolver-edge authorization, document cost, and schema exposure, plus the defaults of a Django Ninja route or a gRPC servicer that a DRF engineer will assume are present |
| The tool-call threat model and the MCP-specific controls | `references/agent-and-llm-interfaces.md` | What changes when the caller is a program driving the backend on someone's behalf; it restates none of the machinery it reuses |
| The container image | `references/deployment-and-runtime.md` | Stops at the artifact the repository produces — base image, `USER`, `.dockerignore`, secrets baked into layers. Orchestrator enforcement is a cross-team recommendation rather than a repository finding, and where a secret comes from at run time is `references/service-identity-and-secrets.md`'s |

**Path traversal.** The split between A01 and `references/file-uploads.md` is
by direction rather than by file type, and it is not the read-against-write
line it resembles. A01 owns the read whose path the request named — the report
download, the export, the artifact or log viewer, flows with no upload in them
at all — along with what Django does and does not protect there.
`references/file-uploads.md` owns the name an upload brought and the key it
landed under, and also the private download of a file the application stored,
which is a read that stays there because the application chose the path rather
than the caller. A05's inventory row for the filesystem path points at A01 and
names `references/file-uploads.md` for the storage-key half.

**Configuration versus runtime.** Split by where the setting lives rather than
by topic, so looking the topic up will misroute: A02 owns what a settings
module or a DNS zone declares, and `references/deployment-and-runtime.md` owns
what the proxy, the process, and the image do with a request once it arrives,
including forwarded-header trust and the client IP that every rate limit and
audit record depends on. A cached response splits on the same line — A01 owns
whether a cached representation may be reused across principals, and
`references/deployment-and-runtime.md` the edge rule that decides what is
cached at all, which is the half a deception attack turns on. Mail
authentication is A02, whether your domain can be forged, while whether your
mailer can be driven is A06.

**Human versus machine identity.** The axis holds except at the two places a
reader actually arrives at it. A07 owns the human principal and every
credential issued to one, including the API-key discipline a static service key
still has to meet — a machine credential governed from the human file.
`references/service-identity-and-secrets.md` owns the machine principal:
mechanism choice, inbound machine-token validation, JWKS caching and rotation,
proxy-set certificate identity, and obtaining a downstream credential by
exchange. The prohibition on forwarding an inbound token to that downstream
service belongs to neither, but to
`references/agent-and-llm-interfaces.md` alongside the tool-call threat model,
and A04 owns the primitives all three are built on.

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
  location, CWE, OWASP mapping, the evidence the finding was confirmed on, and
  a concrete fix. End with what you did *not* review.

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

All three scripts are read-only, stdlib-only, and make no network calls, and all
three take `--json`, which is JSON Lines in each — one object per line, consumed
a record at a time rather than parsed as one document. Run them for triage;
always confirm what they surface by reading the code.

- Entry-point inventory, the instrument for the workflow's first phase:
  `python scripts/entrypoint_inventory.py path/to/project --settings path/to/settings --json`
- One or more entry-point families at a time on a large surface:
  `python scripts/entrypoint_inventory.py path/to/project --kind url,drf,action`
- Settings posture across a whole settings package (never imports the project):
  `python scripts/settings_scan.py path/to/settings/ --json`
- Risky-pattern indicators across a tree:
  `python scripts/dangerous_patterns.py path/to/project`
- The same tree as JSON Lines, filtered, for a large codebase:
  `python scripts/dangerous_patterns.py path/to/project --json --min-severity MEDIUM`
- Confirm the scanner itself before trusting a quiet result:
  `python scripts/dangerous_patterns.py --selftest`

The inventory enumerates the declared entry points — routes at the full prefix
their `include()` chain resolves to, routers and actions, Ninja, GraphQL, gRPC,
Channels, Celery, commands, signals, admin, and middleware — so the review is
derived from the whole surface rather than from the files that looked
interesting, and it marks each HTTP-reachable row as declaring its
authorization, inheriting it from somewhere not visible there, or having none.

All three parse with the `ast` module rather than grepping lines, so a hit is a
structural match — parameterized SQL, `mark_safe` on a constant, and anything
inside a docstring are not reported — every row names the reference file that
owns it, a `dangerous_patterns.py` hit additionally carries a stable rule
identifier, and a file that fails to parse is reported as unparsed rather than
skipped in silence.

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
baseline severity table beneath it, the ASVS 5.0 chapter mapping and when to
cite one, and the report template:
`references/00-methodology-and-severity.md`.
