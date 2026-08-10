# Gemini CLI context: secure-code-auditor

This repo's security instructions live in `SKILL.md` and `references/`. Load
`SKILL.md` first, then the relevant `references/*.md` file. Its router is
grouped into the OWASP Top 10:2025 spine, cross-cutting surfaces, and package
decisions; where two rows could both match, the "Ownership and boundaries"
section below the router names the one file that owns the topic, as a table
with three splits kept in prose. At
review-time `references/01-audit-workflow.md` comes before any topic file: it
owns the sweep, and the topic files answer the questions the sweep generates
rather than the ones the codebase made obvious. See `AGENTS.md` for the full
description. Do not duplicate the content here — read the source files.

The workflow runs scope and the repository-versus-environment boundary first,
then an entry-point inventory covering URLconf chains resolved to their full
prefix rather than the leaf pattern, DRF routers and `@action` methods
including collection actions, Django Ninja, GraphQL, gRPC, Channels, Celery
tasks and beat schedules, management commands, signals, admin registrations
and actions, webhook receivers, MCP tools, and middleware as the one entry
point that fires for every request — which `scripts/entrypoint_inventory.py`
enumerates read-only from the declarations, leaving anything registered at
runtime to the reading pass; then the principals a Django backend
actually distinguishes — down to the worker whose only credential is broker
access and the operator who is two identities at once — and the boundaries
between them; then sources paired to the sink inventory; then hypotheses
ordered by impact against the effort to confirm them, object- and
function-level authorization first because it is the highest-yield class in
Django codebases and usually settled by reading two files; then verification as
a six-item gate — attacker control, reachability, the protections that should
have stopped it, the insufficiency of whatever sanitization is present,
concrete impact, and a catalogue of the benign Django and DRF patterns that
look exactly like defects, each discharged against retrieved text rather than
against remembered behavior — with anything failing attacker control or matching
a benign pattern dropped rather than reported as a caveat, and everything that
survives carrying the shortest source-to-sink path it was confirmed on; every
phase handing the next a written artifact and closing on a property of its
coverage rather than on an amount of reading, which is what lets a tree too
large to read closely be enumerated in full while only the close reading is
rationed per area and any sampled family is recorded as sampled; and a
coverage ledger throughout that keeps what was examined and found clean apart
from what was never opened, since the report's limitations section is written
from the second of those, and that is read back at each phase boundary rather
than recalled; and a mapping of that sweep onto the OWASP Web
Security Testing Guide at section granularity — not at test granularity,
because the guide states its own identifiers change between versions — naming
the sections this skill covers and declaring the client-side chapter, the
reconnaissance tests, and everything needing a proxy or a live target as
non-goals rather than gaps. Confirmed issues are escalated one step
before write-up, so a chain — enumeration into takeover, SSRF into a workload
credential into the object store, a job running with more privilege than the
request that queued it — is one finding at the severity of its outcome with
its links named, rather than three Mediums nobody connects.

Coverage includes the authorization architecture and privilege model (object-,
function-, and field-level authorization, default-deny, authorization test
design), SSRF, impersonation and break-glass privileged access, OAuth2/OIDC and
social login, API-key lifecycle and scoping, password policy at the numbers the
standard actually sets — fifteen characters for a single factor and eight only
inside a multi-factor process, no composition rule and no expiry, and a
blocklist reaching a breach corpus rather than Django's twenty thousand
entries — with passkeys and WebAuthn audited at the configuration surface
because Django ships no native support to audit, agent- and LLM-facing
interfaces (MCP tool surfaces, agent token audience validation, tool scope
versus user permissions, model output and retrieved content as untrusted
input, and the mapping onto the OWASP LLM Top 10 2026 and Agentic Top 10 —
cited at entry-token level with the LLM edition pinned, because the 2026
edition renumbered against 2025 and an unpinned token now names a different
entry), the database as a security boundary (migration versus runtime roles,
row-level security and tenant context on pooled connections, verified database
TLS, field-level encryption, NoSQL injection, transaction isolation and the
retry a raised level requires, and connection exhaustion), the data lifecycle
(deletion and erasure completeness, soft-delete leakage, retention,
anonymization versus pseudonymization, personal-data classification, and
export/subject-access endpoints), service-to-service identity and secrets
(machine-token validation, JWKS caching and rotation, client credentials,
mutual TLS and proxy-set certificate identity, workload identity, secret
delivery, and `SECRET_KEY` rotation), GraphQL and non-DRF API surfaces
(authorization on every resolved edge, schema and type over-exposure, query
depth/alias/token/cost limits, introspection and error masking, mutation mass
assignment, persisted operations, Django Ninja's default of no authentication,
and gRPC, where the servicer answers on a second server that no middleware,
permission class, throttle or CSRF check reaches — a server with no
interceptor serves every registered method to anyone who can open a
connection, an interceptor that authenticates has still authorized nothing,
`grpc.max_send_message_length` and `maximum_concurrent_rpcs` have no default
where the 4 MB receive cap does, an `Any` field is a constructor the sender
picks, and reflection hands over the whole schema), the DRF API surface
(routes where the object check never runs,
function-level authorization on viewset actions, serializer and filter
exposure, throttling mechanics and the atomic `incr` a limit that must hold
needs instead of DRF's read-modify-write, schema and browsable-API exposure,
endpoint inventory, version deprecation, and bulk endpoints), the money,
entitlement, and state-transition flows an audit has to locate before it can
reason about any of them — found from the model fields that hold a balance, a
price, a quantity, a currency, a credit, a plan, a tier, an expiry or a
status, then from every writer of those fields including the management
command, Celery task, admin action, signal receiver, data migration and bulk
queryset write that never reach a view, and finally from the external events
that drive them — each transition settled by asking whether its invariant is
a `CheckConstraint` or a `UniqueConstraint` the database holds or a Python
comparison, a `clean()`, a serializer `validate_` method, or a signal
receiver that holds on one path only, with amount and currency resolved
server-side from an identifier the client supplies, capture, refund and
reversal treated as design questions about irreversibility, compensation and
partial failure rather than as an integration, entitlement grant weighed
against a revocation nobody demonstrates, and side-effecting actions that
spend a budget, notify a third party, or cannot be undone stated as the
general class that email and notification abuse is one worked instance of,
algorithmic
resource exhaustion as the design rule that every caller-controlled value
multiplying work carries a server-enforced ceiling, with a table naming the
surface that enforces each one, the handling of exceptional conditions
(fail-closed error paths, race conditions and TOCTOU,
database constraints versus row locks, idempotency-key design, side effects
ordered against the commit, and regular-expression denial of service),
integrity and cross-system trust (webhook signature verification on the raw
body, timestamp tolerance and event de-duplication, outbound delivery controls,
insecure deserialization including Django's cache, session, and fixture paths,
and Celery task messages as untrusted input), the cryptographic primitives
underneath them (password-hashing family and parameters, upgrade-on-login plus
the wrapped-hasher data migration that moves the dormant accounts it never
reaches — where an Argon2 target must override `verify` as well as `encode`,
because its verification does not re-derive through `encode` the way PBKDF2's
does and a wrapper missing that rejects every correct password — randomness and
token generation, constant-time comparison scoped to where it matters,
per-purpose salt discipline on signed values — including the signed-cookie salt
collision Django fixed in June 2026 and the transitional setting that accepts
the old derivation on 5.2 and 6.0, defaults to off on 6.1, and is removed in
7.0 — key lifecycle and envelope encryption
down to a KMS data key wrapped under an encryption context bound to its own
row, and post-quantum posture), the configuration published in
DNS rather than in code (SPF lookup limits and alignment, DKIM signing through
third-party senders, DMARC rollout under the 2026 specification, CAA, and
dangling-DNS subdomain takeover), deployment and runtime hardening (hybrid
post-quantum key exchange at the edge, where OpenSSL 3.5 already offers and
prefers X25519MLKEM768 and the finding is a pinned group list that excludes it
rather than a feature nobody enabled, forwarded-header trust and reading the
client IP behind proxies, development
tooling and profilers reachable in production, the container image as a
build artifact with a non-root user, a pinned base, and no secret left in a
layer, and the two edge-owned classes carried as cross-team recommendations
rather than repository findings — request smuggling, where two parsers frame
the same request differently, and cache deception, where the edge decides what
is cacheable from what a URL looks like), file uploads from the request through
storage to the reader
(content validation, storage keys that disclose nothing, object-store
configuration and the platform state a code review cannot answer, per-tenant
buckets against a shared bucket with prefixes, delegated upload URLs and what
each unbound constraint permits across S3, GCS, and Azure — which of the three
can bind a size, and what withdrawing one early costs on each —
direct-to-storage uploads held in quarantine until the server verifies them
against the store, scan verdict caching and content disarm, callback trust, the
metadata a store echoes back on serve, private downloads, and CDN cache keys
for private objects),
path traversal on a read whose path the request named, which is the half of
that boundary with no upload in it and where `os.path.join` is not a
containment function -- it never normalizes `..` and an absolute value discards
the base outright, so the storage API that runs `safe_join` and rejects rather
than repairs is the control, and `FileResponse` validates nothing at all,
injection as one bug at many interpreters (the inventory of every sink a
request can reach with the file that owns each one, the method for tracing a
source to one across requests worked end to end on a stored field, SQL and the
identifier positions the ORM does not parameterize, GeoDjango's raster band
index, which PostGIS inlines into the statement rather than binding, and the
spatial lookup that reads a `str` or `dict` value as a raster source to open,
the shell and a program's own option parser, template
injection and server-rendered output, LDAP filters and distinguished names,
response and mail headers, and the duplicated request parameter one reader
takes from `getlist` while another subscripts the `QueryDict`), the build
pipeline as reviewable configuration —
where the useful question is never whether a control is present but what
happens when it says no, so a scanner behind `continue-on-error` or a trailing
`|| true` gates nothing, an SBOM is an inventory and `--require-hashes` on the
install is the only integrity evidence, and a `gh attestation verify` or
`cosign verify` without a pinned signer identity and issuer confirms that a
signature exists rather than who made it; SLSA is claimed at the level the
platform documents and no higher, which on GitHub-hosted runners is Build
Level 2 for artifact attestations alone and Level 3 only where an isolating
reusable workflow generates the provenance; and the boundary is stated rather
than blurred, because registry-side signatures, deploy-time admission
enforcement, and runner isolation are questions for an operator rather than
things a repository can show you — and a dated maintained-package gate for
third-party security dependencies, including the development-only package that
reaches the production requirements file and ships a debugger with it, and the
rule that a Go-binary tool such as Trivy, Grype, Syft, or cosign is documented
as a CI pattern rather than tiered in an index that gates pip-installable
dependencies.

Primary integration is Claude; this file exists so Gemini CLI uses the same
single source of truth. Modes (review-time / write-time), the severity rubric
and how it rates a race and a surviving-personal-data failure, the baseline
severity table under it that makes an ordinary finding class rate the same way
between runs, the findings format including the evidence line every finding
carries, the ASVS 5.0 chapter mapping and the chapters declared out of scope
alongside the terms on which a WSTG section is admissible in the same optional
position,
the write-time secure-default contract with the security-decisions note it
returns in place of a report, and the rule for a default that conflicts with
the request are in `references/00-methodology-and-severity.md`. That file also
indexes which reference carries the write-time rule for each generation moment;
every rule itself lives beside the control it completes rather than in a list.
The version is recorded in `SKILL.md` frontmatter (`metadata.version`).
