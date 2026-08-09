# Gemini CLI context: secure-code-auditor

This repo's security instructions live in `SKILL.md` and `references/`. Load
`SKILL.md` first, then the relevant `references/*.md` file. Its router is
grouped into the OWASP Top 10:2025 spine, cross-cutting surfaces, and package
decisions; where two rows could both match, the "Ownership and boundaries"
section below the router names the one file that owns the topic. See
`AGENTS.md` for the full description. Do not duplicate the content here — read
the source files.

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
assignment, persisted operations, and Django Ninja's default of no
authentication), the DRF API surface (routes where the object check never runs,
function-level authorization on viewset actions, serializer and filter
exposure, throttling mechanics and the atomic `incr` a limit that must hold
needs instead of DRF's read-modify-write, schema and browsable-API exposure,
endpoint inventory, version deprecation, and bulk endpoints), algorithmic
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
collision Django fixed in June 2026 and the transitional setting that goes on
accepting the old derivation until 7.0 — key lifecycle and envelope encryption
down to a KMS data key wrapped under an encryption context bound to its own
row, and post-quantum posture), the configuration published in
DNS rather than in code (SPF lookup limits and alignment, DKIM signing through
third-party senders, DMARC rollout under the 2026 specification, CAA, and
dangling-DNS subdomain takeover), deployment and runtime hardening (hybrid
post-quantum key exchange at the edge, where OpenSSL 3.5 already offers and
prefers X25519MLKEM768 and the finding is a pinned group list that excludes it
rather than a feature nobody enabled, forwarded-header trust and reading the
client IP behind proxies, development
tooling and profilers reachable in production, and the container image as a
build artifact with a non-root user, a pinned base, and no secret left in a
layer), file uploads from the request through storage to the reader
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
injection and server-rendered output, LDAP filters and distinguished names, and
response and mail headers), and a dated maintained-package gate for third-party
security dependencies, including the development-only package that reaches the
production requirements file and ships a debugger with it.

Primary integration is Claude; this file exists so Gemini CLI uses the same
single source of truth. Modes (review-time / write-time), the severity rubric
and how it rates a race and a surviving-personal-data failure, the findings
format, the ASVS 5.0 chapter mapping and the chapters declared out of scope,
the write-time secure-default contract with the security-decisions note it
returns in place of a report, and the rule for a default that conflicts with
the request are in `references/00-methodology-and-severity.md`. That file also
indexes which reference carries the write-time rule for each generation moment;
every rule itself lives beside the control it completes rather than in a list.
The version is recorded in `SKILL.md` frontmatter (`metadata.version`).
