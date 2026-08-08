# AGENTS.md

This repository is a backend security skill. Its canonical instructions live in
`SKILL.md`, which routes to the topic files under `references/`. Any agent
working in this repo should load `SKILL.md` first and then read only the
`references/*.md` file(s) relevant to the task.

Primary integration: **Claude** (Anthropic Agent Skills). The files below let
other agents use the same content; they are pointers, not copies. If anything
here disagrees with `SKILL.md`, `SKILL.md` wins. The current version is recorded
in `SKILL.md` frontmatter (`metadata.version`).

## What this skill does
Reviews backend code for security issues and applies secure defaults while
writing code. Organized on the OWASP Top 10:2025 spine, with stack-agnostic
principle layers and deep Django/DRF implementation layers across category and
cross-cutting references. Coverage includes the authorization architecture and
privilege model (object-, function-, and field-level authorization, default-deny,
authorization test design), impersonation and break-glass privileged access,
OAuth2/OIDC and social-login trust boundaries, API-key lifecycle and scoping,
third-party dependency vetting and maintained-package decisions, file uploads
end to end (content validation, storage keys that disclose nothing,
object-store configuration and the platform state a code review cannot see,
delegated upload URLs and the constraints each one has to bind,
direct-to-storage uploads held in a quarantine prefix until the server
verifies them against the store, callback and event trust, private downloads,
and CDN caching of private objects),
async/Channels, caching, migrations, signals, email/notification abuse,
agent- and LLM-facing interfaces (MCP tool surfaces, agent token audience
validation, tool scope versus user permissions, model output and retrieved
content as untrusted input, per-agent cost limits, and tool-call audit), the
database as a boundary of its own (migration versus runtime roles, row-level
security and tenant context on pooled connections, verified database TLS,
field-level encryption and blind indexes, NoSQL injection, connection
exhaustion, and copies of production data), the data lifecycle and privacy
layer (deletion completeness, soft-delete leakage, erasure fan-out with a
completion ledger, retention enforcement, anonymization versus
pseudonymization, model-layer personal-data classification, and export and
subject-access endpoints), service-to-service identity and secrets management
(machine-authentication mechanism choice, ordered inbound machine-token
validation, JWKS caching and key rotation, proxy-set client-certificate
identity, endpoints authenticated only by network position, downstream token
exchange, secret storage and delivery, and `SECRET_KEY` rotation), GraphQL and
non-DRF API surfaces (resolver-edge authorization, schema and type exposure,
document depth/alias/token/cost limits, introspection and error masking,
mutation mass assignment, batching, persisted operations, and framework
defaults that authenticate nothing), the DRF API surface itself (the routes
where the object check never runs, function-level authorization on viewset
actions, serializer and filter exposure, throttling mechanics, schema and
browsable-API exposure, endpoint inventory and shadow routes, version
deprecation, and bulk endpoints), the handling of exceptional conditions
(fail-closed error paths, race conditions and TOCTOU, database constraints
versus row locks, idempotency-key design, transaction side-effect ordering,
state-transition enforcement, and regular-expression denial of service),
integrity and cross-system trust (the inbound webhook receiver end to end from
raw-body capture through signature, timestamp, and event de-duplication,
outbound delivery that is neither an SSRF proxy nor a retry amplifier, insecure
deserialization including the cache, session, and fixture paths Django
deserializes without being asked, Celery task messages as input from anyone who
can reach the broker, and artifact provenance), the cryptographic primitives
underneath all of it (password-hashing family and parameters tuned to the
hardware that runs them, upgrade-on-login, randomness and token generation,
scoped constant-time comparison, per-purpose salt discipline on signed values,
key lifecycle and envelope encryption with versioned rotation, and post-quantum
posture), the DNS-published configuration that decides whether the domain
itself can be forged (SPF lookup limits and alignment, DKIM signing through a
third-party sender, DMARC rollout under the 2026 specification, CAA, and
dangling-DNS subdomain takeover), deployment/runtime hardening including
forwarded-header trust and reading the client IP behind proxies, development
tooling and profilers reachable in production, and the container image as a
build artifact with a non-root user, a pinned base, and no secret surviving in
a layer, and injection treated as one bug at many interpreters (the inventory
of every sink a request can reach and which reference owns each one, the
method for tracing a source to a sink including the stored-then-used case that
crosses requests, SQL plus the identifier positions the ORM does not
parameterize, the shell and the option parser of the program behind it,
template injection and server-rendered output, LDAP filters and distinguished
names, response and mail headers, and the log line as a record boundary an
attacker can forge).

## Two modes
- Review-time: audit existing code, produce prioritized findings (severity,
  location, CWE + OWASP mapping, concrete fix). Read-only by default.
- Write-time: apply secure defaults and flag risky patterns while generating code.
Mode selection and the findings format are defined in
`references/00-methodology-and-severity.md`.

## How to use the content
1. Read `SKILL.md` for the router, mode logic, and severity summary.
2. Open the `references/*.md` file(s) for the concern in front of you (the table
   in `SKILL.md` maps concern → file).
3. Optional read-only triage (standard library only, no network):
   - `python scripts/settings_scan.py path/to/settings.py`
   - `python scripts/dangerous_patterns.py path/to/project`
Treat script output as leads to verify, not confirmed findings.

## Tool-specific entry points
- Claude Code: `SKILL.md` (native Agent Skill).
- OpenAI Codex CLI: reads this `AGENTS.md`.
- Cursor: `.cursor/rules/secure-code-auditor.mdc`.
- Gemini CLI: `GEMINI.md`.
All of them defer to `SKILL.md` and `references/`.
