# Gemini CLI context: secure-code-auditor

This repo's security instructions live in `SKILL.md` and `references/`. Load
`SKILL.md` first, then the relevant `references/*.md` file. See `AGENTS.md` for
the full description. Do not duplicate the content here — read the source files.

Coverage includes the authorization architecture and privilege model (object-,
function-, and field-level authorization, default-deny, authorization test
design), impersonation and break-glass privileged access, OAuth2/OIDC and social
login, API-key lifecycle and scoping, agent- and LLM-facing interfaces (MCP
tool surfaces, agent token audience validation, tool scope versus user
permissions, model output and retrieved content as untrusted input), the
database as a security boundary (migration versus runtime roles, row-level
security and tenant context on pooled connections, verified database TLS,
field-level encryption, NoSQL injection, and connection exhaustion), the data
lifecycle (deletion and erasure completeness, soft-delete leakage, retention,
anonymization versus pseudonymization, personal-data classification, and
export/subject-access endpoints), service-to-service identity and secrets
(machine-token validation, JWKS caching and rotation, client credentials,
mutual TLS and proxy-set certificate identity, workload identity, secret
delivery, and `SECRET_KEY` rotation), GraphQL and non-DRF API surfaces
(authorization on every resolved edge, schema and type over-exposure, query
depth/alias/token/cost limits, introspection and error masking, mutation mass
assignment, persisted operations, and Django Ninja's default of no
authentication), and a dated maintained-package gate for third-party security
dependencies.

Primary integration is Claude; this file exists so Gemini CLI uses the same
single source of truth. Modes (review-time / write-time), the severity rubric,
and the findings format are in `references/00-methodology-and-severity.md`. The
version is recorded in `SKILL.md` frontmatter (`metadata.version`).
