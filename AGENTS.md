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
third-party dependency vetting and maintained-package decisions, uploads,
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
defaults that authenticate nothing), and deployment/runtime hardening.

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
