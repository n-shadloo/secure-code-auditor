# AGENTS.md

This repository is a backend security skill. Its canonical instructions live in
`SKILL.md`, which routes to the topic files under `references/`. An agent that
works in this repo should load `SKILL.md` first, and then read only the
`references/*.md` file(s) relevant to the task.

Primary integration: **Claude** (Anthropic Agent Skills). The files below let
other agents use the same content. They are pointers, not copies. If anything
here disagrees with `SKILL.md`, `SKILL.md` wins. The current version is
recorded in `SKILL.md` frontmatter (`metadata.version`).

## What this skill does
Reviews backend code for security issues and applies secure defaults while
writing code. Organized on the OWASP Top 10:2025 spine, with stack-agnostic
principle layers and deep Django/DRF implementation layers across category and
cross-cutting references. A review-time sweep is a procedure rather than a
reading order: the phases run scope and environment boundary first, then an
entry-point inventory covering URLconf chains resolved to their full prefix,
DRF routers and `@action` methods, Django Ninja, GraphQL, gRPC, Channels,
Celery tasks and beat schedules, management commands, signals, admin
registrations and actions, webhook receivers, MCP tools, and middleware as the
entry point for every request at once; then the principals a Django backend
distinguishes and the boundaries between them; then sources paired to the sink
inventory; then hypotheses ordered by impact against the effort to confirm
them, authorization first because it is the highest-yield class and the
cheapest to settle; then verification as a gate rather than as advice, where a
hypothesis discharges attacker control, reachability, the protections that
should have stopped it, the insufficiency of any sanitization present,
concrete impact, and a catalog of benign Django and DRF patterns before it
is written up, each discharge resting on retrieved text rather than on what a
decorator or a base class is remembered to do, and one that fails attacker
control or matches a benign pattern is dropped rather than reported with a
hedge. Each phase hands the next a written artifact and closes on a property of
its coverage rather than on an amount of reading, so a tree too large to read
closely is still enumerated in full while only the close reading is rationed,
per area rather than spent on the first lead, with any family read as a sample
recorded as a sample. Throughout, a coverage ledger records what was examined
and found clean separately from what was never opened, which is what the
report's limitations section is written from, and it is read back at each phase
boundary rather than carried in the head.
Confirmed issues are escalated one step before write-up, so a chain is
reported as one finding at the severity of its outcome with its links named
rather than as several low-severity findings nobody connects. Coverage
includes the authorization architecture and
privilege model (object-, function-, and field-level authorization, default-deny,
authorization test design), impersonation and break-glass privileged access,
OAuth2/OIDC and social-login trust boundaries, API-key lifecycle and scoping,
password policy carried from the length floor through to the breached-corpus
screening no built-in validator performs and no maintained package currently
clears the gate to supply, passkey and WebAuthn configuration as the only
audit surface a framework shipping no native support can offer,
third-party dependency vetting and maintained-package decisions including the
development-only package that reaches the production requirements file,
the build pipeline as reviewable configuration (the SBOM generated from the
lockfile rather than from the finished image and why it is an inventory rather
than integrity evidence, the scan gate judged by what its exit code does rather
than by whether the step exists, build provenance and the consumer-side
verification that has to pin a signer identity to prove anything, SLSA Build
levels claimed only where the platform's own documentation supports them, and
the hard line between the artifacts a repository audit can read and the
registry, deploy-time, and runner state it can only ask an operator about),
file uploads end to end (content validation, storage keys that disclose nothing,
object-store configuration and the platform state a code review cannot see,
per-tenant buckets against a shared bucket with prefixes, delegated upload URLs
and the constraints each one has to bind across S3, GCS, and Azure — including
which of them can bind a size and what withdrawing one early actually costs —
direct-to-storage uploads held in a quarantine prefix until the server
verifies them against the store, scan verdict caching and content disarm,
callback and event trust, the metadata a store echoes back on serve, private
downloads, and CDN caching of private objects),
async/Channels including the subscription on its subscribe and publish paths,
caching, migrations, signals, the inventory of every path that moves money,
credits, entitlements, or durable status -- enumerated from the model fields
those values live in rather than from the views, so that the management
command, Celery task, admin action, signal receiver, data migration, and bulk
queryset write that never pass through a request are in it -- with the one
question that decides each transition, whether its invariant is held by the
database or only by Python, amount and currency binding on any flow a client
would otherwise price for itself, capture, refund and reversal as design
questions about which steps are irreversible, which compensate rather than
reverse, and what a partial failure between the provider and the local record
leaves behind, entitlement grant weighed against the revocation nobody
demonstrates, side-effecting actions that spend a budget, notify a third
party, or cannot be undone, with email/notification abuse as the worked
instance of that class, algorithmic resource
exhaustion and the server-enforced bound every caller-controlled input that
multiplies work has to carry,
agent- and LLM-facing interfaces (MCP tool surfaces, agent token audience
validation and the protected-resource metadata the current MCP authorization
revision made mandatory, tool scope versus user permissions, model output and
retrieved content as untrusted input, per-agent cost limits, tool-call audit,
and the entry-token mapping onto the OWASP LLM Top 10 2026 and Agentic Top 10
with the entries a backend skill declares non-goals), the operating agent's
own access while it does the work (the credential files it must never open,
the name-by-location rule for every finding and commit message it writes, the
kind, scope, and life of its own repository credential, CI token, and deploy
key, instructions arriving through repository content, a ticket, or tool
output as data rather than authority, and the confirmation gate on a rotation
or a revocation a finding recommends), the
database as a boundary of its own (migration versus runtime roles, row-level
security and tenant context on pooled connections, verified database TLS,
field-level encryption and blind indexes, NoSQL injection, transaction
isolation and the serialization-failure retry a raised level requires,
connection exhaustion, and copies of production data), the data lifecycle and
privacy layer (deletion completeness, soft-delete leakage, erasure fan-out with a
completion ledger, retention enforcement, anonymization versus
pseudonymization, model-layer personal-data classification, and export and
subject-access endpoints), service-to-service identity and secrets management
(machine-authentication mechanism choice, ordered inbound machine-token
validation, JWKS caching and key rotation, proxy-set client-certificate
identity, endpoints authenticated only by network position, downstream token
exchange, secret storage and delivery, and `SECRET_KEY` rotation), GraphQL and
non-DRF API surfaces (resolver-edge authorization, schema and type exposure,
document depth/alias/token/cost limits, introspection and error masking,
mutation mass assignment, batching, persisted operations, framework defaults
that authenticate nothing, and gRPC as a second server that Django's request
cycle never enters -- every registered method public until an authenticating
interceptor is installed and first in the list, authorization decided per
method rather than by the interceptor that established who is calling, a
send-size limit and a concurrency ceiling that have no default at all beside
a 4 MB receive cap that does, protobuf's `Any` instantiating whichever type
the sender named, unknown fields surviving a binary round trip into whatever
the servicer relays them to, and reflection as the introspection analog
alongside health checking and channelz), the DRF API surface itself (the routes
where the object check never runs, function-level authorization on viewset
actions, serializer and filter exposure, throttling mechanics and the owned
atomic counter a limit that must actually hold needs instead, schema and
browsable-API exposure, endpoint inventory and shadow routes, version
deprecation, and bulk endpoints), the handling of exceptional conditions
(fail-closed error paths, race conditions and TOCTOU, database constraints
versus row locks, idempotency-key design, transaction side-effect ordering,
state-transition enforcement, and regular-expression denial of service),
integrity and cross-system trust (the inbound webhook receiver end to end from
raw-body capture through signature, timestamp, and event de-duplication,
outbound delivery that is neither an SSRF proxy nor a retry amplifier, insecure
deserialization including the cache, session, and fixture paths Django
deserializes without being asked, both task systems a project may be running --
Celery task messages as input from anyone who can reach the broker, and
Django's built-in tasks framework whose default backend runs the task inline in
the request that enqueued it -- and artifact provenance), the cryptographic
primitives
underneath all of it (password-hashing family and parameters tuned to the
hardware that runs them, upgrade-on-login and the wrapped-hasher migration that
moves the dormant accounts it never reaches, randomness and token generation,
scoped constant-time comparison, per-purpose salt discipline on signed values
including the salt-namespace collision Django fixed in its own signed-cookie
helper and the transitional setting that accepts the old derivation by default
on 5.2 and 6.0 but no longer on 6.1,
key lifecycle and envelope encryption with versioned rotation and a data key
wrapped by a KMS under an encryption context bound to its row, and post-quantum
posture), the DNS-published configuration that decides whether the domain
itself can be forged (SPF lookup limits and alignment, DKIM signing through a
third-party sender, DMARC rollout under the 2026 specification, MTA-STS and
TLS-RPT for the transport the message rides on, CAA, and dangling-DNS
subdomain takeover), deployment/runtime hardening including
hybrid post-quantum key exchange at the TLS edge, where a current OpenSSL
already negotiates the group and the finding is a pinned list that excludes it,
forwarded-header trust and reading the client IP behind proxies, development
tooling and profilers reachable in production, the container image as a
build artifact with a non-root user, a pinned base, and no secret surviving in
a layer, and the two edge-owned classes recorded as cross-team recommendations
rather than repository findings (request smuggling between two parsers that
frame a request differently, and cache deception where the edge decides what is
cacheable from what a URL looks like), path traversal on a file read whose path
the request named -- what
`safe_join` and the storage API reject, what `FileResponse` and the
development static view do not, and the identifier-not-a-path pattern that
removes the class -- and injection treated as one bug at many interpreters (the
inventory of every sink a request can reach and which reference owns each one,
the method for tracing a source to a sink, worked end to end on the
stored-then-used case that crosses requests, SQL plus the identifier positions
the ORM does not parameterize, GeoDjango's raster band index and the spatial
lookup that reads its value as a raster source,
the shell and the option parser of the program behind it,
template injection and server-rendered output, LDAP filters and distinguished
names, response and mail headers, the log line as a record boundary an
attacker can forge, and the duplicated request parameter that a check and a use
read differently because one calls `getlist` and the other subscripts the
`QueryDict`).

## Two modes
- Review-time: audit existing code, produce prioritized findings (severity,
  location, CWE + OWASP mapping, an optional ASVS 5.0 chapter, WSTG section, or
  LLM/Agentic Top 10 entry token where the project is actually held to that
  standard, the shortest source-to-sink path the finding was confirmed on
  together with the protection that failed, concrete fix). Read-only by
  default. Load `references/01-audit-workflow.md` before any topic file. It
  owns the sweep that produces the findings, and the topic files answer the
  questions that sweep generates.
- Write-time: apply the standing secure-default contract while you generate
  code. Apply the secure default where it conflicts with the request, and say
  so. Close with a short security-decisions note rather than a findings report.
  The rule for each generation moment sits beside the control it completes, in
  the reference the router already sends you to. A file opened for the concern
  therefore loads the rule for writing it. Mode selection, both output formats,
  the severity rubric including how a race and a surviving-personal-data
  failure are rated, the baseline severity table that makes an ordinary finding
  class reproducible between runs while the rubric keeps deciding the
  borderline one, the ASVS 5.0 chapter mapping with the chapters this skill
  treats as non-goals, the conflict rule, and the convention that every control
  is stated in a review form and a write-time form together are defined in
  `references/00-methodology-and-severity.md`.

## How to use the content
1. Read `SKILL.md` for the router, mode logic, and severity summary.
2. At review-time, read `references/01-audit-workflow.md` next and run its
   phases. The entry-point inventory decides which topic files are needed, and
   the coverage ledger records what each pass reached. That file also carries
   the WSTG mapping at section granularity. That mapping says which
   testing-guide sections this sweep covers, and which are declared non-goals
   rather than gaps.
3. Open the `references/*.md` file(s) for the concern in front of you. The
   router is grouped — the OWASP Top 10:2025 spine, then cross-cutting
   surfaces, then package decisions — so pick the group, then the row.
4. Where two rows could both match, the "Ownership and boundaries" section
   below the router names the single owning file for each contested topic. It
   is a table of topic, owner, and the distinction that decides a case near the
   boundary. Three splits keep a paragraph, because a row would misstate the
   axis they turn on. Every other file cross-references the owner rather than
   restates its rules, and each reference file repeats its own half of that
   rule in its opening paragraph.
5. Optional read-only triage (standard library only, no network; `--json` on any
   of the three is JSON Lines, one object per line, consumed a record at a time):
   - `python scripts/entrypoint_inventory.py path/to/project --settings path/to/settings --json`
   - `python scripts/settings_scan.py path/to/settings/ --json`
   - `python scripts/dangerous_patterns.py path/to/project`
   - `python scripts/dangerous_patterns.py path/to/project --json --min-severity MEDIUM`
   - `python scripts/dangerous_patterns.py --selftest` All three parse with the
     `ast` module rather than match lines, so a hit is a structural match
     rather than a text one. Every row names the reference file that owns it. A
     `dangerous_patterns.py` hit also carries a stable rule identifier. A file
     that fails to parse is reported as unparsed rather than skipped in
     silence. Every `--json` stream ends with one `kind: "summary"` record, so
     an empty stream never occurs.

     The inventory enumerates the declared entry points the sweep starts from —
     routes at their include-resolved prefix, routers and actions, Ninja,
     GraphQL, gRPC, Channels, Celery, commands, signals, admin, middleware. It
     marks each HTTP-reachable row as one of three states: it declares its
     authorization, it inherits it, or it has none. The settings scan reads a
     whole settings package rather than one module, and names which module each
     effective value came from. Treat script output as leads to verify, not
     confirmed findings.

## Tool-specific entry points
- Claude Code: `SKILL.md` (native Agent Skill).
- OpenAI Codex CLI: reads this `AGENTS.md`.
- Cursor: `.cursor/rules/secure-code-auditor.mdc`.
- Gemini CLI: `GEMINI.md`.
All of them defer to `SKILL.md` and `references/`.
