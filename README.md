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
Django are flagged.

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

## Layout

```text
secure-code-auditor/
├── SKILL.md                            # canonical skill and router
├── SELF-IMPROVEMENT.md                 # self-improvement rules
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

## Self-improvement

This skill improves itself. After a task, the agent that used the skill can
correct wrong or old content and add content that the task needed.
`SELF-IMPROVEMENT.md` gives the rules. Each change needs evidence from the task.
The rules keep each change small and keep the core of the skill fixed.

- Your copy: the agent changes your local copy. It writes a record of each
  change to `~/.skill-improvements/secure-code-auditor/`. The record stays after
  an update of the skill. If an update removes a local change, the agent writes
  the change again at the next use.
- The owner: the agent asks you to send the records to the owner as a GitHub
  issue. It sends nothing without your approval. The owner examines each issue
  and adds the change for all users. Pull request creation is restricted to
  collaborators, so this repository takes no pull request.
- To stop it: make the file `~/.skill-improvements/OFF`. Then the agent does not
  change the skill and writes no record.

## Contributing

Issues yes, pull requests no. Pull request creation is restricted to
collaborators, so open an issue and I implement the change myself. See
[CONTRIBUTING.md](CONTRIBUTING.md) for what a good report contains,
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for conduct, and
[SECURITY.md](SECURITY.md) for reporting a vulnerability in the scanners.

## License

MIT. See `LICENSE`.
