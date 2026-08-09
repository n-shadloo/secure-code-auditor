# Security-hardening libraries — vetted decisions

This is a dated decision index, not an install-all list. It is current as of
**9 Aug 2026** for the repository baseline (Django 6.1, 6.0.8, and 5.2.17 LTS,
with DRF 3.18.0). Re-run the A03 dependency gate for the project's actual
Python/Django versions and whenever maintenance, advisories, or compatibility
changes.

**How this file is dated.** One index date in the header governs every version
and classifier claim below, and an entry or section states its own date only
where something was checked on a different day. Every package version and
classifier in this file was re-checked against PyPI on the index date. The
behavioral notes are dated separately and deliberately: what a package ships,
what its defaults are, and what its own source does were not re-read on that
date, so they keep the date stated at the head of their section. Hold that
split on the next sweep. A version is one page away and cheap to re-check, a
default is neither, and collapsing the two would date a claim nobody verified.

Django 6.1 was released on 5 Aug 2026, so most entries below still declare
support through 6.0 and not yet 6.1. Days after a feature release that is the
normal packaging lag rather than a compatibility finding, and it is recorded
here once so that no entry has to repeat it; it becomes a gate question at the
point a project actually moves to 6.1. A package declaring no currently
supported line at all is a different matter, and each one is called out where
it appears.

This file owns the **disposition of a named package** — its tier, its
minimum-safe floor, and the vetting fields behind both, each carrying the date
it was checked. It does not own the gate that produces a disposition:
`a03-software-supply-chain.md` owns dependency vetting, pinning and hashing,
advisory scanning, and SBOM as a method, and this file is that method's
recorded output for one baseline. Nor does it own the controls these packages
implement — every entry defers to the reference that owns the concern, and each
section names it. A platform SDK a project already runs is audited there as a
pattern rather than tiered here.

## Contents
- [Recommendation gate](#recommendation-gate)
- [Recommended or conditional choices](#recommended-or-conditional-choices)
- [Existing-install audit only or rejected candidates](#existing-install-audit-only-or-rejected-candidates)
- [Authorization, object permissions, and impersonation](#authorization-object-permissions-and-impersonation)
- [Agent and MCP interfaces](#agent-and-mcp-interfaces)
- [Service identity and secrets](#service-identity-and-secrets)
- [Data layer and database](#data-layer-and-database)
- [Data lifecycle and privacy](#data-lifecycle-and-privacy)
- [GraphQL and alternative API surfaces](#graphql-and-alternative-api-surfaces)
- [API surface, schema, and bulk operations](#api-surface-schema-and-bulk-operations)
- [Concurrency, idempotency, and regular expressions](#concurrency-idempotency-and-regular-expressions)
- [Integrity, webhooks, and deserialization](#integrity-webhooks-and-deserialization)
- [Cryptographic primitives and password hashing](#cryptographic-primitives-and-password-hashing)
- [Runtime, proxy trust, and operational endpoints](#runtime-proxy-trust-and-operational-endpoints)
- [Use in a review](#use-in-a-review)
- [Review checklist](#review-checklist)

## Recommendation gate

Before recommending a dependency, record: the control and built-in alternative;
maintenance and latest-release signal; known advisories and minimum safe version;
Python/Django/runtime compatibility; license; security-sensitive defaults;
operational/transitive cost; and an exit plan. Classify it as **recommend**,
**conditional**, **existing-install audit only**, or **reject for new use**.
Advisory scanning alone is not vetting.

## Recommended or conditional choices

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| CORS | `django-cors-headers==4.9.0` | **Recommend.** MIT; maintained; Django 6.0 supported. Explicit origin allowlists; no credentialed wildcard/reflection. |
| CSP | Django 6 built-in CSP | **Recommend built-in.** Avoids an extra dependency. For supported pre-6.0 projects only, `django-csp==4.0` is **conditional** through Django 5.2. |
| Login lockout/monitoring | `django-axes==8.3.1` | **Recommend.** MIT/Jazzband; maintained; Django 6.0 supported. Correct trusted-proxy/client-IP handling first; avoid permanent attacker-triggered lockout. |
| TOTP/MFA primitives | `django-otp==1.7.0` | **Recommend.** Maintained; Django 6.0 compatible. Enrollment/removal/recovery still need re-authentication and audit controls. |
| MFA workflow | `django-two-factor-auth==1.18.1` (27 Sep 2025; re-checked 9 Aug 2026) | **Conditional** for compatible Django 5.2 projects; not advertised for Django 6. Re-checked because the project's development branch reads ahead of its release, which is the kind of thing that gets a tier re-proposed: the shipped artifact declares Django 4.2 through 5.2 and no 6.0, so the disposition is unchanged and stays pinned to what the release declares rather than to what the repository says. Re-vet at the next version. |
| JWT | SimpleJWT `5.5.1` (21 Jul 2025; re-checked 9 Aug 2026) | **Conditional** for supported Django 5.2 projects; not advertised for Django 6 — the published classifiers stop at Django 5.2, confirmed on re-check. Two releases in the eighteen months to that date is a slowing cadence rather than an advisory, and none is outstanding. Minimum `5.5.1` includes the CVE-2024-22513 fix. Configure algorithm/issuer/audience/lifetimes/rotation/denylisting. |
| Social/OIDC client | `django-allauth==65.19.0` (6 Aug 2026) | **Recommend; require >=65.16.1.** MIT; Python >=3.10; declares Django 4.2 through 6.1, which makes it one of the few entries here already carrying the new line. Keep automatic email auth/connection and login-on-GET off; enable PKCE per provider; avoid token storage unless needed. |
| REST auth wrapper | `dj-rest-auth==7.2.0` | **Recommend only with reviewed allauth/provider settings.** MIT; Python >=3.10. Prefer code flow/fixed callback and audit which token artifact each endpoint accepts. |
| OAuth/OIDC provider | `django-oauth-toolkit==3.4.0` (23 Jul 2026) | **Recommend; require `>=3.4.0`.** BSD; Python >=3.10; declares Django 4.2 through 6.0. The floor is not a formality: 3.4.0 is a security release, and below it an unauthenticated open redirect is reachable from the authorization endpoint with `prompt=none`, HS256 ID tokens are signed with the hashed rather than the plaintext client secret, cleartext tokens and authorization codes are rendered in the Django admin, client secrets reach debug logs, device-flow `user_code` values are not drawn from a CSPRNG, and redirect-URI matching deviates from RFC 9700 in four ways that accept unregistered query parameters, path segments, credentials, and fragments. An install on 3.3.0 or earlier is a finding on its own weight. Keep PKCE required, exact redirects, narrow scopes, hashed client secrets; OIDC is opt-in. Older installs require `oauthlib>=3.2.2`. |
| Alternate social-auth client | `social-auth-app-django==6.0.1` (24 Jul 2026) | **Recommend; require >=5.6.0.** BSD-3-Clause; declares Django 5.2 and 6.0. Review pipeline/state/redirects; never add `associate_by_email` without a proven provider-specific verified-email policy. |
| WebSockets/ASGI | Channels `4.3.2` | **Recommend.** Django-project maintained; Django 6 supported. Still implement origin checks, per-message authz, bounds, backpressure, and cleanup. |
| Dependency advisories | `pip-audit==2.10.1` | **Recommend as one input.** PyPA-maintained, Apache-2.0. It does not prove maintenance, provenance, compatibility, configuration, or safety. |
| Rich-HTML sanitization | `nh3==0.3.6` | **Recommend when rich HTML is required.** MIT; actively released. Centralize a minimal allowlist and URL-scheme policy; prefer plain text/structured markup. |
| LDAP directory queries and authentication | `django-auth-ldap==5.3.0` (26 Dec 2025) over `python-ldap>=3.4.5`, latest `3.4.7` (20 May 2026); escaping behaviour and advisory checked 8 Aug 2026 | **Recommend the integration where a directory is the identity source; require the `python-ldap>=3.4.5` floor explicitly.** There is no built-in alternative — a directory client is a dependency by definition — so the gate here is about the floor and the defaults rather than the choice. django-auth-ldap is BSD, Python >=3.10, Production/Stable, and declares Django 4.2, 5.2, and 6.0; it escapes filter arguments through `ldap.filter.escape_filter_chars` with escaping on by default, which is the reason to prefer it over hand-assembled filter strings. Advisory: `python-ldap` before 3.4.5 could be made to skip escaping when a `list` or `dict` reached `escape_filter_chars` under the non-default `escape_mode=1` (CVE-2025-61911, moderate); 3.4.5 type-checks the argument. django-auth-ldap's own requirement is only `python-ldap>=3.1`, so installing the integration does not deliver the fix — pin `python-ldap` yourself. Operational cost: `python-ldap` builds against the OpenLDAP client libraries, so it needs system headers in the build image rather than a wheel alone. Review the search filters for any place the project still formats its own, and confirm group-to-permission mapping separately — a successful bind is authentication, not authorization. Exit plan: filter escaping is one function call, so a different client keeps the same call-site discipline. See `a05-injection.md`, "Directory and LDAP injection". |

## Existing-install audit only or rejected candidates

| Candidate | Disposition and safer direction |
|---|---|
| `mozilla-django-oidc==5.0.2` | **Existing-install audit only.** No advertised Django 6 support; PKCE defaults off; open issue #340 documents missing exact issuer/audience validation in the default verification path. Require PKCE plus a reviewed verifier override/replacement, or migrate. |
| `djangorestframework-api-key==3.1.0` | **Existing-install audit only.** No advertised Django 6 support and weak recent maintenance signals. Preserve digest/prefix/expiry/revocation/scoped-model patterns, but add real authorization and never use it as human authentication. |
| `django-ratelimit==4.1.0` | **Reject for new use.** 2023 release and dormant maintenance signals. Use maintained edge/platform limits plus account/tenant/business-flow controls. |
| `django-defender==0.9.8` | **Reject for new use.** 2024 release and stale Python/support signals. Use the layered A06 design; `django-axes` is the vetted login-specific choice. |
| `django-smart-ratelimit==4.12.1` (5 Jun 2026; checked 9 Aug 2026) | **Reject for new use**, and the reason is not the version lag. MIT, genuinely active — 52 releases since July 2025 — and it does declare Django 6.0, so the packaging-lag allowance above would have covered it. It fails two other gate fields. Maintenance signal: one author holds 166 of the repository's commits and the next human contributor has two, a bus factor of one on a project thirteen months old at roughly 82 stars. Security-sensitive default: with `RATELIMIT_BACKEND` unset it selects the in-memory backend, which is per-process, so under Gunicorn or uWSGI the configured limit silently multiplies by the worker count — precisely the failure this gate exists to catch, arriving by default rather than by misconfiguration. Own the atomic counter in `api-drf-specific.md`, "Throttling as quota, not security (API4)". Re-tier if a second active maintainer appears or the default backend changes to one that fails safe. |
| `pwned-passwords-django==5.2.0` (6 Apr 2025; checked 9 Aug 2026) | **Reject as a new recommendation; existing-install audit only.** BSD-3-Clause, and the design is the right one — it screens against the Pwned Passwords corpus through the k-anonymity range API, so no full password hash leaves the process. But its classifiers declare Django 4.2, 5.1, and 5.2 with no Django 6 line sixteen months after release, on a single maintainer, and this gate does not make a new recommendation on undeclared compatibility. Where it is already installed, confirm the validator actually appears in `AUTH_PASSWORD_VALIDATORS`, that the request timeout and the failure branch were chosen rather than inherited, and that nothing logs the candidate password. For new work, own it: `a07-authentication-failures.md`, "Password policy", carries the range-query validator and the offline-blocklist alternative beside it. |
| `django-storages==1.14.6` (2 Apr 2025; re-checked 7 Aug 2026) | **Reject as a new recommendation for this Django 6 baseline; existing-install audit only.** Its own Django classifiers stop at 5.1 — there is no 5.2 and no 6.0 — and there has been no release in sixteen months, so support for either currently supported line is undeclared. Classifiers are advisory rather than install constraints, so an existing install may well run; the rejection is about not making a new recommendation on advertised compatibility, which is the premise of this gate. Where it is already present, audit the four S3 defaults named in `file-uploads.md`, "Object storage configuration" — above all `AWS_S3_CUSTOM_DOMAIN`, which makes `url()` return an unsigned URL unless a CloudFront signer is configured too, silently overriding `AWS_QUERYSTRING_AUTH`. Prefer Django's Storage API plus an official maintained provider SDK. |
| `defusedxml==0.7.1` | **Reject as a new recommendation.** Stale release/maintenance signals. Disable XML or choose a maintained format-specific parser with DTD/entity/network/expansion controls. |
| `python-magic==0.4.27` / `filetype==1.2.0` | **Reject as new recommendations.** Stale release/maintenance signals. Use multiple bounded checks and a maintained parser for each explicitly supported file type. |
| `python-decouple==3.8` | **Reject as a new recommendation.** Stale release signal. Use `os.environ` or the official maintained secrets-manager SDK and validate settings at startup. |
| Object-storage provider SDKs — `boto3`, `google-cloud-storage`, `azure-storage-blob` | **Patterns, not vetting-gate entries**, on the same basis as the cloud KMS SDKs and workload-identity platforms elsewhere in this index. These are the platform SDKs a project already runs, not security packages being selected against alternatives. Audit what a delegated upload or download URL is scoped to and which credential signs it — `file-uploads.md`, "Direct-to-storage uploads" — rather than tiering the cloud provider. |
| Generic “security bundle” packages | **Do not recommend by category alone.** Prefer Django/DRF built-ins and add a narrowly justified dependency only after the A03 gate. |

**Category ruling — general-purpose rate limiting, 9 Aug 2026.** No maintained
general-purpose rate-limiting package clears this gate for the current
baseline. The question recurs often enough — the control is real, the packages
are easy to find, and the reasons each one fails are not the same — that the
ruling is recorded here rather than re-derived. `django-ratelimit` is at 4.1.0
from 2023 and `django-defender` at 0.9.8 from 2024, both dormant.
`django-smart-ratelimit` 4.12.1 is current and actively released but fails on
maintainer concentration and an unsafe default backend, as above.
`django-axes==8.3.1` is unaffected by this ruling and stays a recommend: it
solves the narrower login-lockout problem, not general rate limiting.
Everything else layers: edge and platform limits, plus the owned atomic
counter in `api-drf-specific.md`, "Throttling as quota, not security (API4)".
Re-open the ruling when a limiter ships with more than one active maintainer
and a shared backend by default.

**Standing re-vet triggers, re-checked 9 Aug 2026.** A handful of entries below
are held at their tier by one fact that a single release would overturn, so
each is re-checked every sweep and its status restated here rather than left to
age quietly inside its own row. **None of them moved this pass.**
`django-safedelete` is still 1.4.1 from 5 Mar 2025 with no Django classifiers,
so the cascade behaviour behind its tier is still open. `graphene-django` is
still 3.2.3 from 13 Mar 2025 with classifiers stopping at Django 4.2 — the
release declaring 5.2 or 6.x that would move it back to conditional has not
appeared. `django-ipware` is still 7.0.1 from 19 Apr 2024, as is
`python-ipware` 3.0.0 alongside it. `ariadne-django` is still 0.3.0 from
19 Jul 2022 while Ariadne core reached 1.1.0 on 15 Jun 2026, so the gap between
the core and its Django binding widened rather than closed.
`django-gdpr-assist` is still 1.4.2 with no release since 2022 and its
repository archived read-only, and no maintained successor has taken the
pattern over. The one trigger that did fire — a maintained general-purpose
rate limiter appearing — is ruled on immediately above.

## Authorization, object permissions, and impersonation

The behavioral notes in this section were checked on **1 Aug 2026**; versions
and classifiers carry the index date above. Read with
`authorization-architecture.md` and
`privileged-access-and-impersonation.md`.

Before adding any of these, note that the default recommendation for object
authorization is **queryset scoping**, which needs no dependency at all. Reach
for a package when per-object grants are genuinely data, or when the same
per-object rule is being hand-written across more than a handful of views.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Object permissions (ACL rows) | `django-guardian==3.3.3` (22 Jul 2026) | **Conditional on a Django 6.0 baseline; recommend on 5.2.** BSD-2-Clause; Python >=3.10; actively released (3.3.0–3.3.3 all in 2026), but classifiers still stop at Django 5.2 — do not infer 6.0 support. Requires adding `guardian.backends.ObjectPermissionBackend` to `AUTHENTICATION_BACKENDS`; without it `has_perm(perm, obj)` stays a no-op. Review anonymous-user handling (guardian creates a real anonymous user row), `get_objects_for_user()` query cost, and generic- vs direct-FK permission models on hot paths. |
| Guardian + DRF filtering | `djangorestframework-guardian==0.4.0` (1 Jul 2025) | **Conditional.** BSD-3-Clause; Python >=3.10; classifiers stop at Django 5.2 and the release is over a year old. Provides `ObjectPermissionsFilter`. The `-guardian2` fork (0.7.0, Oct 2024, classifiers to 5.1) is staler — prefer this one or drop the filter and scope the queryset directly. |
| Predicate rules (no DB) | `rules==3.5` (2 Sep 2024) — distributed as `rules`, usually written django-rules | **Conditional; verify in CI.** MIT; in-process predicate functions with no tables and no runtime dependencies, so the exit plan is trivial. But the release is ~2 years old and it declares no Django version classifiers — confirm it against the project's actual Django before relying on it, and prefer queryset scoping where that suffices. |
| Impersonation | `django-hijack==3.7.8` (19 Apr 2026) | **Recommend.** MIT; Python >=3.10; Django 6.0 classifier present; v3 is a security-focused rewrite. Keep `superusers_only` and POST+CSRF; leave `HIJACK_ALLOW_GET_REQUESTS` off. It does not time-box, re-authenticate, or scope down the session — add those yourself. |
| ReBAC engine (external) | `openfga-sdk==0.10.4` (29 Jun 2026) | **Conditional, and only past the ReBAC threshold.** Apache-2.0; Python >=3.10; CNCF-incubating server, self-hostable. Still a 0.x SDK, and you take on a stateful service plus its datastore. Run a current server version and re-run the A03 gate at adoption. |
| ReBAC engine (external) | `authzed==1.25.0` (14 Jul 2026) — SpiceDB client | **Conditional, and only past the ReBAC threshold.** Apache-2.0; Python >=3.10; actively released. Same operational cost as OpenFGA: a separate gRPC service and datastore. |
| In-process policy engine | `casbin==1.43.0` (10 May 2025) | **Conditional.** Apache-2.0; in-process, no separate service; model+policy files cover RBAC/ABAC-style rules. Release is over a year old and `requires_python` is unmaintained (`>=3.3`) — verify against the project's Python. Policy files become a second authorization source of truth; keep them reviewable. |
| Role helper | `django-role-permissions==3.2.0` (9 Jun 2023) | **Reject for new use.** Over three years old with no Django version classifiers; Django 6.0 compatibility unverified. Use Django groups/permissions plus the privilege model in `authorization-architecture.md`. |
| Policy library | `oso==0.27.3` (13 Jan 2024) | **Reject for new use.** The open-source library was deprecated on 18 Dec 2023 in favour of the hosted Oso Cloud; `django-oso` is part of the same deprecated line. Existing installs should plan migration. |
| General policy engine | OPA / Rego | **Reject as an app-level authz choice for a Django backend unless already run org-wide.** Apache-2.0, CNCF-graduated, but there is no first-class Python embedding — you run a sidecar queried over REST or compile policy to WASM. That is real latency, failure-mode, and operational cost for in-process decisions. |

## Agent and MCP interfaces

The defaults in this section were checked on **1 Aug 2026**; versions and
classifiers carry the index date above. Read with
`agent-and-llm-interfaces.md`.

**No package in this area clears the gate for a `recommend` tier.** The default
construction is DRF's own authentication, permission, filter, pagination, and
throttle classes plus a hand-written audience-validating authentication class,
with `django-oauth-toolkit` above where the application is the authorization
server. Every entry below is a disposition for something already installed.

| Candidate | Disposition and review notes |
|---|---|
| `django-mcp-server==0.5.7` (10 Oct 2025) | **Existing-install audit only**, and now on a ten-month release gap that predates the 2026-07-28 specification revision this section is audited against. MIT; publishes DRF viewsets as MCP tools with `authentication_classes`, `permission_classes`, `filter_backends`, and `pagination_class` disabled by default. Every one must be explicitly re-enabled on every tool path; confirm `self.paginator` is not `None` on a list tool. Not a new recommendation. |
| `django-rest-framework-mcp==0.1.0a4` (25 Nov 2025) | **Existing-install audit only.** MIT; alpha, so treat the API as unstable. Defaults are the safe ones — confirm `BYPASS_VIEWSET_AUTHENTICATION`, `BYPASS_VIEWSET_PERMISSIONS`, and `RETURN_200_FOR_ERRORS` are all off, since the last returns HTTP 200 on an auth or permission failure and blinds 4xx-rate alerting. |
| `django-admin-mcp-api` / `django-admin-mcp` | **Reject for production.** Both expose the Django admin as a machine API. The admin was designed as a human interface behind staff/superuser privilege, so the blast radius is the whole model layer; non-browser session or long-lived bearer semantics make it worse. Audit-only where already installed. |
| `mcp-django==0.14.0` (23 Jul 2026) | **Reject for production.** Offers management-command and stateful shell access, which is arbitrary code execution by design. Active maintenance and a Django 6.0 classifier do not move this one: the disposition is about what the package exposes, not how well it is kept. Development tooling only; treat any production install as a Critical finding. |
| `mcp` (Python SDK) | **Infrastructure, not a recommendation target.** 2.0.0 shipped 28 Jul 2026 for the stateless 2026-07-28 specification revision, which is final rather than the draft it was taken for, so a bare `pip install mcp` now resolves to the 2.x line and 1.x is on security fixes only. Pin `mcp>=1.28,<2` until the migration is a deliberate one and re-vet at that point; 2026-07-28 is the audit baseline. |

The MCP authorization requirements themselves — OAuth 2.1, RFC 9728 protected-
resource metadata, RFC 8707 audience-bound tokens, and the prohibition on token
passthrough — are properties of the specification rather than of any transport
package, and none of the three entries above implements them. One package now
does implement part of it: `django-oauth-toolkit` 3.4.0 added first-class MCP
authorization-server support, with RFC 9728 protected-resource metadata,
RFC 8707 resource indicators, and RFC 7591/7592 dynamic client registration.
That is the issuing half only. Validating the audience on the way in is still
the resource server's own work — `service-identity-and-secrets.md`,
"Validating an inbound machine token" — and the passthrough prohibition remains
an architectural rule that no package enforces for you.

## Service identity and secrets

The defaults in this section were checked against the projects' own release
notes on **3 Aug 2026**; versions and classifiers carry the index date above.
Read with `service-identity-and-secrets.md`.

Most of this area is not a dependency at all. `django.core.signing`,
`SECRET_KEY_FALLBACKS`, `salted_hmac`, and the standard library's `secrets`
cover signing and key rotation, and the platform side — workload identity, a
service mesh, a secret manager — sits outside the Python dependency tree and is
a pattern to audit rather than a package to tier.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Validating third-party JWTs | `PyJWT==2.13.0` (21 May 2026) | **Recommend; require `>=2.13.0`** wherever the application is a resource server. MIT; maintained by the original author; Python >=3.9; pure Python, no transitive cost. 2.13.0 is a security release carrying five fixes: a JWK JSON document accepted as a raw HMAC secret, an algorithm-confusion gap the existing PEM/SSH guard did not cover; the header `alg` not bound to the `PyJWK` algorithm, so a caller's `algorithms=[...]` allow-list could be bypassed; `PyJWKClient` accepting non-`http(s)` URI schemes and so reaching `file://` and similar; the JWK-set cache being cleared whenever a fetch raised, turning a transient issuer outage into application-wide authentication failure; and an unconditional base64 decode of a detached payload, an unauthenticated denial-of-service amplifier. Below `2.13.0` is a finding in its own right. |
| JWKS client | `PyJWKClient`, shipped inside PyJWT | **Recommend the built-in** rather than a separate client. Defaults are `cache_jwk_set=True` and `lifespan=300`, the cache lives on the client instance, and an unknown `kid` triggers exactly one refresh-and-retry. Hold one client at module or singleton scope or the cache never applies; leave `cache_keys` off, because that second per-key LRU has no time-based expiry. |
| Service-to-service JWTs | `djangorestframework-simplejwt` | **Out of scope as a machine-identity mechanism; the existing A07 disposition is unchanged.** It issues and verifies tokens the Django application itself minted from a human login. `5.5.1` requires `pyjwt>=1.7.1` with no upper bound, so a `PyJWT>=2.13.0` floor does not conflict with it. |
| Client-credentials issuance | `django-oauth-toolkit` | **Existing disposition above stands.** Relevant here only where the Django application is itself the authorization server minting client-credentials tokens, which is the uncommon case. *Consuming* such tokens needs no dependency beyond PyJWT. |
| Workload identity, mesh, and secret storage | SPIFFE/SPIRE, cloud IAM and secret managers, Envoy/Istio | **Patterns, not vetting-gate entries.** None is a Python dependency of the Django application. Audit how the backend consumes an attested identity or a fetched secret; do not tier the platform. |

## Data layer and database

Read with `data-layer-and-database.md`.

Most of this domain is configuration rather than dependency: role separation,
row-level security, connection verification, statement timeouts, and pool
sizing are database and driver settings, and no package supplies them. The
encryption primitives themselves — `cryptography`, and the one packaged field
library still worth a disposition — are in "Cryptographic primitives and
password hashing" below.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Connection pooling | psycopg 3 with the `pool` extra | **Recommend the built-in.** Django 5.1+ accepts `OPTIONS={"pool": {...}}` on the PostgreSQL backend and Django 6.0 adds async-aware pooling. The option requires psycopg 3 — it is unavailable under psycopg2 — and requires `CONN_MAX_AGE = 0`, or Django raises `ImproperlyConfigured`. PgBouncer stays the choice where a process-external pool is wanted; use session mode when row-level-security context or `search_path` tenancy is in play. |
| Schema-per-tenant | `django-tenants==3.14.0` (5 Aug 2026) | **Conditional, and pin it exactly.** MIT; Production/Stable; declares Django 5.2, 6.0, and 6.1 and Python 3.10–3.13, which makes it one of the few entries here already carrying the new line — it dropped the 4.2 classifier in the same move. Adopt only where schema-per-tenant genuinely is the architecture: it requires session-mode pooling because `search_path` is session state, and migration time scales linearly with tenant count. It is not the default answer to multi-tenancy — scoped querysets plus a cross-tenant test suite are. The pin is not a formality: it went 3.10.2, 3.12.0, 3.13.0, 3.14.0 between 30 Jun and 5 Aug 2026, three of them in the three days around the Django 6.1 release, so an unpinned install moves minor versions underneath a tenancy layer that owns query scoping. |
| MongoDB backend | `django-mongodb-backend==6.0.4` (14 Jul 2026), the 6.0.x line | **Conditional.** MongoDB-maintained, Apache-2.0, Production/Stable, Python 3.12+, version-matched to the Django line — the major/minor tracks Django's, so a 6.1 project waits for a 6.1.x line rather than taking this one. Only where MongoDB is already in the stack. Ordinary ORM `filter()` compiles to an aggregation pipeline and is the safe path; `raw_aggregate()` is the injection-sensitive one and `raw()` is unsupported. |
| Packaged field encryption | `django-encrypted-model-fields`, `django-cryptography` and its Django-5 forks, `django-pgcrypto-fields`, `django-searchable-encrypted-fields`, `django-fernet-fields` | **Reject for new use.** None declares support for Django 5.2 or 6.0 and each has gone more than a year without a release; `django-cryptography` still imports `django.utils.baseconv`, which Django 5 removed. **Existing-install audit only** where one is already present, with a documented migration off it. Build on `cryptography` instead. The single exception in this category, `django-fernet-encrypted-fields`, is tiered conditional in "Cryptographic primitives and password hashing". |

## Data lifecycle and privacy

Read with `data-lifecycle-and-privacy.md`.

The dedicated privacy packages are the weakest category in this index: the
best-known option is archived, the rest are years past their last release, and
none of them closes the related-object leak that makes soft delete unsafe as a
deletion control. Django's own partial `UniqueConstraint`, custom managers,
`FieldFile.delete()`, a management command on a real schedule, and a local
classification convention cover the area without a dependency.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Retention scheduler | `django-celery-beat==2.9.0` | **Recommend as the retention runner.** BSD; Production/Stable; declares Django 5.2 and 6.0. Database-backed schedule with an admin surface and a recorded last-run time, which is what makes a retention policy verifiable. A systemd timer is an equally acceptable runner where Celery is not already deployed. |
| Model history / audit trail | `django-simple-history==3.13.0` | **Recommend as audit tooling, and treat it as a personal-data store.** Django Commons; declares Django 5.2 and 6.0 and Python 3.10–3.14. Its historical tables retain every prior value of every field, including values a subject later asked to erase, so they belong in the retention policy and the erasure fan-out. |
| Non-production synthetic data | `Faker==40.36.0` | **Recommend for generated values.** Actively released. Synthetic data is not anonymized production data; it removes re-identification risk only because it is not derived from anyone. |
| Non-production masking (PostgreSQL) | `postgresql_anonymizer`, 3.x line | **Conditional, and vetted at the database layer rather than through the Python gate.** A PostgreSQL extension providing static masking, dynamic masking, and anonymized dumps with referential-integrity-preserving pseudonymization, which is the mechanism the lower-environment pipeline needs. Confirm the installed version against the project's own security announcements at adoption, and run a current 3.x release. |
| Orphaned-file cleanup | `django-cleanup==9.0.0` | **Conditional.** MIT; Production/Stable; declares no Django version classifiers, so verify against the project's Django. It removes files on ordinary ORM deletes and replacements, but it is bound to model signals, so raw SQL, `_raw_delete()`, `TRUNCATE`, and database-level cascades bypass it. It is convenience, not the erasure guarantee — keep an explicit storage delete in the fan-out. |
| Soft delete (undo semantics) | `django-soft-delete==1.0.23` | **Conditional; verify in CI.** MIT; released Feb 2026 and maintained, but it declares no Django version classifiers and its `requires_python` is unmaintained (`>=3.6`). It supplies filtered and unfiltered managers and nothing more: it does not close the forward-relation, `select_related`, admin, or raw-SQL leaks, so it is an undo feature, never a deletion or privacy control. |

| Candidate | Disposition and safer direction |
|---|---|
| `django-safedelete==1.4.1` | **Existing-install audit only.** BSD-3-Clause but Beta status, last repository activity Mar 2025, no Django version classifiers, and cascade soft-delete raises against `PROTECT` relations. Where it is present, verify Django compatibility and audit the cascade behaviour; do not newly adopt it for a 6.0/5.2 baseline. |
| `pganonymize==0.13.0` (6 Aug 2026) | **Existing-install audit only, and the disposition is about fit rather than maintenance.** MIT, but Beta status, no `requires_python`, and Python classifiers still advertising 2.7. It broke a two-year gap with a release on 6 Aug 2026, so the staleness argument that used to carry this row no longer holds — the reason it is not a recommendation is that it is a standalone CLI operating on a dump, outside the database's own masking rules, where the extension above enforces them in the engine. Acceptable where already used for dump anonymization; prefer the extension for new work. |
| `django-gdpr-assist` | **Reject.** The repository was archived read-only on 21 May 2025 and the package supports neither Django 5.2 nor 6.0. Its per-model privacy declaration is still a good pattern to reimplement locally in a few lines. |
| `django-anon`, `django-GDPR` | **Reject.** No release since 2023, no declared support for a supported Django line, and field-level “anonymizers” built on plain hashes are pseudonymization, not anonymization. |
| Single-maintainer retention packages | **Reject as a category.** A management command plus a scheduled task and a persisted run record is smaller, reviewable, and does not add an unmaintained dependency to the deletion path. |

## GraphQL and alternative API surfaces

The defaults in this section were checked against the packages' own source on
**4 Aug 2026**; versions and classifiers carry the index date above. Read with
`graphql-and-alternative-api-surfaces.md`.

No package in this area ships the controls that make a GraphQL endpoint safe.
Depth, alias, token, and cost limits, resolver-level authorization, and error
masking are all opt-in in every library below, so the disposition decides which
footguns you inherit, not whether you still have to do the work.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| GraphQL on Django (new work) | `strawberry-graphql==0.323.2` (23 Jul 2026) with `strawberry-graphql-django==0.87.0` (6 Aug 2026) | **Conditional; pin both exactly.** MIT; Python >=3.10; the Django package declares Django 5.2 and 6.0. Ships `QueryDepthLimiter`, `MaxAliasesLimiter`, `MaxTokensLimiter`, `AddValidationRules`, `DisableIntrospection`, `MaskErrors`, the `IsAuthenticated`/`HasPerm`/`HasSourcePerm`/`HasRetvalPerm` field extensions, and `DjangoOptimizerExtension` for N+1 — none of them enabled by default. Pre-1.0 on both lines with frequent releases (three on 1 Aug 2026 alone), so an unpinned install is a moving target. Pass limiter extensions as classes or factories; a shared instance carries execution context across concurrent requests. |
| GraphQL on Django (existing install) | `graphene-django==3.2.3` (13 Mar 2025) | **Existing-install audit only.** MIT; classifiers stop at Django 4.2, so it declares no support for 5.2 LTS or 6.0, and there has been no release in roughly seventeen months. An install on a supported Django line is a supply-chain finding under A03, not merely a compatibility note. `DjangoObjectType` with `Meta.model` and neither `fields` nor `exclude` exposes every field behind a `DeprecationWarning`, and `graphene_django.utils.bypass_get_queryset` disables type-level scoping on foreign-key and one-to-one traversal. A release declaring Django 5.2/6.0 would move it back to conditional. |
| GraphQL core validators | `graphene==3.4.3` (9 Nov 2024) | **Transitive; audit, do not add directly.** Supplies `graphene.validation.depth_limit_validator` and `DisableIntrospection`, neither wired into `GraphQLView` by default. Release cadence tracks graphene-django's, which is the concern above. |
| Non-DRF HTTP API | `django-ninja==1.6.2` (18 Mar 2026) | **Conditional.** Declares Django 5.2 and 6.0; healthy adoption. The footgun is the default: an operation is public unless `auth=` is set on the `NinjaAPI`, router, or route, and there is no project-wide default-deny equivalent to `DEFAULT_PERMISSION_CLASSES`. Set `auth=` at the `NinjaAPI` object and treat every `auth=None` as a reviewed exception. |
| Ninja JWT | `django-ninja-jwt==5.4.5` (21 Jul 2026) | **Existing-install audit only.** Actively released, but its classifiers stop at Django 4.1, so compatibility with a 5.2/6.0 baseline is undeclared — verify it in CI. Its `SIGNING_KEY` defaults to Django's `SECRET_KEY`; set an independent key so token forgery and `SECRET_KEY` rotation are not the same event. |
| N+1 mitigation | `DjangoOptimizerExtension` (in strawberry-graphql-django); `graphene-django-optimizer` | **Prefer the built-in.** Strawberry's optimizer needs no new dependency. Reach for `graphene-django-optimizer` only on an existing graphene-django install, at **conditional**, and re-run the A03 gate at adoption. Verify either by query count under a realistically nested document; an optimizer that silently fails to engage looks identical to one that works. |

| Candidate | Disposition and safer direction |
|---|---|
| `ariadne` 1.1.0 (15 Jun 2026) with `ariadne-django` 0.3.0 (19 Jul 2022) | **Reject the Django integration for new use.** Ariadne core is maintained and reached 1.x, but the Django integration has not been released in four years and declares no supported Django version. Where the schema-first style is wanted, mount Ariadne's own ASGI/WSGI application and own the integration deliberately, or use Strawberry. |
| `django-socio-grpc` | **Scoping note, not a tier.** Niche gRPC-for-Django toolkit. If a Django application serves gRPC, audit its handlers with the authorization, input-validation, and limit rules in `graphql-and-alternative-api-surfaces.md`; the transport and mesh belong to `deployment-and-runtime.md` and `service-identity-and-secrets.md`. |
| Persisted-query packages | **No first-party Django option; do not adopt by category.** Operation allowlisting is normally a gateway concern or a small server-side hash registry. An automatic-persisted-query implementation that registers whatever a client first sends is a cache, not an allowlist, and provides none of the security benefit. |

## API surface, schema, and bulk operations

Read with `api-drf-specific.md`. The DRF baseline moved to `3.18.0` (7 Aug
2026) in this pass, and two things about that line matter more than the number.
The security fixes are in `3.17.2` (5 Aug 2026) and not in `3.18.0`: it stopped
`AdminRenderer` disclosing GET-protected data through a validation-error
response, and made `request.data` parsing honour Django's
`DATA_UPLOAD_MAX_MEMORY_SIZE` rather than reading past it. `3.17.2` is
therefore the minimum safe version, and a project that cannot take `3.18.0`
should still be on it. `3.18.0` itself is a feature release: it drops Django
4.2, 5.0, and 5.1 — all end-of-life — adds Django 6.1 support, and changes the
error format that list serializers return to a dict, which is a breaking change
for any client parsing those responses.

The controls that make a DRF surface safe — scoped querysets, allow-listed
serializer fields and filters, per-object authorization on every route — are
framework built-ins and need no dependency. The packages below are for the two
places DRF genuinely ships nothing: an OpenAPI schema worth generating, and
declarative filtering. The bulk packages are listed because they are the ones
already installed when a bulk endpoint turns out to skip every object check.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| OpenAPI schema generation | `drf-spectacular==0.30.0` (6 Jul 2026) | **Recommend, pinned.** BSD-3-Clause; actively released; 0.30.0 added Django 6.0 and DRF 3.17 support. It replaces DRF's own deprecated schema path. Deliberately pre-1.0, so any release may change generated output: pin the exact version and diff the generated schema on upgrade, since the schema is also the inventory artifact an audit diffs against. Set `SERVE_INCLUDE_SCHEMA = False` and gate the schema and UI views — generating a schema and publishing it are separate decisions. No advisory found in OSV, the GitHub Advisory Database, or Snyk as of this date, which is an absence of advisories rather than a guarantee. |
| Declarative filtering | `django-filter==26.1` (11 Jul 2026) | **Recommend, with explicit allowlists only.** BSD-3-Clause; Python >=3.10; declares Django 5.2, 6.0, and 6.1. The package is safe; the usage is what fails review. Declare a `FilterSet` or a narrow `filterset_fields`; never generate filters across a model, and never set `filterset_fields` or `ordering_fields` to `"__all__"`. A filter over a column the caller cannot read is a disclosure oracle regardless of whether the column is serialized. |
| URL-map enumeration (development) | `django-extensions==4.1` (11 Apr 2025) | **Existing-install audit only, and a development dependency at that.** MIT; Production/Stable, but classifiers stop at Django 5.2 and there has been no release in over a year, so 6.0 support is undeclared. Its `show_urls` is a convenient inventory command where it is already present; the equivalent recursion over `get_resolver().url_patterns` needs no dependency, and Django 6.2's built-in `listurls` supersedes both. Never ship it in a production requirements file — it also carries `shell_plus`, `runserver_plus`, and other development-only commands. |

| Candidate | Disposition and safer direction |
|---|---|
| `djangorestframework-bulk==0.2.1` | **Reject.** Last released April 2015 and unmaintained for over a decade. Beyond the supply-chain finding, its bulk update path returns no object, so `check_object_permissions` never runs — a bulk route built on it authorizes nothing per record. Where it is installed, treat every route it serves as an unauthorized write path until proven otherwise. |
| `drf-extensions==0.8.0` | **Reject for new use; existing-install audit only.** BSD; classifiers stop at Django 5.2 and it declares no `requires_python`. Its bulk operations run as queryset-level `update()`/`delete()`, which by design bypass serializer `save`/`delete` and every per-object check. If it is present, audit each bulk route against `api-drf-specific.md`, "Bulk endpoints"; its caching and nested-router features are a separate question. |
| Bulk endpoints generally | **Prefer hand-written over packaged.** A bulk route is a per-object authorization problem, and the packaged mixins exist precisely to skip the per-object path. Loading the set from a requester-scoped queryset, confirming the returned count matches the requested ids, and wrapping the write in a transaction is a short amount of code that no dependency currently gets right. |

## Concurrency, idempotency, and regular expressions

Read with `a10-exceptional-conditions.md`.

This is the area where the built-ins win most clearly. `transaction.atomic()`,
`select_for_update()`, `F()`, `UniqueConstraint`, `CheckConstraint`,
`ExclusionConstraint`, and `transaction.on_commit()` cover the whole in-scope
surface, and the idempotency design is one model with one unique constraint. No
package below beats them on merit for the core controls; the two conditional
entries are for the narrow cases the built-ins genuinely do not reach.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Linear-time regular expressions | `google-re2==1.1.20251105` (5 Nov 2025) | **Conditional, and only where untrusted input must reach a genuinely dangerous pattern.** BSD; `requires_python ~=3.9`; published by the RE2 authors under Google's PyPI organisation and tracking the Google-maintained C++ engine, which guarantees match time linear in the length of the input — the property CPython's `re` cannot offer at any version. It is not a drop-in: backreferences and look-around are unsupported by design, so treat it as a targeted replacement for one pattern rather than a project-wide swap. Nine months since the last release, which tracks the upstream engine's own cadence rather than neglect, but re-check at adoption. Cap input length first; that control costs nothing. |
| Declarative state machines | `django-fsm-2==4.2.4` (16 Mar 2026) | **Conditional.** MIT; Python >=3.10; maintained under `django-commons` and declaring Django 4.2 through 6.0. It makes transitions and their guards readable, but it does not make them concurrency-safe: the guard is an in-memory check followed by `save()`, with no row lock, so a conditional `.update()` or a `select_for_update()` read is still required underneath it. Adopt only where a model already carries enough transitions for the declaration to earn its keep. |

| Candidate | Disposition and safer direction |
|---|---|
| `django-fsm==3.0.1` (7 Oct 2025) | **Reject for new use.** MIT, but PyPI classifies it `Development Status :: 7 - Inactive`, its Django classifiers stop at 5.2, and its own README states the 3.0 line was renamed `viewflow.fsm` with an API that does not work with the previous one. An existing install is therefore pinned to a renamed project: audit the transitions against the concurrency rules in A10 and plan a move to `django-fsm-2` or to plain fields with conditional updates. |
| `re2` (PyPI) | **Reject.** The name resolves to `pyre2 0.2.24`, last released February 2019 by third-party authors. Use `google-re2` above. |
| `regex` (PyPI) | **Reject as a ReDoS control.** Actively maintained and a capable `re` superset, but still a backtracking engine with no linear-time guarantee, so adopting it does not close the weakness it is often suggested for. |
| `django-idempotency-key==1.3.0` (2 May 2023) | **Reject for new use.** MIT, but three years without a release and Django classifiers stopping at 4.2, so support for a 5.2/6.0 baseline is undeclared. The design is a model, a unique constraint, and a short view helper; own it rather than depending on it. |
| `djangorestframework-idempotency-key==1.0.3` (29 Jul 2024) | **Reject for new use.** MIT, no Django version classifiers at all, and `requires_python >=3.6`. Same conclusion as above. |
| Redis distributed-lock packages, as a correctness primitive | **Reject on design rather than on maintenance.** Redlock and single-instance `SET NX PX` provide no fencing token for the protected resource to check, so a lock holder that stalls cannot be excluded; single-instance Redis adds asynchronous-replication failover on top. This disposition does not depend on any individual package's release cadence and does not change if one is refreshed. Acceptable for best-effort de-duplication where a rare double execution is only wasteful — never where correctness depends on it. |
| Transaction-isolation helpers | **Out of scope here; not tiered.** Packages that add isolation levels or retry loops to `atomic()` are a data-layer configuration decision, not a concurrency-bug fix. Vet them against `data-layer-and-database.md` if raising isolation is deliberately on the table. |

## Integrity, webhooks, and deserialization

Read with `a08-integrity-and-deserialization.md`.

Nothing is recommended here, and that is the finding. A conformant inbound
webhook verifier is `hmac.new`, `hmac.compare_digest`, and a model with a unique
constraint — standard library and ORM, perhaps thirty lines, fully reviewable.
Taking a dependency to compute one HMAC widens the supply-chain surface this
skill exists to shrink, and does so on the one route that is unauthenticated by
design. The rule for this area: **verify inbound with the standard library; take
a package only for the outbound interop problem, if at all.**

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Outbound webhook signing to a published spec | `standardwebhooks==1.1.0` (21 Jul 2026) | **Conditional, and only for outbound signing.** MIT; `requires_python >=3.9`; classifiers through Python 3.14; no declared install requirements, which is the reason it clears the gate at all. Justified only where you are publishing webhooks and want consumers to verify against a documented spec rather than a bespoke scheme — that interop is the whole value, and it is real. It is not justified for verifying inbound webhooks: implementing the same construction over `hmac` is a few lines and removes the dependency. Exit plan is to inline the construction, which the spec fully documents. |
| YAML parsing | `PyYAML==6.0.3` (25 Sep 2025) | **Conditional, and the condition is the call site, not the version.** MIT; `requires_python >=3.8`; Production/Stable with classifiers through Python 3.14; maintained. The package is not the risk — its default API is. `yaml.load` with the default loader, `FullLoader`, or `UnsafeLoader`, plus `yaml.unsafe_load` and `yaml.full_load`, construct arbitrary Python objects and are CWE-502 on any input that crossed a trust boundary. Accept an install only with `yaml.safe_load`/`SafeLoader` at every call site, and prefer JSON where the format is yours to choose. Note it is also what makes Django's `yaml` fixture serializer available. |

| Candidate | Disposition and safer direction |
|---|---|
| `svix==1.99.1` (23 Jul 2026) | **Reject for new use as a verification dependency.** MIT and actively released, so this is not a maintenance call. It is a vendor API client whose verifier is incidental, and it pulls `httpx`, `pydantic>=2.10`, `attrs`, `python-dateutil`, `deprecated`, and `standardwebhooks` transitively — six packages to compute one HMAC. Adopt it only if you are already a Svix customer using the API client for its own sake; never add it to a project solely to verify an inbound signature. |
| Vendor SDKs as inbound webhook verifiers, generally | **Do not add one for verification alone.** A provider SDK you already run for its API is fine to verify with — Stripe's library is the ordinary example, and it removes a class of scheme-transcription bugs. Installing an SDK you otherwise have no use for, to check a signature, fails the gate on transitive cost with no control the standard library lacks. |
| Celery, and message brokers generally | **Out of scope here; not tiered.** Celery is infrastructure a project already runs, not a security control being selected, so it does not take a disposition in this index. Audit its configuration against A08 — `accept_content`, the result backend, and who can reach the broker — rather than treating its presence as a package decision. `django-celery-beat` is tiered above for the narrower job of running retention. |

## Cryptographic primitives and password hashing

The defaults in this section — above all the Argon2 parameters below — were
checked against the projects' own source on **7 Aug 2026**; versions and
classifiers carry the index date above. Read with
`a04-cryptographic-failures.md`.

This area is mostly two dependencies and a lot of parameters. The standard
library covers randomness and constant-time comparison outright — `secrets` and
`hmac.compare_digest` need no package — and `django.core.signing` covers signed
values. What genuinely needs a dependency is the Argon2 implementation behind
Django's hasher and the primitives behind an encrypted column.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Password hashing | `argon2-cffi==25.1.0` | **Recommend.** MIT; `requires_python >=3.8`; maintained; it is what `pip install "django[argon2]"` pulls in and what `Argon2PasswordHasher` requires. Note that Django does **not** inherit this library's defaults: `argon2-cffi`'s own `PasswordHasher` is `time_cost=3`, `memory_cost=65536`, `parallelism=4` (the RFC 9106 SECOND profile, exposed as `argon2.profiles.RFC_9106_LOW_MEMORY`), while Django hard-codes `time_cost=2`, `memory_cost=102400`, `parallelism=8` on its own class. Neither tracks the other, so read the numbers off whichever is actually in the hash path, and benchmark rather than accept either. `check_needs_rehash()` is for non-Django callers; Django's `must_update()` already covers upgrade-on-login. |
| Encryption primitives | `cryptography==50.0.0` | **Recommend as the base, not as a field library.** PyCA-maintained, dual Apache-2.0/BSD, healthy cadence; also listed under "Data layer and database" for the storage side. `Fernet` is AES-128-CBC plus HMAC-SHA256 and embeds the encryption time in the token as plaintext; `MultiFernet` supplies key versioning and `rotate()`; `AESGCM` and `ChaCha20Poly1305` supply single-pass AEAD where the Fernet timestamp or the CBC construction is unwanted. |
| Packaged field encryption, the one current option | `django-fernet-encrypted-fields==0.4.0` (14 Apr 2026) | **Conditional, and the condition is key custody.** MIT under Jazzband, `requires_python >=3.10`, released Apr 2026, and its own test matrix runs Django 3.2 through 6.0 — which makes it the only member of this category that is not simply abandoned. Two things stop it short of a recommendation. Its PyPI classifiers are empty, so it *declares* no supported Django version and compatibility has to be verified in CI rather than read off the metadata. More importantly, it derives the Fernet key with PBKDF2-HMAC-SHA256 from Django's `SECRET_KEY` plus a `SALT_KEY` setting, so the signing key and the data-encryption key are the same secret: a `SECRET_KEY` rotation becomes a data re-encryption and a `SECRET_KEY` leak becomes a decryption-key leak. Acceptable where the data is low-sensitivity and that coupling is understood and written down; for anything worth a KMS, hold the key independently and build on `cryptography` directly. |

| Candidate | Disposition and safer direction |
|---|---|
| Cloud KMS SDKs — `boto3`, `google-cloud-kms`, `azure-keyvault-keys` | **Patterns, not vetting-gate entries**, on the same basis as the workload-identity row above. These are the platform SDKs a project already runs, not security packages being selected against alternatives. Audit how the backend wraps and unwraps a data key and whether every unwrap is attributable; do not tier the cloud provider. |
| CipherSweet | **Out of scope for a Python backend.** The reference implementations are PHP and JavaScript, so it is not an option here. It remains a useful published description of the blind-index construction, which `data-layer-and-database.md` implements directly over `hmac`. |
| Post-quantum libraries in application code | **Do not adopt this cycle.** FIPS 203/204/205 are finalized and hybrid key exchange is real, but it belongs at the TLS terminator, not in Django. There is no application-layer control here worth a dependency yet; the in-scope action is the harvest-now-decrypt-later inventory in `a04-cryptographic-failures.md`. |

## Runtime, proxy trust, and operational endpoints

Read with `deployment-and-runtime.md`.

Nothing is recommended here, for the same reason as the webhook section above:
both controls in scope are already built in. Reading the client IP correctly is
a hop count and a list index — DRF exposes it as `NUM_PROXIES`, and outside DRF
it is the few lines in `deployment-and-runtime.md`, "Reading the client IP".
Container posture is a Dockerfile, not a dependency. The packages below are
listed because they are the ones already installed when a review finds a
spoofable throttle key or a SQL console answering on a production host.

| Candidate | Disposition and safer direction |
|---|---|
| `django-ipware==7.0.1` (19 Apr 2024), with `python-ipware==3.0.0` (same date) | **Reject for new use.** MIT, and the design is sound — `proxy_count` and `proxy_trusted_ips` implement exactly the right rule. It fails the gate on maintenance and declared compatibility: more than two years without a release, no Django version classifiers at all, and Python classifiers stopping at 3.12 while Django 6.0 already requires 3.12 or later and 6.1 supports 3.14. Its own README states that it is not a defence against address spoofing on its own and must complement a correctly configured proxy — so it never removes the work of knowing your topology, which is the only hard part. Set DRF's `NUM_PROXIES`, or write the handful of lines directly. Neither adds a dependency to the code path that decides who gets rate-limited and who appears in the audit log. |
| `django-debug-toolbar==7.0.0` | **Reject for production; development dependency only.** This is not a maintenance call — BSD-3-Clause, Python >=3.10, and it declares Django 5.2 and 6.0. It renders SQL, settings, and request internals by design, and CVE-2021-30459 (CVSS 9.8, fixed in 1.11.1, 2.2.1, and 3.2.1) allowed SQL execution through the SQL panel's own form. Keep it out of the production requirements file entirely, so a mistaken `DEBUG = True` raises `ImportError` rather than publishing a console. An install in a production image is a finding on its own weight. |
| `django-silk==5.5.0` (8 Mar 2026) | **Reject for production; development dependency only.** MIT; Python >=3.10; declares Django 4.2 through 6.0 and is actively maintained. The disposition is about where it runs, not whether it is cared for: it publishes a request and SQL profiling UI, and `SILKY_MAX_REQUEST_BODY_SIZE` defaults to `-1`, so it records every request and response body without limit. On a production database that is an unscoped copy of personal data as well as a disclosure surface — see `data-lifecycle-and-privacy.md`. |
| `django-extensions` | **Existing disposition above stands** — development-only, existing-install audit. Restated here for one reason: it carries `runserver_plus`, and therefore the Werkzeug interactive debugger, which is arbitrary code execution by design. That is the most severe item in this table and it usually arrives as a convenience nobody chose deliberately. |
| Metrics and health-check exporters | **Not tiered; audit the exposure rather than the package.** `django-prometheus` and its equivalents are observability infrastructure a project already runs, not a security control being selected against alternatives. The review questions are whether the endpoint is authenticated or bound to an internal interface, and what a health payload discloses about versions and dependency reachability. |

## Use in a review

This index supplies the disposition; the finding is still written against the
project in front of you, whose Python, Django, and DRF versions are the ones
that decide whether an entry applies. Work through it in the order below.

## Review checklist

- [ ] The tier was read as a disposition rather than a score: **recommend** is
      the default choice for this baseline, **conditional** names a condition
      that has to hold in the target project before the choice is sound,
      **existing-install audit only** means audit what is installed and do not
      newly adopt it, and **reject for new use** means the entry is a finding
      waiting to be written up.
- [ ] The installed version and the actual configuration were reported, not
      merely the package name.
- [ ] The version recorded here was checked against the versions the project
      itself declares — its Python, its Django, its DRF — because a tier is
      granted against this file's baseline, not against that project.
- [ ] An install below a stated minimum-safe floor, or outside the
      compatibility a package declares, was written up as a finding on its own
      weight even where the application appears to work.
- [ ] Secure defaults were traced in the target project rather than assumed:
      adapters, pipelines, middleware order, proxy trust, token persistence,
      callbacks, and failure behavior.
- [ ] A re-vet was triggered where one is due — a framework or Python upgrade,
      a relevant advisory, an ownership change, a long release gap, or a change
      in the package's security-sensitive defaults.
- [ ] Every claim taken from this file was read against the date stated above
      it. A date records when the entry was checked and guarantees nothing
      about today, so an entry older than the package's own release cadence is
      re-checked before it is quoted in a finding.
