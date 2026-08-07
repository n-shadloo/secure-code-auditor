# Security-hardening libraries — vetted decisions

This is a dated decision index, not an install-all list. It is current as of
**17 Jul 2026** for the repository baseline (Django 6.0.7 / 5.2.16 LTS and DRF
3.17.1). Re-run the A03 dependency gate for the project's actual Python/Django
versions and whenever maintenance, advisories, or compatibility changes.

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
| Password hashing | `argon2-cffi==25.1.0` | **Recommend.** MIT; maintained; compatible with current Python. Use Django's Argon2 hasher first, retain fallback hashers, and benchmark worker cost. |
| CORS | `django-cors-headers==4.9.0` | **Recommend.** MIT; maintained; Django 6.0 supported. Explicit origin allowlists; no credentialed wildcard/reflection. |
| CSP | Django 6 built-in CSP | **Recommend built-in.** Avoids an extra dependency. For supported pre-6.0 projects only, `django-csp==4.0` is **conditional** through Django 5.2. |
| Login lockout/monitoring | `django-axes==8.3.1` | **Recommend.** MIT/Jazzband; maintained; Django 6.0 supported. Correct trusted-proxy/client-IP handling first; avoid permanent attacker-triggered lockout. |
| TOTP/MFA primitives | `django-otp==1.7.0` | **Recommend.** Maintained; Django 6.0 compatible. Enrollment/removal/recovery still need re-authentication and audit controls. |
| MFA workflow | `django-two-factor-auth==1.18.1` | **Conditional** for compatible Django 5.2 projects; not advertised for Django 6. Re-vet before upgrading. |
| JWT | SimpleJWT `5.5.1` | **Conditional** for supported Django 5.2 projects; not advertised for Django 6. Minimum `5.5.1` includes the CVE-2024-22513 fix. Configure algorithm/issuer/audience/lifetimes/rotation/denylisting. |
| Social/OIDC client | `django-allauth==65.18.0` | **Recommend; require >=65.16.1.** MIT; Python >=3.10; Django 6 supported. Keep automatic email auth/connection and login-on-GET off; enable PKCE per provider; avoid token storage unless needed. |
| REST auth wrapper | `dj-rest-auth==7.2.0` | **Recommend only with reviewed allauth/provider settings.** MIT; Python >=3.10. Prefer code flow/fixed callback and audit which token artifact each endpoint accepts. |
| OAuth/OIDC provider | `django-oauth-toolkit==3.3.0` | **Recommend.** BSD; Python >=3.10; Django 6 supported. Keep PKCE required, exact redirects, narrow scopes, hashed client secrets; OIDC is opt-in. Older installs require `oauthlib>=3.2.2`. |
| Alternate social-auth client | `social-auth-app-django==6.0.0` | **Recommend; require >=5.6.0.** BSD-3-Clause; Django 5.2/6 supported. Review pipeline/state/redirects; never add `associate_by_email` without a proven provider-specific verified-email policy. |
| WebSockets/ASGI | Channels `4.3.2` | **Recommend.** Django-project maintained; Django 6 supported. Still implement origin checks, per-message authz, bounds, backpressure, and cleanup. |
| Dependency advisories | `pip-audit==2.10.1` | **Recommend as one input.** PyPA-maintained, Apache-2.0. It does not prove maintenance, provenance, compatibility, configuration, or safety. |
| Rich-HTML sanitization | `nh3==0.3.6` | **Recommend when rich HTML is required.** MIT; actively released. Centralize a minimal allowlist and URL-scheme policy; prefer plain text/structured markup. |

## Existing-install audit only or rejected candidates

| Candidate | Disposition and safer direction |
|---|---|
| `mozilla-django-oidc==5.0.2` | **Existing-install audit only.** No advertised Django 6 support; PKCE defaults off; open issue #340 documents missing exact issuer/audience validation in the default verification path. Require PKCE plus a reviewed verifier override/replacement, or migrate. |
| `djangorestframework-api-key==3.1.0` | **Existing-install audit only.** No advertised Django 6 support and weak recent maintenance signals. Preserve digest/prefix/expiry/revocation/scoped-model patterns, but add real authorization and never use it as human authentication. |
| `django-ratelimit==4.1.0` | **Reject for new use.** 2023 release and dormant maintenance signals. Use maintained edge/platform limits plus account/tenant/business-flow controls. |
| `django-defender==0.9.8` | **Reject for new use.** 2024 release and stale Python/support signals. Use the layered A06 design; `django-axes` is the vetted login-specific choice. |
| `django-storages==1.14.6` | **Reject as a new recommendation for this Django 6 baseline.** Advertised compatibility/maintenance signals are insufficient. Prefer Django Storage API plus an official maintained provider SDK, or freshly re-vet. |
| `defusedxml==0.7.1` | **Reject as a new recommendation.** Stale release/maintenance signals. Disable XML or choose a maintained format-specific parser with DTD/entity/network/expansion controls. |
| `python-magic==0.4.27` / `filetype==1.2.0` | **Reject as new recommendations.** Stale release/maintenance signals. Use multiple bounded checks and a maintained parser for each explicitly supported file type. |
| `python-decouple==3.8` | **Reject as a new recommendation.** Stale release signal. Use `os.environ` or the official maintained secrets-manager SDK and validate settings at startup. |
| Generic “security bundle” packages | **Do not recommend by category alone.** Prefer Django/DRF built-ins and add a narrowly justified dependency only after the A03 gate. |

## Authorization, object permissions, and impersonation

Versions and classifiers in this section were checked against PyPI on
**1 Aug 2026**; the rest of this file carries the 17 Jul 2026 baseline above.
Read with `authorization-architecture.md` and
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

Versions and defaults in this section were checked on **1 Aug 2026**; the rest
of this file carries the 17 Jul 2026 baseline above. Read with
`agent-and-llm-interfaces.md`.

**No package in this area clears the gate for a `recommend` tier.** The default
construction is DRF's own authentication, permission, filter, pagination, and
throttle classes plus a hand-written audience-validating authentication class,
with `django-oauth-toolkit` above where the application is the authorization
server. Every entry below is a disposition for something already installed.

| Candidate | Disposition and review notes |
|---|---|
| `django-mcp-server==0.5.7` (10 Mar 2026) | **Existing-install audit only.** MIT; publishes DRF viewsets as MCP tools with `authentication_classes`, `permission_classes`, `filter_backends`, and `pagination_class` disabled by default. Every one must be explicitly re-enabled on every tool path; confirm `self.paginator` is not `None` on a list tool. Not a new recommendation. |
| `django-rest-framework-mcp==0.1.0a4` (25 Nov 2025) | **Existing-install audit only.** MIT; alpha, so treat the API as unstable. Defaults are the safe ones — confirm `BYPASS_VIEWSET_AUTHENTICATION`, `BYPASS_VIEWSET_PERMISSIONS`, and `RETURN_200_FOR_ERRORS` are all off, since the last returns HTTP 200 on an auth or permission failure and blinds 4xx-rate alerting. |
| `django-admin-mcp-api` / `django-admin-mcp` | **Reject for production.** Both expose the Django admin as a machine API. The admin was designed as a human interface behind staff/superuser privilege, so the blast radius is the whole model layer; non-browser session or long-lived bearer semantics make it worse. Audit-only where already installed. |
| `mcp-django==0.13.0` | **Reject for production.** Offers management-command and stateful shell access, which is arbitrary code execution by design. Development tooling only; treat any production install as a Critical finding. |
| `mcp` (Python SDK) | **Infrastructure, not a recommendation target.** A v2 line shipped 28 Jul 2026 alongside a draft stateless protocol revision, so a bare `pip install mcp` no longer resolves to the 1.x line. Pin the major version deliberately and re-vet before migrating; the 2025-11-25 specification revision remains the audit baseline. |

The MCP authorization requirements themselves — OAuth 2.1, RFC 9728 protected-
resource metadata, RFC 8707 audience-bound tokens, and the prohibition on token
passthrough — are properties of the specification, not of any package. A
package that implements transport does not implement those.

## Service identity and secrets

Versions and defaults in this section were checked against PyPI and the
projects' own release notes on **3 Aug 2026**; the rest of this file carries
the 17 Jul 2026 baseline above. Read with `service-identity-and-secrets.md`.

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

Versions in this section were checked on **2 Aug 2026**; the rest of this file
carries the 17 Jul 2026 baseline above. Read with
`data-layer-and-database.md`.

Most of this domain is configuration rather than dependency: role separation,
row-level security, connection verification, statement timeouts, and pool
sizing are database and driver settings, and no package supplies them.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| Connection pooling | psycopg 3 with the `pool` extra | **Recommend the built-in.** Django 5.1+ accepts `OPTIONS={"pool": {...}}` on the PostgreSQL backend and Django 6.0 adds async-aware pooling. The option requires psycopg 3 — it is unavailable under psycopg2 — and requires `CONN_MAX_AGE = 0`, or Django raises `ImproperlyConfigured`. PgBouncer stays the choice where a process-external pool is wanted; use session mode when row-level-security context or `search_path` tenancy is in play. |
| Field-encryption primitives | `cryptography==50.0.0` (31 Jul 2026) | **Recommend as the base, not as a field library.** PyCA-maintained, dual Apache-2.0/BSD, healthy cadence. Build encrypt/decrypt and HMAC blind-index helpers on it directly and keep keys outside the database and out of the DSN. |
| Schema-per-tenant | `django-tenants` 3.10.x (Jun 2026) | **Conditional.** MIT; Production/Stable; declares Django 4.2/5.2/6.0 and Python 3.10–3.13; actively maintained. Adopt only where schema-per-tenant genuinely is the architecture: it requires session-mode pooling because `search_path` is session state, and migration time scales linearly with tenant count. It is not the default answer to multi-tenancy — scoped querysets plus a cross-tenant test suite are. |
| MongoDB backend | `django-mongodb-backend`, 6.0.x line (Apr 2026) | **Conditional.** MongoDB-maintained, Apache-2.0, Production/Stable, Python 3.12+, version-matched to the Django line. Only where MongoDB is already in the stack. Ordinary ORM `filter()` compiles to an aggregation pipeline and is the safe path; `raw_aggregate()` is the injection-sensitive one and `raw()` is unsupported. |
| Packaged field encryption | `django-encrypted-model-fields`, `django-cryptography` and its Django-5 forks, `django-pgcrypto-fields`, `django-searchable-encrypted-fields`, `django-fernet-fields` | **Reject for new use — the whole category.** None declares support for Django 5.2 or 6.0 and each has gone more than a year without a release; `django-cryptography` still imports `django.utils.baseconv`, which Django 5 removed. **Existing-install audit only** where one is already present, with a documented migration off it. Build on `cryptography` instead. |

## Data lifecycle and privacy

Versions in this section were checked against PyPI and the projects' own
repositories on **2 Aug 2026**; the rest of this file carries the 17 Jul 2026
baseline above. Read with `data-lifecycle-and-privacy.md`.

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
| `pganonymize==0.12.0` | **Existing-install audit only.** Standalone PostgreSQL CLI, last released 2024. Acceptable where already used for dump anonymization; prefer the maintained extension above for new work. |
| `django-gdpr-assist` | **Reject.** The repository was archived read-only on 21 May 2025 and the package supports neither Django 5.2 nor 6.0. Its per-model privacy declaration is still a good pattern to reimplement locally in a few lines. |
| `django-anon`, `django-GDPR` | **Reject.** No release since 2023, no declared support for a supported Django line, and field-level “anonymizers” built on plain hashes are pseudonymization, not anonymization. |
| Single-maintainer retention packages | **Reject as a category.** A management command plus a scheduled task and a persisted run record is smaller, reviewable, and does not add an unmaintained dependency to the deletion path. |

## GraphQL and alternative API surfaces

Versions and defaults in this section were checked against PyPI and the
packages' own source on **4 Aug 2026**; the rest of this file carries the
17 Jul 2026 baseline above. Read with
`graphql-and-alternative-api-surfaces.md`.

No package in this area ships the controls that make a GraphQL endpoint safe.
Depth, alias, token, and cost limits, resolver-level authorization, and error
masking are all opt-in in every library below, so the disposition decides which
footguns you inherit, not whether you still have to do the work.

| Concern | Choice and version | Disposition and review notes |
|---|---|---|
| GraphQL on Django (new work) | `strawberry-graphql==0.323.2` (23 Jul 2026) with `strawberry-graphql-django==0.86.8` (1 Aug 2026) | **Conditional; pin both exactly.** MIT; Python >=3.10; the Django package declares Django 5.2 and 6.0. Ships `QueryDepthLimiter`, `MaxAliasesLimiter`, `MaxTokensLimiter`, `AddValidationRules`, `DisableIntrospection`, `MaskErrors`, the `IsAuthenticated`/`HasPerm`/`HasSourcePerm`/`HasRetvalPerm` field extensions, and `DjangoOptimizerExtension` for N+1 — none of them enabled by default. Pre-1.0 on both lines with frequent releases (three on 1 Aug 2026 alone), so an unpinned install is a moving target. Pass limiter extensions as classes or factories; a shared instance carries execution context across concurrent requests. |
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

Versions and classifiers in this section were checked against PyPI on
**5 Aug 2026**; the rest of this file carries the 17 Jul 2026 baseline above.
Read with `api-drf-specific.md`. Note that DRF `3.17.2` was published on
5 Aug 2026, after the repository baseline of `3.17.1` was set; it has not been
through the gate here, so treat the baseline as unchanged and re-vet before
moving a project onto it.

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

Versions and classifiers in this section were checked against PyPI and the
projects' own repositories on **7 Aug 2026**; the rest of this file carries the
17 Jul 2026 baseline above. Read with `a10-exceptional-conditions.md`.

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

## Use in a review

- Report the installed version and actual configuration, not merely the package name.
- A package below its minimum safe version or outside declared compatibility is a
  finding even when the application appears to work.
- Secure defaults can change; trace adapters, pipelines, middleware order, proxy
  trust, token persistence, callbacks, and failure behavior in the target project.
- Re-vet after a framework/Python upgrade, relevant advisory, ownership change,
  long release gap, or change in the package's security-sensitive defaults.
