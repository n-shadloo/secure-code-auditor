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

## Use in a review

- Report the installed version and actual configuration, not merely the package name.
- A package below its minimum safe version or outside declared compatibility is a
  finding even when the application appears to work.
- Secure defaults can change; trace adapters, pipelines, middleware order, proxy
  trust, token persistence, callbacks, and failure behavior in the target project.
- Re-vet after a framework/Python upgrade, relevant advisory, ownership change,
  long release gap, or change in the package's security-sensitive defaults.
