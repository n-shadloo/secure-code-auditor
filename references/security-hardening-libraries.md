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

## Use in a review

- Report the installed version and actual configuration, not merely the package name.
- A package below its minimum safe version or outside declared compatibility is a
  finding even when the application appears to work.
- Secure defaults can change; trace adapters, pipelines, middleware order, proxy
  trust, token persistence, callbacks, and failure behavior in the target project.
- Re-vet after a framework/Python upgrade, relevant advisory, ownership change,
  long release gap, or change in the package's security-sensitive defaults.
