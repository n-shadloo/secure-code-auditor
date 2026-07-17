# A07:2025 — Authentication Failures

Password, session, token, federated-login, API-key, recovery, and anti-automation
controls. API mappings include API2:2023 (Broken Authentication).

## Contents

- [Principle](#principle)
- [Sessions](#sessions)
- [JWT](#jwt)
- [Token storage](#token-storage)
- [Brute force and enumeration](#brute-force-and-enumeration)
- [Password reset](#password-reset)
- [MFA](#mfa)
- [OAuth2, OIDC, and social login](#oauth2-oidc-and-social-login)
- [API keys](#api-keys)
- [Review checklist](#review-checklist)

## Principle

Authentication establishes an identity; authorization decides what that identity
may do. Treat passwords, sessions, JWTs, OAuth authorization artifacts, provider
tokens, API keys, recovery links, and MFA factors as distinct credentials with
explicit issuer, audience, lifetime, storage, rotation, revocation, and logging
rules. Fail closed, resist enumeration and automation, and re-authenticate before
sensitive changes. Never infer authorization merely because authentication
succeeded.

## Sessions

- Rotate the session identifier on login and privilege change; invalidate it on
  logout and password reset/change where the product's threat model requires it.
- Use `Secure`, `HttpOnly`, and an appropriate `SameSite` value. Cookie-authenticated
  state changes still need CSRF protection; `SameSite` is defense in depth.
- Bound idle and absolute lifetime for sensitive applications. Do not place
  secrets or authorization decisions in client-readable session data.
- Review custom backends and login views for inactive-user handling. Django's
  default `ModelBackend` rejects inactive users; a custom backend can undo that.
- Re-authenticate and require the current factor before changing password, email,
  MFA, recovery methods, payout details, or other security-sensitive state.

## JWT

- Validate signature, allowed algorithm, issuer, audience, expiry, and not-before.
  Never derive the accepted algorithm from an attacker-controlled header.
- Keep access tokens short-lived. Protect refresh tokens with rotation, reuse
  detection or a denylist where the threat model needs revocation.
- Put only stable identifiers and minimal authorization context in claims. A token
  is a snapshot: permission, tenancy, suspension, and key-rotation changes can make
  long-lived claims stale.
- Keep signing keys out of source, assign key IDs deliberately, rotate keys, and
  prevent a verifier from treating symmetric key material as an asymmetric key.
- SimpleJWT `5.5.1` contains the fix for CVE-2024-22513 but advertises support only
  through Django 5.2. Treat it as conditional on a compatible project, not as a
  Django 6 default; re-check compatibility before adoption.

## Token storage

- Browser applications should prefer secure, HttpOnly cookies when the architecture
  can enforce CSRF. Persistent bearer tokens in `localStorage` are exposed to any
  successful XSS.
- Native/public clients cannot safely keep a client secret; use authorization code
  plus PKCE and platform-protected credential storage.
- Store server-side refresh tokens and provider tokens encrypted or in a secrets
  service when they are genuinely required. Do not persist them “for later.”
- Never place passwords, codes, bearer tokens, refresh tokens, ID tokens, or API
  keys in URLs. Redact authorization headers, cookies, callback parameters, and
  credentials from logs, tracing, errors, analytics, and support exports.

## Brute force and enumeration

Use layered limits across account, normalized identifier, network/device signal,
and high-value flow. Keep responses and timing sufficiently uniform so login,
signup, reset, invite, and MFA endpoints do not reveal account existence. Monitor
distributed attempts and alert on lockout/credential-stuffing patterns. A hard
permanent account lock lets an attacker deny service to a victim; use bounded
backoff, recovery, and risk signals.

`django-axes==8.3.1` passes the maintained-package gate for Django 6.0 login
monitoring/lockout. Its correctness depends on trusted-proxy and client-IP
configuration. It does not replace edge limits, business-flow quotas, MFA, or
compromised-password defenses. `django-defender` does not pass the current gate.

## Password reset

- Return the same public response for existing and absent accounts, and apply the
  same anti-automation controls to both paths.
- Use a cryptographically random, single-use, short-lived token bound to the
  intended account and purpose. Invalidate prior tokens after use and relevant
  credential changes.
- Build absolute reset URLs from a trusted configured origin, not an untrusted Host
  header. Do not leak tokens through Referer, third-party resources, analytics, or
  logs.
- Confirm the new password twice, apply password validators, rotate sessions as
  policy requires, and notify the account through an independent channel without
  including the new credential.

## MFA

- Prefer phishing-resistant factors when the application supports them; otherwise
  TOTP is stronger than SMS. Recovery codes are credentials: generate them with a
  CSPRNG, display once, store only hashes, rate-limit checks, and rotate after use.
- Protect factor enrollment, replacement, and removal with re-authentication and
  an already-trusted factor or a carefully reviewed recovery flow.
- Prevent replay, rate-limit attempts, define clock-skew tolerance narrowly, and
  audit factor lifecycle events without logging secrets.
- `django-otp==1.7.0` passes the current gate and supports Django 6.0.
  `django-two-factor-auth==1.18.1` is conditional for compatible Django 5.2
  projects and must be re-vetted before Django 6 adoption.

## OAuth2, OIDC, and social login

### Principle layer

OAuth delegates authorization; OIDC adds an identity layer. An OAuth access token
is not proof of OIDC identity. For every login transaction:

1. use authorization code flow with PKCE (`S256`); do not use implicit flow or the
   resource-owner-password grant;
2. generate unpredictable `state` and bind it to the initiating browser session,
   provider, redirect target, and short expiry; consume it once;
3. for OIDC, generate and validate a one-time `nonce`;
4. pre-register redirect URIs and require exact matching—no wildcards, suffix
   checks, user-controlled callback, open redirect, or untrusted Host-derived URI;
5. exchange the code only with the intended token endpoint over verified TLS;
6. validate the ID-token signature with an allowed algorithm and trusted key, then
   exact issuer, audience/client ID, expiry/not-before, and nonce;
7. identify the external account by the stable `(issuer, sub)` pair. Do not key an
   account by email, username, `preferred_username`, or other mutable claim; and
8. link accounts only after an explicit authenticated ceremony or a provider-
   specific, proven verified-email policy that handles collisions safely.

Keep provider client secrets, signing keys, authorization codes, and tokens out of
source and logs. Request minimal scopes. Store refresh/access tokens only when the
application needs ongoing provider API access; encrypt them, restrict access,
rotate/revoke them, and delete them on disconnect. Re-authenticate before linking
or unlinking a provider. ASVS 5.0 anchors include V10.1.2, V10.4.1, V10.4.6,
V10.5.1–V10.5.4, V9.2.2, V13.3.1, and V14.2.1.

### Django and DRF implementation layer

Trace the full flow: login-start view, session/state store, provider configuration,
callback, code exchange, token verification, adapter/pipeline, local-account lookup
and linking, token persistence, logout/disconnect, and logs. Test swapped-provider,
state replay, nonce replay, redirect confusion, wrong issuer, wrong audience,
expired token, unverified email, duplicate email, and account-linking takeover.

**django-allauth.** `django-allauth==65.18.0` passes the gate; require
`>=65.16.1` on its current line. Preserve these fail-closed defaults and enable
PKCE in each OAuth/OIDC provider configuration that supports it:

```python
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = False
SOCIALACCOUNT_LOGIN_ON_GET = False
SOCIALACCOUNT_STORE_TOKENS = False
```

Do not enable automatic email authentication/connection as a generic convenience.
Use a reviewed adapter for provider-specific verified-email semantics and explicit
linking. Protect provider secrets stored in `SocialApp` as production secrets.
Use the provider's stable subject, not display or email claims, as identity.

**dj-rest-auth.** `dj-rest-auth==7.2.0` is acceptable as a DRF-facing wrapper only
when the underlying allauth adapter and provider settings satisfy this section.
Prefer the authorization-code path with a fixed configured callback URL. Audit any
endpoint accepting `access_token`, `code`, or `id_token`: each artifact must be
used only for its defined protocol purpose, and an access token alone must not be
accepted as identity proof. Apply CSRF/CORS/session controls to the chosen browser
architecture rather than assuming a REST wrapper removes them.

**django-oauth-toolkit.** `django-oauth-toolkit==3.3.0` passes the gate when the
application is an OAuth authorization/resource server. PKCE is required by
default; keep it required, use authorization code rather than implicit/password
grants, register exact redirect URIs, hash client secrets, issue narrow scopes and
short lifetimes, and enable OIDC only when its signing/claim/key lifecycle has been
reviewed. Older installations must include `oauthlib>=3.2.2` because that release
fixed CVE-2022-36087.

**social-auth-app-django.** `social-auth-app-django==6.0.0` passes the gate; require
`>=5.6.0`. Review the pipeline order, state validation, redirect allowlist, backend
selection, and the stable provider UID. Do not add `associate_by_email` unless the
specific provider guarantees verified email and the product has an explicit
collision/linking policy; the default pipeline's omission is a security boundary.

**mozilla-django-oidc.** Treat `5.0.2` as existing-install audit only, not a new
recommendation: it does not advertise Django 6 support, `OIDC_USE_PKCE` defaults
false, and open issue #340 documents missing exact issuer/audience validation in
the default verification path. Existing use must set `OIDC_USE_PKCE = True`, keep
`OIDC_USE_NONCE`, `OIDC_VERIFY_JWT`, `OIDC_VERIFY_KID`, and TLS verification
enabled, use `S256`, keep unsecured JWTs and token storage disabled, and provide a
reviewed `verify_token` override or replacement that enforces exact issuer and
audience/client ID as well as signature, algorithm, expiry, and nonce. Otherwise,
replace the integration.

SAML, mTLS, and passkeys are outside this skill; when encountered, audit their
maintained library configuration rather than reimplementing protocol internals.

## API keys

### Principle layer

API keys identify an application, project, integration, or automation principal;
they are not end-user sessions and should not silently inherit a human's full
permissions. For every key:

- generate at least 128 bits of CSPRNG entropy; show the secret once;
- store only a cryptographic digest, with a non-secret prefix/key ID for indexed
  lookup; compare digests in constant time;
- bind it to an explicit owner, tenant, environment, scopes, resource constraints,
  creation actor, expiry, last-used metadata, and status;
- support overlapping rotation, immediate revocation, and audit events for create,
  reveal, use, rotate, expire, and revoke without logging the secret;
- transmit only over TLS in a header, never a query string, URL, filename, client-
  side bundle, analytics field, or repository; and
- combine authentication with object/function authorization, quotas, anomaly
  detection, and network restrictions where useful. A known key is not blanket
  authorization.

Use a recognizable prefix plus a secret component so leaked-key scanners and
operators can classify it without exposing the credential. Rate-limit failed
prefix/secret checks without allowing easy denial of service against a known
prefix. Return a generic authentication failure and avoid exposing whether a
prefix exists.

### Django and DRF implementation layer

Implement authentication separately from permission classes and tenant-scoped
querysets. Never use a raw API key as a database lookup value. A small local model
may store `prefix`, `digest`, owner/service account, tenant, scopes, created/expiry/
revoked/last-used fields, and rotation lineage; centralize parsing and verification
in one authentication class and cache only revocation-safe metadata.

`djangorestframework-api-key==3.1.0` is existing-install audit only: it does not
pass the current Django 6/maintenance gate and it explicitly is not end-user
authentication. When found, confirm one-time display, hashed high-entropy keys,
prefix lookup, `expiry_date`, revocation, custom scoped `AbstractAPIKey` model, and
use through `BaseHasAPIKey`; then add real object/function authorization. Prefer a
custom header or `Authorization: Api-Key ...`; reject query-string transport.

For third-party delegated access or complex scopes/consent, prefer a maintained
OAuth client-credentials or authorization-code design over growing a bespoke key
protocol. Keep webhook-signing secrets and request signatures distinct from API
authentication keys, and verify timestamp/replay controls where signed webhooks
are in scope.

## Review checklist

- [ ] authentication and authorization are separate; all backends reject inactive,
      suspended, wrong-tenant, and otherwise ineligible principals;
- [ ] session cookies, CSRF, rotation, idle/absolute lifetime, logout, and sensitive
      re-authentication match the deployment architecture;
- [ ] JWTs have fixed algorithms, issuer/audience/time validation, short lifetime,
      key rotation, and a revocation/staleness strategy; package compatibility is proven;
- [ ] credentials and tokens are absent from URLs, source, logs, traces, analytics,
      errors, and client-readable persistent storage unless explicitly justified;
- [ ] login, reset, signup, invite, MFA, and linking resist enumeration, replay,
      brute force, distributed automation, and attacker-induced permanent lockout;
- [ ] OAuth/OIDC uses code plus PKCE, exact redirects, bound one-time state/nonce,
      full ID-token validation, stable `(issuer, sub)` identity, and safe linking;
- [ ] allauth/dj-rest-auth/OAuth Toolkit/social-auth settings and adapters/pipelines
      preserve the controls above; mozilla-django-oidc is rejected or explicitly hardened;
- [ ] provider tokens are minimally scoped, stored only when needed, protected,
      rotated/revoked, and deleted on disconnect;
- [ ] API keys are high-entropy, one-time-revealed, digest-only, scoped, expiring,
      rotatable, revocable, header-only, safely logged, and followed by authorization;
- [ ] MFA enrollment/removal/recovery is protected, recovery codes are hashed and
      single-use, and all factor lifecycle events are audited without secrets.
