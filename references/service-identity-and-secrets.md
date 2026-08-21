# Service Identity and Secrets

This file covers how a backend proves which *machine* is calling it. It also
covers how the project stores, delivers, rotates, and revokes the credential
material behind that proof.

It covers the choice between a static key, an OAuth client-credentials token,
mutual TLS, and platform workload identity. It covers claim-by-claim
validation of an inbound machine token, JWKS handling and key rotation, and
sender-constrained tokens. It covers a client-certificate identity consumed
from a reverse proxy, and an endpoint authenticated by network position alone.
It covers a downstream credential obtained without a forward of the inbound
one. It covers where secrets live and how they reach the process, the rotation
of Django's `SECRET_KEY`, and the ordered response to a leak.

Maps primarily to CWE-287, CWE-290, CWE-306, CWE-345, CWE-347, CWE-441,
CWE-522, CWE-613, CWE-798, and CWE-918. Relevant OWASP categories include
A02:2025, A04:2025, and A07:2025, and API2:2023 and API8:2023.

Human-facing authentication stays in `a07-authentication-failures.md`. That
covers passwords, sessions, interactive OAuth and OIDC login, MFA, and account
recovery. This file is about principals that are processes.

## Contents
- [Principle](#principle)
- [Choosing a machine-authentication mechanism](#choosing-a-machine-authentication-mechanism)
- [Validating an inbound machine token](#validating-an-inbound-machine-token)
- [JWKS as a rotation-aware trust anchor](#jwks-as-a-rotation-aware-trust-anchor)
- [Sender-constrained tokens](#sender-constrained-tokens)
- [Client-certificate identity behind a proxy](#client-certificate-identity-behind-a-proxy)
- ["Internal" is not an authentication mechanism](#internal-is-not-an-authentication-mechanism)
- [Downstream calls: exchange, do not forward](#downstream-calls-exchange-do-not-forward)
- [Where secrets live and how they reach the process](#where-secrets-live-and-how-they-reach-the-process)
- [Rotating Django's SECRET_KEY](#rotating-djangos-secret_key)
- [Stopping the commit](#stopping-the-commit)
- [Responding to a leaked secret](#responding-to-a-leaked-secret)
- [Out of backend scope](#out-of-backend-scope)
- [Review checklist](#review-checklist)

## Principle

Human authentication asks "which person is this, and are they still who they
claim?" Machine authentication asks a different question. "Which workload is
this, what was it allowed to do, and who is accountable when it does the wrong
thing?" The mechanisms differ because the failure modes differ. A password
leaks, and one account is at risk. A service credential leaks, and every call
that credential can make is at risk. The logs usually hold nothing that
separates the abuse from ordinary traffic.

Three properties order every decision in this file:

1. **Blast radius.** This is what the credential unlocks, and how many
   processes, images, pipelines, and laptops hold a copy of it.
2. **Lifetime.** This is how long a stolen copy stays useful. It is the
   difference between an incident and an outage.
3. **Attributability.** This is whether the logs can say *which* caller did
   it. One shared token across ten services has none.

The invariant is: **prefer an identity the platform can attest over a secret
the workload must hold. Where a secret is unavoidable, prefer a short-lived
derived token over a long-lived static credential. Prefer a credential bound to
its holder over a bearer credential that anyone who copies it can replay.** The
ranking is by blast radius and attributability, not by cryptographic strength.
A correctly generated static API key is cryptographically sound, and it is
still the weakest option on this list.

Severity for findings in this area follows the same weighting. Weight by what
the credential unlocks, and by whether anybody could trace the abuse. Do not
weight by how hard the exploit was. A low-effort exploit against a narrow,
single-purpose internal key can rank below a hard-to-reach credential that
grants account-wide access.

## Choosing a machine-authentication mechanism

**Principle: pick the highest tier the runtime actually supports, and treat
each step down as an accepted risk rather than a default.** The four tiers
below are ordered by blast radius, and not by implementation effort.

1. **Platform workload identity**, where the workload runs somewhere that can
   attest what it is. That place is a cloud VM or container, a Kubernetes pod,
   or a CI runner. SPIFFE and SPIRE, cloud IAM roles attached to a compute
   identity, and CI OIDC federation all issue a short-lived credential bound
   to the attested workload. Thus no long-lived secret exists to leak, and a
   stolen credential is useless off the attested node. SPIRE's default X.509
   SVID lifetime is one hour, which is the order of magnitude to expect. This
   is the top choice wherever it is available.
2. **OAuth 2.0 client-credentials grant** (RFC 6749), where the caller talks
   to a third party, or to a service that already speaks OAuth. The service
   exchanges a client ID and secret for a short-lived access token. A
   private-key `client_assertion` is better than the secret. The service then
   presents the token rather than the credential on each call. That bounds a
   leak to the token lifetime, and it gives per-scope least privilege. RFC
   6749 says refresh tokens should not be issued for this grant, so
   re-authenticate instead. Token lifetimes here are convention rather than
   specification: minutes to an hour is the norm, and the specification fixes
   nothing.
3. **Mutual TLS**, for east-west traffic inside a network whose PKI you own.
   It authenticates both ends. With certificate-bound tokens (RFC 8705), it
   also makes those tokens non-replayable. The cost is certificate issuance,
   distribution, and rotation, which is why it belongs to a mesh or an
   automated issuer rather than to hand-rolled configuration.
4. **A static API key**, as the fallback of last resort. It is acceptable only
   for low-stakes internal traffic where the operational cost of the tiers
   above genuinely is not justified. A static key stays valid until somebody
   rotates it, and most teams never do. It travels on every request, and it is
   hard to attribute after the fact. Where one is unavoidable, apply the full
   key discipline in `a07-authentication-failures.md`, "API keys". That
   discipline is high entropy, digest-only storage, and a non-secret key ID
   logged on every use. It also needs narrow scope, and rotation that does not
   require downtime.

Review notes:

- The finding is rarely "they used the wrong mechanism." It is usually that a
  tier-4 credential does a tier-1 job. That key is static and shared by several
  callers, is never rotated, and grants more than any single caller needs.
- Check a mechanism choice again once a service that had one caller has six.
  Reuse of a single credential across callers destroys attribution silently,
  and no code changes.
- Severity: Medium on its own for an unrotated narrow-scope key. Severity:
  High where the same credential is shared across callers, or grants
  tenant-wide access.

## Validating an inbound machine token

### Principle layer

A signed token is trustworthy only for the issuer, audience, time window, and
purpose it was minted for. Signature validity is necessary, and nowhere near
sufficient. Verify in this order, because each check gates the next. Fail
closed on any missing claim, fetch failure, or exception:

1. **Parse the header, but never trust `alg`.** Select the verification
   algorithm from your own configuration. *Omitted:* algorithm confusion,
   where an attacker makes an RS256 verifier HMAC-verify with the public key
   it published. `alg: none` forgery is the other case. Full token forgery
   (CWE-347).
2. **Resolve the key by `kid` from a trusted JWKS**, never from a `jku` or
   `x5u` the token supplies. *Omitted:* the attacker points you at their own
   key set, or drives a `kid` value into a file path or a SQL query (CWE-347,
   CWE-89).
3. **Verify the signature** with the resolved key and the pinned algorithm.
   *Omitted:* any forged token is accepted.
4. **Validate `exp`, and `nbf` and `iat` where present**, with minimal clock
   skew. *Omitted:* an expired or stolen token stays valid indefinitely
   (CWE-613).
5. **Validate `iss`** by exact match against the expected issuer. *Omitted:*
   any issuer your library happens to trust is accepted (CWE-345).
6. **Validate `aud`** against this service's own identifier. RFC 9068 makes
   this mandatory for JWT access tokens. *Omitted:* a token minted for a
   different API behind the same identity provider replays against you, which
   is a confused deputy (CWE-441, CWE-863).
7. **Validate scope and token type**, which are `scope` and a type marker such
   as `typ: at+jwt`. *Omitted:* an ID token, or a token minted for another
   purpose, passes where an access token was required. An over-scoped token
   also passes for a narrow operation.
8. **Verify the binding where the token is sender-constrained.** Check
   `cnf.jkt` against the DPoP proof key, and `cnf.x5t#S256` against the
   presented client certificate. *Omitted:* you accept a bearer replay of a
   token that was specifically issued not to be one.

### Django & DRF implementation layer

Machine-token verification belongs in a DRF authentication class. It does not
belong in a permission class, and it does not belong inline in a view. One
reviewed code path then covers every endpoint. Return a service principal.
Then let permission classes and scoped querysets decide authority separately.
A valid token is authentication, and never authorization.

```python
# Wrong: the algorithm comes from the token, no issuer or audience is checked,
# and a new JWKS client is built per call.
import jwt

def authenticate(token):
    header = jwt.get_unverified_header(token)
    return jwt.decode(token, key, algorithms=[header["alg"]])
```

```python
# Correct: algorithm pinned in configuration, issuer and audience checked,
# required claims enforced so a token missing one is rejected rather than
# quietly accepted. The client is module-level; see the JWKS section below.
import jwt

_jwks = jwt.PyJWKClient(settings.JWKS_URI)

def authenticate(token):
    signing_key = _jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=settings.EXPECTED_ISSUER,
        audience=settings.EXPECTED_AUDIENCE,
        options={"require": ["exp", "iss", "aud"]},
    )
```

Review notes:

- `options={"require": [...]}` is what makes the check fail closed. Without
  it, a token that simply omits `aud` can pass an audience check the project
  configured but never exercised.
- Test with a token minted for a sibling service behind the same issuer. That
  is the case an audience check exists for. It is also the case a test suite
  built only from valid and expired tokens never covers.
- Require `PyJWT>=2.13.0` for any service in the resource-server role; see
  `security-hardening-libraries.md`, "Service identity and secrets".
- On a gRPC surface these are the same two checks in a different form. The
  token arrives in call metadata rather than in a header. Mutual TLS is
  configured on the server credentials, rather than terminated at a proxy.
  Everything above applies unchanged.
  `graphql-and-alternative-api-surfaces.md`, "gRPC: nothing from the DRF
  request cycle applies", holds the interceptor that has to run them, and the
  rest of that surface.
- SimpleJWT is the wrong tool here. It issues and verifies tokens the Django
  application itself minted from a human login, which is `a07`'s territory. It
  is not a mechanism that accepts an external machine identity.
- Severity: Critical for an unpinned algorithm or an unverified signature.
  Severity: High for a missing `aud` or `iss` check, and higher still where
  several APIs share one identity provider.

**Write-time.** When you generate a verifier for an inbound machine token,
write it as a DRF authentication class. Pass the algorithm from configuration,
`issuer=`, `audience=`, and `options={"require": [...]}` in the same call. A
verifier assembled without the require list accepts a token that simply omits
the claim it was configured to check.

Resolve the key by `kid` from a module-level JWKS client pointed at a
configured URI. Never resolve it from a `jku` or `x5u` the token itself
supplies. Return a service principal, and let permission classes and a scoped
queryset decide authority over it, because a valid token is authentication and
never authorization.

## JWKS as a rotation-aware trust anchor

**Principle: treat the key set as a cached trust anchor that expects
rotation.** Discover the JWKS URI from the issuer's own metadata. Cache the
set process-wide with a bounded lifetime. Refresh once on an unknown `kid`,
and retry. Pin the algorithm from configuration, and resolve strictly by
`kid`. Fail closed on a fetch error, and do not discard keys that are still
valid.

Two failures recur:

- **A fetch on every request** turns the issuer's JWKS endpoint into a
  dependency of every authenticated call. It also turns your application into
  a traffic amplifier against it.
- **A refresh only on cache expiry** fails when the issuer rotates its signing
  key. Every token signed by the new key then fails until the cache expires.
  The fix is the unknown-`kid` refresh, and not a shorter cache lifetime.

In Django, `jwt.PyJWKClient` implements this correctly, with defaults a
developer defeats by accident easily. Verified against PyJWT 2.13.0, the
constructor is `PyJWKClient(uri, cache_keys=False, max_cached_keys=16,
cache_jwk_set=True, lifespan=300, ...)`. Thus the key-set cache is on by
default, and it expires after five minutes. `get_signing_key` refreshes the
set once and retries where a `kid` does not match.

```python
# Wrong: a client per request. The cache lives on the instance, so this
# fetches the JWKS on every authenticated call.
def authenticate(token):
    client = jwt.PyJWKClient(settings.JWKS_URI)
    return client.get_signing_key_from_jwt(token)
```

```python
# Correct: one client for the process lifetime, so the cache is actually used.
_jwks = jwt.PyJWKClient(settings.JWKS_URI)

def authenticate(token):
    return _jwks.get_signing_key_from_jwt(token)
```

Review notes:

- The per-request client is the common defect, and it is invisible in review
  unless you look for where the code constructs the client. The minimal
  examples in circulation all build it inline.
- The unknown-`kid` refresh deliberately bypasses the cache, so a stream of
  bogus `kid` values is one outbound fetch per request. Throttle
  unauthenticated token-bearing endpoints. See `a06-insecure-design.md`.
- `cache_keys=True` adds a second, per-key LRU cache with **no** time-based
  expiry. An entry leaves only when the cache fills. A key the issuer withdrew
  stays usable for verification until the cache evicts it. Leave it off unless
  somebody has reasoned the tradeoff through.
- Below PyJWT 2.13.0 three of these paths are exploitable rather than merely
  awkward. One of them is a JWKS cache that was wiped whenever a fetch raised,
  which turned a transient issuer outage into an application-wide
  authentication failure. Treat the version as a finding in its own right.
- Severity: Medium for the per-request client, on availability and latency.
  Severity: High where a stale or wiped key set fails open rather than closed.

## Sender-constrained tokens

**Principle: constrain a token where it passes through hands you do not trust.
Do this where a replay would be worth more than the cost of a proof of
possession on every request.** DPoP (RFC 9449) binds a token to a key the
client proves it holds, through a per-request signed proof and a `cnf.jkt`
claim. Mutual-TLS-bound tokens (RFC 8705) bind it to the client certificate,
through `cnf.x5t#S256`. In both cases, a stolen token alone is inert.

It is justified where the token crosses an intermediary you do not fully
control, such as a gateway, a backend-for-frontend, or a public mobile client.
It is also justified where the flow is high-value or regulated. A third case
is where token theft through logs, SSRF, or XSS is a live part of the threat
model. DPoP suits a public client, and anywhere TLS client certificates are
impractical. An mTLS binding suits a confidential server-to-server client that
already has PKI.

It is not repaid where traffic is already inside a mutually authenticated
mesh. The transport has sender-constrained it there, and a signed proof per
request gives nothing. It is also not repaid where tokens are short-lived and
low-value enough. The key management and the clock-skew handling then cost
more than the replay window is worth.

Review notes:

- The finding is not "DPoP is missing." It is "this token crosses an untrusted
  intermediary as a plain bearer credential, and nothing detects a replay."
- Where a token carries a `cnf` claim, the resource server must verify the
  binding. A constrained token accepted as a bearer token is worse than one
  nobody constrained. The issuer's threat model now assumes a protection that
  nothing enforces.
- Severity: Medium to High by context, driven by where the token travels.

## Client-certificate identity behind a proxy

**Principle: a proxy-set identity header is a claim, not proof.** It becomes
proof only under two conditions, and both must hold. The proxy overwrites or
strips any inbound copy of the header. The application is reachable *only*
through that proxy. Where either condition fails, any client sets the header
and becomes whichever service it names.

The Django application almost never terminates mutual TLS itself. A proxy does
so, such as nginx, Envoy, an ALB, or a mesh ingress. That proxy then forwards
the verified identity in a header. Envoy and Istio use
`X-Forwarded-Client-Cert`, which Envoy sanitizes by default. RFC 9440
standardizes `Client-Cert`, and requires a strip of an inbound copy. Envoy's
own documentation is explicit that a forwarded value is a hint the caller
sets, and that an internal entity spoofs it easily.

This is the same trust model as `X-Forwarded-For` and `X-Forwarded-Proto` in
`deployment-and-runtime.md`, "Reverse proxy and forwarded headers", and that
section owns the proxy configuration. The consequence differs here. A header
that carries a *verified client certificate* carries an authentication
identity. Thus a spoof of it is an authentication bypass (CWE-290), and not a
client-IP trust problem. Rate the severity accordingly.

```python
# Wrong: the header is read as identity, and nothing establishes that the
# request actually arrived through the proxy that would have verified it.
identity = request.META.get("HTTP_X_FORWARDED_CLIENT_CERT")
```

```python
# Correct: the immediate peer must be the trusted proxy before the header
# means anything, and the header must be present rather than defaulted away.
if request.META.get("REMOTE_ADDR") not in settings.TRUSTED_PROXY_ADDRESSES:
    raise PermissionDenied("Direct access is not permitted")

identity = parse_service_identity(request.META["HTTP_X_FORWARDED_CLIENT_CERT"])
```

Review notes:

- The peer check is necessary and not sufficient. Ask separately whether a
  caller can reach the application port without the proxy. A container port
  published to the node, a service exposed cluster-wide, and a debug listener
  each defeat it.
- Write the trusted-hop assumption down in the settings module, beside the
  header name. A topology assumption that exists only in somebody's memory is
  the one that breaks during a migration.
- `.get()` with a default on an identity header is a fail-open pattern. Index
  the key, and let a missing header raise.
- Severity: High, and Critical where the spoofed identity is a privileged
  service principal.

Require the same termination in front of a webhook receiver, which is
otherwise an unauthenticated public route by construction. A client
certificate demanded at the proxy narrows who can open the connection at all.
It narrows the set from the whole internet to the holders of a certificate you
issued. Thus a forged-signature attempt has to pass the transport before it
reaches the comparison.

It is defense in depth, and not a replacement. The certificate authenticates a
connection, and the HMAC authenticates a message. The first trusts an
intermediary that terminates TLS, and the second does not. Most third-party
providers cannot present a certificate at all. Require it where the sender is
first-party, or where the provider supports it. Keep every step of the
receiver in `a08-integrity-and-deserialization.md` unchanged in either case.

## "Internal" is not an authentication mechanism

**Principle: remove the network assumption, and ask what is left.** For each
internal endpoint, ask what stops an attacker who is *already* inside the
segment. That attacker is a compromised pod, an SSRF pivot, or a supply-chain
foothold. Where the only answer is that they are not supposed to reach it, the
boundary is assumed rather than authenticated (CWE-306). That is the finding.

The recurring shapes:

- an endpoint with no authentication class, or with `AllowAny`, justified in a
  comment as internal only;
- trust derived from source IP, subnet membership, or `X-Forwarded-For`;
- one shared static token used by every internal caller, so there is no
  per-caller attribution and no way to rotate for one of them;
- a header the caller sets, such as `X-Internal: true` or `X-User-Id: 42`,
  treated as established fact rather than as input.

```python
# Wrong: reachability is the only control.
class InternalMetricsView(APIView):
    permission_classes = [AllowAny]  # internal network only
```

```python
# Correct: a per-caller service identity, authenticated and then authorized.
class InternalMetricsView(APIView):
    authentication_classes = [ServiceTokenAuthentication]
    permission_classes = [IsAuthenticatedService]
```

Review notes:

- Network controls stay valuable. They are defense in depth, and a firewall in
  front of an admin surface is still correct. The finding is that the network
  control is the *only* control.
- Check management commands, health and metrics endpoints, and internal
  webhooks specifically. Somebody wrote them before the service had a second
  caller, and nobody has examined them since.
- Severity: High, and Critical where the endpoint mutates state or spans
  tenants.

## Downstream calls: exchange, do not forward

**Principle: a service should exchange an inbound token for a narrowly
audience-bound downstream token, rather than replay the inbound one.** A
forward makes the downstream a confused deputy (CWE-441). It sees a valid
token, cannot tell that the caller is an intermediary, and applies the token's
full authority to a request the intermediary shaped.

`agent-and-llm-interfaces.md`, "Inbound token validation and the passthrough
prohibition" owns the prohibition itself and the agent-specific case.
`a07-authentication-failures.md`, "JWT" owns the general rule. This section
owns what the exchange must actually do, under RFC 8693:

- the grant type is `urn:ietf:params:oauth:grant-type:token-exchange`;
- `subject_token` carries the identity the new token is requested for, and an
  optional `actor_token` carries the acting party. Delegation keeps the actor
  visible in the issued token, and impersonation does not. That distinction is
  the audit trail. See `privileged-access-and-impersonation.md`;
- `resource` (RFC 8707), `audience`, `scope`, and `requested_token_type`
  narrow the result to one downstream. That narrow result is the entire point;
- the token service verifies the incoming token's signature and expiry
  *before* the exchange. It checks that a `may_act` claim authorizes any
  actor, and it downscopes only. An exchange that can widen authority is an
  escalation primitive.

Review notes:

- Where no token service exists, a stored per-downstream service credential or
  a platform-managed identity is an acceptable substitute. A forward is not.
- A service that calls three downstreams needs three narrow credentials, not
  one credential that reaches all three.
- Severity: High.

## Where secrets live and how they reach the process

### Principle layer

Match the delivery mechanism to the strongest identity the runtime can attest.
Minimize how many places and processes can observe the value. Prefer fewer
copies, shorter lifetimes, and narrower readership. Across every runtime the
direction of travel is the same: from a stored static secret toward a
runtime-fetched, workload-identity-gated, short-lived credential. Two things
change between runtimes: who vouches for the workload, and how wide the
exposure surface is.

- **Virtual machine.** Use a file with tight ownership and permissions, read
  at startup. Fetch it from a secret manager under the instance's own attested
  identity where you can. Do not bake a secret into the image, and do not
  commit an environment file.
- **Container.** Use a mounted file or a tmpfs secret rather than an
  environment variable. A runtime fetch from a secret manager, gated by
  workload identity, is better still. No static secret then appears in the
  deployment manifest at all.
- **Managed platform.** Use the platform's own secret store, scoped per
  environment, with its managed identity where one exists.

**The honest position on environment variables.** They are convenient and
conventional. Anything that can inspect the process also reads them from the
process environment. Every child process inherits them, third-party
subprocesses included. Container and orchestrator introspection commands
expose them. Crash dumps, error trackers, and debug output capture them
wholesale.

They are acceptable for a low-risk, non-reused value. For a production service
credential, a mounted file or a secret-manager fetch is the safer default. The
defensible line is not that environment variables are forbidden. It is that
they are the floor, and not the target.

### Django & DRF implementation layer

`deployment-and-runtime.md`, "Database and secrets" owns how the platform
injects the environment, and the rule against a generic environment-parsing
helper. This section owns what the settings module does with the value.

- Read a required secret with `os.environ[...]`, and not with
  `os.environ.get(...)`. A missing production secret then fails at startup,
  rather than silently becomes `None` and disables a check further down.
- Validate the required settings and their types at startup, and fail closed.
  Do not print the value in the error.
- Keep secrets out of `settings.py` literals, out of committed environment
  files, out of fixtures, and out of the container image. A committed secret
  is a finding on its own weight (CWE-798), rated by what it unlocks.
- Never log a settings object, a request header, or a task argument wholesale.
  See `a09-logging-and-alerting.md` for scrubbing. See
  `a08-integrity-and-deserialization.md` for the rule that keeps
  webhook-signing secrets distinct from API authentication keys.
- Add a pre-commit secret scanner, so that the scanner catches the next one
  before anybody pushes it. Detection is cheap, and the response in the next
  section is not.

```python
# Wrong: a literal in source, and a long-lived static credential in the
# environment standing in for a service identity.
SECRET_KEY = "django-insecure-hardcoded-value"
PARTNER_API_TOKEN = os.environ.get("PARTNER_TOKEN", "")
```

```python
# Correct: required at startup, sourced from the injected secret, and with
# rotation support wired in from the beginning rather than added under
# pressure. Service-to-service calls fetch a short-lived token instead of
# holding a static one.
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
SECRET_KEY_FALLBACKS = [
    key for key in [os.environ.get("DJANGO_SECRET_KEY_PREVIOUS")] if key
]
```

Review notes:

- The database connection string is a secret, and it is frequently the one
  left in a compose file or a CI variable. `data-layer-and-database.md` covers
  the connection itself.
- Break-glass credentials have their own custody rules. See
  `privileged-access-and-impersonation.md`.
- CI is a credential store. Prefer OIDC federation from the CI provider to the
  cloud account, over a long-lived deployment key held as a repository secret.
  See `a03-software-supply-chain.md`, "Trust and provenance".
- Severity: High to Critical for a committed secret, by blast radius.
  Severity: Medium for a high-value credential delivered by environment
  variable, where the platform offered better.

## Rotating Django's SECRET_KEY

### Principle layer

Any rotation of a signing key has the same shape. The new key must be able to
sign. The old key must still be able to verify, for at least as long as the
longest-lived artifact signed under it. A rotation with no overlap window is
not a rotation. It is an invalidation, which is sometimes exactly what you
want, and never something to do by accident.

The overlap must also reach every instance *before* any instance starts to
sign with the new key. Otherwise the instances reject each other's freshly
signed data for the length of the deploy.

### Django & DRF implementation layer

Django consults `SECRET_KEY_FALLBACKS` **only to validate** previously signed
data. It always signs new data with the current `SECRET_KEY`. The table below
gives which subsystems that covers, verified against Django 6.0 and 5.2
source:

| Subsystem | Derived from `SECRET_KEY` | Honors `SECRET_KEY_FALLBACKS` |
|---|---|---|
| `django.core.signing` — `Signer`, `TimestampSigner`, `dumps`/`loads` | Yes | Yes; `fallback_keys` defaults to the setting |
| Session authentication hash | Yes | Yes, and a fallback match **upgrades** the session in place — the key is cycled and the hash re-stamped with the current key |
| `PasswordResetTokenGenerator` | Yes | Yes, via `secret_fallbacks` |
| Messages framework cookie storage | Yes, via `get_cookie_signer` | Yes |
| Signed cookies — `get_signed_cookie` / `set_signed_cookie` | Yes, via `get_cookie_signer` | Yes |
| `signed_cookies` session backend | Yes, via signing | Yes |
| `salted_hmac()` | Yes, by default | Only if the caller passes a fallback secret |
| **CSRF** | **No** — the CSRF secret is a random value in the cookie or session | Not applicable |
| Password hashes | **No** — per-password random salt | Not applicable |

**A rotation of `SECRET_KEY` does not invalidate CSRF tokens.** Django
generates the CSRF secret randomly, and stores it in the cookie or the
session. It does not derive it from `SECRET_KEY`. A number of widely
circulated rotation guides list CSRF among the casualties, and it is not one.

The real casualties of a rotation with no fallback are all sessions and
logins, every in-flight password-reset link, and messages-framework cookies.
They also include every `signing.dumps` value, every signed cookie, and every
signed URL, and anything third-party built on `django.core.signing`.

The safe procedure:

1. **Add.** Generate a key with
   `django.core.management.utils.get_random_secret_key()`, which is the same
   helper `startproject` uses. Set it as `SECRET_KEY`, and put the *previous*
   key into `SECRET_KEY_FALLBACKS`. Deploy, and confirm that every instance
   has reloaded. New data signs with the new key, old data still validates,
   and sessions upgrade transparently as users make their next request.
2. **Wait.** Wait at least as long as the longest-lived signed artifact you
   care about. That is usually `SESSION_COOKIE_AGE` or
   `PASSWORD_RESET_TIMEOUT`, whichever is longer.
3. **Remove.** Drop the old key from `SECRET_KEY_FALLBACKS`. Anything still
   signed with it now becomes invalid, which is the intended end state.

**On a rolling fleet, split step 1 in two.** Those three steps assume an
atomic deploy. Where instances update gradually, an updated instance signs
with the new key, and a not-yet-updated instance validates with the old key
only. Signatures therefore fail until the fleet converges.

First ship the new key in `SECRET_KEY_FALLBACKS` on every instance, with the
old key still signing. Then promote the new key to `SECRET_KEY`, and move the
old key into the fallbacks. That order keeps every instance able to validate
both keys at every moment.

Review notes:

- On a *compromise* rotation, deliberately skip the fallback. A hard cut
  invalidates everything the attacker could forge, and the mass logout is the
  price of that. A knowing choice of it is correct. An arrival at it by
  accident is the failure this section exists to prevent.
- On Django 4.1 and earlier, fallbacks did not cover the session
  authentication hash, so even a fallback rotation logged everyone out. Django
  4.2 fixed that. Where a codebase on an old line has a rotation runbook
  written around the old behavior, the runbook is now wrong in the safe
  direction. The codebase is also on an end-of-life Django, which is the
  larger finding (`a03-software-supply-chain.md`).
- Nobody has tested a rotation path that exists only as a wiki page. Ask
  whether the fallback slot is already wired into settings and deployment, as
  in the example above. Otherwise the addition of it is itself a code change
  under incident pressure.

## Stopping the commit

The cheapest response to a leak is the commit that never reaches the
repository. Three layers stop it:

- A pre-commit secret scan on the developer machine catches the accident at
  write time.
- Push protection at the host blocks a push that contains a recognized
  credential. Enable it on a private repository too, and not only on a public
  one.
- A scheduled history scan checks yesterday's commits again under the same
  rules, because a rule added today proves nothing about last year.

A hit in history is a leak, and not a lint. Rotate the secret under
"Responding to a leaked secret" below, even where nobody pushed the commit to
a public remote. A deleted commit does not make the value secret again.

## Responding to a leaked secret

**Principle: rotation is what makes the exposed secret worthless, and
everything else is containment and hygiene.** Order the response by what stops
active abuse fastest. Assume from the first minute that somebody has already
harvested the secret.

1. **Rotate.** Mint a replacement, and move traffic to it. This step is first
   because it is fast, and because it is the step that actually stops the
   abuse. A clean of the history first, while the live credential still works,
   is the common and costly inversion.
2. **Revoke** the old credential at the provider. Rotation and revocation are
   not the same operation. With many providers the old key stays valid until
   somebody explicitly deletes it.
3. **Assess the blast radius.** Establish what the credential granted, what it
   could reach, and whether the project reused the same value anywhere else.
   One leaked secret copied into five services is five incidents.
4. **Review the logs** for use of the credential between exposure and
   revocation. This is where an earlier decision to log a key ID on every use
   pays for itself. Without that decision there is nothing to review.
5. **Scrub the history, and prevent a recurrence.** Rewrite with a
   purpose-built tool such as `git filter-repo` or BFG, and add a pre-commit
   scanner. Treat this as cleanup, and not as the fix. Forks, clones, caches,
   and crawlers may retain the value. A pushed secret is compromised, whatever
   the history looks like afterwards.

For `SECRET_KEY` specifically, "rotate" here means the hard-cut path above,
with no fallback, where you have to assume forged values are already in
flight.

## Out of backend scope

This list mirrors `00-methodology-and-severity.md`, "What to exclude". Do not
search backend code for these items, and do not report their absence as a
backend finding:

- the authorship of SPIRE deployment topology or attestation policy, and the
  operation of a mesh certificate authority. An audit of how the backend
  *consumes* an attested identity is in scope. The operation of the issuer is
  not;
- secret-manager and secret-scanner product comparison;
- hardware-security-module and key-custody procurement, as distinct from how
  the application reaches the key material;
- human-facing mutual TLS, SAML, and passkeys, which stay in
  `a07-authentication-failures.md` at the library-configuration level.

## Review checklist

### Stack-neutral

- [ ] Each machine caller has its own identity. No single static credential is
      shared across callers, and every use is attributable to one of them.
- [ ] Short-lived platform or client-credentials tokens are used where the
      runtime supports them. Any static key is a documented, scoped, rotatable
      exception rather than a default.
- [ ] Every inbound token is verified with an algorithm pinned in
      configuration, never one taken from the token header.
- [ ] `iss` and `aud` are validated by exact match, and `aud` against this
      service's own identifier. Verification fails closed on a missing claim,
      rather than skips the check.
- [ ] `exp` and `nbf` are enforced with minimal clock skew.
- [ ] The key set is cached process-wide, and refreshed once on an unknown key
      identifier. A fetch failure neither opens the gate nor discards keys
      that are still valid.
- [ ] Where a token carries a sender-constraint claim, the server actually
      verifies the binding. It does not accept the token as a bearer
      credential.
- [ ] Any proxy-set identity header is trusted only where the proxy strips
      inbound copies, and where nobody can reach the application directly.
- [ ] No endpoint relies on network position, source address, or a
      caller-supplied header as its authentication.
- [ ] Downstream calls use a separately issued, audience-scoped credential. No
      inbound token is forwarded onward.
- [ ] Production secrets reach the process by mounted file or secret manager
      rather than by environment variable, where the platform allows it.
      Nothing secret is committed or baked into an image.
- [ ] A rotation path exists for every credential, with an overlap window
      sized to the longest-lived artifact signed under the old value.
- [ ] A pre-commit secret scan, host push protection, and a scheduled history
      scan are all in place. A hit in history starts a rotation.
- [ ] The leak response is ordered rotate, revoke, assess, review logs, and
      scrub. Credential use is logged by identifier, so that step four is
      possible.

### Django & DRF

- [ ] Token verification lives in one authentication class, and returns a
      service principal. Permission classes and scoped querysets follow it.
- [ ] `jwt.decode` pins `algorithms`, passes `issuer` and `audience`, and sets
      `options={"require": [...]}`. SimpleJWT is not used as a
      service-identity mechanism.
- [ ] `PyJWKClient` is held at module or singleton scope, and not constructed
      per request. `cache_keys` is left off, unless somebody has reasoned its
      unbounded key lifetime through.
- [ ] `PyJWT>=2.13.0` where the application validates third-party tokens.
- [ ] A trusted-proxy check guards any client-certificate header. The code
      indexes the header, rather than reads it with `.get()` and a default.
- [ ] `SECRET_KEY` is read from an injected secret with `os.environ[...]`.
      `SECRET_KEY_FALLBACKS` is already wired into settings, so a rotation is
      a configuration change rather than a code change.
- [ ] The rotation runbook reflects current Django. CSRF tokens are
      unaffected, and the session hash both consults fallbacks and upgrades in
      place.
- [ ] Required settings are validated at startup, and they fail closed without
      a print of a secret value.
