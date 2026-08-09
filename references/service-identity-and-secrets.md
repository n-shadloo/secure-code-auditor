# Service Identity and Secrets

How a backend proves which *machine* is calling it, and how the credential
material behind that proof is stored, delivered, rotated, and revoked. Covers
choosing between a static key, an OAuth client-credentials token, mutual TLS,
and platform workload identity; validating an inbound machine token claim by
claim; JWKS handling and key rotation; sender-constrained tokens; consuming a
client-certificate identity from a reverse proxy; endpoints authenticated by
network position alone; obtaining a downstream credential without forwarding
the inbound one; where secrets live and how they reach the process; rotating
Django's `SECRET_KEY`; and the ordered response to a leak. Maps primarily to
CWE-287, CWE-290, CWE-306, CWE-345, CWE-347, CWE-441, CWE-522, CWE-613,
CWE-798, and CWE-918; relevant OWASP categories include A02:2025, A04:2025,
and A07:2025, and API2:2023 and API8:2023.

Human-facing authentication — passwords, sessions, interactive OAuth/OIDC
login, MFA, and account recovery — stays in `a07-authentication-failures.md`.
This file is about principals that are processes.

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
- [Responding to a leaked secret](#responding-to-a-leaked-secret)
- [Out of backend scope](#out-of-backend-scope)
- [Review checklist](#review-checklist)

## Principle

Human authentication asks "which person is this, and are they still who they
claim?" Machine authentication asks a different question: "which workload is
this, what was it allowed to do, and who is accountable when it does the wrong
thing?" The mechanisms differ because the failure modes differ. A password
leaks and one account is at risk. A service credential leaks and every call
that credential can make is at risk, usually with nothing in the logs that
separates the abuse from ordinary traffic.

Three properties order every decision in this file:

1. **Blast radius** — what the credential unlocks, and how many processes,
   images, pipelines, and laptops hold a copy of it.
2. **Lifetime** — how long a stolen copy stays useful. This is the difference
   between an incident and an outage.
3. **Attributability** — whether the logs can say *which* caller did it. One
   shared token across ten services has none.

The invariant is: **prefer an identity the platform can attest over a secret
the workload must hold; where a secret is unavoidable, prefer a short-lived
derived token over a long-lived static credential; and prefer a credential
bound to its holder over a bearer credential that anyone who copies it can
replay.** The ranking is by blast radius and attributability, not by
cryptographic strength — a correctly generated static API key is
cryptographically fine and still the weakest option on this list.

Severity for findings in this area follows the same weighting. Weight by what
the credential unlocks and whether abuse could be traced, not by how hard the
exploit was. A low-effort exploit against a narrow, single-purpose internal key
can rank below a hard-to-reach credential that grants account-wide access.

## Choosing a machine-authentication mechanism

**Principle: pick the highest tier the runtime actually supports, and treat
each step down as an accepted risk rather than a default.** The four tiers
below are ordered by blast radius, not by implementation effort.

1. **Platform workload identity**, where the workload runs somewhere that can
   attest what it is — a cloud VM or container, a Kubernetes pod, a CI runner.
   SPIFFE/SPIRE, cloud IAM roles attached to a compute identity, and CI OIDC
   federation all issue a short-lived credential bound to the attested
   workload, so no long-lived secret exists to leak and a stolen credential is
   useless off the attested node. SPIRE's default X.509 SVID lifetime is one
   hour, which is the order of magnitude to expect. This is the top choice
   whenever it is available.
2. **OAuth 2.0 client-credentials grant** (RFC 6749), where the caller talks to
   a third party or to a service that already speaks OAuth. The service
   exchanges a client ID and secret — or, better, a private-key
   `client_assertion` — for a short-lived access token, and presents the token
   rather than the credential on each call. That bounds a leak to the token
   lifetime and gives per-scope least privilege. RFC 6749 says refresh tokens
   should not be issued for this grant; re-authenticate instead. Token
   lifetimes here are convention rather than specification — minutes to an
   hour is the norm, and the specification fixes nothing.
3. **Mutual TLS**, for east-west traffic inside a network whose PKI you own. It
   authenticates both ends and, with certificate-bound tokens (RFC 8705),
   makes those tokens non-replayable. The cost is certificate issuance,
   distribution, and rotation, which is why it belongs to a mesh or an
   automated issuer rather than to hand-rolled configuration.
4. **A static API key**, as the fallback of last resort — acceptable only for
   low-stakes internal traffic where the operational cost of the tiers above
   genuinely is not justified. A static key stays valid until somebody rotates
   it, and most teams never do; it travels on every request; and it is hard to
   attribute after the fact. Where one is unavoidable, apply the full key
   discipline in `a07-authentication-failures.md`, "API keys": high entropy,
   digest-only storage, a non-secret key ID logged on every use, narrow scope,
   and rotation that does not require downtime.

Review notes:

- The finding is rarely "they used the wrong mechanism." It is usually that a
  tier-4 credential is doing a tier-1 job — one static key, shared by several
  callers, never rotated, granting more than any single caller needs.
- A mechanism choice made when the service had one caller is worth re-checking
  once it has six. Reuse of a single credential across callers destroys
  attribution silently, without any code changing.
- Severity: Medium on its own for an unrotated narrow-scope key; High where the
  same credential is shared across callers or grants tenant-wide access.

## Validating an inbound machine token

### Principle layer

A signed token is trustworthy only for the issuer, audience, time window, and
purpose it was minted for. Signature validity is necessary and nowhere near
sufficient. Verify in this order, because each check gates the next, and fail
closed on any missing claim, fetch failure, or exception:

1. **Parse the header, but never trust `alg`.** Select the verification
   algorithm from your own configuration. *Omitted:* algorithm confusion —
   an RS256 verifier tricked into HMAC-verifying with the public key it
   published — and `alg: none` forgery. Full token forgery (CWE-347).
2. **Resolve the key by `kid` from a trusted JWKS**, never from a `jku` or
   `x5u` the token supplies. *Omitted:* the attacker points you at their own
   key set, or drives a `kid` value into a file path or SQL query
   (CWE-347, CWE-89).
3. **Verify the signature** with the resolved key and the pinned algorithm.
   *Omitted:* any forged token is accepted.
4. **Validate `exp`, and `nbf`/`iat` where present**, with minimal clock skew.
   *Omitted:* an expired or stolen token stays valid indefinitely (CWE-613).
5. **Validate `iss`** by exact match against the expected issuer. *Omitted:*
   any issuer your library happens to trust is accepted (CWE-345).
6. **Validate `aud`** against this service's own identifier. RFC 9068 makes
   this mandatory for JWT access tokens. *Omitted:* a token minted for a
   different API behind the same identity provider replays against you — a
   confused deputy (CWE-441, CWE-863).
7. **Validate scope and token type** — `scope`, and a type marker such as
   `typ: at+jwt`. *Omitted:* an ID token or a token minted for another purpose
   passes where an access token was required, or an over-scoped token is
   accepted for a narrow operation.
8. **Verify the binding if the token is sender-constrained** — `cnf.jkt`
   against the DPoP proof key, `cnf.x5t#S256` against the presented client
   certificate. *Omitted:* you accept a bearer replay of a token that was
   specifically issued not to be one.

### Django & DRF implementation layer

Machine-token verification belongs in a DRF authentication class, not in a
permission class and not inline in a view, so that one reviewed code path
covers every endpoint. Return a service principal, then let permission classes
and scoped querysets decide authority separately — a valid token is
authentication, never authorization.

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

- `options={"require": [...]}` is what makes the check fail closed. Without it,
  a token that simply omits `aud` can pass an audience check that was
  configured but never exercised.
- Test with a token minted for a sibling service behind the same issuer. That
  is the case an audience check exists for, and it is the case a test suite
  built only from valid and expired tokens never covers.
- Require `PyJWT>=2.13.0` for any service in the resource-server role; see
  `security-hardening-libraries.md`, "Service identity and secrets".
- On a gRPC surface these are the same two checks in different clothing — the
  token arrives in call metadata rather than in a header, and mutual TLS is
  configured on the server credentials rather than terminated at a proxy — so
  everything above applies unchanged; the interceptor that has to run them,
  and the rest of that surface, are in
  `graphql-and-alternative-api-surfaces.md`, "gRPC: nothing from the DRF
  request cycle applies".
- SimpleJWT is the wrong tool here. It issues and verifies tokens the Django
  application itself minted from a human login, which is `a07`'s territory, not
  a mechanism for accepting an external machine identity.
- Severity: Critical for an unpinned algorithm or an unverified signature;
  High for a missing `aud` or `iss` check, and higher still where several APIs
  share one identity provider.

**Write-time.** When generating a verifier for an inbound machine token, write
it as a DRF authentication class and pass the algorithm from configuration,
`issuer=`, `audience=`, and `options={"require": [...]}` in the same call,
because a verifier assembled without the require list accepts a token that
simply omits the claim it was configured to check. Resolve the key by `kid`
from a module-level JWKS client pointed at a configured URI, never from a
`jku` or `x5u` the token itself supplies, and return a service principal that
permission classes and a scoped queryset then decide authority over, since a
valid token is authentication and never authorization.

## JWKS as a rotation-aware trust anchor

**Principle: treat the key set as a cached trust anchor that expects
rotation.** Discover the JWKS URI from the issuer's own metadata, cache the set
process-wide with a bounded lifetime, refresh once on an unknown `kid` and
retry, pin the algorithm from configuration, and resolve strictly by `kid`.
Fail closed on a fetch error without discarding keys that are still valid.

Two failures recur:

- **Fetching on every request** turns the issuer's JWKS endpoint into a
  dependency of every authenticated call, and your application into a traffic
  amplifier against it.
- **Refreshing only on cache expiry** means that when the issuer rotates its
  signing key, every token signed by the new key fails until the cache expires.
  The fix is the unknown-`kid` refresh, not a shorter cache lifetime.

In Django, `jwt.PyJWKClient` implements this correctly, with defaults that are
easy to defeat by accident. Verified against PyJWT 2.13.0: the constructor is
`PyJWKClient(uri, cache_keys=False, max_cached_keys=16, cache_jwk_set=True,
lifespan=300, ...)`, so the key-set cache is on by default and expires after
five minutes, and `get_signing_key` refreshes the set once and retries when a
`kid` does not match.

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
  unless you look for where the client is constructed. The minimal examples in
  circulation all build it inline.
- The unknown-`kid` refresh deliberately bypasses the cache, so a stream of
  bogus `kid` values is one outbound fetch per request. Throttle unauthenticated
  token-bearing endpoints; see `a06-insecure-design.md`.
- `cache_keys=True` adds a second, per-key LRU cache with **no** time-based
  expiry — entries leave only when the cache fills. A key withdrawn by the
  issuer stays usable for verification until it is evicted. Leave it off unless
  the tradeoff has been reasoned through.
- Below PyJWT 2.13.0 three of these paths are exploitable rather than merely
  awkward, including a JWKS cache that was wiped whenever a fetch raised,
  turning a transient issuer outage into an application-wide authentication
  failure. Treat the version as a finding in its own right.
- Severity: Medium for the per-request client (availability and latency); High
  where a stale or wiped key set fails open rather than closed.

## Sender-constrained tokens

**Principle: constrain a token when it will pass through hands you do not
trust and a replay would be worth more than the cost of proving possession on
every request.** DPoP (RFC 9449) binds a token to a key the client proves it
holds, via a per-request signed proof and a `cnf.jkt` claim. Mutual-TLS-bound
tokens (RFC 8705) bind it to the client certificate, via `cnf.x5t#S256`.
Either way, a stolen token alone is inert.

Justified where the token crosses intermediaries you do not fully control —
gateways, a backend-for-frontend, public mobile clients — where the flow is
high-value or regulated, or where token theft through logs, SSRF, or XSS is a
live part of the threat model. DPoP suits public clients and anywhere TLS
client certificates are impractical; mTLS binding suits confidential
server-to-server clients that already have PKI.

Not repaid where traffic is already inside a mutually authenticated mesh — the
transport has sender-constrained it, and adding a signed proof per request buys
nothing — or where tokens are short-lived and low-value enough that the key
management and clock-skew handling cost more than the replay window is worth.

Review notes:

- The finding is not "DPoP is missing." It is "this token crosses an untrusted
  intermediary as a plain bearer credential and nothing detects a replay."
- If a token carries a `cnf` claim, the resource server must verify the
  binding. Accepting a constrained token as a bearer token is worse than never
  constraining it, because the issuer's threat model now assumes a protection
  that is not being enforced.
- Severity: Medium to High by context, driven by where the token travels.

## Client-certificate identity behind a proxy

**Principle: a proxy-set identity header is a claim, not proof.** It becomes
proof only under two conditions, and both must hold: the proxy overwrites or
strips any inbound copy of the header, and the application is reachable *only*
through that proxy. If either fails, any client sets the header and becomes
whichever service it names.

The Django application almost never terminates mutual TLS itself. A proxy does
— nginx, Envoy, an ALB, a mesh ingress — and forwards the verified identity in
a header. Envoy and Istio use `X-Forwarded-Client-Cert`, which Envoy sanitizes
by default; RFC 9440 standardizes `Client-Cert` and requires stripping an
inbound copy. Envoy's own documentation is explicit that forwarded values are a
hint set by the caller and easily spoofed by an internal entity.

This is the same trust model as `X-Forwarded-For` and `X-Forwarded-Proto` in
`deployment-and-runtime.md`, "Reverse proxy and forwarded headers", and that
section owns the proxy configuration. What differs here is the consequence: a
header carrying a *verified client certificate* carries an authentication
identity, so spoofing it is an authentication bypass (CWE-290) rather than a
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

- The peer check is necessary and not sufficient. Ask separately whether the
  application port is reachable without traversing the proxy at all: a
  container port published to the node, a service exposed cluster-wide, or a
  debug listener each defeat it.
- Write the trusted-hop assumption down in the settings module next to the
  header name. A topology assumption that only exists in someone's memory is
  the one that breaks during a migration.
- `.get()` with a default on an identity header is a fail-open pattern. Index
  the key and let a missing header raise.
- Severity: High, and Critical where the spoofed identity is a privileged
  service principal.

The same termination is worth requiring in front of a webhook receiver, which
is otherwise an unauthenticated public route by construction. A client
certificate demanded at the proxy narrows who can even open the connection
from the whole internet to the holders of a certificate you issued, so a
forged-signature attempt has to get past the transport before it reaches the
comparison. It is defense in depth and not a replacement: the certificate
authenticates a connection while the HMAC authenticates a message, an
intermediary that terminates TLS is trusted by the first and not by the
second, and most third-party providers cannot present a certificate at all.
Require it where the sender is first-party or the provider supports it, and
keep every step of the receiver in `a08-integrity-and-deserialization.md`
unchanged either way.

## "Internal" is not an authentication mechanism

**Principle: remove the network assumption and ask what is left.** For each
internal endpoint, ask what stops an attacker who is *already* inside the
segment — a compromised pod, an SSRF pivot, a supply-chain foothold. If the
only answer is that they are not supposed to be able to reach it, the boundary
is assumed rather than authenticated (CWE-306), and that is the finding.

The recurring shapes:

- an endpoint with no authentication class, or `AllowAny`, justified in a
  comment as internal only;
- trust derived from source IP, subnet membership, or `X-Forwarded-For`;
- one shared static token used by every internal caller, so there is no
  per-caller attribution and no way to rotate for one of them;
- a header the caller sets — `X-Internal: true`, `X-User-Id: 42` — treated as
  established fact rather than as input.

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

- Network controls stay valuable — they are defense in depth, and firewalling
  an admin surface is still correct. The finding is that the network control is
  the *only* control.
- Check management commands, health and metrics endpoints, and internal
  webhooks specifically. They are the ones written before the service had a
  second caller and never revisited.
- Severity: High, and Critical where the endpoint mutates state or spans
  tenants.

## Downstream calls: exchange, do not forward

**Principle: a service should exchange an inbound token for a narrowly
audience-bound downstream token rather than replaying the inbound one.**
Forwarding makes the downstream a confused deputy (CWE-441): it sees a valid
token, cannot tell that the caller is an intermediary, and applies the token's
full authority to a request the intermediary shaped.

`agent-and-llm-interfaces.md`, "Inbound token validation and the passthrough
prohibition" owns the prohibition itself and the agent-specific case;
`a07-authentication-failures.md`, "JWT" owns the general rule. What belongs
here is what the exchange must actually do, under RFC 8693:

- the grant type is `urn:ietf:params:oauth:grant-type:token-exchange`;
- `subject_token` carries the identity the new token is requested for, and an
  optional `actor_token` carries the acting party. Delegation keeps the actor
  visible in the issued token; impersonation does not, and that distinction is
  the audit trail — see `privileged-access-and-impersonation.md`;
- `resource` (RFC 8707), `audience`, `scope`, and `requested_token_type` narrow
  the result to one downstream. This narrowing is the entire point;
- the token service verifies the incoming token's signature and expiry
  *before* exchanging, checks that a `may_act` claim authorizes any actor, and
  downscopes only. An exchange that can widen authority is an escalation
  primitive.

Review notes:

- Where no token service exists, a stored per-downstream service credential or
  a platform-managed identity is an acceptable substitute. Forwarding is not.
- A service that calls three downstreams needs three narrow credentials, not
  one credential that reaches all three.
- Severity: High.

## Where secrets live and how they reach the process

### Principle layer

Match the delivery mechanism to the strongest identity the runtime can attest,
and minimize how many places and processes can observe the value. Fewer copies,
shorter lifetimes, narrower readership. Across every runtime the direction of
travel is the same — from a stored static secret toward a runtime-fetched,
workload-identity-gated, short-lived credential. What changes between runtimes
is who vouches for the workload and how wide the exposure surface is.

- **Virtual machine.** A file with tight ownership and permissions, read at
  startup, ideally fetched from a secret manager using the instance's own
  attested identity. Do not bake secrets into the image and do not commit an
  environment file.
- **Container.** A mounted file or tmpfs secret rather than an environment
  variable, and better still a runtime fetch from a secret manager gated by
  workload identity, so no static secret appears in the deployment manifest at
  all.
- **Managed platform.** The platform's own secret store, scoped per
  environment, with its managed identity where one exists.

**The honest position on environment variables.** They are convenient and
conventional, and they are also readable from the process environment by
anything that can inspect the process, inherited by every child process
including third-party subprocesses, exposed by container and orchestrator
introspection commands, and captured wholesale by crash dumps, error trackers,
and debug output. They are acceptable for low-risk, non-reused values. For
production service credentials a mounted file or a secret-manager fetch is the
safer default. The defensible line is not that environment variables are
forbidden — it is that they are the floor, not the target.

### Django & DRF implementation layer

`deployment-and-runtime.md`, "Database and secrets" owns how the environment is
injected and the rule against a generic environment-parsing helper. What
belongs here is what the settings module does with the value.

- Read required secrets with `os.environ[...]`, not `os.environ.get(...)`, so a
  missing production secret fails at startup rather than silently becoming
  `None` and disabling a check further down.
- Validate required settings and types at startup and fail closed, without
  printing the value in the error.
- Keep secrets out of `settings.py` literals, out of committed environment
  files, out of fixtures, and out of the container image. A committed secret is
  a finding on its own weight (CWE-798), rated by what it unlocks.
- Never log settings objects, request headers, or task arguments wholesale; see
  `a09-logging-and-alerting.md` for scrubbing, and `a08-integrity-and-deserialization.md`
  for keeping webhook-signing secrets distinct from API authentication keys.
- Add a pre-commit secret scanner so the next one is caught before it is
  pushed. Detection is cheap; the response in the next section is not.

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

- The database connection string is a secret and frequently the one left in a
  compose file or a CI variable. `data-layer-and-database.md` covers the
  connection itself.
- Break-glass credentials have their own custody rules; see
  `privileged-access-and-impersonation.md`.
- CI is a credential store. Prefer OIDC federation from the CI provider to the
  cloud account over a long-lived deployment key held as a repository secret;
  see `a03-software-supply-chain.md`, "Trust and provenance".
- Severity: High to Critical for a committed secret, by blast radius; Medium
  for high-value credentials delivered by environment variable where the
  platform offered better.

## Rotating Django's SECRET_KEY

### Principle layer

Any rotation of a signing key has the same shape: the new key must be able to
sign, and the old key must still be able to verify, for at least as long as the
longest-lived artifact signed under it. A rotation with no overlap window is
not a rotation, it is an invalidation — sometimes exactly what you want, and
never something to do by accident. The overlap must also reach every instance
*before* any instance starts signing with the new key, or instances will reject
each other's freshly signed data for the length of the deploy.

### Django & DRF implementation layer

`SECRET_KEY_FALLBACKS` is consulted **only to validate** previously signed
data. New data is always signed with the current `SECRET_KEY`. Which subsystems
that covers, verified against Django 6.0 and 5.2 source:

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

**Rotating `SECRET_KEY` does not invalidate CSRF tokens.** The CSRF secret is
generated randomly and stored in the cookie or session; it is not derived from
`SECRET_KEY`. A number of widely circulated rotation guides list CSRF among the
casualties, and it is not one. The real casualties of a rotation with no
fallback are all sessions and logins, every in-flight password-reset link,
messages-framework cookies, every `signing.dumps` value and signed cookie and
signed URL, and anything third-party built on `django.core.signing`.

The safe procedure:

1. **Add.** Generate a key with
   `django.core.management.utils.get_random_secret_key()` — the same helper
   `startproject` uses. Set it as `SECRET_KEY` and put the *previous* key into
   `SECRET_KEY_FALLBACKS`. Deploy, and confirm every instance has reloaded.
   New data signs with the new key, old data still validates, and sessions
   upgrade transparently as users make their next request.
2. **Wait.** At least as long as the longest-lived signed artifact you care
   about — usually `SESSION_COOKIE_AGE` or `PASSWORD_RESET_TIMEOUT`, whichever
   is longer.
3. **Remove.** Drop the old key from `SECRET_KEY_FALLBACKS`. Anything still
   signed with it now becomes invalid, which is the intended end state.

Review notes:

- On a *compromise* rotation, deliberately skip the fallback. A hard cut
  invalidates everything the attacker could forge, and the mass logout is the
  price of that. Choosing it knowingly is correct; arriving at it by accident
  is the failure this section exists to prevent.
- On Django 4.1 and earlier, fallbacks did not cover the session
  authentication hash, so even a fallback rotation logged everyone out. That
  was fixed in 4.2. If a codebase on an old line has rotation runbooks written
  around the old behavior, the runbook is now wrong in the safe direction —
  but the codebase is on an end-of-life Django, which is the larger finding
  (`a03-software-supply-chain.md`).
- A rotation path that exists only as a wiki page has not been tested. Ask
  whether the fallback slot is already wired into settings and deployment, as
  in the example above, or whether adding it is itself a code change under
  incident pressure.

## Responding to a leaked secret

**Principle: rotation is what renders the exposed secret worthless; everything
else is containment and hygiene.** Order the response by what stops active
abuse fastest, and assume from the first minute that the secret has already
been harvested.

1. **Rotate** — mint a replacement and cut traffic over to it. This is first
   because it is fast and because it is the step that actually stops the
   bleeding. Cleaning history first, while the live credential still works, is
   the common and costly inversion.
2. **Revoke** the old credential at the provider. Rotation and revocation are
   not the same operation: with many providers the old key stays valid until
   it is explicitly deleted.
3. **Assess blast radius** — what it granted, what it could reach, and whether
   the same value was reused anywhere else. One leaked secret copy-pasted into
   five services is five incidents.
4. **Review logs** for use of the credential between exposure and revocation.
   This is where an earlier decision to log a key ID on every use pays for
   itself; without it there is nothing to review.
5. **Scrub history and prevent recurrence** — rewrite with a purpose-built
   tool such as `git filter-repo` or BFG, and add a pre-commit scanner. Treat
   this as cleanup, not as the fix: forks, clones, caches, and crawlers may
   retain the value. A pushed secret is compromised regardless of what the
   history looks like afterwards.

For `SECRET_KEY` specifically, "rotate" here means the hard-cut path above —
no fallback — if you have to assume forged values are already in flight.

## Out of backend scope

Mirroring `00-methodology-and-severity.md`, "What to exclude" — do not search
backend code for these, and do not report their absence as a backend finding:

- authoring SPIRE deployment topology or attestation policy, and operating a
  mesh certificate authority. Auditing how the backend *consumes* an attested
  identity is in scope; running the issuer is not;
- secret-manager and secret-scanner product comparison;
- hardware-security-module and key-custody procurement, as distinct from how
  the application reaches the key material;
- human-facing mutual TLS, SAML, and passkeys, which stay in
  `a07-authentication-failures.md` at the library-configuration level.

## Review checklist

### Stack-neutral

- [ ] Each machine caller has its own identity; no single static credential is
      shared across callers, and every use is attributable to one of them.
- [ ] Short-lived platform or client-credentials tokens are used where the
      runtime supports them, and any static key is a documented, scoped,
      rotatable exception rather than a default.
- [ ] Every inbound token is verified with an algorithm pinned in
      configuration, never one taken from the token header.
- [ ] `iss` and `aud` are validated by exact match, `aud` against this
      service's own identifier, and verification fails closed on a missing
      claim rather than skipping the check.
- [ ] `exp` and `nbf` are enforced with minimal clock skew.
- [ ] The key set is cached process-wide, refreshed once on an unknown key
      identifier, and a fetch failure neither opens the gate nor discards keys
      that are still valid.
- [ ] Where a token carries a sender-constraint claim, the binding is actually
      verified rather than the token accepted as a bearer credential.
- [ ] Any proxy-set identity header is trusted only where the proxy strips
      inbound copies and the application cannot be reached directly.
- [ ] No endpoint relies on network position, source address, or a
      caller-supplied header as its authentication.
- [ ] Downstream calls use a separately issued, audience-scoped credential;
      no inbound token is forwarded onward.
- [ ] Production secrets reach the process by mounted file or secret manager
      rather than environment variable where the platform allows it, and
      nothing secret is committed or baked into an image.
- [ ] A rotation path exists for every credential, with an overlap window sized
      to the longest-lived artifact signed under the old value.
- [ ] The leak response is ordered rotate, revoke, assess, review logs, scrub —
      and credential use is logged by identifier so step four is possible.

### Django & DRF

- [ ] Token verification lives in one authentication class, returns a service
      principal, and is followed by permission classes and scoped querysets.
- [ ] `jwt.decode` pins `algorithms`, passes `issuer` and `audience`, and sets
      `options={"require": [...]}`; SimpleJWT is not used as a service-identity
      mechanism.
- [ ] `PyJWKClient` is held at module or singleton scope, not constructed per
      request, and `cache_keys` is left off unless its unbounded key lifetime
      has been reasoned through.
- [ ] `PyJWT>=2.13.0` where the application validates third-party tokens.
- [ ] A trusted-proxy check guards any client-certificate header, and the
      header is indexed rather than `.get()`-with-a-default.
- [ ] `SECRET_KEY` is read from an injected secret with `os.environ[...]`, and
      `SECRET_KEY_FALLBACKS` is already wired into settings so a rotation is a
      configuration change rather than a code change.
- [ ] The rotation runbook reflects current Django: CSRF tokens are unaffected,
      and the session hash both consults fallbacks and upgrades in place.
- [ ] Required settings are validated at startup and fail closed without
      printing secret values.
