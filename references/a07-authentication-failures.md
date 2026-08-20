# A07:2025 — Authentication Failures

Password, session, token, federated-login, API-key, recovery, and anti-automation
controls. API mappings include API2:2023 (Broken Authentication).

This file owns the **human principal** — proving a person is who they claim to
be, and the lifecycle of every credential issued to one. A machine principal is
a different problem: `service-identity-and-secrets.md` owns machine-token
validation, JWKS rotation, mutual TLS, and workload identity, while the API-key
discipline here stays the bar a static service key still has to meet.
`a04-cryptographic-failures.md` owns the hashing family, its parameters, and
the generation of every token this file then stores;
`a06-insecure-design.md` owns which flows need anti-automation; and
`authorization-architecture.md` takes over the moment identity is established,
because authentication ends where authorization begins.

## Contents

- [Principle](#principle)
- [The user model as an identity contract](#the-user-model-as-an-identity-contract)
- [Password policy](#password-policy)
- [Sessions](#sessions)
- [Session engines, rotation, and revocation](#session-engines-rotation-and-revocation)
- [JWT](#jwt)
- [Token storage](#token-storage)
- [Brute force and enumeration](#brute-force-and-enumeration)
- [Password reset](#password-reset)
- [Email change and purpose-bound tokens](#email-change-and-purpose-bound-tokens)
- [MFA](#mfa)
- [OAuth2, OIDC, and social login](#oauth2-oidc-and-social-login)
- [REMOTE_USER and header authentication](#remote_user-and-header-authentication)
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

## The user model as an identity contract

### Principle layer

Authentication compares a submitted identifier against a stored one. Which
field is the identifier, what transformation runs before it is stored, and
what the store treats as equal are all part of the identity model, and none
of the three is visible at the login view. Two accounts are the same
principal exactly when those three answers agree.

They disagree in one of two directions and each has its own failure. Where
the comparison is looser than the uniqueness constraint, two rows answer to
one typed identifier and which one authenticates is a database detail. Where
it is stricter, the owner cannot reach their own account and registers a
second one.

Unicode widens that gap rather than creating it. NFKC normalization maps
distinct inputs onto one string — a fullwidth `ａ` onto `a`, the `ﬁ` ligature
onto `fi` — so two registrations that looked different collide afterward and
one of them is now an existing account. Case folding is the same shape with a
different table: `str.lower()` and `str.casefold()` are not one function, and
`casefold()` maps `ß` to `ss` where `lower()` leaves it. Homoglyphs need no
normalization at all — a Cyrillic `а` in a username, a display name, or an
email domain renders identically to the Latin letter and compares unequal,
which is the direction that favors an attacker, because the impersonating
value is the new row rather than the existing one.

One rule covers all of it. **Normalize once, at the boundary, in one
documented form; store the normalized value; enforce uniqueness on the stored
value; compare the stored value.** A second normalization applied at another
layer in another form is a second identity model, and the system now has two.

Disabling an account is part of the same contract. It ends access only on the
paths that re-read the account, so a credential carrying its own
authorization and never revalidated outlives the disable by its own lifetime.
That is why the offboarding control in `authorization-architecture.md`,
"Identity lifecycle and provisioning desynchronization", enumerates
credentials rather than trusting a flag.

### Django & DRF implementation layer

Three class attributes carry the contract, and only two do what their names
suggest.

- **`USERNAME_FIELD`** names the field `authenticate()` looks up and
  `get_username()` returns. It has to be unique.
- **`EMAIL_FIELD`** names the field mail flows address, read through
  `get_email_field_name()`, which falls back to `"email"` when the attribute
  is absent.
- **`REQUIRED_FIELDS`** is prompted by `createsuperuser` and by nothing else.
  It constrains no form, no serializer, and no API; `auth.checks` verifies
  only that it is a list and that it excludes `USERNAME_FIELD`. Reading it as
  a validation rule is the common error.

`BaseUserManager.get_by_natural_key()` is one exact lookup —
`self.get(**{USERNAME_FIELD: username})` — so the case behavior of every
login belongs to the column's collation rather than to Django. PostgreSQL
compares case-sensitively by default and MySQL's default collations do not,
which makes the same code two identity models: on MySQL `Alice` logs in as
`alice` and cannot register a second account beside her, and on PostgreSQL
she does neither — the login fails and the registration succeeds. Read off
the Django 6.0.7 and 5.2.15 source on 14 Aug 2026.

`BaseUserManager.normalize_email()` lowercases **the domain part only**. That
is correct — the local part is case-sensitive to the mail standards — and it
is routinely mistaken for a full normalization: `Alice@Example.COM` is stored
`Alice@example.com`. `AbstractBaseUser.normalize_username()` applies
`unicodedata.normalize("NFKC", ...)`. Neither runs on a bare `.save()`:
`normalize_username` is called from `AbstractBaseUser.clean()` and
`normalize_email` from `AbstractUser.clean()`, so both reach a ModelForm and
the admin through `full_clean()`, and `UserManager._create_user_object()`
calls both directly. A DRF serializer, a hand-written signup view, or a
social-auth adapter that assigns the field itself runs none of them, which is
how one project ends up normalizing on half its write paths.

Django compares identity two ways itself, which is the clearest available
demonstration that the comparison is a choice rather than a property of the
data. `PasswordResetForm.get_users()` filters `email__iexact`, re-filters
through `_unicode_ci_compare()` — NFKC plus `casefold()` — and mails **every**
surviving match. Login, against the same rows, does the exact lookup above.
A project on a case-sensitive collation therefore has a reset flow that finds
an account the login flow will not.

`UnicodeUsernameValidator`, the default on `AbstractUser.username`, is
`r"^[\w.@+-]+\Z"` with `flags = 0`, so `\w` matches any Unicode word
character and a Cyrillic `аdmin` passes. `ASCIIUsernameValidator` is the same
expression under `re.ASCII` and is the right choice wherever a username is
displayed as identity. Neither addresses confusability inside a mixed-script
value, and a display name has no validator at all.

**Uniqueness has to sit on the value the comparison reads.** `unique=True`
constrains the stored bytes, so where the application normalizes before
comparing but stores what was typed, the constraint does not cover the
comparison — and an application-level "does this exist yet" query followed by
a save is a race rather than a control (`a10-exceptional-conditions.md`).

```python
# Wrong: nothing normalizes. On a case-sensitive collation
# Alice@example.com and alice@example.com become two accounts that
# unique=True cannot see are the same one, and the owner of either is locked
# out the moment they type their address the other way.
class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    USERNAME_FIELD = "email"
```

```python
# Correct: one normalization function on every write path, and a constraint
# over the same transformation. Lower() and casefold() are different
# functions -- use the one the database can express on both sides.
import unicodedata

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.db.models.functions import Lower


def normalize_identity(value):
    value = unicodedata.normalize("NFKC", value)
    return BaseUserManager.normalize_email(value).lower()


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra):
        user = self.model(email=normalize_identity(email), **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    USERNAME_FIELD = "email"
    objects = UserManager()

    def clean(self):
        super().clean()
        self.email = normalize_identity(self.email)

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower("email"), name="uniq_email_ci"),
        ]
```

This manager is an identity example. The password-policy rule above still
applies to any path that gives it a human-chosen password.

**`is_active` reaches further than a login form and stops short of a token.**
`AbstractBaseUser` sets a class attribute `is_active = True` and
`ModelBackend.user_can_authenticate()` reads `getattr(user, "is_active",
True)`, so a custom user model that never declares the field is permanently
active and nothing reports it — the reason the example above declares it.
Where the field exists, `ModelBackend` rejects the user at `authenticate()`
**and** at `get_user()`, which is the session-load path, so a live session
stops working on its next request, and `ModelBackend._get_permissions()`
returns an empty set for an inactive user besides. What the flag cannot reach
is a credential validated without reading the row:
`JWTStatelessUserAuthentication` builds its principal from the token claims
and issues no query, so `is_active` is never consulted and the token stands
until it expires. Checked against SimpleJWT 5.5.1 source on 14 Aug 2026,
where `JWTAuthentication` does check it under `CHECK_USER_IS_ACTIVE`,
default `True`; DRF's `TokenAuthentication` re-reads `token.user.is_active`
on every request.

**Choose the user model in the first commit.** `AUTH_USER_MODEL` is resolved
at migration time and every migration already pointing at `auth.User` goes on
pointing at it, so a late move is a schema problem before it is a security
one. The security consequence is the workaround teams reach for instead:
identity is bolted onto a profile row, `USERNAME_FIELD` stays `username`, the
address people actually log in with lives on a related model under its own
uniqueness rule or none, and the normalization rule above now has two homes
that will drift.

**Write-time.** When generating a project's user model, declare a custom
model in the first migration even where the default would serve, and settle
`USERNAME_FIELD` and the normalization function in that same edit, because
both are cheap now and neither is retrofittable once foreign keys exist.
Route every write of the identifier through one normalization function — the
manager, `clean()`, and any serializer or social adapter that creates a user
— and add the database constraint over the same transformation in the same
change, since the constraint is what makes the rule true for the write path
somebody adds later. When the model does not inherit `AbstractUser`, declare
`is_active` explicitly: inherited from `AbstractBaseUser` it is a constant
`True`, and every deactivation feature built on it will appear to work.

## Password policy

### Principle layer

NIST SP 800-63B-4 states the password-verifier requirements normatively, and
the first of them is the one most projects fail without noticing. Section
3.1.1.2, requirement 1: a password used as a **single-factor** authentication
mechanism SHALL be a minimum of **15 characters**; a password used only as
part of a multi-factor process MAY be shorter but SHALL still be a minimum of
**eight**. Both halves of that split are SHALL-level, and the 15-character
floor is the one that governs the ordinary case of a site where a password
alone logs a user in. The revision matters here — the 2017 edition asked only
for eight, so guidance and validators inherited from it are a tier low.

The rest of the section, in its own grammar:

- a maximum length of at least 64 characters SHOULD be permitted, and the
  entire submitted password SHALL be verified rather than truncated;
- other composition rules — required mixtures of character types — SHALL NOT
  be imposed, a point section 3.1.1.1 repeats;
- subscribers SHALL NOT be required to change passwords periodically, but a
  change SHALL be forced on evidence that the authenticator is compromised;
- on every request to establish or change a password, the prospective secret
  SHALL be compared against a blocklist of known commonly used, expected, or
  compromised values. The **entire** password is compared rather than
  substrings, and the list is expected to draw on previous breach corpuses,
  dictionary words, and context-specific words such as the name of the
  service and the username. A password found on it SHALL be rejected and the
  reason SHALL be given;
- password managers SHALL be allowed and the paste function SHOULD be
  permitted;
- a password hint reachable by an unauthenticated claimant SHALL NOT be
  stored, and knowledge-based authentication or security questions SHALL NOT
  be used when choosing a password; and
- failed-attempt rate limiting SHALL be implemented — the control this file
  covers under "Brute force and enumeration".

Storage is a separate requirement, met elsewhere: salted and hashed with a
salt of at least 32 bits. `a04-cryptographic-failures.md` owns the hashing
family and its parameters.

### Django & DRF implementation layer

`AUTH_PASSWORD_VALIDATORS` ships four validators, and mapping them onto the
requirements above locates the one gap that matters:

- `MinimumLengthValidator` defaults to `min_length=8`. Raise it to 15 wherever
  the password is a single factor. Eight is defensible only where a second
  factor is genuinely enforced for every account that can reach the flow,
  which is a claim about the whole login path rather than about this setting.
- `CommonPasswordValidator` lowercases the candidate and checks it against a
  list of 20,000 common passwords. That is a blocklist in form but nowhere
  near breach scale, and it is the requirement projects most often believe
  they have already satisfied. Its `password_list_path` option takes a custom
  file of one lowercase password per line.
- `UserAttributeSimilarityValidator` covers the context-specific-words clause
  for the user's own attributes.
- `NumericPasswordValidator` rejects an all-numeric password.

The validators run where `validate_password()` runs, and nowhere else. The
built-in auth forms and views call it. `set_password()`, the model
constructor, and a manager `create_user()` path do not call it, so a password
set through one of them meets no policy at all. Call
`validate_password(password, user=user)` in every custom signup, invitation,
reset, change, admin, import, and API path that takes a human-chosen
password. For an account that must hold no password, call
`set_unusable_password()`.

Django imposes no maximum length, no composition rules, and no periodic
expiry. The last two are the correct default rather than gaps, because the
requirement is to *not* impose them — a project that added a character-class
rule or an expiry job is the finding. The one requirement no built-in meets is
**breached-corpus screening**, and no package currently clears the gate to
provide it: `pwned-passwords-django==5.2.0` (6 Apr 2025, re-checked 9 Aug
2026) declares Django 4.2, 5.1, and 5.2 with no Django 6 line at all, on a
single maintainer. Own the check instead.

```python
# Wrong: the floor is Django's default of eight and the only blocklist is the
# 20,000-entry common-password list, so a nine-character password sitting in
# last year's breach corpus is accepted. The two additions make it worse
# rather than better -- a character-class rule and an expiry job are both
# SHALL NOTs, and both push users toward predictable mutations of one secret.
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "myproject.validators.RequireMixedCharacterClassesValidator"},
]
PASSWORD_EXPIRY_DAYS = 90
```

```python
# Correct: 15 for a single factor, the built-ins that map to real
# requirements kept, and a breach-corpus check that no built-in provides. The
# range query sends the first five hex characters of the SHA-1 digest and
# never the password or the full digest, so the candidate never leaves the
# process.

# myproject/validators.py
import hashlib
import logging
import urllib.error
import urllib.request

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


class BreachedPasswordValidator:
    def validate(self, password, user=None):
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        lookup = urllib.request.Request(
            f"{settings.PWNED_RANGE_ENDPOINT}{prefix}",
            headers={"Add-Padding": "true"},
        )
        try:
            with urllib.request.urlopen(lookup, timeout=2) as response:
                # Cap the read: a third party controls this response body,
                # and an unbounded read hands it a memory exhaustion.
                body = response.read(2_000_000).decode("utf-8")
        except (urllib.error.URLError, TimeoutError):
            # Fail open, deliberately and visibly. Failing closed denies every
            # password change during someone else's outage; whichever way the
            # product decides, it gets logged rather than silently skipped.
            logger.warning("breach screening unavailable", exc_info=True)
            return
        for line in body.splitlines():
            candidate, _sep, count = line.partition(":")
            if candidate == suffix and int(count) > 0:
                raise ValidationError(
                    _("This password has appeared in a known data breach."),
                    code="password_breached",
                )

    def get_help_text(self):
        return _("Your password must not appear in a known data breach.")


# settings.py
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation"
        ".UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation"
        ".MinimumLengthValidator",
        "OPTIONS": {"min_length": 15},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "myproject.validators.BreachedPasswordValidator"},
]
```

State the cost of that check rather than absorbing it. It is an outbound call
to a third party on every password set and change, so password changes now
depend on that service's availability and latency, the endpoint joins the
hosts the egress policy has to allow, and a five-character hash prefix is
disclosed to it. The `Add-Padding` header adds decoy entries so that the
entry count varies inside a band, and the response length stops identifying
the queried prefix; the responses are not the same size. The
fail-open branch is a decision and not a default: failing closed is the
stronger posture and the right one for a high-assurance product, but it
denies every password change during an outage nobody in the project controls.
SHA-1 appears here as a lookup key for the range API and nowhere else —
storage remains whatever `PASSWORD_HASHERS` selects.

Where an outbound call is unacceptable — an air-gapped deployment, a privacy
review that will not clear it, or a flow that cannot take the latency — the
offline alternative is `CommonPasswordValidator` pointed at a much larger
local list through `password_list_path`. It needs no network and discloses
nothing; the trade is that the file has to be obtained, reviewed for its
license, shipped with the image, and refreshed on a schedule somebody owns,
and a list nobody refreshed is the failure it was added to prevent.

**Write-time.** When generating `AUTH_PASSWORD_VALIDATORS`, or any flow that
sets or changes a password, put `min_length` at 15 unless a second factor is
enforced for every account that can reach the flow, and add the
breach-screening validator in the same edit, because a project that ships the
four defaults has met the blocklist requirement in form only and nothing
later prompts a revisit. Do not generate a character-class rule or a
password-expiry job even when the ticket asks for one: both are SHALL NOTs
under SP 800-63B-4, and expiry in particular is the control most often added
by reflex. Where a maximum length is needed, set it at 64 or above and never
truncate before hashing.

## Sessions

- Rotate the session identifier on login and privilege change; invalidate it on
  logout and password reset/change where the product's threat model requires it.
  Which Django call does which, and what the backend has to be for revocation
  to mean anything at all, are in the next section.
- Use `Secure`, `HttpOnly`, and an appropriate `SameSite` value; the full
  `SESSION_*`/`CSRF_*` matrix and the setting behind each flag are in
  `a02-security-misconfiguration.md`. Cookie-authenticated state changes still
  need CSRF protection; `SameSite` is defense in depth.
- Bound idle and absolute lifetime for sensitive applications. Do not place
  secrets or authorization decisions in client-readable session data.
- Review custom backends and login views for inactive-user handling. Django's
  default `ModelBackend` rejects inactive users; a custom backend can undo that.
- Re-authenticate and require the current factor before changing password, email,
  MFA, recovery methods, payout details, or other security-sensitive state.

## Session engines, rotation, and revocation

### Principle layer

Two questions decide what a session is worth. **Where the state lives**,
because you can only revoke what you hold a record of; and **when the
identifier changes**, because an identifier that survives a privilege change
is a session-fixation vector. A design that answers the second and not the
first can end a session on the way out and cannot end one on demand.

Revocation is the half that gets assumed. A self-contained credential — a
signed cookie, a bearer token — carries its own authority, so "log out" is a
request to the holder rather than an instruction to the server. Where the
product needs log-out-everywhere, forced re-authentication, or an operator
kill switch, that is a design requirement selecting the storage, not a
feature to be added on top of one.

### Django & DRF implementation layer

`SESSION_ENGINE` selects one of five backends, and what separates them is
durability and whether a record exists to delete. Read off the Django 6.0.7
source on 14 Aug 2026:

| Backend | State lives in | Revocation | Loss mode |
|---|---|---|---|
| `db` (default) | a `django_session` row | delete the row | none; needs `clearsessions` scheduled |
| `cached_db` | the cache, then the row | `delete()` clears both | a cache miss falls back to the row |
| `cache` | the cache only | delete the key | an eviction or a flush ends every session |
| `file` | one file per session | delete the file | per host unless the path is shared |
| `signed_cookies` | the client | **none** | nothing to lose and nothing to revoke |

`signed_cookies` is the one to flag. `SessionStore.exists()` returns `False`
unconditionally and `delete()` only clears the client-side value, so the
server holds no record: a cookie copied before logout stays valid until
`SESSION_COOKIE_AGE` runs out, and there is no per-session lever to end it
early. The two that exist are wholesale — a `SECRET_KEY` rotation with no
fallback ends every user's session at once
(`service-identity-and-secrets.md`, "Rotating Django's SECRET_KEY"), and a
password change ends one user's through the auth hash below.
Its payload is **signed and not encrypted** — `signing.dumps` with
compression — so everything in `request.session` is readable by the browser
and by anyone who captured the cookie. `cache` has the mirror-image problem:
revocation works, and an ordinary eviction or a routine `FLUSHALL` logs
everybody out, which is an availability failure a deploy can cause by
accident. `cached_db` reads the cache and falls back to the row, so a flush
costs a query rather than a session.

Rotation is three calls, and the first does less than it is credited with.
`login()` calls `cycle_key()` — a new key, the same data, the old record
deleted — **only where the session carries no authenticated user**. That is
the fixation case, so the control is present where it counts, but a session
that already holds an authenticated user takes a different branch: a
different user or a mismatched auth hash flushes, and the *same* user logging
in again gets neither call, leaving the identifier unchanged. `login()` also
calls `rotate_token()`, which cycles the CSRF secret. `logout()` calls
`flush()`: the data is cleared, the record deleted, and the key set to
`None`.

`update_session_auth_hash(request, user)` is the third, and the one a
password change needs. `get_session_auth_hash()` is a `salted_hmac` over the
password field — and through the HMAC key over `SECRET_KEY` — which
`django.contrib.auth.get_user()` recomputes and constant-time-compares on
**every** request. Rewriting the password therefore invalidates every session
the user has, including the one making the change; `update_session_auth_hash`
cycles that session's key and re-stamps its hash so it survives. Django's own
`PasswordChangeView` calls it. A hand-written DRF endpoint usually does not,
and the symptom — the caller is logged out by their own password change — is
read as a bug and fixed by removing the invalidation.

```python
# Wrong: correct in every respect except that the caller is logged out by
# the change they just made, which is the failure that gets "fixed" by
# weakening the invalidation instead of exempting this session from it.
class ChangePasswordView(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save(update_fields=["password"])
        return Response(status=204)
```

```python
# Correct: every other session dies -- which is the intent -- and this one is
# re-keyed and re-stamped by the same call. On a token-authenticated API
# there is no session to exempt, so the equivalent is to delete or rotate the
# caller's tokens here rather than to leave them standing.
class ChangePasswordView(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save(update_fields=["password"])
        update_session_auth_hash(request, request.user)
        return Response(status=204)
```

The endpoint also verifies the current password, and it carries the
login-flow limits from "Brute force and enumeration".

Treat log-out-everywhere as a stated requirement rather than a side effect of
this behavior. A password change already delivers it; a product that needs
the same effect without one needs either a stored session record to delete or
a per-user credential version the session-load path reads. `get_user()` also
tries `SECRET_KEY_FALLBACKS` before giving up, and a fallback match cycles
the key and re-stamps the hash in place, which is what makes a key rotation
survivable at all.

**Write-time.** When generating a settings module, leave `SESSION_ENGINE` at
`db` unless the request asked for a different trade, and never generate
`signed_cookies` for an authenticated application: it removes revocation
entirely and publishes the session payload to the client, and both are
properties of the first version that nothing later reopens. When generating
any endpoint that sets a password — reset, change, or admin-side — call
`update_session_auth_hash()` in the same edit for the session case, and
delete or rotate the caller's tokens for the token case, because the
invalidation is the control and the exemption for the current session is the
part that has to be written deliberately. When generating a forced-logout or
log-out-everywhere feature, choose a backend with a server-side record
first: the feature cannot be added to a session the server never stored.

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
- Revalidate on every request rather than caching a principal for the life of a
  session, and reject a token whose `aud` does not name this service. An
  audience check is what stops a token minted for another resource from being
  replayed here.
- **Never forward an inbound token to a downstream service.** The downstream
  cannot tell that the caller is an intermediary, so it applies the token's full
  authority to a request the intermediary shaped — a confused deputy (CWE-441).
  Obtain a separately issued, downstream-scoped credential for the next hop.
  See `agent-and-llm-interfaces.md`, "Inbound token validation and the
  passthrough prohibition".
- SimpleJWT `5.5.1` contains the fix for CVE-2024-22513 but advertises support only
  through Django 5.2 — re-confirmed on 9 Aug 2026 against the classifiers the
  release publishes, which top out there, on an artifact from 21 July 2025.
  Treat it as conditional on a compatible project, not as a Django 6 default;
  re-check compatibility before adoption.
- A token minted by *another* system for a *machine* caller is a different
  problem from one this application issued. The ordered claim-by-claim
  verification, JWKS caching and rotation, sender-constrained tokens, and the
  library floor are in `service-identity-and-secrets.md`, "Validating an
  inbound machine token". SimpleJWT is not a service-identity mechanism.

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

The device-cookie pattern is the answer to the denial-of-service edge above.
On each successful login, set a signed cookie that names the account. On a
later attempt, throttle the `(account, device-cookie)` pair separately from an
attempt that carries no valid cookie. The owner on a known device continues to
log in, and an unknown device gets the hard limit. Sign the cookie with
`django.core.signing` under its own salt (`a04-cryptographic-failures.md`,
"Signing and salt discipline"), and carry the account identifier and a version
inside it. Increase the version on a credential change, so an old cookie stops
working.

**Write-time.** When generating a login, signup, reset, invite, or MFA
endpoint, return the same public response on the account-exists and
account-absent branches and wire the lockout in the same change rather than
after the first credential-stuffing run, because both the oracle and the
missing limit are properties of the first version and neither shows up as a
failing test. Reach for `django-axes` at its defaults and settle the
trusted-proxy and client-IP configuration in that edit, since a lockout keyed
on a spoofable address locks out whichever principal the attacker names. Two
adjacent defaults belong to the same moment: the credential the flow issues is
single-use and expiring, and the session identifier is rotated on login and on
any privilege change, so a session captured before the change does not survive
it.

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

## Email change and purpose-bound tokens

The email address is the account's recovery root, so a change of address is a
privileged operation.

- Re-authenticate before the change. Require the current password or a fresh
  session, and the second factor where the account has one.
- Send a confirmation link to the new address. The change happens on
  confirmation, never on request.
- Notify the old address. Give that notice a revert path, and keep the path
  valid after the change completes.
- Never carry the new address inside a client-held signed token. Hold the
  address on the server, keyed by the token.

`default_token_generator` hashes five values into a reset token. They are the
user's primary key, the password hash, the `last_login` timestamp, the token
time, and the email address. The list comes from Django 6.0.7 source, checked
on 20 Aug 2026. The address is one of the five, so a change of address already
invalidates every outstanding reset token on that account. A custom generator
or a stored token row does not get that property: invalidate the outstanding
tokens in the same transaction as the address change.

That design is single-purpose. Reuse it for email confirmation, and the link's
validity starts to depend on unrelated logins. A reset token also becomes
exchangeable for a confirmation, because the same user state produces the same
token. Issue purpose-bound tokens instead. Subclass
`PasswordResetTokenGenerator` for each purpose, give the subclass its own
`key_salt`, and override `_make_hash_value()` to append the purpose string and
the normalized target address. A single-use random token row with an expiry is
the alternative.

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
  projects and must be re-vetted before Django 6 adoption, re-confirmed on
  9 Aug 2026: the shipped artifact declares Django 4.2 through 5.2 and no
  Django 6 line. Its development branch reads ahead of that, so pin the
  disposition to what the release declares rather than to what the repository
  says, and re-check when the next version ships.

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

Requirements 2, 5, and 6 are together the defense against the **mix-up
attack**, which is the name the advisories use for it. Where a client
supports more than one provider, an attacker who can influence which provider
a login started with induces the client to send an authorization code to the
wrong token endpoint, or to accept an assertion from one issuer as though it
came from the intended one. Binding the authorization response to the issuer
that produced it — `state` bound to the provider, the code exchanged only at
that provider's token endpoint, and an exact issuer check on the ID token —
is what closes it, and each of the three is already required above.

Keep provider client secrets, signing keys, authorization codes, and tokens out of
source and logs. Request minimal scopes. Store refresh/access tokens only when the
application needs ongoing provider API access; encrypt them, restrict access,
rotate/revoke them, and delete them on disconnect. Re-authenticate before linking
or unlinking a provider. ASVS 5.0 covers this flow in V10, where V10.2 and
V10.5 carry the client and relying-party duties above while V10.4 carries the
authorization-server duties a client depends on rather than implements, and
ID-token claim validation sits in V9. `00-methodology-and-severity.md` holds
the chapter mapping and the rule for when to cite one at all.

### Django & DRF implementation layer

Trace the full flow: login-start view, session/state store, provider configuration,
callback, code exchange, token verification, adapter/pipeline, local-account lookup
and linking, token persistence, logout/disconnect, and logs. Test swapped-provider,
state replay, nonce replay, redirect confusion, wrong issuer, wrong audience,
expired token, unverified email, duplicate email, and account-linking takeover.

**django-allauth.** `django-allauth==65.19.0` passes the gate; require
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

**django-oauth-toolkit.** `django-oauth-toolkit==3.4.0` passes the gate when the
application is an OAuth authorization/resource server, and `>=3.4.0` is a floor
rather than a preference: 3.4.0 fixed an unauthenticated open redirect from the
authorization endpoint under `prompt=none`, HS256 ID tokens signed with the
hashed instead of the plaintext client secret, cleartext tokens and codes
rendered in the admin, client secrets written to debug logs, predictable
device-flow `user_code` values, and four redirect-URI matching deviations from
RFC 9700. Treat an install at 3.3.0 or earlier as a finding. PKCE is required by
default; keep it required, use authorization code rather than implicit/password
grants, register exact redirect URIs, hash client secrets, issue narrow scopes and
short lifetimes, and enable OIDC only when its signing/claim/key lifecycle has been
reviewed. Older installations must include `oauthlib>=3.2.2` because that release
fixed CVE-2022-36087.

**social-auth-app-django.** `social-auth-app-django==6.0.1` passes the gate; require
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

Service-to-service mutual TLS **is** in scope and lives in
`service-identity-and-secrets.md`, along with certificate-bound tokens and the
proxy-set client-certificate identity a Django application actually consumes.
Human-facing mTLS and SAML stay outside this skill; when encountered, audit
their maintained library configuration rather than reimplementing protocol
internals.

**Passkeys and WebAuthn** are audited at that same depth, and the depth is a
finding about the ecosystem rather than a gap: Django ships no native WebAuthn
support through 6.1, so there is no framework surface to review — only a
library's configuration, since the registration and authentication ceremonies
belong to a vetted implementation and not to a hand-written one. On allauth,
WebAuthn is inert until `MFA_SUPPORTED_TYPES` names `"webauthn"`; the default
is `["recovery_codes", "totp"]`. `MFA_PASSKEY_LOGIN_ENABLED` and
`MFA_PASSKEY_SIGNUP_ENABLED` both default to `False`, and the first is not a
convenience toggle — turning it on makes a passkey a complete login rather
than a second factor, which changes the authentication model and needs the
recovery path reviewed with it. The second additionally requires mandatory
email verification with `ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED`.
`MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN` exists for localhost development and is
a finding anywhere else, because relying-party ID and origin binding are what
stop a credential registered for one site from being replayed at another.
Underneath sit `webauthn` (py_webauthn) `3.0.0` and Yubico's `fido2` `2.2.1`,
both released 29 June 2026 and checked 9 Aug 2026; neither declares a Django
version because neither is a Django package, so they are version floors to
confirm rather than gate entries. Check that the user-verification requirement
matches the assurance the flow claims, and that registration and
authentication responses are verified server-side rather than trusted.

## REMOTE_USER and header authentication

`RemoteUserMiddleware` logs in whoever `request.META["REMOTE_USER"]` names.
Under WSGI that key comes from the server's own authentication module, and not
from a client header. CGI mapping turns a client-sent `Remote-User` header into
`HTTP_REMOTE_USER`, which is a different key. The custom-header variants are
the trap. A subclass with `header = "HTTP_X_REMOTE_USER"` trusts a
client-settable header. It is safe only where the proxy overwrites that header
on every request, and strips every inbound copy, error paths and internal hops
included (`deployment-and-runtime.md`, "Reverse proxy and forwarded headers").

- Set `RemoteUserBackend.create_unknown_user = False`, unless the design
  deliberately creates a user from the header. The default is `True`, so every
  name the header carries becomes a database user.
- `PersistentRemoteUserMiddleware` sets `force_logout_if_no_header = False`, so
  the session survives after the header disappears. Use it only on a login
  endpoint that the proxy guards, and never site-wide beside another login
  path.
- Normalization at the edge is part of the control. A header that differs only
  by an underscore, or by a duplicate name, must not reach Django.

**Write-time.** Do not generate a custom-header subclass unless the request
names the fronting proxy. When you do generate one, write the proxy
strip-and-set rule into the deployment notes in the same edit.

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

### Django & DRF implementation layer

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
- [ ] password validators set a 15-character floor wherever the password is a
      single factor, impose no composition rule and no periodic expiry, and
      screen the candidate against a breach corpus rather than against the
      20,000-entry common-password list alone;
- [ ] the user model normalizes its identifier once, on every write path, and
      the database enforces uniqueness over the value the login comparison
      reads rather than over whatever was typed;
- [ ] `is_active` is a declared field rather than the inherited constant, and
      every credential path re-reads it or expires quickly enough to stand in
      for that;
- [ ] session cookies, CSRF, rotation, idle/absolute lifetime, logout, and sensitive
      re-authentication match the deployment architecture;
- [ ] `SESSION_ENGINE` keeps a server-side record wherever revocation, forced
      logout, or an operator kill switch is a requirement, and no
      authenticated application runs on `signed_cookies`;
- [ ] every path that sets a password calls `update_session_auth_hash()` for
      the session it runs in and invalidates the caller's other credentials;
- [ ] JWTs have fixed algorithms, issuer/audience/time validation, short lifetime,
      key rotation, and a revocation/staleness strategy; package compatibility is proven;
- [ ] machine tokens from an external issuer are verified against a cached,
      rotation-aware key set, with the algorithm pinned in configuration and
      required claims enforced rather than assumed;
- [ ] tokens are revalidated per request, audience is checked against this
      service, and no inbound token is forwarded to a downstream hop;
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
      single-use, and all factor lifecycle events are audited without secrets;
- [ ] an email change re-authenticates, completes on confirmation at the new
      address, notifies the old one, and any purpose other than password reset
      uses its own token generator rather than `default_token_generator`;
- [ ] no header carries an identity into `RemoteUserMiddleware` unless the
      proxy overwrites it and strips every inbound copy, and
      `create_unknown_user` is `False` unless the design provisions users.
