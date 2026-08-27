# A07:2025 — Authentication Failures

This file covers password, session, token, federated-login, API-key, recovery,
and anti-automation controls. API mappings include API2:2023 (Broken
Authentication).

This file owns the **human principal**. It owns the proof that a person is who
they claim to be, and the lifecycle of every credential issued to one. A
machine principal is a different problem. `service-identity-and-secrets.md`
owns machine-token validation, JWKS rotation, mutual TLS, and workload
identity. The API-key discipline here stays the bar a static service key still
has to meet.

`a04-cryptographic-failures.md` owns the hashing family, its parameters, and
the generation of every token this file then stores. `a06-insecure-design.md`
owns which flows need anti-automation. `authorization-architecture.md` takes
over the moment identity is established, because authentication ends where
authorization begins.

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

Authentication establishes an identity. Authorization decides what that
identity may do. Treat passwords, sessions, JWTs, OAuth authorization
artifacts, provider tokens, API keys, recovery links, and MFA factors as
distinct credentials. Give each one explicit issuer, audience, lifetime,
storage, rotation, revocation, and logging rules. Fail closed, resist
enumeration and automation, and re-authenticate before a sensitive change.
Never infer authorization merely because authentication succeeded.

## The user model as an identity contract

### Principle layer

Authentication compares a submitted identifier against a stored one. Three
answers make up the identity model. They are which field is the identifier,
what transformation runs before the store writes it, and what the store treats
as equal. None of the three is visible at the login view. Two accounts are the
same principal exactly when those three answers agree.

They disagree in one of two directions, and each direction has its own
failure. Where the comparison is looser than the uniqueness constraint, two
rows answer to one typed identifier, and a database detail decides which one
authenticates. Where the comparison is stricter, the owner cannot reach their
own account, and registers a second one.

Unicode widens that gap rather than creates it. NFKC normalization maps
distinct inputs onto one string, such as a fullwidth `ａ` onto `a`, or the `ﬁ`
ligature onto `fi`. Thus two registrations that looked different collide
afterward, and one of them is now an existing account. Case folding is the
same shape with a different table. `str.lower()` and `str.casefold()` are not
one function, and `casefold()` maps `ß` to `ss` where `lower()` leaves it.

Homoglyphs need no normalization at all. A Cyrillic `а` in a username, a
display name, or an email domain renders identically to the Latin letter, and
compares unequal. That is the direction that favors an attacker, because the
impersonating value is the new row rather than the existing one.

One rule covers all of it. **Normalize once, at the boundary, in one
documented form; store the normalized value; enforce uniqueness on the stored
value; compare the stored value.** A second normalization applied at another
layer in another form is a second identity model, and the system now has two.

A disabled account is part of the same contract. The disable ends access only
on the paths that re-read the account. Thus a credential that carries its own
authorization, and that nothing revalidates, outlives the disable by its own
lifetime. That is why the offboarding control in
`authorization-architecture.md`, "Identity lifecycle and provisioning
desynchronization", enumerates credentials rather than trusts a flag.

### Django & DRF implementation layer

Three class attributes carry the contract, and only two do what their names
suggest.

- **`USERNAME_FIELD`** names the field `authenticate()` looks up and
  `get_username()` returns. It has to be unique.
- **`EMAIL_FIELD`** names the field mail flows address, read through
  `get_email_field_name()`, which falls back to `"email"` when the attribute
  is absent.
- **`REQUIRED_FIELDS`** is prompted by `createsuperuser` and by nothing else.
  It constrains no form, no serializer, and no API. `auth.checks` verifies
  only that it is a list, and that it excludes `USERNAME_FIELD`. A reader who
  takes it for a validation rule makes the common error.

`BaseUserManager.get_by_natural_key()` is one exact lookup,
`self.get(**{USERNAME_FIELD: username})`. Thus the case behavior of every
login belongs to the column's collation rather than to Django. PostgreSQL
compares case-sensitively by default, and MySQL's default collations do not.
That makes the same code two identity models. On MySQL `Alice` logs in as
`alice`, and cannot register a second account beside her. On PostgreSQL she
does neither: the login fails and the registration succeeds.

Read off the Django 6.0.7 and 5.2.15 source on 14 Aug 2026.

`BaseUserManager.normalize_email()` lowercases **the domain part only**. That
is correct, because the local part is case-sensitive to the mail standards.
Reviewers routinely mistake it for a full normalization: `Alice@Example.COM`
is stored as `Alice@example.com`. `AbstractBaseUser.normalize_username()`
applies `unicodedata.normalize("NFKC", ...)`.

Neither one runs on a bare `.save()`. `AbstractBaseUser.clean()` calls
`normalize_username`, and `AbstractUser.clean()` calls `normalize_email`, so
both reach a ModelForm and the admin through `full_clean()`.
`UserManager._create_user_object()` calls both directly. A DRF serializer, a
hand-written signup view, or a social-auth adapter that assigns the field
itself runs none of them. That is how one project normalizes on half its write
paths.

Django compares identity two ways itself. That is the clearest available
demonstration that the comparison is a choice rather than a property of the
data. `PasswordResetForm.get_users()` filters `email__iexact`, then re-filters
through `_unicode_ci_compare()`, which is NFKC plus `casefold()`. It mails
**every** surviving match. Login, against the same rows, does the exact lookup
above. A project on a case-sensitive collation therefore has a reset flow that
finds an account the login flow will not.

Override `get_users()` onto the one normalization function, and filter the
exact column. Leave it alone, and recovery keeps a comparison the login path
does not have. That divergence lands in the flow that gives out account
access, and it mails a link for every row it matches.

`UnicodeUsernameValidator`, the default on `AbstractUser.username`, is
`r"^[\w.@+-]+\Z"` with `flags = 0`. Thus `\w` matches any Unicode word
character, and a Cyrillic `аdmin` passes. `ASCIIUsernameValidator` is the same
expression under `re.ASCII`, and it is the right choice wherever a username is
displayed as identity. Neither one addresses confusability inside a
mixed-script value, and a display name has no validator at all.

Reject an identifier that mixes scripts at registration, unless the product
serves a population that needs the mix. The display name is the harder half,
because it carries no uniqueness rule, no validator, and no normalization.
Never derive an authority claim from a name a user chose. Render a staff,
system, or support actor from the row's own role in the template. A Cyrillic
`Аdmin` in the database then cannot render as one in the product.

**Uniqueness has to sit on the value the comparison reads.** `unique=True`
constrains the stored bytes. Thus where the application normalizes before it
compares, but stores what the user typed, the constraint does not cover the
comparison. An application-level "does this exist yet" query followed by a
save is a race rather than a control (`a10-exceptional-conditions.md`).

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
# Correct: the stored value is the normalized value, so the database compares
# the same bytes the login lookup compares. save() carries the transformation,
# because clean() reaches a form and reaches no serializer. The read side
# normalizes through the same function, or the owner of alice@example.com
# cannot log in as Alice@Example.COM.
import unicodedata

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models


def normalize_identity(value):
    if not value:
        raise ValidationError("This field is required.")
    value = unicodedata.normalize("NFKC", value)
    value = BaseUserManager.normalize_email(value).lower()
    # Validate what gets stored rather than what arrived. normalize_email
    # passes "admin" and "a@b@c.com" through unchanged, and the EmailField
    # check runs on a form and not on save().
    validate_email(value)
    return value


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra):
        # save() normalizes, so this path inherits the guarantee.
        user = self.model(email=email, **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def _lookup_value(self, username):
        try:
            return normalize_identity(username)
        except ValidationError:
            # A malformed identifier is a failed login and not a 500. The
            # miss also keeps ModelBackend on its dummy-hash branch.
            raise self.model.DoesNotExist

    def get_by_natural_key(self, username):
        return self.get(email=self._lookup_value(username))

    async def aget_by_natural_key(self, username):
        return await self.aget(email=self._lookup_value(username))


class User(AbstractBaseUser):
    # unique=True over the stored value is the whole constraint, because the
    # stored value is already normalized. A Lower() or a casefold() expression
    # here is a second comparison function, and thus a second identity model.
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    USERNAME_FIELD = "email"
    objects = UserManager()

    def save(self, *args, **kwargs):
        self.email = normalize_identity(self.email)
        super().save(*args, **kwargs)
```

This manager is an identity example. The password-policy rule above still
applies to any path that gives it a human-chosen password.

**`is_active` reaches further than a login form and stops short of a token.**
`AbstractBaseUser` sets a class attribute `is_active = True`, and
`ModelBackend.user_can_authenticate()` reads `getattr(user, "is_active",
True)`. Thus a custom user model that never declares the field is permanently
active, and nothing reports it. That is the reason the example above declares
it.

Where the field exists, `ModelBackend` rejects the user at `authenticate()`
**and** at `get_user()`, which is the session-load path. Thus a live session
stops working on its next request. `ModelBackend._get_permissions()` also
returns an empty set for an inactive user.

The flag cannot reach a credential that the code validates without a read of
the row. `JWTStatelessUserAuthentication` builds its principal from the token
claims and issues no query, so nothing consults `is_active`, and the token
stands until it expires. Checked against SimpleJWT 5.5.1 source on 14 Aug
2026, where `JWTAuthentication` does check it under `CHECK_USER_IS_ACTIVE`,
default `True`. DRF's `TokenAuthentication` re-reads `token.user.is_active` on
every request. The `authtoken` `Token` model stores the key as plain text, so
apply the API-key rules below to every install.

**Choose the user model in the first commit.** Django resolves
`AUTH_USER_MODEL` at migration time, and every migration that already points
at `auth.User` continues to point at it. Thus a late move is a schema problem
before it is a security one. The security consequence is the workaround teams
use instead. Identity sits on a profile row, and `USERNAME_FIELD` stays
`username`. The address people actually log in with lives on a related model,
under its own uniqueness rule or under none. The normalization rule above now
has two homes, and they will diverge.

**Write-time.** When you generate a project's user model, declare a custom
model in the first migration, even where the default would serve. Settle
`USERNAME_FIELD` and the normalization function in that same edit. Both are
cheap now, and you cannot add either one once foreign keys exist.

Route every write of the identifier through one normalization function, and
put the call in `save()`. `clean()` reaches a form and the admin, and it
reaches no serializer, no social adapter, and no bare `.save()`. Store the
normalized value, and put `unique=True` on that stored column. Never express
the transformation a second time as a database function. `Lower()` in SQL and
`str.lower()` in Python are two functions over Unicode, and thus two identity
models again. Normalize the submitted identifier on the read side through the
same function. Override `get_by_natural_key()` **and** `aget_by_natural_key()`,
because `ModelBackend.aauthenticate()` calls the second one and inherits
nothing from the first. When the model does not inherit `AbstractUser`, declare
`is_active` explicitly. Inherited from `AbstractBaseUser` it is a constant
`True`, and every deactivation feature built on it appears to work.

## Password policy

### Principle layer

NIST SP 800-63B-4 states the password-verifier requirements normatively, and
most projects fail the first of them without notice. Section 3.1.1.2,
requirement 1 states two floors. A password used as a **single-factor**
authentication mechanism SHALL be a minimum of **15 characters**. A password
used only as part of a multi-factor process MAY be shorter, but SHALL still be
a minimum of **eight**. Both halves of that split are SHALL-level. The
15-character floor governs the ordinary case of a site where a password alone
logs a user in. The revision matters here. The 2017 edition asked only for
eight, so guidance and validators inherited from it are a tier low.

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
  substrings. The list is expected to draw on previous breach corpuses,
  dictionary words, and context-specific words such as the name of the service
  and the username. A password found on it SHALL be rejected and the reason
  SHALL be given;
- password managers SHALL be allowed and the paste function SHOULD be
  permitted;
- a password hint reachable by an unauthenticated claimant SHALL NOT be stored.
  Knowledge-based authentication or security questions SHALL NOT be used when
  choosing a password; and
- failed-attempt rate limiting SHALL be implemented — the control this file
  covers under "Brute force and enumeration".

Storage is a separate requirement, met elsewhere. The password is salted and
hashed with a salt of at least 32 bits. `a04-cryptographic-failures.md` owns
the hashing family and its parameters.

### Django & DRF implementation layer

`AUTH_PASSWORD_VALIDATORS` ships four validators. A map of them onto the
requirements above locates the one gap that matters:

- `MinimumLengthValidator` defaults to `min_length=8`. Raise it to 15 wherever
  the password is a single factor. Eight is defensible only where the flow
  genuinely enforces a second factor for every account that can reach it. That
  is a claim about the whole login path, rather than about this setting.
- `CommonPasswordValidator` lowercases the candidate and checks it against a
  list of 20,000 common passwords. That is a blocklist in form, but it is
  nowhere near breach scale. It is the requirement projects most often believe
  they have already satisfied. Its `password_list_path` option takes a custom
  file of one lowercase password per line.
- `UserAttributeSimilarityValidator` covers the context-specific-words clause
  for the user's own attributes.
- `NumericPasswordValidator` rejects an all-numeric password.

The validators run where `validate_password()` runs, and nowhere else. The
built-in auth forms and views call it. `set_password()`, the model
constructor, and a manager `create_user()` path do not call it. A password set
through one of them meets no policy at all. Call `validate_password(password,
user=user)` in every custom signup, invitation, reset, change, admin, import,
and API path that takes a human-chosen password. For an account that must hold
no password, call `set_unusable_password()`.

Django imposes no maximum length, no composition rules, and no periodic
expiry. The last two are the correct default rather than gaps, because the
requirement is to *not* impose them. A project that added a character-class
rule or an expiry job is the finding.

**The no-truncation clause is a claim about the hasher, and this file is where
the length policy is set.** `BCryptPasswordHasher` sets `digest = None`, so
bcrypt compares the first 72 bytes and discards the rest. Django's own
docstring says so. Two passwords that share a 72-byte prefix then both
authenticate, while the validators and the breach check read the whole string.
The policy and the compared secret have come apart. `BCryptSHA256PasswordHasher`
hashes with SHA-256 first, so it carries no such limit, and neither does
`argon2` nor `pbkdf2_sha256`. Read off the Django 6.0.7 source on 27 Aug 2026.
A maximum length above 72 on the plain bcrypt hasher is a finding.
`a04-cryptographic-failures.md` owns which family to select.

**"A change SHALL be forced on evidence of compromise" needs a mechanism.**
The clause above is a requirement rather than a policy statement. Put a flag on
the user row, and read it on the authenticated request path. When it is set,
every request routes to the change flow and reaches nothing else. Clear the
flag in the same transaction that writes the new password. Call
`set_unusable_password()` where the evidence covers the credential itself. The
session and token invalidation is the one a change already performs. A flag
that only a login template reads is not the control, because an API client
renders no template and its token stands.

The one requirement no built-in meets is **breached-corpus screening**, and no
package currently clears the gate to provide it.
`pwned-passwords-django==5.2.0` (6 Apr 2025, re-checked 9 Aug 2026) declares
Django 4.2, 5.1, and 5.2, with no Django 6 line at all, on a single
maintainer. Own the check instead.

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
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


class BreachedPasswordValidator:
    def __init__(self):
        self.endpoint = settings.PWNED_RANGE_ENDPOINT
        # Assert the scheme once, at load. A typo that reads "http://" sends
        # the prefix in cleartext to whoever is on the path.
        if not self.endpoint.startswith("https://"):
            raise ImproperlyConfigured("PWNED_RANGE_ENDPOINT must be https.")

    def validate(self, password, user=None):
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        lookup = urllib.request.Request(
            f"{self.endpoint}{prefix}",
            headers={"Add-Padding": "true"},
        )
        try:
            with urllib.request.urlopen(lookup, timeout=2) as response:
                # urlopen follows a redirect, and it permits an https-to-http
                # one. Confirm where the body actually came from.
                if not response.url.startswith(self.endpoint):
                    raise ValueError("redirected off the configured endpoint")
                # Cap the read: a third party controls this response body,
                # and an unbounded read hands it a memory exhaustion.
                body = response.read(2_000_000).decode("utf-8")
            breached = self._is_breached(body, suffix)
        except (urllib.error.URLError, TimeoutError, ValueError):
            # One exit for every failure. ValueError belongs here: it catches
            # the malformed line, and UnicodeDecodeError subclasses it. Without
            # it a hostile or truncated body turns every password change into a
            # 500, which is the opposite of the posture this branch selected.
            logger.warning("breach screening unavailable", exc_info=True)
            return
        if breached:
            raise ValidationError(
                _("This password has appeared in a known data breach."),
                code="password_breached",
            )

    @staticmethod
    def _is_breached(body, suffix):
        for line in body.splitlines():
            candidate, _sep, count = line.partition(":")
            if candidate == suffix:
                return int(count) > 0
        return False

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

State the cost of that check rather than absorb it. It is an outbound call to
a third party on every password set and change. Thus password changes now
depend on that service's availability and latency. The endpoint joins the
hosts the egress policy has to allow, and the call discloses a five-character
hash prefix to it. The `Add-Padding` header adds decoy entries, so the entry
count varies inside a band. The response length stops identifying the queried
prefix. The responses are not the same size.

The fail-open branch is a decision and not a default. A closed failure is the
stronger posture, and the right one for a high-assurance product. It also
denies every password change during an outage nobody in the project controls.

Alert on that branch, whichever way the product decided. A log line that
nobody reads cannot be told apart from a working control. The branch is also
reachable on purpose. An attacker who blocks the egress path turns the
screening off for every account, and sees no failure. An attacker who gets
this application's own address throttled at the third party does the same.
This is the one SHALL-level check that no built-in provides, so its silent
absence is the finding.
SHA-1 appears here as a lookup key for the range API and nowhere else. Storage
remains whatever `PASSWORD_HASHERS` selects.

An outbound call is unacceptable in some deployments. Those are an air-gapped
deployment, a privacy review that will not clear it, or a flow that cannot take
the latency. The offline alternative there is `CommonPasswordValidator` pointed
at a much larger local list through `password_list_path`. It needs no network,
and it discloses nothing. The trade is that somebody has to obtain the file and
review its license. That person also has to ship it with the image, and refresh
it on a schedule they own. A list nobody refreshed is the failure it was added
to prevent.

**Write-time.** When you generate `AUTH_PASSWORD_VALIDATORS`, or any flow that
sets or changes a password, put `min_length` at 15. The exception is a flow
that enforces a second factor for every account that can reach it. Add the
breach-screening validator in the same edit. A project that ships the four
defaults has met the blocklist requirement in form only, and nothing later
prompts a review.

Do not generate a character-class rule or a password-expiry job, even when the
ticket asks for one. Both are SHALL NOTs under SP 800-63B-4, and teams add
expiry in particular by reflex. Where the product needs a maximum length, set
it at 64 or above, and never truncate before the hash.

## Sessions

- Rotate the session identifier on login and on a privilege change. Invalidate
  it on logout, and on a password reset or change, where the product's threat
  model requires it. The next section gives which Django call does which, and
  what the backend has to be before revocation means anything at all.
- Use `Secure`, `HttpOnly`, and an appropriate `SameSite` value.
  `a02-security-misconfiguration.md` holds the full `SESSION_*` and `CSRF_*`
  matrix, and the setting behind each flag. A cookie-authenticated state
  change still needs CSRF protection. `SameSite` is defense in depth.
- **A DRF login endpoint carries no CSRF protection until you add it.** Two
  defaults meet here. `APIView.as_view()` returns `csrf_exempt(view)`, so
  `CsrfViewMiddleware` never runs on it. `SessionAuthentication.authenticate()`
  returns `None` for a request that carries no authenticated user, so
  `enforce_csrf()` never runs either. Checked against the DRF 3.16.1 source on
  27 Aug 2026. A hand-written view that calls `login()` therefore accepts a
  cross-site POST. The attacker logs the victim into an account the attacker
  owns, and then reads what the victim types into it. Apply `csrf_protect` to
  the login view, or gate the flow on a one-time token the login page issues.
- Bound the idle lifetime and the absolute lifetime for a sensitive
  application. Do not place a secret or an authorization decision in
  client-readable session data.
- Review each custom backend and login view for its treatment of an inactive
  user. Django's default `ModelBackend` rejects an inactive user, and a custom
  backend can remove that behavior.
- Re-authenticate and require the current factor before a change to a
  password, an email, MFA, a recovery method, payout details, or other
  security-sensitive state.
- Make the result of that ceremony a bounded artifact rather than a flag on
  the session. A flag lasts as long as the session does, so one hijack after
  one ceremony gives an attacker durable privilege over every sensitive
  operation. Hold the artifact server side. Bind it to the user, to the one
  operation, and to a short expiry, and consume it once.

## Session engines, rotation, and revocation

### Principle layer

Two questions decide what a session is worth. The first is **where the state
lives**, because you can revoke only what you hold a record of. The second is
**when the identifier changes**, because an identifier that survives a
privilege change is a session-fixation vector. A design that answers the
second and not the first can end a session at logout, and cannot end one on
demand.

Revocation is the half teams assume. A self-contained credential, such as a
signed cookie or a bearer token, carries its own authority. Thus "log out" is
a request to the holder rather than an instruction to the server. Where the
product needs log-out-everywhere, forced re-authentication, or an operator
kill switch, that is a design requirement that selects the storage. It is not
a feature you add to a storage already chosen.

### Django & DRF implementation layer

`SESSION_ENGINE` selects one of five backends. Durability separates them, and
so does whether a record exists to delete. Read off the Django 6.0.7 source on
14 Aug 2026:

| Backend | State lives in | Revocation | Loss mode |
|---|---|---|---|
| `db` (default) | a `django_session` row | delete the row | none; needs `clearsessions` scheduled |
| `cached_db` | the cache, then the row | `delete()` clears both | a cache miss falls back to the row |
| `cache` | the cache only | delete the key | an eviction or a flush ends every session |
| `file` | one file per session | delete the file | per host unless the path is shared |
| `signed_cookies` | the client | **none** | nothing to lose and nothing to revoke |

`signed_cookies` is the one to flag. `SessionStore.exists()` returns `False`
unconditionally, and `delete()` only clears the client-side value. Thus the
server holds no record. A cookie copied before logout stays valid until
`SESSION_COOKIE_AGE` expires, and there is no per-session control to end it
early. The two controls that exist are wholesale. A `SECRET_KEY` rotation with
no fallback ends every user's session at once
(`service-identity-and-secrets.md`, "Rotating Django's SECRET_KEY"). A
password change ends one user's session through the auth hash below.

Its payload is **signed and not encrypted**, through `signing.dumps` with
compression. Thus the browser can read everything in `request.session`, and so
can anyone who captured the cookie. `cache` has the mirror-image problem.
Revocation works, and an ordinary eviction or a routine `FLUSHALL` logs
everybody out, which is an availability failure a deploy can cause by
accident. `cached_db` reads the cache and falls back to the row, so a flush
costs a query rather than a session.

Rotation is three calls, and the first does less than its reputation suggests.
`login()` calls `cycle_key()` **only where the session carries no
authenticated user**. `cycle_key()` writes a new key, keeps the same data, and
deletes the old record. That is the fixation case, so the control is present
where it counts. A session that already holds an authenticated user takes a
different branch. A different user, or a mismatched auth hash, flushes the
session. The *same* user who logs in again gets neither call, which leaves the
identifier unchanged.

`login()` also calls `rotate_token()`, which cycles the CSRF secret.
`logout()` calls `flush()`, which clears the data, deletes the record, and
sets the key to `None`.

`update_session_auth_hash(request, user)` is the third call, and the one a
password change needs. `get_session_auth_hash()` is a `salted_hmac` over the
password field, and through the HMAC key over `SECRET_KEY`.
`django.contrib.auth.get_user()` recomputes it and constant-time-compares it
on **every** request. A rewrite of the password therefore invalidates every
session the user has, including the one that makes the change.
`update_session_auth_hash` cycles that session's key and re-stamps its hash,
so it survives.

Django's own `PasswordChangeView` calls it. A hand-written DRF endpoint
usually does not. The symptom is that the caller is logged out by their own
password change. A developer reads that symptom as a bug, and corrects it by a
removal of the invalidation.

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

The endpoint also verifies the current password, and it carries the login-flow
limits from "Brute force and enumeration". Notify the account through an
independent channel on every change, and not on a reset alone. Without that
notice a hijacked session changes the password in silence, and the owner
learns of it at the next failed login.

Treat log-out-everywhere as a stated requirement, rather than as a side effect
of this behavior. A password change already delivers it. A product that needs
the same effect without a password change needs one of two things. It needs a
stored session record to delete, or a per-user credential version the
session-load path reads. `get_user()` also tries `SECRET_KEY_FALLBACKS` before
it fails. A fallback match cycles the key and re-stamps the hash in place,
which is what makes a key rotation survivable at all.

**Write-time.** When you generate a settings module, leave `SESSION_ENGINE` at
`db`, unless the request asked for a different trade. Never generate
`signed_cookies` for an authenticated application. It removes revocation
entirely, and it publishes the session payload to the client. Both are
properties of the first version that nothing later reopens.

When you generate any endpoint that sets a password, call
`update_session_auth_hash()` in the same edit for the session case. That
covers a reset, a change, and an admin-side path. Delete or rotate the
caller's tokens for the token case. The invalidation is the control, and the
exemption for the current session is the part you have to write deliberately.
When you generate a forced-logout or log-out-everywhere feature, choose a
backend with a server-side record first. You cannot add the feature to a
session the server never stored.

## JWT

- Validate the signature, the allowed algorithm, the issuer, the audience, the
  expiry, and the not-before claim. Never derive the accepted algorithm from
  an attacker-controlled header.
- Keep access tokens short-lived. The lifetime **is** the revocation delay for
  a self-contained token, so set it against what the offboarding requirement
  allows rather than against what is convenient. Protect refresh tokens with
  rotation, reuse detection, or a denylist, where the threat model needs
  revocation.
- **Never authenticate a human principal with
  `JWTStatelessUserAuthentication`.** It builds the principal from the claims
  and issues no query. A disable, a suspension, a permission change, and a
  tenancy move therefore all fail to reach the holder. Use `JWTAuthentication`
  for a person, and leave `CHECK_USER_IS_ACTIVE` at its default of `True`. The
  stateless class suits a machine caller whose token is short enough that the
  expiry stands in for the read.
- Put only stable identifiers and minimal authorization context in the claims.
  A token is a snapshot. A change to a permission, a tenancy, a suspension, or
  a key rotation can make a long-lived claim stale.
- Keep signing keys out of source. Assign key IDs deliberately. Rotate the
  keys. Prevent a verifier from a read of symmetric key material as an
  asymmetric key.
- Revalidate on every request, rather than cache a principal for the life of a
  session. Reject a token whose `aud` does not name this service. An audience
  check is what stops a replay here of a token minted for another resource.
- **Never forward an inbound token to a downstream service.** The downstream
  service cannot tell that the caller is an intermediary. Thus it applies the
  token's full authority to a request the intermediary shaped, which is a
  confused deputy (CWE-441). Obtain a separately issued, downstream-scoped
  credential for the next hop. See `agent-and-llm-interfaces.md`, "Inbound
  token validation and the passthrough prohibition".
- SimpleJWT `5.5.1` contains the fix for CVE-2024-22513, but it advertises
  support only through Django 5.2. Re-confirmed on 9 Aug 2026 against the
  classifiers the release publishes, which stop there, on an artifact from 21
  July 2025. Treat it as conditional on a compatible project, not as a Django
  6 default. Check the compatibility again before adoption.
- A token minted by *another* system for a *machine* caller is a different
  problem from one this application issued. `service-identity-and-secrets.md`,
  "Validating an inbound machine token", holds the ordered claim-by-claim
  verification, JWKS caching and rotation, sender-constrained tokens, and the
  library floor. SimpleJWT is not a service-identity mechanism.

## Token storage

- A browser application should prefer secure, HttpOnly cookies where the
  architecture can enforce CSRF. A persistent bearer token in `localStorage`
  is exposed to any successful XSS.
- A native or public client cannot safely keep a client secret. Use
  authorization code plus PKCE, and platform-protected credential storage.
- Store server-side refresh tokens and provider tokens encrypted, or in a
  secrets service, where they are genuinely required. Do not persist them “for
  later.”
- Never place a password, a code, a bearer token, a refresh token, an ID
  token, or an API key in a URL. Redact authorization headers, cookies,
  callback parameters, and credentials from logs, tracing, errors, analytics,
  and support exports.
- The authorization response is the one exception, because the code flow this
  file requires returns `code` and `state` in the callback query string. Three
  conditions keep it an exception. The code is single-use and short-lived. The
  callback response carries `Referrer-Policy: no-referrer`. The log pipeline
  redacts `code` and `state` from the request line at every hop. Without them
  the edge logs hold live codes, and a third-party resource on the callback
  page carries one out through `Referer`.

## Brute force and enumeration

Use layered limits across the account, the normalized identifier, the network
or device signal, and the high-value flow. Keep responses and timing uniform
enough that the login, signup, reset, invite, and MFA endpoints do not reveal
account existence. Uniform bytes are half of that. A branch that returns
before the password hash runs answers faster, and the latency is the oracle.
Monitor distributed attempts, and alert on lockout and credential-stuffing
patterns. A hard permanent account lock lets an attacker deny service to a
victim. Use bounded backoff, recovery, and risk signals.

`ModelBackend` already carries the login half of that. On a miss it calls
`UserModel().set_password(password)`, so an absent account costs the same hash
as a present one. Read off the Django 6.0.7 source on 27 Aug 2026. A custom
backend, or a DRF login view that looks the user up itself, returns early on
`DoesNotExist` and drops that branch. The oracle comes back, and no test
fails. Run the hasher on the miss in every backend you write. Equalize the
reset path the same way, where the mail send is the work that differs.

**Aggregate the network signal to a prefix.** A single address is not a
network identity. One ordinary IPv6 allocation gives a client a /64. An
attacker therefore uses a fresh source address for each attempt, and a
per-address limit counts one attempt against each. Key the network layer on
the routed prefix rather than on the address. Keep a global velocity limit
above it that no rotation of a per-key value escapes. Treat rapid rotation
inside one prefix as an attack signal rather than as traffic.

`django-axes==8.3.1` passes the maintained-package gate for Django 6.0 login
monitoring and lockout. Its correctness depends on the trusted-proxy and
client-IP configuration. It does not replace edge limits, business-flow
quotas, MFA, or compromised-password defenses. `django-defender` does not pass
the current gate.

The device-cookie pattern is the answer to the denial-of-service edge above.
On each successful login, set a signed cookie that names the account. On a
later attempt, throttle the `(account, device-cookie)` pair separately from an
attempt that carries no valid cookie. The owner on a known device continues to
log in, and an unknown device gets the hard limit.

Sign the cookie with `django.core.signing` under its own salt
(`a04-cryptographic-failures.md`, "Signing and salt discipline"). A signed
payload is readable, so carry an opaque device identifier and a version inside
it, and never the account address. Hold the link to the account in a
server-side device row, which is also the record that makes a revocation
possible. Set `Secure`, `HttpOnly`, and `SameSite` on the cookie, and give it
an expiry. Increase the version on a credential change, so that an old cookie
stops working. Revoke the device row on a lockout event too. This cookie
waives a limit, so whoever steals one holds the lenient guessing rate against
the account it names until something ends it.

**Write-time.** When you generate a login, signup, reset, invite, or MFA
endpoint, return the same public response on the account-exists and
account-absent branches. Wire the lockout in the same change, rather than
after the first credential-stuffing run. Both the oracle and the missing limit
are properties of the first version, and neither one appears as a failing
test.

Never leave `django-axes` at its defaults, because they contradict the
principle above. Read off the django-axes 8.3.1 source on 27 Aug 2026:
`AXES_FAILURE_LIMIT` is 3, `AXES_LOCKOUT_PARAMETERS` is `["ip_address"]`, and
`AXES_COOLOFF_TIME` is `None`. A `None` cool-off is a permanent lock, and the
library names its own message `AXES_PERMALOCK_MESSAGE`. Only an `axes_reset`
management command ends it. Three failures from one address therefore lock
that address out until an operator intervenes. A shared address then locks out
every user behind it, and an attacker who changes address is never limited.

Set a bounded `AXES_COOLOFF_TIME` in the same edit that installs the package.
Name the normalized identifier in `AXES_LOCKOUT_PARAMETERS`, beside the
network signal, so that the limit follows the account an attacker targets.
Review `AXES_RESET_ON_SUCCESS`, which is `False`. Settle the trusted-proxy and
client-IP configuration in that edit as well. A lockout keyed on a spoofable
address locks out whichever principal the attacker names. Two adjacent
defaults belong to the same moment. The credential the flow issues is
single-use and expiring. The session identifier is rotated on login and on
any privilege change, so a session captured before the change does not
survive it.

## Password reset

- Return the same public response for an existing account and an absent
  account. Apply the same anti-automation controls to both paths.
- Use a cryptographically random, single-use, short-lived token bound to the
  intended account and purpose. Invalidate a prior token after use, and after
  a relevant credential change.
- Build an absolute reset URL from a trusted configured origin, not from an
  untrusted Host header. Do not leak a token through Referer, a third-party
  resource, analytics, or logs.
- Confirm the new password twice. Apply the password validators. Rotate the
  sessions as the policy requires. Notify the account through an independent
  channel, and do not include the new credential.
- **A completed reset never satisfies the second factor.** A reset proves
  control of the recovery channel, and it proves nothing about an enrolled
  factor. Challenge the factor before the flow issues a session or a token.
  Otherwise whoever holds the mailbox holds the account, and every MFA control
  in this file is reachable around rather than through. Where the factors are
  genuinely lost, route the user to a separate recovery flow. Give that flow
  its own delay, its own notice to the old channel, and a human review.
- Bound the token lifetime rather than inherit it. `PASSWORD_RESET_TIMEOUT`
  defaults to `60 * 60 * 24 * 3`, which is three days. Read off the Django
  6.0.7 `global_settings` on 27 Aug 2026. A link stays actionable for that
  whole window inside a forwarded mailbox or a proxy log. Set the value to
  what the flow needs.

## Email change and purpose-bound tokens

The email address is the account's recovery root, so a change of address is a
privileged operation.

- Re-authenticate before the change. Require the current password, and require
  the second factor where the account has one. A live session is not a
  substitute for either one. A hijacked session is exactly what an attacker
  holds, and it reads as fresh under any natural implementation. The address
  is the recovery root, so a possession-only branch here hands over the whole
  account through the reset flow afterward.
- Send a confirmation link to the new address. The change happens on
  confirmation, never on request.
- Notify the old address. Give that notice a revert path, and keep the path
  valid after the change completes. The completion must not end it, and a
  short expiry must. Give the path one use and its own re-authentication.
  Leave it unbounded, and any later control of the old mailbox repoints the
  recovery root and takes the account.
- Never carry the new address inside a client-held signed token. Hold the
  address on the server, keyed by the token.

`default_token_generator` hashes five values into a reset token. They are the
user's primary key, the password hash, the `last_login` timestamp, the token
time, and the email address. The list comes from Django 6.0.7 source, checked
on 20 Aug 2026. The address is one of the five, so a change of address already
invalidates every outstanding reset token on that account. A custom generator
or a stored token row does not get that property. Invalidate the outstanding
tokens in the same transaction as the address change.

That design is single-purpose. Reuse it for email confirmation, and the link's
validity starts to depend on unrelated logins. A reset token also becomes
exchangeable for a confirmation, because the same user state produces the same
token.

Issue purpose-bound tokens instead. Subclass `PasswordResetTokenGenerator` for
each purpose. Give the subclass its own `key_salt`. Override
`_make_hash_value()` to append the purpose string and the normalized target
address. A single-use random token row with an expiry is the alternative.

The subclass takes two properties with it, and neither one is per purpose.
`check_token()` reads `settings.PASSWORD_RESET_TIMEOUT` directly, so every
purpose shares the one lifetime and no purpose can shorten it. Single use is
also inherited rather than implemented: the token dies because the hashed user
state changes on completion. A purpose that changes none of that state
therefore replays for the whole shared window. Prefer the stored token row for
such a purpose. Consume that row atomically (`a10-exceptional-conditions.md`,
"Races, TOCTOU, and adversarial sequencing").

## MFA

- Prefer a phishing-resistant factor where the application supports one.
  Otherwise TOTP is stronger than SMS. Recovery codes are credentials.
  Generate them with a CSPRNG, display each one once, store only hashes,
  rate-limit the checks, and rotate them after use.
- Give each recovery code at least 128 bits of entropy, or hash it with the
  password hasher. "Store only hashes" is not the whole rule. A short code
  under a fast digest is exhaustible from one database copy. The rate limit on
  the endpoint does not reach a search that never calls the endpoint.
- **Encrypt the TOTP shared secret at rest.** A seed is a standing credential
  rather than a verifier, so a hash cannot stand in for it.
  `django-otp==1.7.0` stores `TOTPDevice.key` as a hex `CharField`, which every
  database copy, backup, and snapshot discloses. Read off the shipped 1.7.0
  source on 27 Aug 2026. One read then generates a valid code for every
  enrolled user, for as long as the enrollment lasts, and the account owner
  sees nothing. `data-layer-and-database.md`, "Field-level encryption and
  searchable lookups", holds the mechanism and its cost. Add the seed column
  to the export and redaction rules in the same change.
- Protect factor enrollment, replacement, and removal with re-authentication.
  Also require an already-trusted factor, or a carefully reviewed recovery
  flow.
- Prevent replay. Rate-limit the attempts. Define the clock-skew tolerance
  narrowly. Audit the factor lifecycle events, and do not log a secret.
- `django-otp==1.7.0` passes the current gate and supports Django 6.0.
  `django-two-factor-auth==1.18.1` is conditional for a compatible Django 5.2
  project, and you must re-vet it before Django 6 adoption. Re-confirmed on 9
  Aug 2026: the shipped artifact declares Django 4.2 through 5.2, and no
  Django 6 line. Its development branch reads ahead of that. Pin the
  disposition to what the release declares, rather than to what the repository
  says, and check again when the next version ships.

## OAuth2, OIDC, and social login

### Principle layer

OAuth delegates authorization, and OIDC adds an identity layer. An OAuth
access token is not proof of OIDC identity. For every login transaction:

1. use authorization code flow with PKCE (`S256`); do not use implicit flow or the
   resource-owner-password grant;
2. generate an unpredictable `state`. Bind it to the initiating browser
   session, the provider, the redirect target, and a short expiry. Consume it
   once;
3. for OIDC, generate and validate a one-time `nonce`;
4. pre-register the redirect URIs and require an exact match. Permit no
   wildcard, no suffix check, no user-controlled callback, no open redirect,
   and no untrusted Host-derived URI. A post-logout redirect target is a
   redirect URI, and it takes the same exact match. An unchecked one is an
   open redirect on the authentication domain itself;
5. exchange the code only with the intended token endpoint over verified TLS;
6. validate the ID-token signature with an allowed algorithm and a trusted
   key. Then validate the exact issuer, the audience or client ID, the expiry
   and not-before, and the nonce;
7. identify the external account by the stable `(issuer, sub)` pair. Do not
   key an account by email, username, `preferred_username`, or another mutable
   claim; and
8. link accounts only after an explicit authenticated ceremony, or after a
   provider-specific, proven verified-email policy that handles collisions
   safely.

Requirements 2, 5, and 6 are together the defense against the **mix-up
attack**, which is the name the advisories use for it. Where a client supports
more than one provider, an attacker can influence which provider a login
started with. That attacker then induces the client to send an authorization
code to the wrong token endpoint. The attacker can also induce it to accept an
assertion from one issuer as though it came from the intended one.

A binding of the authorization response to the issuer that produced it is what
closes the attack. That binding is `state` bound to the provider, and the code
exchanged only at that provider's token endpoint. It also carries an exact
issuer check on the ID token. Each of the three is already required above.

Keep provider client secrets, signing keys, authorization codes, and tokens
out of source and logs. Request minimal scopes. Store a refresh or access
token only where the application needs ongoing provider API access. Encrypt
those tokens, restrict access to them, rotate and revoke them, and delete them
on disconnect. Re-authenticate before a link or an unlink of a provider.

ASVS 5.0 covers this flow in V10. V10.2 and V10.5 carry the client and
relying-party duties above. V10.4 carries the authorization-server duties a
client depends on rather than implements. ID-token claim validation sits in
V9. `00-methodology-and-severity.md` holds the chapter mapping, and the rule
for when to cite one at all.

### Django & DRF implementation layer

Trace the full flow. It covers the login-start view, the session and state
store, the provider configuration, the callback, and the code exchange. It also
covers the token verification, the adapter or pipeline, the local-account
lookup and link, the token persistence, the logout or disconnect, and the logs.
Test swapped-provider, state replay, nonce replay, redirect confusion, wrong
issuer, wrong audience, expired token, unverified email, duplicate email, and
account-linking takeover.

**django-allauth.** `django-allauth==65.19.0` passes the gate. Require
`>=65.16.1` on its current line. Preserve these fail-closed defaults, and
enable PKCE in each OAuth and OIDC provider configuration that supports it:

```python
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = False
SOCIALACCOUNT_LOGIN_ON_GET = False
SOCIALACCOUNT_STORE_TOKENS = False
```

Do not enable automatic email authentication or connection as a generic
convenience. Use a reviewed adapter for provider-specific verified-email
semantics, and for an explicit link. Protect provider secrets stored in
`SocialApp` as production secrets. Use the provider's stable subject as
identity, not a display claim or an email claim.

**dj-rest-auth.** `dj-rest-auth==7.2.0` is acceptable as a DRF-facing wrapper
only where the underlying allauth adapter and provider settings satisfy this
section. Prefer the authorization-code path with a fixed configured callback
URL. Audit any endpoint that accepts `access_token`, `code`, or `id_token`.
Each artifact must serve only its defined protocol purpose, and an access
token alone must not pass as identity proof. Apply the CSRF, CORS, and session
controls to the chosen browser architecture. Do not assume that a REST wrapper
removes them.

**django-oauth-toolkit.** `django-oauth-toolkit==3.4.0` passes the gate where
the application is an OAuth authorization or resource server. `>=3.4.0` is a
floor rather than a preference. 3.4.0 fixed an unauthenticated open redirect
from the authorization endpoint under `prompt=none`. It fixed HS256 ID tokens
signed with the hashed client secret instead of the plaintext one, and
cleartext tokens and codes rendered in the admin. It fixed client secrets
written to debug logs, predictable device-flow `user_code` values, and four
redirect-URI matching deviations from RFC 9700. Treat an install at 3.3.0 or
earlier as a finding.

PKCE is required by default. Keep it required. Use authorization code rather
than an implicit or password grant. Register exact redirect URIs. Hash the
client secrets. Issue narrow scopes and short lifetimes. Enable OIDC only
after a review of its signing, claim, and key lifecycle. An older installation
must include `oauthlib>=3.2.2`, because that release fixed CVE-2022-36087.

**social-auth-app-django.** `social-auth-app-django==6.0.1` passes the gate.
Require `>=5.6.0`. Review the pipeline order, the state validation, the
redirect allowlist, the backend selection, and the stable provider UID. Do not
add `associate_by_email` unless the specific provider guarantees a verified
email, and the product has an explicit collision and linking policy. The
default pipeline omits it, and that omission is a security boundary.

**mozilla-django-oidc.** Treat `5.0.2` as existing-install audit only, not as
a new recommendation. It does not advertise Django 6 support, and
`OIDC_USE_PKCE` defaults to false. Open issue #340 documents missing exact
issuer and audience validation in the default verification path.

An existing use must set `OIDC_USE_PKCE = True`. It must keep `OIDC_USE_NONCE`,
`OIDC_VERIFY_JWT`, `OIDC_VERIFY_KID`, and TLS verification enabled. It must use
`S256`, and keep unsecured JWTs and token storage disabled. It must provide a
reviewed `verify_token` override or replacement. That code enforces the exact
issuer and the audience or client ID, as well as the signature, the algorithm,
the expiry, and the nonce. Otherwise, replace the integration.

Service-to-service mutual TLS **is** in scope, and it lives in
`service-identity-and-secrets.md`. That file also holds certificate-bound
tokens and the proxy-set client-certificate identity a Django application
actually consumes. Human-facing mTLS and SAML stay outside this skill. Where
you meet one, audit its maintained library configuration rather than
reimplement the protocol internals.

Audit **passkeys and WebAuthn** at that same depth. The depth is a finding
about the ecosystem rather than a gap. Django ships no native WebAuthn support
through 6.1, so there is no framework surface to review, only a library's
configuration. The registration and authentication ceremonies belong to a
vetted implementation, and not to a hand-written one.

On allauth, WebAuthn is inert until `MFA_SUPPORTED_TYPES` names `"webauthn"`.
The default is `["recovery_codes", "totp"]`. `MFA_PASSKEY_LOGIN_ENABLED` and
`MFA_PASSKEY_SIGNUP_ENABLED` both default to `False`, and the first is not a
convenience toggle. It makes a passkey a complete login rather than a second
factor, which changes the authentication model and needs the recovery path
reviewed with it. The second one additionally requires mandatory email
verification with `ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED`.

`MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN` exists for localhost development, and it
is a finding anywhere else. The relying-party ID and the origin binding are
what stop a replay at another site of a credential registered for one site.
Underneath sit `webauthn` (py_webauthn) `3.0.0` and Yubico's `fido2` `2.2.1`,
both released 29 June 2026 and checked 9 Aug 2026. Neither declares a Django
version, because neither is a Django package, so they are version floors to
confirm rather than gate entries. Check that the user-verification requirement
matches the assurance the flow claims. Check that the server verifies the
registration and authentication responses, rather than trusts them.

## REMOTE_USER and header authentication

`RemoteUserMiddleware` logs in whoever `request.META["REMOTE_USER"]` names.
Under WSGI that key comes from the server's own authentication module, and not
from a client header. CGI mapping turns a client-sent `Remote-User` header
into `HTTP_REMOTE_USER`, which is a different key.

The custom-header variants are the trap. A subclass with `header =
"HTTP_X_REMOTE_USER"` trusts a client-settable header. It is safe only where
the proxy overwrites that header on every request, and strips every inbound
copy. That includes the error paths and the internal hops
(`deployment-and-runtime.md`, "Reverse proxy and forwarded headers").

Under ASGI the picture is different, and Django's own documentation says the
spoofing warning applies there in all configurations. An ASGI server cannot
put a trusted value in the environ, so no key is out of the client's reach.
The default `header = "REMOTE_USER"` therefore reads `HTTP_REMOTE_USER` under
ASGI, which is the client-sent header.

From Django 6.1 the framework reads a custom `header` exactly as written under
ASGI. Django 5.2 and 6.0 added an `HTTP_` prefix to it on the async path only.
One subclass therefore resolved two different keys under WSGI and ASGI. Write
the full key yourself now. `header = "HTTP_AUTHUSER"` receives an `AuthUser:`
request header. Verified against the 6.1, 6.0, and 5.2 source on 20 Aug 2026.

That change is silent on upgrade. A 6.0 ASGI subclass with `header =
"X_REMOTE_USER"` reads a key nothing populates on 6.1, so the lookup raises
`KeyError` on every request. `RemoteUserMiddleware` fails closed there,
because `force_logout_if_no_header` defaults to `True`.
`PersistentRemoteUserMiddleware` sets it to `False`, so the missing header
logs nobody out. The session then outlives any revocation at the proxy.

Django 6.1 also removed the shim for a subclass that overrides
`process_request()` and not `aprocess_request()`. Django 6.0 warned, and still
ran the sync override through `sync_to_async`. Django 6.1 calls
`aprocess_request()` directly, so it skips the override under ASGI while the
base class still authenticates. Any check the subclass added there stops
running. Override both methods, or move the check into `RemoteUserBackend`.

- Set `RemoteUserBackend.create_unknown_user = False`, unless the design
  deliberately creates a user from the header. The default is `True`, so every
  name the header carries becomes a database user.
- `PersistentRemoteUserMiddleware` sets `force_logout_if_no_header = False`,
  so the session survives after the header disappears. Use it only on a login
  endpoint that the proxy guards. Never use it site-wide beside another login
  path.
- Normalization at the edge is part of the control. A header that differs only
  by an underscore, or by a duplicate name, must not reach Django.

**Write-time.** Do not generate a custom-header subclass unless the request
names the fronting proxy. When you do generate one, write the proxy
strip-and-set rule into the deployment notes in the same edit. Write the
`HTTP_` prefix into the `header` value yourself when the target is Django 6.1.

## API keys

### Principle layer

API keys identify an application, a project, an integration, or an automation
principal. They are not end-user sessions, and they should not silently
inherit a human's full permissions. For every key:

- generate at least 128 bits of CSPRNG entropy; show the secret once;
- store only a cryptographic digest, with a non-secret prefix or key ID for an
  indexed lookup. Compare the digests in constant time;
- bind it to an explicit owner, tenant, environment, scopes, resource
  constraints, creation actor, expiry, last-used metadata, and status;
- support overlapping rotation, immediate revocation, and audit events for
  create, reveal, use, rotate, expire, and revoke, without a log of the
  secret;
- transmit only over TLS in a header. Never transmit one in a query string, a
  URL, a filename, a client-side bundle, an analytics field, or a repository;
  and
- combine authentication with object and function authorization, quotas,
  anomaly detection, and network restrictions where useful. A known key is not
  blanket authorization.

Use a recognizable prefix plus a secret component, so that a leaked-key
scanner and an operator can classify the key without exposure of the
credential. Rate-limit failed prefix and secret checks, and do not permit an
easy denial of service against a known prefix. Return a generic authentication
failure. Do not disclose whether a prefix exists.

### Django & DRF implementation layer

Implement authentication separately from the permission classes and the
tenant-scoped querysets. Never use a raw API key as a database lookup value. A
small local model may store `prefix`, `digest`, the owner or service account,
the tenant, and the scopes. It may also store the created, expiry, revoked, and
last-used fields, and the rotation lineage. Centralize the parse and the
verification in one authentication class, and cache only revocation-safe
metadata.

`djangorestframework-api-key==3.1.0` is existing-install audit only. It does
not pass the current Django 6 and maintenance gate, and it explicitly is not
end-user authentication. Where you find it, confirm one-time display, hashed
high-entropy keys, prefix lookup, `expiry_date`, revocation, a custom scoped
`AbstractAPIKey` model, and use through `BaseHasAPIKey`. Then add real object
and function authorization. Prefer a custom header or `Authorization: Api-Key
...`. Reject query-string transport.

For third-party delegated access, or for complex scopes and consent, prefer a
maintained OAuth client-credentials or authorization-code design over a
bespoke key protocol. Keep webhook-signing secrets and request signatures
distinct from API authentication keys. Verify the timestamp and replay
controls where signed webhooks are in scope.

## Review checklist

- [ ] Authentication and authorization are separate. Every backend rejects an
      inactive, suspended, wrong-tenant, or otherwise ineligible principal.
- [ ] The password validators set a 15-character floor wherever the password
      is a single factor. They impose no composition rule and no periodic
      expiry. They screen the candidate against a breach corpus, rather than
      against the 20,000-entry common-password list alone.
- [ ] The user model normalizes its identifier once, on every write path, and
      through the same function on the read path. The database enforces
      uniqueness over the value the login comparison reads, rather than over
      whatever the user typed. No second case function sits in SQL. Recovery
      resolves the same principal set that login does.
- [ ] `is_active` is a declared field rather than the inherited constant.
      Every credential path re-reads it, or expires quickly enough to stand in
      for that read.
- [ ] The session cookies, CSRF, rotation, idle and absolute lifetime, logout,
      and sensitive re-authentication match the deployment architecture. Every
      session-authenticated login endpoint enforces CSRF itself, because DRF
      enforces none before the user is authenticated. Re-authentication mints
      a bounded artifact rather than a session flag.
- [ ] `SESSION_ENGINE` keeps a server-side record wherever revocation, forced
      logout, or an operator kill switch is a requirement. No authenticated
      application runs on `signed_cookies`.
- [ ] Every path that sets a password calls `update_session_auth_hash()` for
      the session it runs in, and invalidates the caller's other credentials.
- [ ] JWTs have fixed algorithms, issuer, audience, and time validation, a
      short lifetime, key rotation, and a revocation or staleness strategy.
      The package compatibility is proven.
- [ ] Machine tokens from an external issuer are verified against a cached,
      rotation-aware key set. The algorithm is pinned in configuration, and
      the required claims are enforced rather than assumed.
- [ ] Tokens are revalidated per request. The audience is checked against this
      service. No inbound token is forwarded to a downstream hop.
- [ ] Credentials and tokens are absent from URLs, source, logs, traces,
      analytics, errors, and client-readable persistent storage, unless
      explicitly justified.
- [ ] Login, reset, signup, invite, MFA, and linking resist enumeration,
      replay, brute force, distributed automation, and attacker-induced
      permanent lockout. The lockout has a bounded cool-off and a key that a
      change of source address does not escape. Every custom backend runs the
      password hash on a lookup miss.
- [ ] OAuth and OIDC use code plus PKCE, exact redirects, and a bound one-time
      state and nonce. They use full ID-token validation, stable
      `(issuer, sub)` identity, and safe linking.
- [ ] The allauth, dj-rest-auth, OAuth Toolkit, and social-auth settings,
      adapters, and pipelines preserve the controls above. mozilla-django-oidc
      is rejected or explicitly hardened.
- [ ] Provider tokens are minimally scoped, stored only where needed,
      protected, rotated and revoked, and deleted on disconnect.
- [ ] API keys are high-entropy, one-time-revealed, digest-only, scoped,
      expiring, rotatable, revocable, header-only, safely logged, and followed
      by authorization.
- [ ] MFA enrollment, removal, and recovery are protected. Recovery codes are
      hashed and single-use. TOTP seeds are encrypted at rest. No completed
      password reset satisfies the second factor. Every factor lifecycle event
      is audited without a secret.
- [ ] An email change re-authenticates on a knowledge factor, and never on
      session possession alone. It completes on confirmation at the new
      address, and notifies the old one. The revert path is single-use and
      expiring. Any purpose other than password reset uses its own token
      generator, rather than `default_token_generator`.
- [ ] No header carries an identity into `RemoteUserMiddleware` unless the
      proxy overwrites it and strips every inbound copy. `create_unknown_user`
      is `False`, unless the design provisions users.
