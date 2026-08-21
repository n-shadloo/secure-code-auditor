# A04:2025 — Cryptographic Failures

This file covers password hashing, randomness and token generation,
constant-time comparison, and signing. It also covers data in transit and at
rest, key lifecycle, and where secrets live.

This file owns the **choice of primitive and its parameters**, and the life of
a key from generation to destruction. It does not own the places that consume
those choices. `data-layer-and-database.md` owns the encrypted-column
mechanism and the blind index. `service-identity-and-secrets.md` owns secret
storage, delivery, and `SECRET_KEY` rotation. `deployment-and-runtime.md` owns
TLS at the edge. `a07-authentication-failures.md` owns password policy and the
API-key lifecycle.

A primitive you implement yourself is out of scope by rule. The answer is
always a vetted library.

## Contents
- [Principle](#principle)
- [Password hashing](#password-hashing)
- [Password validators](#password-validators)
- [Secrets](#secrets)
- [Randomness and token generation](#randomness-and-token-generation)
- [Constant-time comparison](#constant-time-comparison)
- [Signing and salt discipline](#signing-and-salt-discipline)
- [Data in transit and at rest](#data-in-transit-and-at-rest)
- [Key lifecycle and envelope encryption](#key-lifecycle-and-envelope-encryption)
- [Cryptographic agility and algorithm lifecycle](#cryptographic-agility-and-algorithm-lifecycle)
- [Post-quantum posture](#post-quantum-posture)
- [Review checklist](#review-checklist)

## Principle

Cryptography fails less from broken algorithms than from wrong choices around
them. Those choices are fast hashes for passwords, secrets in source,
plaintext transport, weak or homemade signing, and sensitive data stored where
it need not be. The principle is **use vetted primitives with sane parameters,
keep keys out of code, encrypt in transit always, and minimize what you
store**. Never invent crypto. Never compare secrets with a non-constant-time
`==`.

Know what the category actually catches in the field. Three of the most common
CWEs OWASP maps to A04:2025 are about **randomness**, not about ciphers. They
are CWE-331 (insufficient entropy), CWE-338 (cryptographically weak PRNG), and
CWE-1241 (predictable algorithm in a random number generator). CWE-327 (broken
or risky algorithm) stands beside them. A guessable token is a cryptographic
failure in exactly the same sense that a fast password hash is. Reviewers miss
it more often than any other item here.

## Password hashing

Maps to CWE-916 (password hash with insufficient computational effort) and
CWE-327 (broken or risky algorithm).

### Principle layer

A password hash is the only defense that still applies once somebody has
copied the database. Its strength is a **cost you choose**: memory, time, and
parallelism. Thus the two decisions are the family and the parameters, and
projects skip the second one. A memory-hard function with defaults nobody ever
measured is a defensible starting point. The same function with parameters
chosen for a 2019 laptop is not.

Choose in this order:

- **Argon2id** for new work. Memory-hard, so a GPU or ASIC attacker has to buy
  memory bandwidth rather than just arithmetic.
- **scrypt** where Argon2 is genuinely unavailable. Also memory-hard.
- **bcrypt** only for legacy compatibility, and only with the 72-byte input
  limit understood (below).
- **PBKDF2** only where a FIPS-140 requirement forces it. It is not memory-hard
  and buys the least resistance per unit of defender cost.

The published floors, as identifiers rather than folklore:

| Source | Configuration |
|---|---|
| OWASP Password Storage Cheat Sheet, minimum | Argon2id, m=19 MiB (19,456 KiB), t=2, p=1 |
| Same, equivalent-security alternatives | m=46 MiB/t=1, m=12 MiB/t=3, m=9 MiB/t=4, m=7 MiB/t=5, all at p=1 |
| RFC 9106, FIRST RECOMMENDED | Argon2id, t=1, p=4, m=2 GiB, 128-bit salt, 256-bit tag |
| RFC 9106, SECOND RECOMMENDED | Argon2id, t=3, p=4, m=64 MiB |
| OWASP scrypt fallback | N=2^17, r=8, p=1 |
| OWASP bcrypt, legacy only | work factor ≥ 10, 72-byte password limit |
| OWASP PBKDF2, FIPS-140 only | ≥ 600,000 iterations with HMAC-SHA-256 |

Treat OWASP's numbers as the floor and RFC 9106's as the target envelope, then
tune rather than copy:

1. Fix **p** to the cores you are willing to spend per hash.
2. Set **m** to the memory each concurrent login can afford. Peak logins per
   second multiplied by **m** has to fit inside the worker's real headroom.
   Otherwise a login spike becomes an out-of-memory event, and the
   availability incident costs more than the parameter bought.
3. Raise **t** until a single hash costs the most latency the login path can
   absorb.

Measure on the hardware that will run it in production. A figure benchmarked
on a developer laptop describes nothing about the worker, in either direction.
Re-tune on a schedule. The parameter that was expensive for an attacker three
years ago is cheap now, and nothing in the system will tell you.

Never store a password with a fast hash (`md5`, `sha1`, a bare `sha256`).
Never store one without a per-password salt. Never store one with anything
reversible. An encrypted password is a finding, not a mitigation, because
whoever holds the key holds the plaintext.

### Django & DRF implementation layer

Django hard-codes its own parameters on each hasher class rather than
inheriting the library's, so verify against the Django version in front of you.
As of Django 6.1, 6.0, and 5.2 LTS:

| Hasher | Shipped defaults |
|---|---|
| `Argon2PasswordHasher` | Argon2id, `time_cost=2`, `memory_cost=102400` (100 MiB), `parallelism=8` |
| `PBKDF2PasswordHasher` | 1,500,000 iterations on 6.1; 1,200,000 on 6.0; 1,000,000 on 5.2 LTS |
| `ScryptPasswordHasher` | `work_factor=2**14`, `block_size=8`, `parallelism=5` |

Seven things follow from that table, and a reviewer meets the first one most
often:

1. **The default ordering is the finding, not the parameters.** Django's
   shipped `PASSWORD_HASHERS` is PBKDF2, then PBKDF2SHA1, then Argon2, then
   BCryptSHA256, then Scrypt. Argon2 is **third**. An install of `argon2-cffi`
   does not move it, and nothing warns you. A project that never set
   `PASSWORD_HASHERS` hashes with PBKDF2, whatever its requirements file
   holds. Grep for the setting. Its absence is the finding.
2. **Django's Argon2 defaults are not the weak part.** At 100 MiB they sit
   well above OWASP's 19 MiB floor. They are also not `argon2-cffi`'s
   defaults. That library's own `PasswordHasher` is `t=3`, `m=64 MiB`, `p=4`,
   the RFC 9106 SECOND profile, and neither set tracks the other. Do not
   reason from one to the other. Read the numbers off the version you are
   running.
3. **A raised cost parameter propagates by itself.** `check_password()` takes
   a `setter` callback, and `Argon2PasswordHasher.must_update()` compares
   every stored parameter against the class attributes. Thus a subclass with
   higher costs re-hashes each user on their next successful login, with no
   application code at all. `argon2-cffi`'s `check_needs_rehash()` is the
   equivalent for non-Django callers. A project that wires it into a Django
   login path duplicates machinery the framework already runs.
4. **Never remove an entry from `PASSWORD_HASHERS`.** Django can only upgrade
   a hash whose algorithm is still listed. A removal of the old entry does not
   migrate those users. It locks them out.
5. **`ScryptPasswordHasher`'s default `work_factor=2**14` is below OWASP's
   2^17 floor.** Where scrypt is the choice, subclass it rather than accept
   the default.
6. **`BCryptPasswordHasher` truncates silently at 72 bytes**, so a long
   passphrase contributes nothing past that point.
   `BCryptSHA256PasswordHasher` pre-hashes with SHA-256 first and does not.
   Only the latter belongs in the list.
7. **Mixed algorithms in one user table are a user-enumeration timing oracle**,
   and Django's own documentation says so. A login for a user whose hash is in
   a non-preferred algorithm takes measurably different time. The comparison is
   a login for a user who does not exist. Upgrade-on-login shrinks the exposure
   as people sign in. The residue is the dormant accounts that never do. See
   `a07-authentication-failures.md`, "Brute force and enumeration".

```python
# Wrong: the parameters are inherited rather than chosen, and trimming the list
# to "the good one" means Django can no longer read — or upgrade — any hash
# written under the algorithms that were removed. Those users cannot log in.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
]
```

```python
# Correct: the preferred hasher is explicit and its cost is chosen rather than
# inherited, and the fallbacks stay so existing hashes can still be read and
# upgraded on login.

# myproject/hashers.py
from django.contrib.auth.hashers import Argon2PasswordHasher


class TunedArgon2PasswordHasher(Argon2PasswordHasher):
    # Benchmarked on the production worker, not on a laptop. p drops to the
    # RFC 9106 lane count because this worker dedicates four cores per hash,
    # and the budget freed by that goes into m and t, which is where it buys
    # the most. must_update() re-hashes each user at their next login on any
    # change to these, so a later increase needs no migration.
    time_cost = 3
    memory_cost = 131072  # 128 MiB, up from Django's 100
    parallelism = 4


# settings.py
PASSWORD_HASHERS = [
    "myproject.hashers.TunedArgon2PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]
```

**Package decision (9 Aug 2026):** `argon2-cffi==25.1.0` passes the
maintained-package gate. Install it with `pip install "django[argon2]"`. Put a
hasher of yours in front of Django's. Record the benchmark that produced the
parameters. See `security-hardening-libraries.md`, "Cryptographic primitives
and password hashing".

### Migrating a hasher family

Point 7 above names a residue and stops there. Upgrade-on-login fires only for
accounts whose owner logs in, so dormant ones hold the legacy algorithm
indefinitely. A reorder of `PASSWORD_HASHERS` does nothing for them. Django
documents the way out, and the useful property is that it needs no plaintext.
Re-encode the **stored digest** under the preferred hasher, and every row
moves in one pass, whether or not its owner ever returns.

The wrapper hashes the legacy digest in place of the password. Three parts:

1. A hasher that subclasses the target, with its own `algorithm` string. It
   also carries an `encode_<legacy>_hash` helper that the migration calls with
   the digest read out of the column.
2. A one-way data migration that splits each stored value, re-wraps it, and
   writes it back.
3. Both the wrapper and the legacy hasher left in `PASSWORD_HASHERS`, so
   `identify_hasher` can still read what is stored.

**Django's own example wraps into PBKDF2, and that recipe does not transfer to
Argon2 unchanged.** `PBKDF2PasswordHasher.verify` re-derives through
`self.encode`, so an override of `encode` is enough to carry verification with
it. `Argon2PasswordHasher.verify` does not re-derive: it hands the raw
password straight to the argon2 library. Thus a wrapper that overrides only
`encode` migrates every row and then rejects every correct password. That is a
lockout that passes code review, because the migration half works. An Argon2
target needs an override of `verify` too, which recovers the reused salt
through the inherited `decode()`:

```python
# Correct: the stored digest is re-encoded under Argon2 with no plaintext in
# play, so the dormant rows move along with everyone else's.

# myproject/hashers.py
from django.contrib.auth.hashers import Argon2PasswordHasher, MD5PasswordHasher


class Argon2WrappedMD5PasswordHasher(Argon2PasswordHasher):
    algorithm = "argon2_wrapped_md5"

    def _legacy_digest(self, password, salt):
        legacy = MD5PasswordHasher().encode(password, salt)
        _, _, md5_hash = legacy.split("$", 2)
        return md5_hash

    def encode_md5_hash(self, md5_hash, salt):
        # What the migration calls. It wraps a digest already sitting in the
        # column, which is the whole reason the pass needs nobody to log in.
        return super().encode(md5_hash, salt)

    def encode(self, password, salt):
        return self.encode_md5_hash(self._legacy_digest(password, salt), salt)

    def verify(self, password, encoded):
        # Mandatory for an Argon2 target, unlike Django's PBKDF2 example. The
        # inherited verify would check the raw password against a hash taken
        # over the MD5 digest and fail every migrated login.
        salt = self.decode(encoded)["salt"]
        return super().verify(self._legacy_digest(password, salt), encoded)
```

```python
# Correct: one-way, and it reads the legacy salt back out of the stored value
# rather than minting a new one -- the wrapper needs that same salt at login
# to rebuild the inner digest.

# accounts/migrations/0007_wrap_md5_into_argon2.py
from django.db import migrations

from myproject.hashers import Argon2WrappedMD5PasswordHasher


def wrap_md5_hashes(apps, schema_editor):
    User = apps.get_model("auth", "User")
    hasher = Argon2WrappedMD5PasswordHasher()
    alias = schema_editor.connection.alias
    legacy = (
        User.objects.using(alias)
        .filter(password__startswith="md5$")
        .order_by("pk")
    )
    for user in legacy.iterator(chunk_size=500):
        _, salt, md5_hash = user.password.split("$", 2)
        user.password = hasher.encode_md5_hash(md5_hash, salt)
        user.save(update_fields=["password"])


class Migration(migrations.Migration):
    dependencies = [("accounts", "0006_previous")]
    operations = [migrations.RunPython(wrap_md5_hashes)]
```

After the pass a row reads `argon2_wrapped_md5$...`, which is Argon2 over an
MD5 digest. A guess now costs an Argon2 evaluation rather than an MD5 one. At
the owner's next login, `check_password` sees a stored algorithm that is not
the preferred one. It re-hashes the plaintext it was just handed, and the row
lands on plain `argon2$...`. Nobody is prompted, and nothing is reset. Four
things to know before you run it:

- **Every live session ends the moment the migration lands.**
  `get_session_auth_hash()` is an HMAC of the password field, and `get_user()`
  compares it on each request. Thus a rewrite of every row invalidates every
  session at once. There is no request in flight to call
  `update_session_auth_hash()` for. Schedule and announce this effect rather
  than avoid it.
- **A short legacy salt is a hard stop for an Argon2 target.** Argon2 rejects
  a salt under 8 bytes outright, so a row whose salt is shorter cannot be
  wrapped into it. Such a row needs a different target, or the reset path
  below.
- **The data-migration form is fine here** in a way the key-rotation pass
  earlier in this file is not. It depends on no key that will later be
  destroyed. The resumability argument still holds at scale. A user table large
  enough to time out a deploy wants the same chunked management command.
- **A wrap raises the cost of future cracking and undoes no past exposure.**
  It protects the copy in your database. A copy already taken is still
  crackable at the legacy cost.

**When to force a reset instead.** Django documents the wrap and does not say
when to abandon it, so these are engineering criteria rather than doctrine.
Each one makes a wrap insufficient rather than merely slower:

- **The legacy hashes have been exposed.** Only a password the leaked digests
  no longer describe devalues them.
- **The legacy scheme is unsalted.** Precomputation against exposed unsalted
  digests is cheap enough that the first criterion is effectively already met.
- **No verifier can be reconstructed.** The values are truncated,
  foreign-format, or short-salted, and they will not re-encode into a wrapper.
  There is nothing to wrap.
- **A compliance obligation mandates rotation** on deprecation of the
  algorithm.

A reset costs what a wrap does not. It interrupts every user at once. Support
absorbs the ones who no longer control the registered address. The reset mail
is a phishing template in the same week you told everyone to expect one. Where
none of the four holds, wrap. A wrap closes the dormant gap immediately,
including the timing difference point 7 leaves open. The expiry of a chosen
subset stays available as a separate decision.

**Write-time.** When you move a project onto a different hasher family, write
the wrapper and its data migration in the same change as the
`PASSWORD_HASHERS` reorder. The reorder alone reaches only the accounts that
log in, and it leaves the rest on the old algorithm with nothing reporting
that it did. Override `verify` alongside `encode` whenever the target is
Argon2. Check the pair against a real legacy hash before the migration runs,
rather than after. A wrapper that encodes correctly and verifies wrongly looks
right in review, and it locks out everyone it just migrated.

### Peppering

A pepper is a site-wide secret that the hasher mixes into the password, and
that the database never holds. A database-only dump therefore cannot start an
offline guess at all. Django peppers nothing by default. The supported spelling
is a wrapping hasher: subclass the Argon2 hasher, and HMAC the password with a
key from the secret manager before the hash. Use the same wrapper form as the
migration above. Keep the key in the secret manager rather than in
`SECRET_KEY`.

Rotation is a new wrap version, not a mass reset. A pepper is defense in depth
for the database-dump case, and never a substitute for the parameters above.
Rate a missing pepper as no finding. Name it as available hardening where the
threat model is a database-only compromise.

## Password validators

Configure `AUTH_PASSWORD_VALIDATORS` (length, common-password, numeric,
user-attribute similarity). This is your baseline against weak and reused
credentials. This file does not own the policy those validators encode.
`a07-authentication-failures.md`, "Password policy", carries the SP 800-63B-4
requirements each one maps to. It also carries the length floor that sits above
Django's default, and the breached-corpus screening no built-in provides.
Lockout and breach handling are in the same file, under "Brute force and
enumeration".

## Secrets

- `SECRET_KEY`, JWT `SIGNING_KEY`, DB passwords, and third-party API keys load
  from the environment or a secrets manager. Never write them as literals in
  `settings.py`, and never commit them. `service-identity-and-secrets.md`
  gives how the settings module reads a required value, and why it must fail
  at startup.
- `SECRET_KEY_FALLBACKS` lets the previous key continue to *validate* while
  the new key signs, which is what makes a rotation survivable. It does not
  cover everything derived from the key. Contrary to a widely repeated claim,
  a rotation does not invalidate CSRF tokens.
  `service-identity-and-secrets.md`, "Rotating Django's SECRET_KEY", holds the
  subsystem-by-subsystem breakdown, the two-phase procedure, and the
  deliberate hard cut after a compromise.
- `service-identity-and-secrets.md` holds where secrets should live per
  runtime, how they reach the process, and the ordered response to a leak. It
  also holds the machine-to-machine credentials themselves: client-credentials
  tokens, mutual TLS, and workload identity. This file keeps the primitives
  underneath them.
- A hardcoded or committed secret is a finding on its own (High–Critical,
  depending on what it unlocks). See `dangerous_patterns.py` for detection,
  and the deployment and libraries files for `.env` hygiene.

## Randomness and token generation

Maps to CWE-330 (insufficiently random values), CWE-338 (cryptographically weak
PRNG), CWE-331 (insufficient entropy), and CWE-340 (predictable from observable
state).

### Principle layer

A bearer token's only security property is that nobody can produce a valid one
without receipt of it. That reduces the requirement to two things. It comes
from a cryptographically secure source. It has enough entropy that no attacker
can guess it. 128 bits is the floor, and 256 bits costs nothing extra.

Two further rules keep it that way. **One purpose per token**, so nobody can
present a value minted for one flow to another. **Store long-lived tokens
hashed**, so a database read does not supply working credentials.

The anti-patterns, all of which appear in real code:

- **Sequential or auto-increment ids as tokens.** The next one is the current
  one plus one.
- **Timestamp-derived values.** The attacker knows roughly when it was issued,
  which reduces the search to the resolution of the clock.
- **`random.*`.** Python's default generator is a Mersenne Twister, seeded and
  fully reconstructible. An attacker who observes enough consecutive outputs
  recovers its internal state, and then computes every future value. It is a
  statistical generator, not a cryptographic one, and the two are not
  interchangeable.
- **Timestamped UUIDs as secrets.** UUIDv1 and UUIDv7 embed a timestamp by
  design and are meant to be sortable, not unguessable.
- **UUIDv4 as an authorization decision.** It is random, but it is roughly 122
  bits. More importantly, possession of an identifier is not the same as
  authorization to use it. An unguessable URL is not an access control. See
  `a01-broken-access-control.md`.
- **One token reused across purposes**, which turns any single leak into every
  capability that token can reach.

### Django & DRF implementation layer

- `secrets.token_urlsafe()` and `secrets.token_hex()` are the correct
  generators. Both default to `secrets.DEFAULT_ENTROPY`, which is 32 bytes or
  256 bits, so the bare call is already the right size. `secrets` draws from
  the OS CSPRNG throughout. `compare_digest` is `hmac.compare_digest`, and
  `choice`, `randbelow`, and `randbits` come from `random.SystemRandom`.
- `django.utils.crypto.get_random_string` is also CSPRNG-backed. It is
  `secrets.choice` over a 62-character alphanumeric alphabet, about 5.95 bits
  per character. That makes the common 12-character call roughly 71 bits. That
  size is adequate for a filename suffix or a nonce, and short for a bearer
  credential. Pass a longer length, or use `token_urlsafe`.
- `django.core.management.utils.get_random_secret_key()` generates a
  `SECRET_KEY`. It is what `startproject` uses.
- Password-reset and email-verification tokens should use Django's
  `PasswordResetTokenGenerator` rather than a hand-rolled value. It is
  single-use by construction, because the hash covers the user's current
  password hash and last-login timestamp. `PASSWORD_RESET_TIMEOUT` also makes
  it time-limited.
- A long-lived API key is stored as a hash plus a short non-secret prefix for
  lookup, never as the raw value. `a07-authentication-failures.md`, "API
  keys", holds the full key lifecycle: prefixes, scoping, expiry, and
  revocation.

```python
# Wrong: a statistical PRNG, far too little entropy, and derived from a value
# the caller already knows, so the "secret" is reconstructible.
import random
import time

token = f"{user.pk}-{int(time.time())}-{random.randint(1000, 9999)}"
```

```python
# Correct: OS CSPRNG, 256 bits by default, and namespaced per purpose so this
# token cannot be replayed against a different flow.
import secrets

token = secrets.token_urlsafe()  # DEFAULT_ENTROPY == 32 bytes
```

**Write-time.** When you generate a token or any other secret, call `secrets`
and take its default length rather than size the value yourself. The bare call
is already 256 bits, and a hand-chosen length is the one that turns out to be
the 71 bits above. Mint one token per purpose, and store the long-lived ones
hashed. Use `PasswordResetTokenGenerator` where the flow is a reset or a
verification, rather than re-implement single use and expiry.

Two decisions travel with the value, and they are cheapest in the same edit.
Any `Signer` or `TimestampSigner` that carries it takes a per-purpose `salt=`.
The check that later compares it against a stored copy uses
`hmac.compare_digest` over fixed-length digests. That applies wherever the
scope section below says the comparison is itself the gate.

### Commonly mistaken for a finding

**`random` for retry jitter, sampling, backoff, shuffling a display order, or a
test fixture.** The anti-pattern list above names `random.*` outright, and
`import random` is a one-line grep with no context in it. Thus every call site
reads as CWE-338 on sight. Predictability is only a defect where the design
relies on unpredictability as the security property. The deciding question is
what the value becomes. This becomes a finding for a credential, a token, a
reset link, or a session identifier. It becomes a finding for anything else
whose whole defense is that nobody can guess it. A delay, a sample, an
ordering, or a fixture makes it the correct choice of generator.

**Write-time.** When you generate a value whose only requirement is
statistical spread, call `random`. Jitter on a retry, a sampled subset, and a
shuffled order are the examples. Leave `secrets` for the values whose security
property is that nobody can predict them. A project that uses the CSPRNG
everywhere hides the signal that makes the real misuse visible in review.

## Constant-time comparison

Maps to CWE-208 (observable timing discrepancy).

Scope this one deliberately. `==` on a secret is a real finding in a specific
set of places, and noise everywhere else. A review that flags every string
comparison in a codebase teaches people to ignore the flag.

**Where it matters** — a caller-supplied value is compared against a stored one
and *that comparison is the gate*:

- API keys and bearer tokens checked directly against a stored value.
- HMAC and webhook signatures (`a08-integrity-and-deserialization.md` owns the
  full receiver).
- Password-reset, email-verification, and invitation tokens.
- CSRF tokens, MFA and OTP codes.

**Where it is noise:**

- Anything already run through a password KDF. The KDF dominates the timing,
  and the comparison is over fixed-length digests.
- Non-secret identifiers, such as usernames, object ids, and tenant slugs.
  Their timing leaks nothing that is not already public, and enumeration
  through them is an authorization question, not a timing one.
- A comparison whose result the attacker cannot observe through response
  timing, because the surrounding work swamps the signal.

In Django, `django.utils.crypto.constant_time_compare` is
`secrets.compare_digest(force_bytes(val1), force_bytes(val2))`. Two properties
matter in review. It is constant-time **only for equal-length inputs**,
because the underlying comparison short-circuits on a length mismatch. That
behavior is adequate for the fixed-length digests Django compares with it. For
a **variable-length** secret, that length difference is itself the leak.
Compare fixed-length HMACs of the two values instead of the values themselves:

```python
# Wrong: byte-by-byte with an early exit, so response time reveals how many
# leading bytes were right and the key can be recovered one byte at a time.
if provided_key == stored_key:
    ...
```

```python
# Correct: fixed-length digests, so neither the content nor the length of the
# supplied value changes how long the comparison takes.
import hashlib
import hmac


def digest(value: str) -> bytes:
    return hmac.new(COMPARISON_KEY, value.encode(), hashlib.sha256).digest()


if hmac.compare_digest(digest(provided_key), digest(stored_key)):
    ...
```

## Signing and salt discipline

Maps to CWE-345 (insufficient verification of data authenticity) and CWE-347
(improper verification of a cryptographic signature).

### Principle layer

A signature proves that somebody holding the key minted a value. It does not
prove *what the value was minted for*. If one key signs every kind of token,
every token is interchangeable. An attacker who can legitimately obtain one
then gets the others for free. The fix is **domain separation**: bind each
purpose into the signed material, so a token minted for one flow fails
verification in another.

Two further rules travel with it. Every signed artifact needs a **maximum
age** appropriate to its own purpose. A password-reset link is measured in
hours, and an unsubscribe link possibly in months. Do not use the same number
for both. **Signing is not encryption**: a signed payload is authenticated,
not confidential, and anyone holding it can read it.

### Django & DRF implementation layer

Use `django.core.signing` — `Signer`, `TimestampSigner`, `dumps`/`loads` —
rather than assemble an HMAC by hand. Verified against Django 6.0 and 5.2,
`Signer` defaults to the project `SECRET_KEY` with `SECRET_KEY_FALLBACKS`
honored, `sep=":"`, `algorithm="sha256"`, and a `salt` that defaults to
`"<module>.<ClassName>"`. Thus every unnamed `Signer` in the project shares
the salt `"django.core.signing.Signer"`, and `dumps`/`loads` share
`"django.core.signing"`. Django computes the signature over `salt + "signer"`,
which is exactly the namespacing hook.

Django's own docstring states that a salt left at its default is a security
risk. A salt reused across parts of an application without good cause is the
same risk.

```python
# Wrong: both flows sign the same user id with the same default salt, so the
# two tokens are byte-identical. A reset link the user requested themselves is
# a valid email-change confirmation, and the account can be moved to an
# attacker's address without them ever seeing a confirmation prompt.
from django.core.signing import TimestampSigner

reset_token = TimestampSigner().sign(user.pk)
email_change_token = TimestampSigner().sign(user.pk)
```

```python
# Correct: one salt per purpose, so a token minted for one flow fails
# verification in the other, and a max_age chosen for each flow rather than
# shared by accident.
from django.core.signing import TimestampSigner

reset_token = TimestampSigner(salt="accounts.password-reset").sign(user.pk)
email_change_token = TimestampSigner(salt="accounts.email-change").sign(user.pk)

# Verification, per purpose:
user_pk = TimestampSigner(salt="accounts.password-reset").unsign(
    reset_token, max_age=3600
)
```

Review notes:

- `salted_hmac()` defaults to `algorithm="sha1"` on 6.1, 6.0, and 5.2, with a
  documented transition to `"sha256"` in Django 7.0. It is still an HMAC and
  not a broken construction. Pass `algorithm="sha256"` explicitly in new code,
  so that the value does not change under you at the upgrade. From Django 6.1
  the implicit default is deprecated. `salted_hmac()` and
  `django.core.signing.base64_hmac()` warn until the caller names the
  algorithm. Treat that warning as the migration notice: the digest changes at
  7.0, and every value derived from it stops verifying.
- `signing.dumps()` produces signed, base64-encoded, **readable** output. Do
  not put anything confidential in it.
- `service-identity-and-secrets.md`, "Rotating Django's SECRET_KEY", gives
  which subsystems `SECRET_KEY_FALLBACKS` covers during a rotation, and the
  two-phase procedure.
- Django made this exact mistake in its own signed-cookie helper. That case is
  worth knowing, because it shows the failure is a collision rather than a
  weak signature. `get_signed_cookie()` built its salt from the cookie name
  and the `salt` argument, joined together, so two distinct pairs could
  produce one salt. `a02-security-misconfiguration.md`, "Signed cookies and
  the legacy salt fallback", holds the version floor, the transitional
  setting, and the audit.

## Data in transit and at rest

- TLS everywhere (see deployment). The database connection must be *verified*,
  not merely encrypted. On PostgreSQL that means `sslmode=verify-full` with a
  pinned root certificate, because `require` encrypts and accepts whatever
  answered. See `data-layer-and-database.md`, "Verified database connections".
- Store only the sensitive data you need. **Never store raw card data.** Use
  the gateway's tokenization or hosted flows (see A08 and the DRF file for
  payment specifics). Almost every packaged Django field-encryption library is
  now unmaintained. For fields that must be encrypted at rest, build on PyCA
  `cryptography` with keys held outside the database. Add a keyed blind index
  where the column must stay searchable. `data-layer-and-database.md`,
  "Field-level encryption and searchable lookups", gives the mechanism, its
  cost, and what a blind index leaks. The key's own lifecycle is below.
- Volume encryption does not satisfy a requirement that a column be encrypted.
  It defends stolen media and backups, and it is transparent to any
  authenticated connection. Column encryption keeps the value ciphertext in
  the query result unless the application holds the key.
  `data-layer-and-database.md`, "Field-level encryption and searchable
  lookups", gives the threat model that justifies the column, and the query
  cost it removes.

## Key lifecycle and envelope encryption

Maps to CWE-324 (use of a key past its expiration date), CWE-321 (hard-coded
cryptographic key), and CWE-311 (missing encryption of sensitive data).
Reviewers often reach for CWE-320 (Key Management Errors) here, but it is a
category, and CWE's mapping guidance prohibits a category in a finding.

### Principle layer

A key has a life: **generate → store → use → rotate → revoke → destroy**. Most
projects implement the first three and discover the rest during an incident.
At that point a rotation means a re-encryption of a table nobody has a script
for.

**Envelope encryption** is the shape that makes the rest tractable. Encrypt the
data with a **data encryption key (DEK)**. Encrypt the DEK with a
**key-encryption key (KEK)** that never leaves a KMS or HSM. Store the wrapped
DEK beside the ciphertext. The plaintext DEK exists only briefly in application
memory. Three things follow, and they are the whole reason to do it. The key
that matters is never in a config file to be leaked. Every unwrap is an audited
KMS call, and a KEK rotation is one operation instead of a table scan.

Rotation without downtime is **versioning**, not replacement. New writes use
the new key version. Reads try the current version, then each prior one in
turn. A background job re-encrypts what already exists. Destroy the old
version only once an audit shows nothing references it.

Two distinctions are worth holding. A re-wrap of a DEK under a new KEK is
*not* a re-encryption of the data, because it changes only who can unwrap it.
And the destruction of a key version before that reference audit is not
rotation, it is data loss.

Re-encryption is a **data migration**, with the properties every data
migration needs: chunked, idempotent, and resumable from a stored watermark. A
pass that has to start again after a crash is one that will not finish on a
large table.

### Django & DRF implementation layer

`data-layer-and-database.md`, "Field-level encryption and searchable lookups"
owns the storage mechanism, the query cost, and the blind index. This section
owns the primitive and the key's life around it.

- **The choice of primitive.** `Fernet` is AES-128-CBC with PKCS7 padding and
  a separate HMAC-SHA256, encrypt-then-MAC, with an `os.urandom` IV. It is a
  sound, hard-to-misuse default. Know one property before you use it on a
  column. A Fernet token embeds the encryption time **in plaintext**, so the
  column leaks when each row was last written. Where that is sensitive, or
  where a single-pass AEAD is preferred, use `AESGCM` or `ChaCha20Poly1305`
  and own the nonce. Never reuse a nonce under one key, which for GCM is
  catastrophic rather than merely untidy.
- **`MultiFernet` is the in-process model of key versioning.** It encrypts
  with the first key in the list, and it decrypts with each key in turn. Its
  `rotate()` re-encrypts an existing token under the primary key, and it
  preserves the original timestamp.
- **Do not derive a field-encryption key from `SECRET_KEY`.** It collapses two
  independent secrets into one. A `SECRET_KEY` rotation then becomes a full
  data re-encryption, and a `SECRET_KEY` leak becomes a decryption-key leak.
  Keep them separate, so that you can rotate them on separate schedules.
- The re-encryption pass belongs in a **management command**, not in a
  migration file. Migrations run inside deploy transactions, and they are hard
  to resume. Their history should not depend on key material that will be
  destroyed.

```python
# Wrong: rotation by replacement. The moment the new key ships, every row
# written under the old one raises InvalidToken, and there is no path back.
from cryptography.fernet import Fernet
from django.conf import settings

fernet = Fernet(settings.CURRENT_KEY)
```

```python
# Correct: versioned keys, newest first, and a resumable pass that re-encrypts
# existing rows so the old version can eventually be retired.
from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings
from django.core.management.base import BaseCommand

# Newest first: encryption always uses the first key, decryption tries each in
# turn, so both versions are readable while the re-encryption pass runs.
CIPHER = MultiFernet([Fernet(k) for k in settings.FIELD_KEYS])


class Command(BaseCommand):
    """Re-encrypt under the primary key. Resumable: --after is the last pk
    completed, so a crash costs one batch rather than the whole run."""

    def add_arguments(self, parser):
        parser.add_argument("--after", type=int, default=0)
        parser.add_argument("--batch", type=int, default=1000)

    def handle(self, *args, **options):
        last, size = options["after"], options["batch"]
        while True:
            rows = list(Patient.objects.filter(pk__gt=last).order_by("pk")[:size])
            if not rows:
                break
            for row in rows:
                # rotate() decrypts with whichever version applies and
                # re-encrypts under the primary key; a row already on the
                # primary key is unchanged in effect, which makes a re-run safe.
                row.ssn = CIPHER.rotate(row.ssn)
            Patient.objects.bulk_update(rows, ["ssn"])
            last = rows[-1].pk
            self.stdout.write(f"completed through pk={last}")
```

The batch read and `bulk_update` overwrite a row the application changed in
between. Use `select_for_update()` or a write-quiet window, and run the
command again.

**Package decision (7 Aug 2026):** `cryptography==50.0.0` is the recommended
base, and `django-fernet-encrypted-fields==0.4.0` is **conditional**. The
condition is its key derivation. It derives the Fernet key from `SECRET_KEY`
and a `SALT_KEY` setting, which is exactly the coupling the bullet above warns
against. See `security-hardening-libraries.md`, "Cryptographic primitives and
password hashing".

### Envelope encryption against a KMS

The `MultiFernet` example above is the fallback, and this section is precise
about what it does not achieve. It versions keys correctly, but every version
is in `settings.FIELD_KEYS`. Thus the process holds the material that decrypts
the whole table for its entire lifetime. A configuration leak is a plaintext
leak, and nothing anywhere records which rows were read. Envelope encryption
moves each of those. The KEK stays in the KMS, and the only key in the process
is a per-row DEK that lives for one request. Each unwrap is a call somebody can
audit and revoke.

Three details carry the pattern, and projects leave out the middle one.
`generate_data_key` returns both halves at once. `Plaintext` is the DEK you
encrypt with. `CiphertextBlob` is the same DEK wrapped under the KEK, which is
what the row stores. `EncryptionContext` is non-secret additional authenticated
data. `decrypt` fails with `InvalidCiphertextException` unless the caller
supplies it again as a case-sensitive exact match. Thus a context bound to the
table and row stops an attacker from unwrapping a DEK lifted out of one row
against another.

The context also has to be **stable from the first write**. Thus you cannot
derive it from a primary key the row does not have yet.

```python
# Correct: the KEK never leaves the KMS, each row carries its own wrapped DEK,
# and the encryption context ties that DEK to the row it belongs to.
import os

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.db import models

kms = boto3.client("kms")
KEK_ALIAS = "alias/app-dek"


class Patient(models.Model):
    # The wrapped DEK travels beside the ciphertext, so a row carries
    # everything needed to read it except the KEK -- which is exactly the one
    # thing a stolen dump or a replica does not come with.
    ssn_ciphertext = models.BinaryField()
    ssn_nonce = models.BinaryField()
    wrapped_dek = models.BinaryField()

    def _encryption_context(self):
        # Not secret, but authenticated. KMS refuses the unwrap unless decrypt
        # supplies this same dict, so the DEK is useless against another row.
        return {"table": "accounts_patient", "row_id": str(self.pk)}

    def set_ssn(self, ssn):
        if self.pk is None:
            # The context is part of the ciphertext's identity, so it has to
            # be stable from the first write. Wrapping under an unsaved pk
            # binds the DEK to "None" and every later unwrap fails.
            raise ValueError("save the row before encrypting a field into it")
        response = kms.generate_data_key(
            KeyId=KEK_ALIAS,
            KeySpec="AES_256",
            EncryptionContext=self._encryption_context(),
        )
        dek = response["Plaintext"]
        nonce = os.urandom(12)
        self.wrapped_dek = response["CiphertextBlob"]
        self.ssn_nonce = nonce
        self.ssn_ciphertext = AESGCM(dek).encrypt(nonce, ssn.encode(), None)

    def get_ssn(self):
        # KeyId is optional for a symmetric KEK because KMS reads it from the
        # blob; naming it anyway means a swapped blob is rejected rather than
        # decrypted under whatever key it happens to point at.
        dek = kms.decrypt(
            CiphertextBlob=bytes(self.wrapped_dek),
            EncryptionContext=self._encryption_context(),
            KeyId=KEK_ALIAS,
        )["Plaintext"]
        return AESGCM(dek).decrypt(
            bytes(self.ssn_nonce), bytes(self.ssn_ciphertext), None
        ).decode()
```

Two review notes on the shape. The plaintext DEK is a local and nothing else.
It is not an attribute on the instance, not a cache entry, and not a log
field. Its short lifetime is the only property that distinguishes this from a
key held in settings. Python cannot actually zero an immutable `bytes`, so
"never stored" is the achievable guarantee rather than "erased."

A DEK per row makes `get_ssn` one KMS call per row. That turns any list view
over the model into a per-row round trip and a per-row bill. Scope the pattern
to narrow, rarely-listed, high-sensitivity columns. Or widen the DEK to a
tenant or a batch, and accept the coarser blast radius deliberately.

The equivalents are named rather than tiered. GCP Cloud KMS wraps and unwraps
a locally-generated DEK through `encrypt` and `decrypt` on the key path, and
Tink's `KmsEnvelopeAead` automates the generate-and-wrap step. Azure Key Vault
uses `wrapKey` and `unwrapKey`. These are platform SDKs a project already
runs, not security packages chosen against alternatives. Therefore
`security-hardening-libraries.md`, "Cryptographic primitives and password
hashing", records all three as patterns rather than gives a provider a
disposition.

**Write-time.** When you generate field encryption against a KMS, pass an
`EncryptionContext` on `generate_data_key` in the same edit that writes the
`decrypt` call. A wrapped DEK created without one can never acquire the
binding afterwards without a re-encryption of the column. The pair works only
if both sides carry the identical dict. Bind it to a value the row already
has, rather than to a pk it is about to receive. Add the `wrapped_dek` column
in the same migration as the ciphertext column, so that no row can exist
without its key. Keep the plaintext DEK in a local rather than on the model
instance.

## Cryptographic agility and algorithm lifecycle

Maps to CWE-757 (selection of less-secure algorithm during negotiation) and
CWE-327 (use of a broken or risky cryptographic algorithm).

### Principle layer

**You will need to change an algorithm before you need to change a key.** Key
rotation runs on a schedule you set. An algorithm change arrives on someone
else's schedule: a published break, a deprecation notice, or a compliance
date. It lands on code written as though one algorithm would hold forever.
Design for the harder change, and the easier one comes free.

One property makes that possible: **every stored cryptographic value records
what produced it.** Keep the algorithm identifier and the key identifier with
the ciphertext, the signature, or the hash. Keep them as data beside the
value, rather than as knowledge inside whichever function currently reads it.

Two inferences are worth a rejection by name. **Do not infer the algorithm
from the payload**, and **do not infer it from the length.** A 32-byte digest
is SHA-256 until something else is also 32 bytes. At that moment every stored
value becomes ambiguous at once, and no later code recovers a distinction the
format never recorded.

**Verification reads the stored identifier, then checks it against a
server-side allow list.** A read of an identifier is not trust in it. The read
selects among algorithms the server has already decided it accepts, and a
value that names anything else is rejected input, not an instruction. A
verifier that honors the algorithm the data names is the algorithm-confusion
defect. `service-identity-and-secrets.md`, "Validating an inbound machine
token" owns that defect for tokens, `alg: none` and the RS256-to-HS256 swap
included.

**The migration has four steps, and the third is the one that gets skipped.**

1. **Dual read.** Accept the old algorithm and the new one.
2. **Single write.** Emit only the new one, so the old population can only
   shrink.
3. **Measure.** Count what still carries the old identifier, and keep counting
   until it reaches zero and stays there.
4. **Retire the read path.** Remove the old branch — and only then the key.

A migration that skips step 3 never finishes. Steps 1 and 2 are a morning's
work and feel like completion. Thus the dual-read branch survives
indefinitely, and the broken algorithm stays a live, reachable code path. Step
3 is the only one of the four that produces evidence. It turns "we migrated"
into a claim with a number behind it.

**Keep one inventory of every algorithm in use**, with its location, owner,
and review date. It covers the password hasher list, signing, tokens, field
encryption, webhook signatures, and transport ciphers. Its worth is not the
list itself. Its worth is that the next published break becomes a lookup
rather than a codebase search under time pressure. The
harvest-now-decrypt-later inventory in "Post-quantum posture" is this one
inventory answering a single question, not a second one to maintain.

**The failure mode to name is a value no code path can read**, because the key
or the algorithm went away before the data did. A team can retire the old read
path while rows still carry the old identifier, or destroy a key version
something still references. Neither one fails at deploy. Each fails at the
first read of an old row, and by that point the plaintext is gone.

This is a data-loss defect that arrives through a security change, which is
why it clears review. The change looks like remediation, and the reviewer
checks that the weak algorithm is gone rather than that everything written
under it moved first.

### Django & DRF implementation layer

Django already models the pattern in three places, which makes them the shape
to copy rather than material to restate:

- **A password hash is self-describing.** The encoded string carries its
  algorithm in the first `$`-separated field, `identify_hasher` dispatches on
  it, and `PASSWORD_HASHERS` is the allow list. That is the stored identifier,
  the allow list, and dual read in one mechanism. "Migrating a hasher family"
  above is steps 3 and 4 applied to the population upgrade-on-login cannot
  reach.
- **`MultiFernet` and `SECRET_KEY_FALLBACKS` are dual read for keys**: a list
  whose first entry writes and whose every entry reads.
- **A `kid` in a JWS header is the stored key identifier**, resolved against a
  published set — `service-identity-and-secrets.md`, "JWKS as a
  rotation-aware trust anchor".

The gap is almost always the project's own crypto rather than Django's. A
field encrypted with `Fernet`, an HMAC over a webhook body, and a signed
download token are the examples. A project typically persists each one as bare
output, with the algorithm implied by whichever line reads it. Give them the
self-describing shape.

```python
# Wrong: the column holds raw ciphertext. Changing the primitive means a data
# migration with no way to tell a converted row from an unconverted one.
record.payload = fernet.encrypt(plaintext)

# Correct: the value names the key version and algorithm it was written
# under, so the reader dispatches on data and step 3 has something to count.
record.payload = b"v2:aesgcm:" + nonce + ciphertext
```

One Django case is worth a statement, because it looks marked and is not.
**`django.core.signing.Signer` records no algorithm in its output.** The value
is `payload:signature`, and `algorithm` defaults to `sha256`. A change to it
raises `BadSignature` on every value signed under the old one. Verified on
Django 6.0.7, 14 August 2026. Only the signature length distinguishes the two
encodings, which is the inference this section rejects.

Thus a signer algorithm change has no dual read available. Bound it with the
maximum age "Signing and salt discipline" already requires, and let every
value still in flight expire before the old algorithm goes. An algorithm
change under a field encryption is a data migration in
`data-layer-and-database.md`, "Field-level encryption and searchable lookups".
That section owns the blind index that has to be rebuilt when the primitive
beneath it changes.

**Write-time.** When you generate code that writes a ciphertext, a signature,
or a non-password digest, record two identifiers in the stored format. Record
the algorithm identifier and the key identifier. Make that change in the same
edit. The format is fixed the moment the first row is written, and every later
migration is priced by that decision.

When you generate a verifier, read the identifier out of the value. Check it
against a constant allow list in the project, never against the value's own
claim. When you generate the change that removes an algorithm, generate step
3's count query alongside it. Leave the old read path until that query returns
zero.

## Post-quantum posture

This is the sober version, because this area attracts more urgency than it
currently earns for a backend.

NIST finalized the first post-quantum standards in August 2024: **FIPS 203**
(ML-KEM, key encapsulation), **FIPS 204** (ML-DSA), and **FIPS 205**
(SLH-DSA). NIST also selected HQC in 2025 as a backup KEM, which is still in
standardization. NIST's transition guidance (IR 8547) deprecates
quantum-vulnerable public-key algorithms after 2030, and disallows them after
2035. It expects high-risk systems to move sooner.

What that means for a Django backend right now:

- **The one action worth taking is an inventory.** Identify data whose
  confidentiality has to outlive the migration window, which is anything that
  must still be secret past the 2035 horizon. That is the "harvest now,
  decrypt later" exposure: an adversary records ciphertext today, and decrypts
  it once the hardware exists. Records with a long retention requirement are
  the ones that matter, and a session cookie is not. Feed the result into the
  personal-data inventory in `data-lifecycle-and-privacy.md`.
- **Hybrid TLS key exchange is a deployment decision, not application code.**
  The TLS terminator negotiates it, and on a current OpenSSL it is already the
  default rather than something to adopt. Thus the finding is a group list
  that pins it out, not a missing feature. See `deployment-and-runtime.md`,
  "Hybrid post-quantum key exchange".
- **Symmetric primitives are not the urgent case.** A quantum adversary gets
  at most a quadratic speedup against a well-chosen symmetric cipher or hash,
  and AES-256 and SHA-256 carry margin for that. The pressure is on the
  public-key key exchange that protects long-lived confidential data.
- **Nothing here justifies a post-quantum library in application code** this
  cycle. Nothing here justifies a re-encryption of a database, or a change of
  token signatures to ML-DSA. Treat a recommendation to do any of those today
  as premature, and challenge it.

Severity: **Low now, latent.** This is an inventory item, not a fix. A report
that states it as anything more spends credibility that the rest of the report
needs.

## Review checklist

### Stack-neutral

- [ ] Passwords go through a memory-hard KDF, with Argon2id preferred and
      scrypt acceptable. The parameters are chosen explicitly and benchmarked
      on production hardware, not inherited and never measured.
- [ ] Argon2id parameters meet at least the OWASP floor of m=19 MiB, t=2, p=1.
      The memory cost multiplied by peak concurrent logins still fits the
      worker's real headroom.
- [ ] No password is stored under a fast hash, without a per-password salt, or
      under any reversible scheme.
- [ ] Every bearer secret comes from a cryptographic source with at least 128
      bits of entropy. There is no `random.*`, no sequential id, no
      timestamp-derived value, and no timestamped UUID as a secret. Long-lived
      ones are stored hashed.
- [ ] Each signed or minted token is scoped to a single purpose, so nobody can
      present one to a different flow. Each one carries a maximum age chosen
      for that purpose.
- [ ] Caller-supplied secrets that gate access are compared in constant time.
      Variable-length secrets are compared as fixed-length HMACs, so that the
      length itself does not leak.
- [ ] Encryption keys have a documented lifecycle. They are versioned, and
      wrapped by a KEK held in a KMS or HSM rather than in configuration. They
      are rotatable without downtime, and destroyed only after an audit shows
      no ciphertext references them.
- [ ] Where a KMS holds the KEK, every data key is generated and unwrapped
      under an encryption context. That context is bound to the row the key
      belongs to. The plaintext data key lives in a local, rather than on an
      instance, in a cache, or in a log line.
- [ ] Re-encryption after a key rotation exists as a chunked, resumable,
      idempotent job rather than as an intention.
- [ ] Every stored ciphertext, signature, and non-password digest carries its
      algorithm identifier and key identifier as data. No reader infers either
      one from the payload or from the value's length.
- [ ] Verification selects the algorithm by a check of the stored identifier
      against a server-side allow list. It never accepts the algorithm the
      value names for itself.
- [ ] Each algorithm migration in progress has all four steps. They are dual
      read, single write, and a count of what remains on the old identifier.
      The fourth removes the old read path, only once that count is zero. No
      old key or read path was retired before the count proved nothing still
      needs it.
- [ ] One inventory names every algorithm in use with its location, owner, and
      review date. It covers the hasher list, signing, tokens, field
      encryption, webhook signatures, and transport ciphers.
- [ ] Data whose confidentiality must outlive the post-quantum migration
      window is inventoried for harvest-now-decrypt-later exposure.

### Django & DRF

- [ ] `PASSWORD_HASHERS` is set explicitly with a memory-hard hasher first,
      because its absence means the project is on PBKDF2 regardless of what is
      installed. No entry has been removed, so old hashes can still upgrade on
      login.
- [ ] Cost increases are applied by a subclass of the hasher, so
      `must_update()` re-hashes users at their next login. `BCryptSHA256`
      rather than `BCrypt` is listed. Any scrypt use is subclassed above
      Django's default `work_factor`.
- [ ] A wrapped-hasher data migration carries a change of hasher *family*,
      rather than a reorder of `PASSWORD_HASHERS` alone. Dormant accounts
      therefore move too. An Argon2 target overrides `verify` as well as
      `encode`, or every migrated login fails.
- [ ] `AUTH_PASSWORD_VALIDATORS` configured.
- [ ] Tokens use `secrets.token_urlsafe`, `get_random_secret_key()`, or
      `PasswordResetTokenGenerator`. They do not use `get_random_string` at a
      short hand-picked length, such as the common 12 characters for a bearer
      credential.
- [ ] Every `Signer` / `TimestampSigner` passes a purpose-specific `salt`
      rather than accepting the default, and `unsign` passes a `max_age`.
- [ ] Secret comparisons use `constant_time_compare` or `hmac.compare_digest`.
      The codebase does not apply them to non-secret identifiers instead.
- [ ] No secrets are in source or VCS, and they load from the environment or a
      secrets manager. A rotation path exists with an overlap window sized to
      the longest-lived signed artifact, and `SECRET_KEY_FALLBACKS` is wired
      into settings before it is needed.
- [ ] Field-encryption keys are independent of `SECRET_KEY`, so the two rotate
      on separate schedules and one leak is not both.
- [ ] TLS is in use in transit, with the database connection *verified* rather
      than only encrypted. No raw card data is stored. Disk encryption is not
      counted as column encryption.
