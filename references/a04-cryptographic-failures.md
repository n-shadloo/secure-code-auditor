# A04:2025 — Cryptographic Failures

Password hashing, randomness and token generation, constant-time comparison,
signing, data in transit and at rest, key lifecycle, and where secrets live.

This file owns the **choice of primitive and its parameters**, and the life of
a key from generation to destruction. It does not own the places those choices
are consumed: `data-layer-and-database.md` owns the encrypted-column mechanism
and the blind index, `service-identity-and-secrets.md` owns secret storage,
delivery, and `SECRET_KEY` rotation, `deployment-and-runtime.md` owns TLS at
the edge, and `a07-authentication-failures.md` owns password policy and the
API-key lifecycle. Implementing a primitive yourself is out of scope by rule —
the answer is always a vetted library.

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
them: fast hashes for passwords, secrets in source, plaintext transport, weak or
homemade signing, and sensitive data stored where it needn't be. The principle
is **use vetted primitives with sane parameters, keep keys out of code, encrypt
in transit always, and minimize what you store**. Never invent crypto; never
compare secrets with a non-constant-time `==`.

Worth knowing what the category actually catches in the field: three of the
most common CWEs OWASP maps to A04:2025 are about **randomness**, not about
ciphers — CWE-331 (insufficient entropy), CWE-338 (cryptographically weak
PRNG), and CWE-1241 (predictable algorithm in a random number generator),
alongside CWE-327 (broken or risky algorithm). A guessable token is a
cryptographic failure in exactly the same sense that a fast password hash is,
and it is the one reviewers skip past most often.

## Password hashing

Maps to CWE-916 (password hash with insufficient computational effort) and
CWE-327 (broken or risky algorithm).

### Principle layer

A password hash is the only defense that still applies once the database has
already been copied. Its strength is a **cost you choose** — memory, time, and
parallelism — so the two decisions are the family and the parameters, and the
second is the one projects skip. A memory-hard function with defaults nobody
ever measured is a defensible starting point; the same function with parameters
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
2. Set **m** to the memory each concurrent login can afford — peak logins per
   second multiplied by **m** has to fit inside the worker's real headroom, or
   a login spike becomes an out-of-memory event and the availability incident
   costs more than the parameter bought.
3. Raise **t** until a single hash costs the most latency the login path can
   absorb.

Measure on the hardware that will run it in production. A figure benchmarked on
a developer laptop describes nothing about the worker, in either direction.
Re-tune on a schedule: the parameter that was expensive for an attacker three
years ago is cheap now, and nothing in the system will tell you.

Never store a password with a fast hash (`md5`, `sha1`, a bare `sha256`), never
without a per-password salt, and never with anything reversible. Encrypting a
password is a finding, not a mitigation — whoever holds the key holds the
plaintext.

### Django & DRF implementation layer

Django hard-codes its own parameters on each hasher class rather than
inheriting the library's, so verify against the Django version in front of you.
As of Django 6.0 and 5.2 LTS:

| Hasher | Shipped defaults |
|---|---|
| `Argon2PasswordHasher` | Argon2id, `time_cost=2`, `memory_cost=102400` (100 MiB), `parallelism=8` |
| `PBKDF2PasswordHasher` | 1,200,000 iterations on 6.0; 1,000,000 on 5.2 LTS |
| `ScryptPasswordHasher` | `work_factor=2**14`, `block_size=8`, `parallelism=5` |

Seven things follow from that table, and the first is the one that actually
shows up in review:

1. **The default ordering is the finding, not the parameters.** Django's
   shipped `PASSWORD_HASHERS` is PBKDF2, then PBKDF2SHA1, then Argon2, then
   BCryptSHA256, then Scrypt. Argon2 is **third**. Installing `argon2-cffi`
   does not move it, and nothing warns you: a project that never set
   `PASSWORD_HASHERS` is hashing with PBKDF2 no matter what is in its
   requirements file. Grep for the setting; its absence is the finding.
2. **Django's Argon2 defaults are not the weak part.** At 100 MiB they sit well
   above OWASP's 19 MiB floor. They are also not `argon2-cffi`'s defaults —
   that library's own `PasswordHasher` is `t=3`, `m=64 MiB`, `p=4`, the RFC 9106
   SECOND profile — and neither tracks the other. Do not reason from one to the
   other; read the numbers off the version you are running.
3. **Raising a cost parameter propagates by itself.** `check_password()` takes
   a `setter` callback, and `Argon2PasswordHasher.must_update()` compares every
   stored parameter against the class attributes, so a subclass with higher
   costs re-hashes each user on their next successful login with no application
   code at all. `argon2-cffi`'s `check_needs_rehash()` is the equivalent for
   non-Django callers; wiring it into a Django login path duplicates machinery
   the framework already runs.
4. **Never remove an entry from `PASSWORD_HASHERS`.** Django can only upgrade a
   hash whose algorithm is still listed. Removing the old entry does not
   migrate those users, it locks them out.
5. **`ScryptPasswordHasher`'s default `work_factor=2**14` is below OWASP's
   2^17 floor.** If scrypt is the choice, subclass it rather than accepting the
   default.
6. **`BCryptPasswordHasher` truncates silently at 72 bytes**, so a long
   passphrase contributes nothing past that point.
   `BCryptSHA256PasswordHasher` pre-hashes with SHA-256 first and does not.
   Only the latter belongs in the list.
7. **Mixed algorithms in one user table are a user-enumeration timing oracle**,
   and Django's own documentation says so: a login for a user whose hash is in
   a non-preferred algorithm takes measurably different time from a login for a
   user who does not exist. Upgrade-on-login shrinks the exposure as people
   sign in; the residue is the dormant accounts that never do. See
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

**Package decision (9 Aug 2026):** `argon2-cffi==25.1.0` passes the maintained-
package gate. Install it with `pip install "django[argon2]"`, put a hasher of
yours in front of Django's, and record the benchmark that produced the
parameters. See `security-hardening-libraries.md`, "Cryptographic primitives
and password hashing".

### Migrating a hasher family

Point 7 above names a residue and stops there: upgrade-on-login fires only for
accounts whose owner logs in, so dormant ones hold the legacy algorithm
indefinitely, and reordering `PASSWORD_HASHERS` does nothing for them. Django
documents the way out, and the useful property is that it needs no plaintext —
re-encode the **stored digest** under the preferred hasher, and every row moves
in one pass whether or not its owner ever comes back.

The wrapper hashes the legacy digest in place of the password. Three parts:

1. A hasher subclassing the target, with its own `algorithm` string and an
   `encode_<legacy>_hash` helper that the migration calls with the digest read
   out of the column.
2. A one-way data migration that splits each stored value, re-wraps it, and
   writes it back.
3. Both the wrapper and the legacy hasher left in `PASSWORD_HASHERS`, so
   `identify_hasher` can still read what is stored.

**Django's own example wraps into PBKDF2, and that recipe does not transfer to
Argon2 unchanged.** `PBKDF2PasswordHasher.verify` re-derives through
`self.encode`, so overriding `encode` is enough to carry verification with it.
`Argon2PasswordHasher.verify` does not — it hands the raw password straight to
the argon2 library — so a wrapper that overrides only `encode` migrates every
row and then rejects every correct password, which is a lockout that passes
code review because the migration half works. An Argon2 target needs `verify`
overridden too, recovering the reused salt through the inherited `decode()`:

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

After the pass a row reads `argon2_wrapped_md5$...` — Argon2 over an MD5
digest, so a guess now costs an Argon2 evaluation rather than an MD5 one. At
the owner's next login `check_password` sees a stored algorithm that is not the
preferred one, re-hashes the plaintext it was just handed, and the row lands on
plain `argon2$...`. Nobody is prompted and nothing is reset. Four things to
know before running it:

- **Every live session ends the moment the migration lands.**
  `get_session_auth_hash()` is an HMAC of the password field and `get_user()`
  compares it on each request, so rewriting every row invalidates every session
  at once. There is no request in flight to call `update_session_auth_hash()`
  for, so this is scheduled and announced rather than avoided.
- **A short legacy salt is a hard stop for an Argon2 target.** Argon2 rejects a
  salt under 8 bytes outright, so rows whose salt is shorter cannot be wrapped
  into it — they need a different target or the reset path below.
- **The data-migration form is fine here** in a way the key-rotation pass
  earlier in this file is not, because it depends on no key that will later be
  destroyed. The resumability argument still holds at scale: a user table large
  enough to time out a deploy wants the same chunked management command.
- **Wrapping raises the cost of future cracking and undoes no past exposure.**
  It protects the copy in your database. A copy already taken is still
  crackable at the legacy cost.

**When to force a reset instead.** Django documents the wrap and does not say
when to give up on it, so these are engineering criteria rather than doctrine.
Each makes wrapping insufficient rather than merely slower:

- **The legacy hashes have been exposed.** Only a password the leaked digests
  no longer describe devalues them.
- **The legacy scheme is unsalted.** Precomputation against exposed unsalted
  digests is cheap enough that the first criterion is effectively already met.
- **No verifier can be reconstructed** — truncated, foreign-format, or
  short-salted values that will not re-encode into a wrapper. There is nothing
  to wrap.
- **A compliance obligation mandates rotation** on deprecation of the
  algorithm.

Reset costs what wrapping does not: every user is interrupted at once, support
absorbs the ones who no longer control the registered address, and the reset
mail is a phishing template in the same week you told everyone to expect one.
Where none of the four holds, wrap — it closes the dormant gap immediately,
including the timing difference point 7 leaves open, and expiring a chosen
subset stays available as a separate decision.

**Write-time.** When moving a project onto a different hasher family, write the
wrapper and its data migration in the same change as the `PASSWORD_HASHERS`
reorder, because the reorder alone reaches only the accounts that log in and
leaves the rest on the old algorithm with nothing reporting that it did.
Override `verify` alongside `encode` whenever the target is Argon2, and check
the pair against a real legacy hash before the migration runs rather than
after — a wrapper that encodes correctly and verifies wrongly looks right in
review and locks out everyone it just migrated.

### Peppering

A pepper is a site-wide secret that the hasher mixes into the password, and
that the database never holds. A database-only dump therefore cannot start an
offline guess at all. Django peppers nothing by default. The supported spelling
is a wrapping hasher: subclass the Argon2 hasher, and HMAC the password with a
key from the secret manager before the hash. Use the same wrapper form as the
migration above, and keep the key in the secret manager rather than in
`SECRET_KEY`.

Rotation is a new wrap version, not a mass reset. A pepper is defense in depth
for the database-dump case, and never a substitute for the parameters above.
Rate a missing pepper as no finding. Name it as available hardening where the
threat model is a database-only compromise.

## Password validators

Configure `AUTH_PASSWORD_VALIDATORS` (length, common-password, numeric,
user-attribute similarity). This is your baseline against weak and reused
credentials. The policy those validators encode is not this file's:
`a07-authentication-failures.md`, "Password policy", carries the SP 800-63B-4
requirements each one maps to, the length floor that sits above Django's
default, and the breached-corpus screening no built-in provides. Lockout and
breach handling are in the same file under "Brute force and enumeration".

## Secrets

- `SECRET_KEY`, JWT `SIGNING_KEY`, DB passwords, and third-party API keys load
  from the environment or a secrets manager — never literals in `settings.py`,
  never committed. Read required values with `os.environ[...]`, so a missing
  production secret fails at startup instead of becoming `None` and quietly
  disabling a check downstream.
- `SECRET_KEY_FALLBACKS` lets the previous key keep *validating* while the new
  key signs, which is what makes a rotation survivable. It does not cover
  everything derived from the key, and — contrary to a widely repeated claim —
  rotation does not invalidate CSRF tokens. The subsystem-by-subsystem
  breakdown, the two-phase procedure, and the deliberate hard cut after a
  compromise are in `service-identity-and-secrets.md`, "Rotating Django's
  SECRET_KEY".
- Where secrets should live per runtime, how they reach the process, and the
  ordered response to a leak are in `service-identity-and-secrets.md`, as are
  machine-to-machine credentials themselves — client-credentials tokens, mutual
  TLS, and workload identity. This file keeps the primitives underneath them.
- A hardcoded or committed secret is a finding on its own (High–Critical
  depending on what it unlocks). See `dangerous_patterns.py` for detection and
  the deployment/libraries files for `.env` hygiene.

## Randomness and token generation

Maps to CWE-330 (insufficiently random values), CWE-338 (cryptographically weak
PRNG), CWE-331 (insufficient entropy), and CWE-340 (predictable from observable
state).

### Principle layer

A bearer token's only security property is that nobody can produce a valid one
without being given it. That collapses the requirement to two things: it comes
from a cryptographically secure source, and it has enough entropy that guessing
is hopeless — 128 bits is the floor and 256 bits costs nothing extra. Two
further rules keep it that way: **one purpose per token**, so a value minted for
one flow cannot be presented to another, and **store long-lived tokens hashed**,
so a database read does not hand over working credentials.

The anti-patterns, all of which appear in real code:

- **Sequential or auto-increment ids as tokens.** The next one is the current
  one plus one.
- **Timestamp-derived values.** The attacker knows roughly when it was issued,
  which reduces the search to the resolution of the clock.
- **`random.*`.** Python's default generator is a Mersenne Twister, seeded and
  fully reconstructible: observing enough consecutive outputs recovers its
  internal state and yields every future value. It is a statistical generator,
  not a cryptographic one, and the two are not interchangeable.
- **Timestamped UUIDs as secrets.** UUIDv1 and UUIDv7 embed a timestamp by
  design and are meant to be sortable, not unguessable.
- **UUIDv4 as an authorization decision.** It is random, but it is roughly 122
  bits and — more importantly — possessing an identifier is not the same as
  being authorized to use it. An unguessable URL is not an access control; see
  `a01-broken-access-control.md`.
- **One token reused across purposes**, which turns any single leak into every
  capability that token can reach.

### Django & DRF implementation layer

- `secrets.token_urlsafe()` and `secrets.token_hex()` are the correct
  generators. Both default to `secrets.DEFAULT_ENTROPY`, which is 32 bytes /
  256 bits, so the bare call is already the right size. `secrets` draws from the
  OS CSPRNG throughout — `compare_digest` is `hmac.compare_digest`, and
  `choice`, `randbelow`, and `randbits` come from `random.SystemRandom`.
- `django.utils.crypto.get_random_string` is also CSPRNG-backed: it is
  `secrets.choice` over a 62-character alphanumeric alphabet, about 5.95 bits
  per character. That makes the common 12-character call roughly 71 bits —
  fine for a filename suffix or a nonce, short for a bearer credential. Pass a
  longer length or use `token_urlsafe`.
- `django.core.management.utils.get_random_secret_key()` generates a
  `SECRET_KEY`; it is what `startproject` uses.
- Password-reset and email-verification tokens should use Django's
  `PasswordResetTokenGenerator` rather than a hand-rolled value: it is
  single-use by construction, because the hash covers the user's current
  password hash and last-login timestamp, and it is time-limited by
  `PASSWORD_RESET_TIMEOUT`.
- A long-lived API key is stored as a hash plus a short non-secret prefix for
  lookup, never as the raw value. The full key lifecycle — prefixes, scoping,
  expiry, and revocation — is in `a07-authentication-failures.md`, "API keys".

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

**Write-time.** When generating a token or any other secret, call `secrets`
and take its default length rather than sizing the value yourself, because the
bare call is already 256 bits and a length chosen by hand is the one that
turns out to be the 71 bits above. Mint one per purpose and store the
long-lived ones hashed, and reach for `PasswordResetTokenGenerator` where the
flow is a reset or a verification instead of re-implementing single use and
expiry. Two decisions travel with the value and are cheapest in the same edit:
any `Signer` or `TimestampSigner` carrying it takes a per-purpose `salt=`, and
the check that later compares it against a stored copy uses
`hmac.compare_digest` over fixed-length digests wherever the scope section
below says the comparison is itself the gate.

### Commonly mistaken for a finding

**`random` for retry jitter, sampling, backoff, shuffling a display order, or
a test fixture.** The anti-pattern list above names `random.*` outright, and
`import random` is a one-line grep with no context in it, so every call site
reads as CWE-338 on sight. Predictability is only a defect where
unpredictability was the security property being relied on. The deciding
question is what the value becomes: a credential, a token, a reset link, a
session identifier, or anything else whose whole defense is that it cannot be
guessed makes this a finding, and a delay, a sample, an ordering, or a
fixture makes it the correct choice of generator.

**Write-time.** When generating a value whose only requirement is statistical
spread — jitter on a retry, a sampled subset, a shuffled order — call
`random` and leave `secrets` for the values whose security property is that
nobody can predict them, because reaching for the CSPRNG everywhere blurs the
signal that makes the real misuse visible in review.

## Constant-time comparison

Maps to CWE-208 (observable timing discrepancy).

Scope this one deliberately. `==` on a secret is a real finding in a specific
set of places and cargo-cult noise everywhere else, and a review that flags
every string comparison in a codebase trains people to ignore the flag.

**Where it matters** — a caller-supplied value is compared against a stored one
and *that comparison is the gate*:

- API keys and bearer tokens checked directly against a stored value.
- HMAC and webhook signatures (`a08-integrity-and-deserialization.md` owns the
  full receiver).
- Password-reset, email-verification, and invitation tokens.
- CSRF tokens, MFA and OTP codes.

**Where it is noise:**

- Anything already run through a password KDF. The KDF dominates the timing and
  the comparison is over fixed-length digests.
- Non-secret identifiers — usernames, object ids, tenant slugs. Their timing
  leaks nothing that is not already public, and enumeration through them is an
  authorization question, not a timing one.
- A comparison whose result the attacker cannot observe through response
  timing, because the surrounding work swamps the signal.

In Django, `django.utils.crypto.constant_time_compare` is
`secrets.compare_digest(force_bytes(val1), force_bytes(val2))`. Two properties
matter in review. It is constant-time **only for equal-length inputs** — the
underlying comparison short-circuits on a length mismatch, which is fine for
the fixed-length digests Django compares with it. And for a **variable-length**
secret, that length difference is itself the leak, so compare fixed-length
HMACs of the two values instead of the values themselves:

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

A signature proves a value was minted by someone holding the key. It does not
prove *what the value was minted for*. If one key signs every kind of token,
every token is interchangeable, and an attacker who can legitimately obtain one
gets the others for free. The fix is **domain separation**: bind each purpose
into the signed material, so a token minted for one flow fails verification in
another.

Two further rules travel with it. Every signed artifact needs a **maximum age**
appropriate to its own purpose — a password-reset link measured in hours, an
unsubscribe link possibly in months, and not the same number for both. And
**signing is not encryption**: a signed payload is authenticated, not
confidential, and anyone holding it can read it.

### Django & DRF implementation layer

Use `django.core.signing` — `Signer`, `TimestampSigner`, `dumps`/`loads` —
rather than assembling an HMAC by hand. Verified against Django 6.0 and 5.2,
`Signer` defaults to the project `SECRET_KEY` with `SECRET_KEY_FALLBACKS`
honored, `sep=":"`, `algorithm="sha256"`, and a `salt` that defaults to
`"<module>.<ClassName>"` — so every unnamed `Signer` in the project shares the
salt `"django.core.signing.Signer"`, and `dumps`/`loads` share
`"django.core.signing"`. The signature is computed over `salt + "signer"`, which
is exactly the namespacing hook, and Django's own docstring states that leaving
the salt at its default or reusing one across parts of an application without
good cause is a security risk.

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

- `salted_hmac()` defaults to `algorithm="sha1"` on Django 6.0 and 5.2, with a
  documented transition to `"sha256"` in Django 7.0. It is still an HMAC and
  not a broken construction, but pass `algorithm="sha256"` explicitly in new
  code so the value does not change under you at the upgrade.
- `signing.dumps()` produces signed, base64-encoded, **readable** output. Do not
  put anything confidential in it.
- Which subsystems `SECRET_KEY_FALLBACKS` covers during a rotation, and the
  two-phase procedure, are in `service-identity-and-secrets.md`, "Rotating
  Django's SECRET_KEY".
- Django made this exact mistake in its own signed-cookie helper, which is
  worth knowing because it shows the failure is a collision rather than a
  weak signature: `get_signed_cookie()` built its salt by concatenating the
  cookie name and the `salt` argument, so two distinct pairs could produce
  one salt. The version floor, the transitional setting, and the audit are in
  `a02-security-misconfiguration.md`, "Signed cookies and the legacy salt
  fallback".

## Data in transit and at rest

- TLS everywhere (see deployment). The database connection must be *verified*,
  not merely encrypted: on PostgreSQL that means `sslmode=verify-full` with a
  pinned root certificate, since `require` encrypts and accepts whatever
  answered. See `data-layer-and-database.md`, "Verified database connections".
- Store only the sensitive data you need. **Never store raw card data** — use the
  gateway's tokenization/hosted flows (see A08 and the DRF file for payment
  specifics). For fields that must be encrypted at rest, almost every packaged
  Django field-encryption library has gone unmaintained — build on PyCA
  `cryptography` with keys held outside the database, and add a keyed blind
  index where the column must stay searchable. The mechanism, its cost, and what
  a blind index leaks are in `data-layer-and-database.md`, "Field-level
  encryption and searchable lookups"; the key's own lifecycle is below.
- Full-disk and cloud-volume encryption answer the stolen-disk threat and
  nothing else. They do not protect a value from a compromised running database
  or an over-privileged query path, so they do not satisfy a requirement that a
  column be encrypted. The distinction is what the threat can already see:
  volume encryption defends stolen media and backups and is transparent to any
  authenticated connection, so it stops none of the paths that actually leak a
  column — an injected read, a stolen database credential, an over-privileged
  operator, a replica nobody remembered. Column encryption keeps the value
  ciphertext in the query result unless the application holds the key.
- Encrypting a column is a real cost, not a default: it removes `LIKE`, ranges,
  ordering, uniqueness, and useful indexing on that column. Justify it per
  column, for narrowly-scoped high-sensitivity values that are rarely queried
  by content, rather than adopting it wholesale.

## Key lifecycle and envelope encryption

Maps to CWE-324 (use of a key past its expiration date), CWE-321 (hard-coded
cryptographic key), and CWE-311 (missing encryption of sensitive data).
CWE-320 (Key Management Errors) is the identifier often reached for here, but
it is a category, which CWE's mapping guidance prohibits citing in a finding.

### Principle layer

A key has a life: **generate → store → use → rotate → revoke → destroy**. Most
projects implement the first three and discover the rest during an incident, at
which point rotating means re-encrypting a table nobody has a script for.

**Envelope encryption** is the shape that makes the rest tractable. Encrypt the
data with a **data encryption key (DEK)**; encrypt the DEK with a
**key-encryption key (KEK)** that never leaves a KMS or HSM; store the wrapped
DEK beside the ciphertext. The plaintext DEK exists only briefly in application
memory. Three things follow, and they are the whole reason to bother: the key
that matters is never in a config file to be leaked, every unwrap is an audited
KMS call, and rotating the KEK is one operation instead of a table scan.

Rotation without downtime is **versioning**, not replacement. New writes use the
new key version; reads try the current version and fall back through prior ones;
a background job re-encrypts what already exists; the old version is destroyed
only once an audit shows nothing references it. Two distinctions to hold on to:
re-wrapping a DEK under a new KEK is *not* re-encrypting the data — it changes
only who can unwrap it — and destroying a key version before that reference
audit is not rotation, it is data loss.

Re-encryption is a **data migration**, with the properties every data migration
needs: chunked, idempotent, resumable from a stored watermark. A pass that has
to start over after a crash is one that will not finish on a large table.

### Django & DRF implementation layer

`data-layer-and-database.md`, "Field-level encryption and searchable lookups"
owns the storage mechanism, the query cost, and the blind index. What belongs
here is the primitive and the key's life around it.

- **Choosing the primitive.** `Fernet` is AES-128-CBC with PKCS7 padding and a
  separate HMAC-SHA256, encrypt-then-MAC, with an `os.urandom` IV. It is a
  sound, hard-to-misuse default. Know one property before using it on a column:
  a Fernet token embeds the encryption time **in plaintext**, so the column
  leaks when each row was last written. Where that is sensitive, or where a
  single-pass AEAD is preferred, use `AESGCM` or `ChaCha20Poly1305` and own the
  nonce — never reuse a nonce under one key, which for GCM is catastrophic
  rather than merely untidy.
- **`MultiFernet` is the in-process model of key versioning.** It encrypts with
  the first key in the list and decrypts by trying each in turn, and its
  `rotate()` re-encrypts an existing token under the primary key while
  preserving the original timestamp.
- **Do not derive a field-encryption key from `SECRET_KEY`.** It collapses two
  independent secrets into one: a `SECRET_KEY` rotation becomes a full data
  re-encryption, and a `SECRET_KEY` leak becomes a decryption-key leak. Keep
  them separate so they can be rotated on separate schedules.
- The re-encryption pass belongs in a **management command**, not a migration
  file. Migrations run inside deploy transactions, are hard to resume, and
  their history should not depend on key material that will be destroyed.

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
between; use `select_for_update()` or a write-quiet window, and re-run.

**Package decision (7 Aug 2026):** `cryptography==50.0.0` is the recommended
base and `django-fernet-encrypted-fields==0.4.0` is **conditional**, with the
condition being its key derivation — it derives the Fernet key from
`SECRET_KEY` and a `SALT_KEY` setting, which is exactly the coupling the bullet
above warns against. See `security-hardening-libraries.md`, "Cryptographic
primitives and password hashing".

### Envelope encryption against a KMS

The `MultiFernet` example above is the fallback, and it is worth being precise
about what it falls short of. It versions keys correctly, but every version is
in `settings.FIELD_KEYS`, so the process holds the material that decrypts the
whole table for its entire lifetime, a configuration leak is a plaintext leak,
and nothing anywhere records which rows were read. Envelope encryption moves
each of those: the KEK stays in the KMS, the only key in the process is a
per-row DEK that lives for one request, and each unwrap is a call somebody can
audit and revoke.

Three details carry the pattern, and the middle one is the one projects leave
out. `generate_data_key` returns both halves at once — `Plaintext`, the DEK you
encrypt with, and `CiphertextBlob`, the same DEK wrapped under the KEK, which
is what the row stores. `EncryptionContext` is non-secret additional
authenticated data, and `decrypt` fails with `InvalidCiphertextException`
unless it is supplied again as a case-sensitive exact match — so binding it to
the table and row is what stops a wrapped DEK lifted out of one row from being
unwrapped against another. And the context has to be **stable from the first
write**, which means it cannot be derived from a primary key the row does not
have yet.

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

Two review notes on the shape. The plaintext DEK is a local and nothing else —
not an attribute on the instance, not a cache entry, not a log field — because
its short lifetime is the only property that distinguishes this from holding
the key in settings; Python cannot actually zero an immutable `bytes`, so
"never stored" is the achievable guarantee rather than "erased." And a DEK per
row makes `get_ssn` one KMS call per row, which turns any list view over the
model into a per-row round trip and a per-row bill — scope the pattern to
narrow, rarely-listed, high-sensitivity columns, or widen the DEK to a tenant
or a batch and accept the coarser blast radius deliberately.

The equivalents, named rather than tiered: GCP Cloud KMS wraps and unwraps a
locally-generated DEK through `encrypt` and `decrypt` on the key path, with
Tink's `KmsEnvelopeAead` automating the generate-and-wrap step, and Azure Key
Vault uses `wrapKey` and `unwrapKey`. These are platform SDKs a project already
runs, not security packages being chosen against alternatives, so
`security-hardening-libraries.md`, "Cryptographic primitives and password
hashing", records all three as patterns rather than giving a provider a
disposition.

**Write-time.** When generating field encryption against a KMS, pass an
`EncryptionContext` on `generate_data_key` in the same edit that writes the
`decrypt` call, because a wrapped DEK created without one can never acquire the
binding afterwards without re-encrypting the column, and the pair only works if
both sides carry the identical dict. Bind it to a value the row already has
rather than to a pk it is about to be assigned, add the `wrapped_dek` column in
the same migration as the ciphertext column so no row can exist without its
key, and keep the plaintext DEK in a local rather than on the model instance.

## Cryptographic agility and algorithm lifecycle

Maps to CWE-757 (selection of less-secure algorithm during negotiation) and
CWE-327 (use of a broken or risky cryptographic algorithm).

### Principle layer

**You will need to change an algorithm before you need to change a key.** Key
rotation runs on a schedule you set; an algorithm change arrives on someone
else's — a published break, a deprecation notice, a compliance date — and
lands on code written as though one algorithm would hold forever. Design for
the harder change and the easier one comes free.

One property makes that possible: **every stored cryptographic value records
what produced it.** Keep the algorithm identifier and the key identifier with
the ciphertext, the signature, or the hash, as data beside the value rather
than as knowledge inside whichever function currently reads it.

Two inferences are worth rejecting by name. **Do not infer the algorithm from
the payload**, and **do not infer it from the length.** A 32-byte digest is
SHA-256 right up until something else is also 32 bytes; at that moment every
stored value becomes ambiguous at once, and no later code recovers a
distinction the format never recorded.

**Verification reads the stored identifier, then checks it against a
server-side allow list.** Reading an identifier is not trusting it: it selects
among algorithms the server has already decided it accepts, and one naming
anything else is rejected input, not an instruction. A verifier that honors
the algorithm the data names is the algorithm-confusion defect, which
`service-identity-and-secrets.md`, "Validating an inbound machine token" owns
for tokens — `alg: none` and the RS256-to-HS256 swap included.

**The migration has four steps, and the third is the one that gets skipped.**

1. **Dual read.** Accept the old algorithm and the new one.
2. **Single write.** Emit only the new one, so the old population can only
   shrink.
3. **Measure.** Count what still carries the old identifier, and keep counting
   until it reaches zero and stays there.
4. **Retire the read path.** Remove the old branch — and only then the key.

A migration that skips step 3 never finishes. Steps 1 and 2 are a morning's
work and feel like completion, so the dual-read branch survives indefinitely
and the broken algorithm stays a live, reachable code path. Step 3 is the only
one of the four that produces evidence — it turns "we migrated" into a claim
with a number behind it.

**Keep one inventory of every algorithm in use** — location, owner, review
date — covering the password hasher list, signing, tokens, field encryption,
webhook signatures, and transport ciphers. Its worth is not the list but that
the next published break becomes a lookup rather than a codebase search under
time pressure. The harvest-now-decrypt-later inventory in "Post-quantum
posture" is this one answering a single question, not a second to maintain.

**The failure mode to name is a value no code path can read**, because the key
or the algorithm went away before the data did. Retiring the old read path
while rows still carry the old identifier, or destroying a key version
something still references, does not fail at deploy — it fails at the first
read of an old row, by which point the plaintext is gone. This is a data-loss
defect arriving through a security change, which is why it clears review: the
change looks like remediation, and the reviewer checks that the weak algorithm
is gone rather than that everything written under it moved first.

### Django & DRF implementation layer

Django already models the pattern in three places, which makes them the shape
to copy rather than material to restate:

- **A password hash is self-describing.** The encoded string carries its
  algorithm in the first `$`-separated field, `identify_hasher` dispatches on
  it, and `PASSWORD_HASHERS` is the allow list — stored identifier, allow
  list, and dual read in one mechanism. "Migrating a hasher family" above is
  steps 3 and 4 applied to the population upgrade-on-login cannot reach.
- **`MultiFernet` and `SECRET_KEY_FALLBACKS` are dual read for keys**: a list
  whose first entry writes and whose every entry reads.
- **A `kid` in a JWS header is the stored key identifier**, resolved against a
  published set — `service-identity-and-secrets.md`, "JWKS as a
  rotation-aware trust anchor".

The gap is almost always the project's own crypto rather than Django's. A
field encrypted with `Fernet`, an HMAC over a webhook body, a signed download
token: each is typically persisted as bare output with the algorithm implied
by whichever line reads it. Give them the self-describing shape.

```python
# Wrong: the column holds raw ciphertext. Changing the primitive means a data
# migration with no way to tell a converted row from an unconverted one.
record.payload = fernet.encrypt(plaintext)

# Correct: the value names the key version and algorithm it was written
# under, so the reader dispatches on data and step 3 has something to count.
record.payload = b"v2:aesgcm:" + nonce + ciphertext
```

One Django case is worth stating because it looks marked and is not.
**`django.core.signing.Signer` records no algorithm in its output.** The value
is `payload:signature`, `algorithm` defaults to `sha256`, and changing it
raises `BadSignature` on every value signed under the old one — verified on
Django 6.0.7, 14 August 2026. Only the signature length distinguishes the two
encodings, which is the inference this section rejects. So a signer algorithm
change has no dual read available: bound it with the maximum age "Signing and
salt discipline" already requires, and let every value still in flight expire
before the old algorithm goes. An algorithm change under a field encryption is
a data migration in `data-layer-and-database.md`, "Field-level encryption and
searchable lookups", which owns the blind index that has to be rebuilt when
the primitive beneath it changes.

**Write-time.** When generating code that writes a ciphertext, a signature, or
a non-password digest, put the algorithm identifier and the key identifier
into the stored format in the same change, because the format is fixed the
moment the first row is written and every later migration is priced by that
decision. When generating a verifier, read the identifier out of the value and
check it against a constant allow list in the project, never against the
value's own claim. When generating the change that removes an algorithm,
generate step 3's count query alongside it and leave the old read path until
that query returns zero.

## Post-quantum posture

The sober version, because this area attracts more urgency than it currently
earns for a backend.

NIST finalized the first post-quantum standards in August 2024 — **FIPS 203**
(ML-KEM, key encapsulation), **FIPS 204** (ML-DSA), and **FIPS 205** (SLH-DSA)
— and selected HQC in 2025 as a backup KEM still being standardized. NIST's
transition guidance (IR 8547) deprecates quantum-vulnerable public-key
algorithms after 2030 and disallows them after 2035, with high-risk systems
expected to move sooner.

What that means for a Django backend right now:

- **The one action worth taking is an inventory.** Identify data whose
  confidentiality has to outlive the migration window — anything that must
  still be secret past the 2035 horizon. That is the "harvest now, decrypt
  later" exposure: an adversary recording ciphertext today to decrypt once the
  hardware exists. Records with a long retention requirement are the ones that
  matter; a session cookie is not. Feed the result into the personal-data
  inventory in `data-lifecycle-and-privacy.md`.
- **Hybrid TLS key exchange is a deployment decision, not application code.**
  It is negotiated by the TLS terminator, and on a current OpenSSL it is
  already the default rather than something to adopt — which makes the finding
  a group list that pins it out, not a missing feature. See
  `deployment-and-runtime.md`, "Hybrid post-quantum key exchange".
- **Symmetric primitives are not the urgent case.** A quantum adversary gets at
  most a quadratic speedup against a well-chosen symmetric cipher or hash, and
  AES-256 and SHA-256 carry margin for that. The pressure is on public-key key
  exchange protecting long-lived confidential data.
- **Nothing here justifies adopting a post-quantum library in application
  code** this cycle, or re-encrypting a database, or swapping token signatures
  to ML-DSA. A recommendation to do any of those today should be treated as
  premature and challenged.

Severity: **Low now, latent.** This is an inventory item, not a fix, and
reporting it as anything more spends credibility that the rest of the report
needs.

## Review checklist

### Stack-neutral

- [ ] Passwords go through a memory-hard KDF — Argon2id preferred, scrypt
      acceptable — with parameters chosen explicitly and benchmarked on
      production hardware, not inherited and never measured.
- [ ] Argon2id parameters meet at least the OWASP floor of m=19 MiB, t=2, p=1,
      and the memory cost multiplied by peak concurrent logins still fits the
      worker's real headroom.
- [ ] No password is stored under a fast hash, without a per-password salt, or
      under any reversible scheme.
- [ ] Every bearer secret comes from a cryptographic source with at least 128
      bits of entropy — no `random.*`, no sequential ids, no timestamp-derived
      values, no timestamped UUIDs as secrets — and long-lived ones are stored
      hashed.
- [ ] Each signed or minted token is scoped to a single purpose, so one cannot
      be presented to a different flow, and carries a maximum age chosen for
      that purpose.
- [ ] Caller-supplied secrets that gate access are compared in constant time,
      and variable-length secrets are compared as fixed-length HMACs so the
      length itself does not leak.
- [ ] Encryption keys have a documented lifecycle: versioned, wrapped by a KEK
      held in a KMS or HSM rather than sitting in configuration, rotatable
      without downtime, and destroyed only after an audit shows no ciphertext
      references them.
- [ ] Where a KMS holds the KEK, every data key is generated and unwrapped
      under an encryption context bound to the row it belongs to, and the
      plaintext data key lives in a local rather than on an instance, in a
      cache, or in a log line.
- [ ] Re-encryption after a key rotation exists as a chunked, resumable,
      idempotent job rather than as an intention.
- [ ] Every stored ciphertext, signature, and non-password digest carries its
      algorithm identifier and key identifier as data, and no reader infers
      either one from the payload or from the value's length.
- [ ] Verification selects the algorithm by checking the stored identifier
      against a server-side allow list, never by accepting the algorithm the
      value names for itself.
- [ ] Each algorithm migration in progress has all four steps — dual read,
      single write, a count of what remains on the old identifier, and removal
      of the old read path only once that count is zero — and no old key or
      read path was retired before the count proved nothing still needs it.
- [ ] One inventory names every algorithm in use with its location, owner, and
      review date, covering the hasher list, signing, tokens, field
      encryption, webhook signatures, and transport ciphers.
- [ ] Data whose confidentiality must outlive the post-quantum migration
      window is inventoried for harvest-now-decrypt-later exposure.

### Django & DRF

- [ ] `PASSWORD_HASHERS` is set explicitly with a memory-hard hasher first —
      its absence means the project is on PBKDF2 regardless of what is
      installed — and no entry has been removed, so old hashes can still
      upgrade on login.
- [ ] Cost increases are applied by subclassing the hasher, so
      `must_update()` re-hashes users at their next login; `BCryptSHA256`
      rather than `BCrypt` is listed; any scrypt use is subclassed above
      Django's default `work_factor`.
- [ ] A change of hasher *family* is carried by a wrapped-hasher data
      migration rather than by reordering `PASSWORD_HASHERS` alone, so dormant
      accounts move too, and an Argon2 target overrides `verify` as well as
      `encode` or every migrated login fails.
- [ ] `AUTH_PASSWORD_VALIDATORS` configured.
- [ ] Tokens use `secrets.token_urlsafe`, `get_random_secret_key()`, or
      `PasswordResetTokenGenerator` — not `get_random_string` at a short
      hand-picked length such as the common 12 characters for a bearer
      credential.
- [ ] Every `Signer` / `TimestampSigner` passes a purpose-specific `salt`
      rather than accepting the default, and `unsign` passes a `max_age`.
- [ ] Secret comparisons use `constant_time_compare` or
      `hmac.compare_digest`, and the codebase is not sprinkling them over
      non-secret identifiers instead.
- [ ] No secrets in source or VCS; loaded from env/secrets manager; a rotation
      path exists with an overlap window sized to the longest-lived signed
      artifact, and `SECRET_KEY_FALLBACKS` is wired into settings before it is
      needed.
- [ ] Field-encryption keys are independent of `SECRET_KEY`, so the two rotate
      on separate schedules and one leak is not both.
- [ ] TLS in transit, with the database connection *verified* rather than only
      encrypted; no raw card data stored; disk encryption is not counted as
      column encryption.
