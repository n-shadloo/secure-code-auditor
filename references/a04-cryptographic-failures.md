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

A password hash is the only defence that still applies once the database has
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

**Package decision (7 Aug 2026):** `argon2-cffi==25.1.0` passes the maintained-
package gate. Install it with `pip install "django[argon2]"`, put a hasher of
yours in front of Django's, and record the benchmark that produced the
parameters. See `security-hardening-libraries.md`, "Cryptographic primitives
and password hashing".

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
honoured, `sep=":"`, `algorithm="sha256"`, and a `salt` that defaults to
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

Maps to CWE-320 (key management errors), CWE-321 (hard-coded cryptographic
key), and CWE-311 (missing encryption of sensitive data).

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

**Package decision (7 Aug 2026):** `cryptography==50.0.0` is the recommended
base and `django-fernet-encrypted-fields==0.4.0` is **conditional**, with the
condition being its key derivation — it derives the Fernet key from
`SECRET_KEY` and a `SALT_KEY` setting, which is exactly the coupling the bullet
above warns against. See `security-hardening-libraries.md`, "Cryptographic
primitives and password hashing".

## Post-quantum posture

The sober version, because this area attracts more urgency than it currently
earns for a backend.

NIST finalized the first post-quantum standards in August 2024 — **FIPS 203**
(ML-KEM, key encapsulation), **FIPS 204** (ML-DSA), and **FIPS 205** (SLH-DSA)
— and selected HQC in 2025 as a backup KEM still being standardized. NIST has
stated it will deprecate quantum-vulnerable algorithms by 2035, with high-risk
systems expected to move sooner.

What that means for a Django backend right now:

- **The one action worth taking is an inventory.** Identify data whose
  confidentiality has to outlive the migration window — anything that must
  still be secret past the 2035 horizon. That is the "harvest now, decrypt
  later" exposure: an adversary recording ciphertext today to decrypt once the
  hardware exists. Records with a long retention requirement are the ones that
  matter; a session cookie is not. Feed the result into the personal-data
  inventory in `data-lifecycle-and-privacy.md`.
- **Hybrid TLS key exchange is a deployment decision, not application code.**
  It is negotiated by the TLS terminator; see `deployment-and-runtime.md`.
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
- [ ] Re-encryption after a key rotation exists as a chunked, resumable,
      idempotent job rather than as an intention.
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
- [ ] `AUTH_PASSWORD_VALIDATORS` configured.
- [ ] Tokens use `secrets.token_urlsafe`, `get_random_secret_key()`, or
      `PasswordResetTokenGenerator` — not `get_random_string` at its short
      default length for a bearer credential.
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
