# A04:2025 — Cryptographic Failures

Password hashing, data in transit and at rest, signing, reset tokens, and where
secrets live.

## Contents
- [Principle](#principle)
- [Password hashing](#password-hashing)
- [Password validators](#password-validators)
- [Secrets](#secrets)
- [Data in transit and at rest](#data-in-transit-and-at-rest)
- [Signing and tokens](#signing-and-tokens)
- [Review checklist](#review-checklist)

## Principle

Cryptography fails less from broken algorithms than from wrong choices around
them: fast hashes for passwords, secrets in source, plaintext transport, weak or
homemade signing, and sensitive data stored where it needn't be. The principle
is **use vetted primitives with sane parameters, keep keys out of code, encrypt
in transit always, and minimize what you store**. Never invent crypto; never
compare secrets with a non-constant-time `==`.

## Password hashing

Django hashes with the first entry of `PASSWORD_HASHERS` and can transparently
upgrade older hashes on login. Put a memory-hard hasher first:

```python
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",   # requires argon2-cffi
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]
```

- Prefer **Argon2id** (`pip install "django[argon2]"`). PBKDF2 is acceptable but
  weaker against GPU attack. Never remove existing entries — they're needed to
  read and upgrade old hashes.
- Never store passwords with `md5`/`sha1`/`sha256` directly or with any
  reversible scheme.

**Package decision (17 Jul 2026):** `argon2-cffi==25.1.0` passes the maintained-
package gate. Put Django's Argon2 hasher first, keep the framework's fallback
hashers so older hashes can upgrade on login, and benchmark memory/time cost on
production-shaped workers. See `security-hardening-libraries.md`.

## Password validators

Configure `AUTH_PASSWORD_VALIDATORS` (length, common-password, numeric,
user-attribute similarity). This is your baseline against weak and reused
credentials; see the auth file for lockout and breach handling.

## Secrets

- `SECRET_KEY`, JWT `SIGNING_KEY`, DB passwords, and third-party API keys load
  from the environment or a secrets manager — never literals in `settings.py`,
  never committed. Rotate `SECRET_KEY` via `SECRET_KEY_FALLBACKS` so existing
  sessions/tokens survive the change.
- A hardcoded or committed secret is a finding on its own (High–Critical
  depending on what it unlocks). See `dangerous_patterns.py` for detection and
  the deployment/libraries files for `.env` hygiene.

## Data in transit and at rest

- TLS everywhere (see deployment). The database connection must be *verified*,
  not merely encrypted: on PostgreSQL that means `sslmode=verify-full` with a
  pinned root certificate, since `require` encrypts and accepts whatever
  answered. See `data-layer-and-database.md`, "Verified database connections".
- Store only the sensitive data you need. **Never store raw card data** — use the
  gateway's tokenization/hosted flows (see A08 and the DRF file for payment
  specifics). For fields that must be encrypted at rest, note that the packaged
  Django field-encryption libraries have all gone unmaintained — build on PyCA
  `cryptography` with keys held outside the database, and add a keyed blind
  index where the column must stay searchable. The mechanism, its cost, and what
  a blind index leaks are in `data-layer-and-database.md`, "Field-level
  encryption and searchable lookups".
- Full-disk and cloud-volume encryption answer the stolen-disk threat and
  nothing else. They do not protect a value from a compromised running database
  or an over-privileged query path, so they do not satisfy a requirement that a
  column be encrypted.

## Signing and tokens

- Use Django's `signing` (`Signer`, `TimestampSigner`, `dumps`/`loads`) for
  signed values instead of rolling your own HMAC.
- Password-reset and email-verification tokens should use Django's token
  generators (single-use, time-limited); don't build predictable tokens from a
  user id or timestamp.
- Compare secrets/tokens with `hmac.compare_digest` (or
  `django.utils.crypto.constant_time_compare`), never `==`, to avoid timing
  leaks.

## Review checklist

- [ ] Argon2 (or at least PBKDF2) first in `PASSWORD_HASHERS`; no reversible
      password storage.
- [ ] `AUTH_PASSWORD_VALIDATORS` configured.
- [ ] No secrets in source or VCS; loaded from env/secrets manager; rotation path
      exists.
- [ ] TLS in transit, with the database connection *verified* rather than only
      encrypted; no raw card data stored; disk encryption is not counted as
      column encryption.
- [ ] Signing/reset tokens use Django's primitives; secret comparisons are
      constant-time.
