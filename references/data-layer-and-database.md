# Database and Data-Layer Security

This file treats the database as its own security boundary rather than as
trusted storage behind the application. The controls in scope are privilege
separation between migration and runtime roles, row-level security, and whether
tenant context survives a connection pool. They also cover verified transport
to the database, field-level encryption and searchable lookups, and injection
into document and key-value stores. They also cover read-replica staleness in
authorization decisions, connection exhaustion, and where copies of production
data are allowed to travel.

Maps primarily to CWE-250, CWE-269, CWE-284, CWE-295, CWE-311, CWE-89, CWE-943,
and CWE-400. Relevant OWASP categories include A01:2025, A02:2025, A04:2025,
A05:2025, and A06:2025, and API1:2023.

This file owns **the database as a boundary of its own**. That scope is
privilege separation between the migration role and the runtime role. It covers
row-level security and the tenant context that has to survive a pooled
connection. It also holds verified transport, the encrypted column, and the
blind index over it. It holds the isolation level the connection runs at, and
the copies of production data that are allowed to travel.

This file defers for the rules those mechanisms carry out. `a05-injection.md`
owns injection mechanics, and that includes the raw paths enumerated here and
the GeoDjango lookup positions PostGIS inlines rather than binds.
`a04-cryptographic-failures.md` owns the cryptographic principle and the key
lifecycle. `authorization-architecture.md` owns the tenant model this isolation
enforces. `data-lifecycle-and-privacy.md` owns whether a row is really gone.
`deployment-and-runtime.md` owns the network, cache, broker, and secret
delivery around all of it.

## Contents
- [Principle](#principle)
- [Database roles and privilege separation](#database-roles-and-privilege-separation)
- [Row-level security as a backstop](#row-level-security-as-a-backstop)
- [Tenant context on a pooled connection](#tenant-context-on-a-pooled-connection)
- [Verified database connections](#verified-database-connections)
- [Field-level encryption and searchable lookups](#field-level-encryption-and-searchable-lookups)
- [Raw SQL as an isolation bypass](#raw-sql-as-an-isolation-bypass)
- [NoSQL and key-value injection](#nosql-and-key-value-injection)
- [Read replicas and stale authorization](#read-replicas-and-stale-authorization)
- [Transaction isolation and serialization failures](#transaction-isolation-and-serialization-failures)
- [Connection exhaustion and query timeouts](#connection-exhaustion-and-query-timeouts)
- [Copies of production data](#copies-of-production-data)
- [Review checklist](#review-checklist)

## Principle

Application-layer controls all share one assumption: that every path to the
data goes through the application. Raw SQL, a management command, a Celery
task, an analytics job, a psql session, and a restored backup each falsify it.
So the data layer needs its own answers to three questions, independent of the
request path:

1. **What can this connection do?** The principal the application connects as
   defines the blast radius of any injection or code-execution foothold. A
   process that only reads and writes rows should not be able to alter schema,
   read tables it was never granted, or grant itself anything.
2. **What can this connection see?** Isolation you have to remember to apply is
   not isolation. Where the consequence of one forgotten filter is cross-tenant
   disclosure, push the predicate to the layer that enforces it on every access
   path. Do this only if you can guarantee that the context that layer reads is
   set correctly and cannot leak between callers.
3. **Where else does this data exist?** Every copy — replica, search index,
   export, backup, staging dump — inherits the data and none of the
   authorization. Copies are where data leaks after the application is secure.

Two related properties complete the set. The connection must be **verified**,
not merely encrypted. Connections are a **bounded resource**, and their
exhaustion is an availability failure the application can inflict on itself.

Defense in depth here is genuinely depth, not duplication. Row-level security
and field-level encryption are backstops behind scoped querysets and data
minimization. An adoption of either as a *primary* control tends to produce a
false sense of isolation rather than isolation. The same is true of an adoption
without the operational discipline it demands.

## Database roles and privilege separation

**Principle: the process that changes the shape of the data store must not be
the same principal that serves requests against it.** Migrations need
CREATE/ALTER/DROP. The request-serving process never does. Use one role for
schema changes and one role for runtime. The runtime role holds no DDL and no
ability to grant.

This split has a clear benefit. An injection or RCE foothold in the running
application cannot drop or alter tables. It cannot read tables that were never
granted, and it cannot escalate its own rights. It does not buy **row
isolation**. A runtime role with `SELECT` on a table sees every row in it
unless query scoping or row-level security narrows the result.

```sql
-- The migration role owns the objects and holds DDL.
CREATE ROLE app_migrator LOGIN PASSWORD '...';

-- The runtime role gets DML and sequence usage only.
CREATE ROLE app_runtime LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA app TO app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_runtime;
-- USAGE gives nextval, which is what an INSERT needs. SELECT would also
-- expose last_value, and one shared sequence counts every tenant's rows.
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_runtime;

-- Without these two, every future migration's tables are invisible to the
-- runtime role and the split appears to "break Django" after the next deploy.
ALTER DEFAULT PRIVILEGES FOR ROLE app_migrator IN SCHEMA app
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app_migrator IN SCHEMA app
  GRANT USAGE ON SEQUENCES TO app_runtime;

-- The application cannot create objects, so it cannot shadow or self-grant.
REVOKE CREATE ON SCHEMA app FROM app_runtime;

-- The blanket grant above also reached the bookkeeping table that records
-- which migrations ran. Only `migrate` writes it. Take those writes back.
REVOKE INSERT, UPDATE, DELETE ON app.django_migrations FROM app_runtime;
```

In Django, the split is a settings module used only by `migrate`:

```python
# migrator_settings.py — used only for `manage.py migrate`, never by the server.
from .settings import *

DATABASES["default"]["USER"] = "app_migrator"
DATABASES["default"]["PASSWORD"] = os.environ["MIGRATOR_DB_PASSWORD"]
# The import carried the runtime OPTIONS with it. Keep the TLS keys, and drop
# the pool and the startup statement timeout, which belong to request serving.
DATABASES["default"]["OPTIONS"] = {
    k: v
    for k, v in DATABASES["default"]["OPTIONS"].items()
    if k not in {"pool", "options"}
}
```

Review notes:

- A missing `ALTER DEFAULT PRIVILEGES` is the single most common reason teams
  abandon the split and return to one superuser. Check for it before you
  conclude that the split works.
- The test runner needs `CREATEDB`. Give that to a dedicated CI role, not to
  the runtime role.
- An application that connects as the table **owner** or as a superuser also
  defeats row-level security entirely (below). This split is therefore a
  prerequisite for that control rather than an alternative to it.
- `ON ALL TABLES` and `ALTER DEFAULT PRIVILEGES` also grant the runtime role
  DML on tables the request path never writes. That set holds the rows which
  grant a role or a tenant membership, and the migration bookkeeping table. An
  injection foothold then edits its own rights. It can also mark a pending
  security migration as applied, so that the next deploy skips it. Revoke the
  writes the request path does not make. `a09-logging-and-alerting.md` holds
  the same rule for the audit sink.
- The migration role owns the tables, so no policy below applies to it, and
  each migration it runs is privileged code. Keep `MIGRATOR_DB_PASSWORD` on
  the release host alone. A request-serving process that can read it holds an
  owner credential, and the split then gives nothing.
- `migrator_settings.py` imports the runtime settings, so it inherits
  `OPTIONS`. A large `CREATE INDEX` then aborts at the runtime statement
  timeout. Teams answer that failed deploy by raising the timeout for every
  request path, which removes the bound below. Override `OPTIONS` for the
  migrator alias instead.
- Severity: Medium on its own, High where it multiplies the blast radius of a
  reachable injection sink.

## Row-level security as a backstop

**Principle: an application filter is opt-in. You start with access to
everything and you must remember to narrow, so its failure mode is "leak
everything." Database-enforced predicates invert that default for every access
path.**

Row-level security defends against exactly one thing that queryset scoping
cannot: *the query nobody remembered to scope*. That includes paths the ORM
never sees. Adopt it as a backstop behind scoped querysets. Do **not** adopt it
when:

- the application is small or the tenant count is low. A mandatory
  tenant-scoped manager with a cross-tenant test suite then gets most of the
  benefit at a fraction of the operational cost;
- the team cannot commit to the connection discipline in the next section.
  Row-level security wired to a session-scoped setting behind a
  transaction-mode pooler is a cross-tenant breach, not a control;
- the team cannot absorb the debugging cost. Unset context yields *zero rows*
  rather than an error, so bugs present as mysteriously empty results.

Three non-negotiables if you adopt it:

```sql
ALTER TABLE app.invoice ENABLE ROW LEVEL SECURITY;
-- Without FORCE, the table owner bypasses every policy and nothing errors.
ALTER TABLE app.invoice FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON app.invoice
  USING (tenant_id = current_setting('app.current_tenant')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
```

1. The application connects as a **non-owner, non-superuser** role that does
   not hold `BYPASSRLS`. Policies do not apply to owners or superusers, and a
   `BYPASSRLS` role bypasses them as well. That attribute belongs to the role
   rather than to the table, so it appears in no policy listing. Read it from
   `pg_roles.rolbypassrls`.
2. `ENABLE` **and** `FORCE`. `ENABLE` alone leaves the owner exempt silently.
3. Tenant context is **transaction-scoped**, never session-scoped.

A reviewer should check two details explicitly. The single-argument
`current_setting('app.current_tenant')` **raises** when the setting is unset,
which fails loudly. The two-argument
`current_setting('app.current_tenant', true)` returns NULL, which makes the
predicate false and returns zero rows silently. Pick deliberately, and know
which one the policy in front of you uses. Policies also live in the database
catalog, not in `migrations/`. They therefore **drift** from the schema unless
you create and alter them inside migrations like any other object.

A `WITH CHECK` clause stops a write that inserts or updates a row into another
tenant. For an `ALL` or an `UPDATE` policy with no `WITH CHECK` clause,
PostgreSQL uses the `USING` expression as the check as well. The trap is a
`FOR SELECT` policy next to a separate permissive write policy. The read
predicate never applies to the write, and permissive policies combine with
`OR`. Write both clauses explicitly on every policy that permits a write, so
the reviewer reads the write rule directly.

`FORCE` also reaches the migration role, because that role owns the table. A
data migration that writes a row then fails the `WITH CHECK` clause. Teams
drop `FORCE` to make the deploy pass, and the owner exemption reopens
silently. Set the tenant context inside the data migration instead, exactly as
the request path sets it.

**The tenant setting is not a credential.** Any role can call
`set_config('app.current_tenant', ...)`. PostgreSQL guards a custom setting
with no privilege, and no `REVOKE` takes that ability away. So the policy
holds against the query nobody scoped, and it holds nothing against SQL an
attacker already controls. Never treat row-level security as a mitigation when
you score an injection finding. Do not lower that finding's severity for it.

Teams answer this by moving the setting into a `SECURITY DEFINER` function.
That function runs as its owner, and the owner is exempt from every policy.
Two rules therefore apply to each definer function a migration creates. It
validates that the caller may act for the tenant it is asked to set. It also
pins `SET search_path = pg_catalog, app` in its own definition. Without the
pinned path, a role that creates an object in a reachable schema supplies the
function the definer body calls.

That last rule depends on which roles can create an object. PostgreSQL 15
removed the `CREATE` privilege that `PUBLIC` held on schema `public`. An
upgraded cluster and a restored dump keep the old grant. Read the privilege
from the cluster rather than from the release number.

**A policy protects one relation, and not the rows that relation holds.** Any
other relation that returns the same rows carries its own policies, or none. A
blanket schema grant reaches all three below, so check each one.

- **A partition.** `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`
  never recurse to a partition, and `CREATE POLICY` names one relation. A
  query that names the partition directly therefore reads every tenant's rows,
  and no `WITH CHECK` clause runs on a write. Create the policy and both flags
  on each partition, inside the migration that creates the partition. Where
  that is not practical, grant the runtime role nothing on the partition.
- **A view.** PostgreSQL applies the policies of the **view owner** to the
  base relation, and not the policies of the caller. The view therefore
  answers with whatever its owner may read. Where that owner bypasses the
  policy — an owner without `FORCE`, or a `BYPASSRLS` role — the view returns
  every row to every role that can read it. On PostgreSQL 15 and later,
  `security_invoker = true` makes the caller's policies apply instead.
- **A materialized view.** It stores the rows that its query selected. No
  policy runs when a role reads that stored copy.

Note for operations: `pg_dump` sets `row_security` to `off` by default, so it
dumps all the rows. A role that policies restrict, and that cannot bypass
them, gets an error instead of a partial dump. The `--enable-row-security`
flag is the opt-in that makes the output policy-filtered, and that is the
silently **incomplete** dump. Give backups a dedicated role that reads every
row it must read. A restore test that compares the row counts proves it.

## Tenant context on a pooled connection

**Principle: ambient context that outlives the unit of work finally reaches the
wrong principal.** This is the same invariant as request-scoped identity in
`async-and-channels.md`, applied to the database connection.

```python
# Wrong: session-scoped. On a pooled connection the setting survives the
# request and is still set when the backend is handed to the next client.
with connection.cursor() as cur:
    cur.execute("SET app.current_tenant = %s", [tenant_id])
```

```python
# Correct: transaction-scoped. Postgres pops the setting at COMMIT or
# ROLLBACK, so it cannot outlive the work it belongs to.
from django.db import connection, transaction

with transaction.atomic():
    with connection.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)", [str(tenant_id)]
        )
    # ORM queries inside this block now see only this tenant's rows.
```

Seven conditions break it, in the order a reviewer meets them:

- **Transaction-mode pooling plus a session `SET`.** The backend returns to the
  pool at COMMIT with the tenant setting still on it, and the pool hands it to
  another client. This is the canonical failure, and it is a cross-tenant
  disclosure, not a bug with a workaround.
- **A second connection alias.** The setting belongs to one connection. A read
  replica, and the `serializable` alias below, each open a connection of their
  own and carry no tenant. `connection` is the default alias, so a helper that
  uses it sets the context on the wrong connection. Set the context with
  `connections[alias].cursor()` inside every `atomic(using=alias)` block that
  reaches a table with a policy.
- **`SET LOCAL` outside a transaction.** In autocommit it warns and does
  nothing, so the policy sees no tenant and every query returns zero rows.
  `set_config(..., true)` fails the same way and warns about nothing, because
  it applies to its own statement alone. Middleware that sets the context
  before the view opens `atomic()` breaks this way.
- **A nested `atomic()` block.** Django opens a savepoint for it, and
  PostgreSQL cancels a setting when a rollback returns to a savepoint that
  precedes it. An inner block that sets the context and then rolls back
  therefore leaves the outer work with no tenant, and raises nothing. Set the
  context as the first statement of the outermost `atomic()` block.
- **Workers, tasks, and management commands that never set context.** Under
  row-level security they fail closed and return nothing, which is safe but
  looks like a data bug. Under queryset scoping alone the same code path fails
  *open* and processes every tenant's rows. Wrap task entry points in the same
  context the request path sets.
- **`transaction.on_commit()` and post-commit signal code.** The callback runs
  after COMMIT, and COMMIT pops the setting. Every query the callback makes
  therefore runs with no tenant. Open a new `atomic()` block in the callback
  and set the context again, or hand the work to a task that sets it at entry.
- **Schema-per-tenant.** `django-tenants` and similar carry tenant identity in
  the connection's `search_path`, which is session state with the same pooling
  hazard. Use session-mode pooling with schema-per-tenant, or the search path
  leaks across pooled connections.

Test it the way the leak happens. Run two requests for different tenants
against the same pooled connection, and assert that the second sees nothing of
the first. A single-connection test suite passes while production leaks. Run
that test against each alias which reaches a table with a policy.

## Verified database connections

**Principle: encryption without authentication of the peer is not
confidentiality — it protects against a passive listener and not against the
machine that answered.**

On PostgreSQL, only `verify-ca` and `verify-full` validate the server
certificate. `require` encrypts and accepts whatever presents itself, so it
does not defend against an in-path attacker. `verify-full` also checks the
hostname, and it is the target. Where the driver supports it,
`channel_binding=require` binds the authentication exchange to the TLS channel.

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        # Options go to libpq. "require" would encrypt without verifying
        # anything about the server that answered.
        "OPTIONS": {
            "sslmode": "verify-full",
            "sslrootcert": "/etc/ssl/certs/db-root.crt",
        },
    }
}
```

The connection string itself is a credential. Keep the DSN out of version
control, out of logs and error reports, and out of anything that renders
settings (`a09-logging-and-alerting.md`). `deployment-and-runtime.md` owns
network placement, firewall rules, and certificate distribution.

## Field-level encryption and searchable lookups

**Principle: encryption removes the database's ability to reason about a value.
You have to re-add searchability deliberately, and that addition leaks
something.**

Field-level encryption is justified when the threat model includes a party who
can read the raw table but must not read the value. That party is a compromised
or curious database operator, an exposed backup, or a shared or managed
database instance. A compliance requirement that the *column* be encrypted also
justifies it. It is not justified as generic "encrypt everything." Full-disk
and cloud-volume encryption already answer the stolen-disk threat
transparently, and they are usually already on. They do nothing against a
compromised running database, an over-privileged query path, or a leaked dump
that an authorized role took. **Disk encryption is not column encryption**, and
a claim that it is becomes a finding when a requirement says otherwise.

State the cost to stakeholders before the migration, because it is total. An
encrypted column is opaque to the database. It supports no `LIKE`, no range
query, no ordering, no `UNIQUE`, no useful `db_index`, and no server-side join.
Database-side functions such as `pgcrypto` are only marginally better than
plaintext against this threat model. The key transits to the server, and it can
surface in query logs and server memory. **Application-layer encryption keeps
the key off the database entirely**, which is the stronger posture and the one
that survives a compromised database host.

A **blind index** recovers exact-match lookup. Store a keyed HMAC of the
normalized plaintext alongside the randomized ciphertext, and query on the
HMAC.

```python
import hashlib
import hmac
import os
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_VERSION = "v1"


def canonical(value: str) -> str:
    # One function for every writer and every lookup. A second normalization
    # somewhere else produces a second index for one identity.
    return unicodedata.normalize("NFKC", value).strip().casefold()


def encrypt_value(value: str, *, row_id: str, column: str) -> bytes:
    # Randomized: two identical plaintexts produce different ciphertexts, so
    # the column leaks nothing about equality. Not searchable, by design.
    # associated_data binds the value to its row and its column, so the same
    # value moved onto another row no longer decrypts.
    nonce = os.urandom(12)
    aad = f"{KEY_VERSION}|{column}|{row_id}".encode()
    key = ENCRYPTION_KEYS[KEY_VERSION]
    token = AESGCM(key).encrypt(nonce, value.encode(), aad)
    # The stored value names the key that wrote it, so a rotation can read it.
    return f"{KEY_VERSION}:".encode() + nonce + token


def blind_index(value: str, *, tenant_id: str) -> str:
    # Keyed apart from the ciphertext, so the index key decrypts nothing.
    # Keyed per tenant as well, so equal values in two tenants do not match.
    tenant_key = hmac.new(
        BLIND_INDEX_KEY, str(tenant_id).encode(), hashlib.sha256
    ).digest()
    digest = hmac.new(tenant_key, canonical(value).encode(), hashlib.sha256)
    return digest.hexdigest()


# Lookup: User.objects.get(email_bidx=blind_index("a@b.example", tenant_id=t))
```

State the tradeoff. Do not hide it. The blind index is deterministic, so it
leaks equality: equal plaintexts produce equal indexes. It therefore supports
frequency analysis on low-entropy columns.

**A value that authenticates itself still moves.** A ciphertext with no
associated data verifies wherever it is stored. A principal that holds DML on
the table copies a valid pair of ciphertext and blind index from one row onto
another. The victim's address then decrypts to the attacker's address, and a
password reset reaches the attacker. Bind every value to its row and its
column, as the example does. Treat a failed decryption as a security event
rather than as data corruption.

The bound row identity must exist before the value is written. A primary key
that the application generates satisfies this. Where the database assigns the
key, write the row first and set the encrypted column in the same transaction.

The blind index also restores the constraint the ciphertext lost. Where the
plaintext column was unique, add a `UniqueConstraint` on the blind-index
column in the same migration. Make it composite with the tenant column where
the identity is unique inside one tenant alone. Without that constraint, two
concurrent registrations both read no row and both insert, and one identity
becomes two accounts.

Use a per-field key distinct from the encryption key, and normalize through
one shared function. Unicode carries more than one encoding for one identity,
so normalize the form as well as the case. A backfill or an import that
normalizes differently writes an index that no lookup matches. Do not
blind-index a low-cardinality field whose distribution is itself sensitive. Do
**not** use deterministic encryption of the whole column to gain
searchability. It leaks the same equality with no advantage over a separate
index and a randomized ciphertext.

Key storage, rotation, and managed-KMS integration are a separate concern from
the storage mechanism, and this file does not cover them. The minimum is that
the key lives outside the database and outside the repository
(`a04-cryptographic-failures.md`, "Secrets"). The key must also be versioned,
so a rotation is a background re-encryption rather than an outage
(`a04-cryptographic-failures.md`, "Key lifecycle and envelope encryption"). A
field key derived from `SECRET_KEY` is the common shortcut and the one to flag.
It turns a signing-key rotation into a data-re-encryption event.

**Write-time.** When you generate a field whose value the database must not
read, write four things in the single edit that adds the field. Write the
randomized ciphertext column, and a blind index for each exact-match lookup the
code actually performs. Write a `UniqueConstraint` on each blind index that
replaces a unique plaintext column. Write a key read from outside the database
and outside the repository. If you add searchability afterwards, you must
re-encrypt every row that already exists. A column that shipped readable stays
readable in every backup taken since.

Key the blind index separately from the ciphertext, and derive neither from
`SECRET_KEY`. That derivation turns a signing-key rotation into a
data-re-encryption event. Where the requirement is only the stolen-disk threat,
say that volume encryption already answers it, and add no encrypted column at
all.

**Package decision (2 Aug 2026, revisited 7 Aug 2026):** almost every packaged
Django field-encryption library fails the A03 gate. None of the widely cited
options declares support for Django 5.2 or 6.0, and each has gone more than a
year without a release. The one current exception,
`django-fernet-encrypted-fields`, is **conditional** rather than recommended,
because it derives its key from `SECRET_KEY` and a `SALT_KEY` setting. Build on
PyCA `cryptography` directly. See `security-hardening-libraries.md`,
"Cryptographic primitives and password hashing".

## Raw SQL as an isolation bypass

`a05-injection.md` owns injection mechanics and the parameterization rule. The
data-layer addition is that a raw path is a **double** escape hatch. It
bypasses the tenant-scoping manager *and* any row-level security context the
ORM path would have carried. A query that is perfectly parameterized can
therefore still be a cross-tenant read. Audit every hit for isolation as well
as for injection.

Enumerate this inventory during review. Each entry reaches the database without
the ORM's guarantees:

- `Manager.raw()`, `QuerySet.extra()`, and `RawSQL` from
  `django.db.models.expressions`;
- `connection.cursor()` and `connections[alias].cursor()` followed by
  `execute()`, `executemany()`, or `callproc()`;
- `annotate()`, `aggregate()`, `filter()`, or `order_by()` carrying a `RawSQL`
  or an `extra(select=...)`;
- `Func` and custom `Expression` subclasses whose `template` or `function` is
  built from input;
- `COPY` in either direction, through `cursor.copy()` on psycopg 3 or
  `copy_expert()` on psycopg2. It moves rows in bulk and carries no tenant
  filter of its own;
- any `%`, f-string, `.format()`, or concatenation within reach of the above.

Write the same finding on every hit: **`params` binds values, not
identifiers.** `WHERE col = %s` with parameters is safe. A table name, a column
name, or an `ASC`/`DESC` direction spliced into the string is not safe, and no
placeholder exists for it. Those need an allowlist. Static analysis helps with
discovery: Bandit's `B610` and `B611` flag `.extra()` and `RawSQL`
respectively, as leads to verify rather than findings.

## NoSQL and key-value injection

**Principle: treat *structure* as untrusted, not only values.**
Parameterization answers string injection. Document stores take queries as
structured objects. The attack substitutes an operator object where the
application expected a scalar. No string concatenation is involved, and no
amount of escaping helps.

```python
# Wrong: body["username"] can arrive as {"$ne": null} and turn an equality
# check into "match any user", which is an authentication bypass.
db.users.find_one({"username": body["username"], "active": True})
```

```python
# Correct: a typed serializer field rejects a dict before it becomes an
# operator; the cast at the query site is belt-and-braces for other callers.
username = serializer.validated_data["username"]   # guaranteed to be a str
db.users.find_one({"username": str(username), "active": True})
```

Validate the whole structure, and not the top level alone. A serializer that
guarantees one scalar says nothing about a filter, a sort specification, or a
pipeline stage that the code builds around it. Reject a key that starts with
`$` at every depth. Reject a key that holds a `.` on a write path, because a
dotted key addresses a field inside a nested document. Reject a non-scalar
value where the query expects a scalar, rather than cast it. A cast is a last
line behind a serializer, and it validates no shape.

Allowlist the fields a caller can query, and the operators a caller can name.
An allowlist of operators is the only form that survives a new operator in the
next release of the store.

Django's own ORM is SQL-only, so this arrives through explicit integrations:

- **MongoDB.** The official `django-mongodb-backend` compiles ordinary ORM
  `filter()` calls into an aggregation pipeline, which is not string-built and
  is the safe path. The exposure is a raw PyMongo `find()` and a backend
  `raw_aggregate()` that receives an attacker-shaped dict. Disable server-side
  JavaScript. Never place user input near `$where` or `mapReduce`, which
  evaluate JavaScript on the server and are code execution rather than mere
  injection. A `$regex` built from input is a blind-enumeration oracle even
  where it cannot bypass the check outright.
- **Redis.** The realistic exposures are an unauthenticated or reachable
  instance and untrusted data driving dangerous commands, rather than classical
  injection. Broker and cache exposure, including the Lua sandbox-escape
  advisories, are in `deployment-and-runtime.md`, "Queue and broker exposure".

A wrapper that *handles* operators is not a wrapper that *forbids
attacker-supplied operator structure*. Several document-store libraries have
shipped fixes for this class, and then shipped a second fix for the same class
reached by a different path. Validate the shape at the boundary, and do not
rely on the driver.

## Read replicas and stale authorization

**Principle: an authorization decision must read from a consistent source.
Eventual consistency is a security boundary, not only a user-experience
concern.**

A read of *permission state* from a lagging replica authorizes actions the
primary has already denied. That state is role, group membership, tenant
membership, a revocation or denylist entry, or a feature gate that grants
access. The revocation window is the replication lag, and it is invisible to
every test that runs against a single database.

In Django this is a router decision. Pin the models that carry authorization
state, and the session and token models, to the primary alias. Never make a
security decision on a replica read. Django's documented primary/replica router
example is deliberately simple, and the documentation notes that it does not
address replication lag at all. It is a starting point, not a security control.

Write the router to deny by default. A router that names the models it pins is
an allowlist, and the next model to carry authorization state is missing from
it. An API key, a deny list, a lockout counter, and a feature gate each arrive
later, and each one reads a replica. Send every read to the primary, and name
the models a replica may serve.

A router sees only a read that reaches the database. The `cached_db` session
backend reads the cache first, and reaches the row on a miss alone. So the pin
on the session model does not make that read current. Any decision that turns
on a session being revoked reads the primary itself.

The same reasoning covers other denormalized copies of authorization-relevant
state. `authorization-architecture.md`, "Search indexes and denormalized
copies" holds the general treatment. Severity is typically High, because the
observable effect is that access continues after revocation.

## Transaction isolation and serialization failures

**Principle: a raised isolation level moves an invariant out of application
code and into the database's concurrency control. It is only a control if the
application retries what the database aborts to hold it.**

Django runs on `READ COMMITTED`. That is PostgreSQL's own default. On MySQL it
is a deliberate override of the server's `REPEATABLE READ`. Django's databases
reference gives the reason: under the server default, the `IntegrityError`
retry of `get_or_create()` can fail to see the row that just committed. Under
`READ COMMITTED` every statement sees the latest committed data. That property
also makes a `select_for_update()` re-read correct in
`a10-exceptional-conditions.md`, "Races, TOCTOU, and adversarial sequencing".

`SERIALIZABLE` buys the invariants a row lock cannot express. Those are an
aggregate over many rows, or a predicate over rows that do not exist yet and
therefore cannot be locked. PostgreSQL's `REPEATABLE READ` is snapshot
isolation, and it does not reach that. It aborts a transaction that modifies a
row another transaction already changed. It permits write skew across different
rows, so an invariant over two rows still needs `SERIALIZABLE`. Both levels
hold the guarantee when they abort transactions, and not when they block them.

Under `SERIALIZABLE`, PostgreSQL raises a serialization failure — SQLSTATE
`40001` — at commit on any transaction whose outcome no serial order could have
produced. `REPEATABLE READ` aborts the update conflict it detects. So a raised
isolation level with no retry loop is not a stronger guarantee. It is the same
guarantee with a new class of runtime error. It surfaces as a 500 under exactly
the concurrency it was introduced to survive.

### Configuring it

Isolation is a property of the connection. Set it in `DATABASES`. A view does
not choose it:

```python
from django.db.backends.postgresql.psycopg_any import IsolationLevel

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "app",
    },
    # A second alias onto the same database, so the raised level applies to
    # the flows that need it instead of to every query the project runs.
    "serializable": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "app",
        "OPTIONS": {"isolation_level": IsolationLevel.SERIALIZABLE},
    },
}
```

On MySQL and MariaDB the same `OPTIONS` key takes a string: `"read committed"`,
`"repeatable read"`, or `"serializable"`. `None` means "use whatever the server
is configured for", which makes the effective level invisible to the
repository. Name the level.

Django has no per-transaction isolation, which is why the second alias is the
usual shape. `transaction.atomic(using="serializable")` and `.using(...)` on
the queryset put one flow at the higher level, while the rest of the
application stays on `READ COMMITTED`. Two aliases onto one database are two
connections, and they count twice against the pool sizing below.

`isolation_level` applies to the connection that the driver opened. A
transaction-mode pooler can run the transaction on a different server
connection, and the flow then runs at the server's default and raises nothing.
Prove the level rather than assume it. Read `SHOW transaction_isolation`
inside the transaction, in a startup check or in the test that covers the
flow.

### The retry loop is not optional

```python
# Correct: the whole transaction re-runs, because a serialization failure
# invalidates everything the aborted attempt read as well as everything it
# wrote. The retry is outside atomic(), since a transaction that has raised
# cannot be used further.
import random
import time

from django.db import DatabaseError, transaction

RETRYABLE_SQLSTATES = {"40001", "40P01"}  # serialization failure, deadlock
MAX_ATTEMPTS = 5


def is_retryable(exc):
    # psycopg 3 exposes sqlstate on the error, and psycopg2 exposes pgcode.
    # Both expose diag.sqlstate, so this classifier holds on either driver.
    diag = getattr(exc.__cause__, "diag", None)
    return getattr(diag, "sqlstate", None) in RETRYABLE_SQLSTATES


def rebalance(*, account_id):
    for attempt in range(MAX_ATTEMPTS):
        try:
            with transaction.atomic(using="serializable"):
                # The alias on atomic() does not route the ORM. Every queryset,
                # save, lock, and on_commit inside post_entries must name
                # using="serializable", or that work runs on the default
                # connection, outside this transaction.
                return post_entries(account_id=account_id)
        except DatabaseError as exc:
            if not is_retryable(exc) or attempt == MAX_ATTEMPTS - 1:
                raise
            # Jitter, so the callers that conflicted do not retry together.
            time.sleep(0.05 * 2**attempt * (0.5 + random.random()))
```

- **Retry from the top, reads included.** If you re-run only the write, you
  re-apply a decision computed from a snapshot the database has just rejected.
  That is the original defect with a retry loop around it.
- **Catch outside the `atomic()` block.** If you handle the error inside it,
  the transaction stays marked for rollback, and every subsequent query raises
  `TransactionManagementError`.
- **Everything the block does must be safe to run more than once.** External
  calls, mail, and task dispatch belong in `transaction.on_commit()`.
  `a10-exceptional-conditions.md` owns that order and the idempotency it
  implies.
- **Bound the attempts, back off, and add jitter.** An uncapped retry loop
  under contention is a caller-triggered load multiplier of its own
  (`a06-insecure-design.md`, "Algorithmic resource exhaustion"). Equal backoff
  re-synchronizes the callers that just conflicted, so the next round
  conflicts again. The sleep also holds the request's database connection, so
  a retry storm consumes the pool that the section below caps.
- **Test the classifier against the driver in use.** A classifier that reads
  the wrong attribute returns `None` rather than an error. Every serialization
  failure then reaches the caller, and the loop still looks correct in review.
  Teams answer those 500s by deleting the loop or the alias, which removes the
  control instead of the defect.
- **Deadlocks retry on the same path** and occur at every isolation level.
  Write the loop wherever lock order is not provably consistent.

### The judgment: constraints before isolation

For most invariants a raised isolation level is an expensive answer to a
question that `READ COMMITTED` with a constraint has already settled.
Uniqueness, value bounds, and non-overlap are properties of the data. A
`UniqueConstraint`, a `CheckConstraint`, or an `ExclusionConstraint` therefore
enforces them on every path — admin, shell, migration, raw SQL — at no
concurrency cost. Each one fails deterministically with an `IntegrityError`
rather than load-dependently at commit. That is the order
`a10-exceptional-conditions.md` already applies between a constraint and a row
lock, extended by one step: constraint, then lock, then isolation.

`SERIALIZABLE` earns its place where the invariant belongs to a set rather than
to a row. Such an invariant is a balance that must hold across many entries. It
can also be a scheduling rule over rows not yet inserted, or a report that has
to be internally consistent. It also needs a retry loop on every path that
writes through that alias. A global raise of the level to fix one flow imposes
aborts on every other flow. A project that has raised it has also changed what
`get_or_create()` guarantees underneath it.

**Write-time.** When you generate code that runs under a raised isolation
level, write the bounded retry loop around the `atomic()` block in the same
change. A serialization failure is an ordinary outcome of `SERIALIZABLE` rather
than an exceptional one. Code that ships without the loop turns a routine abort
into a 500 the first time two callers overlap. Where the invariant is
uniqueness, a value bound, or non-overlap, generate the database constraint
instead, and leave the connection on `READ COMMITTED`.

## Connection exhaustion and query timeouts

**Principle: connections are a bounded, exhaustible resource. Cap concurrency
at a pool you control and time-bound every query, so no single caller can
consume the ceiling.**

The mechanism is direct. Every worker and thread holds database connections,
and the server has a hard `max_connections` ceiling. Each backend is a real
process with a real memory cost. Under load, or with slow queries, held
connections accumulate. When demand exceeds the ceiling, the server refuses new
connections and the whole application fails at once. Persistent connections
multiply what the application holds, and a long transaction pins a connection
for the entire request.

The controls follow, in order of leverage:

- **Put a pool between the application and the database and cap it.** On Django
  5.1+ with psycopg 3 this is built in, and Django 6.0 adds async-aware
  pooling. PgBouncer remains the option for a process-external pool. The pool's
  maximum size is the defense, but Django builds one pool for each process.
  Multiply the maximum size by the processes and by the hosts to get the total
  backends. Only PgBouncer caps that total from outside the processes.
- **Set a server-side statement timeout** so a slow or hostile query cannot pin
  a connection indefinitely.
- **Size deliberately**: hosts × workers × threads × per-worker connections
  must stay under `max_connections`, with headroom left for migrations and
  operator sessions.
- **Bind the ceiling and the timeouts to the database role.** The arithmetic
  above is a plan, and a scale-out event or a rolling restart breaks it.
  `ALTER ROLE app_runtime CONNECTION LIMIT n` refuses connection n + 1 at the
  server, whatever the application believes it opened. Leave headroom for
  the migration role and for an operator session, or the outage locks you out
  of its own repair. `statement_timeout` bounds one statement, and not a
  transaction that waits between statements. So set
  `idle_in_transaction_session_timeout`, `lock_timeout`, and `temp_file_limit`
  on the role as well.
- **Use `ATOMIC_REQUESTS` knowingly.** It is good for write consistency, and it
  holds a connection and an open transaction for the whole of every view.
  Exclude long-running views, streaming views, and external-call views.
  `a10-exceptional-conditions.md` holds its correctness role.

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        # Pooling requires CONN_MAX_AGE = 0; Django raises
        # ImproperlyConfigured if persistent connections are also enabled.
        # The "pool" option needs psycopg 3 and is unavailable under psycopg2.
        "CONN_MAX_AGE": 0,
        "OPTIONS": {
            "pool": {"min_size": 2, "max_size": 10},
            # A startup option belongs to the connection the driver opened.
            # A transaction-mode pooler can hand the work a different server
            # connection, so set the same bound on the role as well.
            "options": "-c statement_timeout=15000",
        },
    }
}
```

A setting on the role is a default and not a ceiling. The runtime role can
raise `statement_timeout` in its own session, so that bound holds the slow
query rather than the hostile one. `CONNECTION LIMIT` and `temp_file_limit`
differ, because the runtime role cannot raise either one.

Under async and Channels, `CONN_MAX_AGE = 0` is required for a different
reason: Django's own persistent-connection reuse is not safe across the async
boundary. The two rules agree; see `async-and-channels.md`.
`a06-insecure-design.md` owns rate limits and cost limits at the request layer.

## Copies of production data

The backend team and the infrastructure team own different halves of this, and
the seam is where it goes wrong. **Infrastructure owns** the backup artifact.
That covers encryption at rest with a key separate from the live data, and
immutability and offline copies against ransomware. It also covers restore
tests and storage access control. **The backend owns what is in the copy and
where copies are allowed to travel:**

- Protect sensitive columns *before* they reach a backup. Where field
  encryption is in place, the dump inherits ciphertext. Where it is not, the
  dump is plaintext, whatever the configuration of the bucket.
- Production data is masked, subsetted, or synthetic before it reaches
  development, staging, demo, or analytics environments. A raw production dump
  in a lower environment inherits none of production's access control. Breaches
  in non-production environments are far more common than teams assume.
- Application-level export, download, report, and "admin backup" features are
  authorization-checked, rate-limited, and audited. They are a legitimate,
  authenticated exfiltration path and are frequently the only one an attacker
  needs (`a01-broken-access-control.md`, `a09-logging-and-alerting.md`).
- Fixtures, seed data, and anonymization scripts contain no real secrets and no
  real personal data.

Restores deserve their own line. A restore re-materializes rows that erasure or
revocation had removed. Any deletion guarantee therefore has to account for
what is in the backups and for how long. `data-lifecycle-and-privacy.md` holds
the deletion guarantee itself. That guarantee is the fan-out that reaches every
copy, the per-target completion ledger, and the per-subject key destruction for
stores which cannot delete in place.

## Review checklist

### Stack-neutral

- [ ] The application connects as a role that cannot change schema, cannot read
      what it was not granted, and cannot grant. Schema changes use a separate
      principal.
- [ ] Any database-enforced isolation is a backstop behind scoped querysets,
      and is forced for owners as well as others. No role holds an attribute
      that bypasses it. Every other relation that returns the same rows
      carries the same predicate. Migrations define it, rather than a manual
      step.
- [ ] The identity that reaches the database is scoped to the unit of work. It
      cannot survive on a pooled connection into the next caller's request,
      and it is present on every connection that work touches.
- [ ] Background workers, scheduled jobs, operator commands, and code that
      runs after the commit establish the same isolation context as the
      request path, or fail closed.
- [ ] The database connection verifies the server certificate rather than only
      encrypting; the connection string is handled as a secret.
- [ ] Encrypted columns are justified by a threat inside the database's trust
      boundary, and disk-level encryption is not counted as column encryption.
- [ ] Any searchable-encryption scheme states what it leaks; blind-index keys
      are separate from encryption keys. Each stored value names the key
      version that wrote it, and is bound to the row and the column that hold
      it.
- [ ] Every path that reaches the store without the application's query layer is
      audited for isolation bypass, not only for injection.
- [ ] Query input is validated for shape as well as value, at every depth, so
      a client cannot substitute an operator object for a scalar.
- [ ] Authorization state is never read from an eventually consistent copy,
      and never from a cache the read path consults before the database.
- [ ] Any isolation level above the backend default has a bounded retry of the
      whole transaction beside it. The review chose it only after it ruled out
      a database constraint.
- [ ] Connection concurrency is capped by a pool and by a limit on the
      database role, and every query is time-bounded server-side.
- [ ] No raw production data in lower environments; export and report features
      are authorized, bounded, and audited.

### Django & DRF

- [ ] `migrate` runs under a migration role, and the server runs under a
      DML-only role. `ALTER DEFAULT PRIVILEGES` is set, so new migrations'
      tables stay readable. The test runner's `CREATEDB` belongs to a CI role.
      The runtime role holds no write on the migration bookkeeping table.
- [ ] Row-level security uses `ENABLE` **and** `FORCE`, the application role is
      neither the table owner nor a `BYPASSRLS` role, and `WITH CHECK` covers
      writes as well as reads. Each partition, view, and materialized view
      over a protected table is checked in its own right.
- [ ] Tenant context is set with `set_config(..., true)` as the first
      statement of the outermost `transaction.atomic()`, never a session `SET`
      and never inside a nested block; schema-per-tenant deployments use
      session-mode pooling.
- [ ] Every other alias, and every `on_commit()` callback that queries, sets
      the tenant context of its own.
- [ ] `OPTIONS` sets `sslmode=verify-full` with a pinned root certificate.
- [ ] Field encryption is built on PyCA `cryptography` with keys outside the
      database; no abandoned field-encryption package is relied on.
- [ ] `raw()`, `extra()`, `RawSQL`, and cursor calls pass values through
      `params`, take identifiers from an allowlist, and re-apply tenant scoping.
- [ ] PyMongo and `raw_aggregate()` calls receive serializer-validated scalars;
      server-side JavaScript and `$where` are not reachable from input.
- [ ] A database router sends every read to the primary and names the models
      a replica may serve. A session read that the cache answers reaches no
      router, so a revocation check reads the primary itself.
- [ ] `OPTIONS["isolation_level"]` is named rather than left to the server. A
      raised level is scoped to its own alias rather than applied globally,
      and the effective level is proven at run time rather than assumed. The
      retry classifier reads a field that the project's driver sets. Side
      effects inside a retried `atomic()` block defer to
      `transaction.on_commit()`.
- [ ] `OPTIONS` sets a pool `max_size` and a `statement_timeout`; a
      `CONNECTION LIMIT` and an idle-in-transaction timeout on the role back
      both; `CONN_MAX_AGE = 0` accompanies pooling; `ATOMIC_REQUESTS` excludes
      long-running and streaming views.
- [ ] Cross-tenant and connection-reuse isolation tests exist and run against a
      pooled configuration, not a single connection.
