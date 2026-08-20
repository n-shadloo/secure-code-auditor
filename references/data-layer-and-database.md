# Database and Data-Layer Security

The database treated as its own security boundary rather than as trusted
storage behind the application. Covers privilege separation between migration
and runtime roles, row-level security and how tenant context survives (or
doesn't survive) a connection pool, verified transport to the database,
field-level encryption and searchable lookups, injection into document and
key-value stores, read-replica staleness in authorization decisions, connection
exhaustion, and where copies of production data are allowed to travel. Maps
primarily to CWE-250, CWE-269, CWE-284, CWE-295, CWE-311, CWE-89, CWE-943,
and CWE-400; relevant OWASP categories include A01:2025, A02:2025,
A04:2025, A05:2025, and A06:2025, and API1:2023.

This file owns **the database as a boundary of its own** — privilege
separation between the migration role and the runtime role, row-level
security, the tenant context that has to survive a pooled connection, verified
transport, the encrypted column and the blind index over it, the isolation
level the connection runs at, and the copies of production data that are
allowed to travel. It defers for the rules those mechanisms carry out:
`a05-injection.md` owns injection mechanics including
the raw paths enumerated here and the GeoDjango lookup positions PostGIS
inlines rather than binds, `a04-cryptographic-failures.md` owns the
cryptographic principle and the key lifecycle,
`authorization-architecture.md` owns the tenant model this isolation enforces,
`data-lifecycle-and-privacy.md` owns whether a row is really gone, and
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
   path — but only if you can guarantee the context that layer reads is set
   correctly and cannot leak between callers.
3. **Where else does this data exist?** Every copy — replica, search index,
   export, backup, staging dump — inherits the data and none of the
   authorization. Copies are where data leaks after the application is secure.

Two related properties round it out: the connection must be **verified**, not
merely encrypted, and connections are a **bounded resource** whose exhaustion is
an availability failure the application can inflict on itself.

Defense in depth here is genuinely depth, not duplication. Row-level security
and field-level encryption are backstops behind scoped querysets and data
minimization; adopting either as a *primary* control, or adopting it without
the operational discipline it demands, tends to produce a false sense of
isolation rather than isolation.

## Database roles and privilege separation

**Principle: the process that changes the shape of the data store must not be
the same principal that serves requests against it.** Migrations need
CREATE/ALTER/DROP; the request-serving process never does. One role for
schema changes, one for runtime, and the runtime role holds no DDL and no
ability to grant.

What it buys: an injection or RCE foothold in the running application cannot
drop or alter tables, cannot read tables that were never granted, and cannot
escalate its own rights. What it does not buy: **row isolation**. A runtime
role with `SELECT` on a table sees every row in it unless query scoping or
row-level security narrows the result.

```sql
-- The migration role owns the objects and holds DDL.
CREATE ROLE app_migrator LOGIN PASSWORD '...';

-- The runtime role gets DML and sequence usage only.
CREATE ROLE app_runtime LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA app TO app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO app_runtime;

-- Without these two, every future migration's tables are invisible to the
-- runtime role and the split appears to "break Django" after the next deploy.
ALTER DEFAULT PRIVILEGES FOR ROLE app_migrator IN SCHEMA app
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app_migrator IN SCHEMA app
  GRANT USAGE, SELECT ON SEQUENCES TO app_runtime;

-- The application cannot create objects, so it cannot shadow or self-grant.
REVOKE CREATE ON SCHEMA app FROM app_runtime;
```

In Django, the split is a settings module used only by `migrate`:

```python
# migrator_settings.py — used only for `manage.py migrate`, never by the server.
from .settings import *

DATABASES["default"]["USER"] = "app_migrator"
DATABASES["default"]["PASSWORD"] = os.environ["MIGRATOR_DB_PASSWORD"]
```

Review notes:

- Missing `ALTER DEFAULT PRIVILEGES` is the single most common reason teams
  abandon the split and go back to one superuser. Check for it before
  concluding the split is working.
- The test runner needs `CREATEDB`. Give that to a dedicated CI role, not to
  the runtime role.
- An application connecting as the table **owner** or as a superuser also
  defeats row-level security entirely (below), so this is a prerequisite for
  that control rather than an alternative to it.
- Severity: Medium on its own, High where it multiplies the blast radius of a
  reachable injection sink.

## Row-level security as a backstop

**Principle: application filtering is opt-in — you start with access to
everything and remember to narrow — so its failure mode is "leak everything."
Database-enforced predicates invert that default for every access path.**

Row-level security defends against exactly one thing that queryset scoping
cannot: *the query nobody remembered to scope*. That includes paths the ORM
never sees. It is worth adopting as a backstop behind scoped querysets, and it
is worth **not** adopting when:

- the application is small or the tenant count is low, where a mandatory
  tenant-scoped manager plus a cross-tenant test suite gets most of the benefit
  at a fraction of the operational cost;
- the team cannot commit to the connection discipline in the next section —
  row-level security wired to a session-scoped setting behind a
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

1. The application connects as a **non-owner, non-superuser** role. Policies do
   not apply to owners or superusers.
2. `ENABLE` **and** `FORCE`. `ENABLE` alone leaves the owner exempt silently.
3. Tenant context is **transaction-scoped**, never session-scoped.

Two details a reviewer should check explicitly. The single-argument
`current_setting('app.current_tenant')` **raises** when the setting is unset,
which fails loudly; the two-argument `current_setting('app.current_tenant',
true)` returns NULL, which makes the predicate false and returns zero rows
silently. Pick deliberately, and know which one the policy in front of you
uses. And policies live in the database catalog, not in `migrations/`, so they
**drift** from the schema unless they are created and altered inside migrations
like any other object.

A `WITH CHECK` clause stops a write from inserting or updating a row into
another tenant. For an `ALL` or an `UPDATE` policy with no `WITH CHECK`
clause, PostgreSQL uses the `USING` expression as the check as well. The trap
is a `FOR SELECT` policy next to a separate permissive write policy. The read
predicate never applies to the write, and permissive policies combine with
`OR`. Write both clauses explicitly on every policy that permits a write, so
the reviewer reads the write rule directly.

Note for operations: `pg_dump` sets `row_security` to `off` by default, so it
dumps all the rows. A role that policies restrict, and that cannot bypass
them, gets an error instead of a partial dump. The `--enable-row-security`
flag is the opt-in that makes the output policy-filtered, and that is the
silently **incomplete** dump. Give backups a dedicated role that reads every
row it must read. A restore test that compares the row counts proves it.

## Tenant context on a pooled connection

**Principle: ambient context that outlives the unit of work will eventually be
read by the wrong principal.** This is the same invariant as request-scoped
identity in `async-and-channels.md`, applied to the database connection.

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

What breaks it, in the order a reviewer will meet it:

- **Transaction-mode pooling plus a session `SET`.** The backend returns to the
  pool at COMMIT with the tenant setting still on it and is handed to another
  client. This is the canonical failure and it is a cross-tenant disclosure,
  not a bug with a workaround.
- **`SET LOCAL` outside a transaction.** In autocommit it warns and does
  nothing, so the policy sees no tenant and every query returns zero rows.
- **Workers, tasks, and management commands that never set context.** Under
  row-level security they fail closed and return nothing, which is safe but
  looks like a data bug. Under queryset scoping alone the same code path fails
  *open* and processes every tenant's rows. Wrap task entry points in the same
  context-setting the request path uses.
- **Schema-per-tenant.** `django-tenants` and similar carry tenant identity in
  the connection's `search_path`, which is session state with the same pooling
  hazard. Use session-mode pooling with schema-per-tenant, or the search path
  leaks across pooled connections.

Test it the way the leak happens: run two requests for different tenants
against the same pooled connection and assert the second sees nothing of the
first. A single-connection test suite will pass while production leaks.

## Verified database connections

**Principle: encryption without authentication of the peer is not
confidentiality — it protects against a passive listener and not against the
machine that answered.**

On PostgreSQL, only `verify-ca` and `verify-full` validate the server
certificate; `require` encrypts and accepts whatever presents itself, so it
does not defend against an in-path attacker. `verify-full` additionally checks
the hostname and is the target. Where the driver supports it,
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

The connection string itself is a credential: keep the DSN out of version
control, out of logs and error reports, and out of anything that renders
settings (`a09-logging-and-alerting.md`). Network placement, firewalling, and
certificate distribution are in `deployment-and-runtime.md`.

## Field-level encryption and searchable lookups

**Principle: encryption removes the database's ability to reason about a value.
Searchability has to be re-added deliberately, and re-adding it leaks
something.**

Field-level encryption is justified when the threat model includes a party who
can read the raw table but must not read the value: a compromised or curious
database operator, an exposed backup, a shared or managed database instance, or
a compliance requirement that the *column* be encrypted. It is not justified as
generic "encrypt everything." Full-disk and cloud-volume encryption already
answer the stolen-disk threat transparently and are usually already on; they do
nothing against a compromised running database, an over-privileged query path,
or a leaked dump taken by an authorized role. **Disk encryption is not column
encryption**, and treating it as such is a finding when a requirement says
otherwise.

The cost is total and worth stating to stakeholders before the migration: an
encrypted column is opaque to the database. No `LIKE`, no range query, no
ordering, no `UNIQUE`, no useful `db_index`, no server-side join on it.
Database-side functions such as `pgcrypto` are only marginally better than
plaintext against this threat model, because the key transits to the server and
can surface in query logs and server memory. **Application-layer encryption
keeps the key off the database entirely**, which is the stronger posture and the
one that survives a compromised database host.

Exact-match lookup is recovered with a **blind index**: store, alongside the
randomized ciphertext, a keyed HMAC of the normalized plaintext, and query on
the HMAC.

```python
import hashlib
import hmac

from cryptography.fernet import Fernet


def encrypt_value(value: str) -> bytes:
    # Randomized: two identical plaintexts produce different ciphertexts, so
    # the column leaks nothing about equality. Not searchable, by design.
    return Fernet(FERNET_KEY).encrypt(value.encode())


def blind_index(value: str) -> str:
    # Deterministic, and keyed with a different key from the ciphertext, so
    # possession of the index key alone does not decrypt anything.
    normalized = value.strip().lower().encode()
    return hmac.new(BLIND_INDEX_KEY, normalized, hashlib.sha256).hexdigest()


# Lookup: User.objects.get(email_bidx=blind_index("a@b.example"))
```

State the tradeoff rather than burying it. The blind index is deterministic, so
it leaks equality — equal plaintexts produce equal indexes — and therefore
supports frequency analysis on low-entropy columns. Use a per-field key
distinct from the encryption key, normalize consistently, and do not blind-index
a low-cardinality field whose distribution is itself sensitive. Do **not** reach
for deterministic encryption of the whole column to gain searchability: it leaks
the same equality with no advantage over a separate index and a randomized
ciphertext.

Key storage, rotation, and managed-KMS integration are a separate concern from
the storage mechanism and are not covered here; the minimum is that the key
lives outside the database and outside the repository
(`a04-cryptographic-failures.md`, "Secrets"), and that it is versioned so a
rotation is a background re-encryption rather than an outage
(`a04-cryptographic-failures.md`, "Key lifecycle and envelope encryption").
Deriving the field key from `SECRET_KEY` is the common shortcut and the one to
flag: it makes a signing-key rotation into a data-re-encryption event.

**Write-time.** When generating a field that holds a value the database must
not be able to read, write the randomized ciphertext column, a blind index for
each exact-match lookup the code actually performs, and a key read from
outside the database and outside the repository, in the single edit that adds
the field — adding searchability afterwards means re-encrypting every row that
already exists, and a column that shipped readable stays readable in every
backup taken since. Key the blind index separately from the ciphertext and
derive neither from `SECRET_KEY`, because that turns a signing-key rotation
into a data-re-encryption event. Where the requirement is only the stolen-disk
threat, say that volume encryption already answers it and add no encrypted
column at all.

**Package decision (2 Aug 2026, revisited 7 Aug 2026):** almost every packaged
Django field-encryption library fails the A03 gate — none of the widely cited
options declares support for Django 5.2 or 6.0 and each has gone more than a
year without a release. The one current exception,
`django-fernet-encrypted-fields`, is **conditional** rather than recommended,
because it derives its key from `SECRET_KEY` and a `SALT_KEY` setting. Build on
PyCA `cryptography` directly. See `security-hardening-libraries.md`,
"Cryptographic primitives and password hashing".

## Raw SQL as an isolation bypass

Injection mechanics and the parameterization rule are in
`a05-injection.md`. The data-layer addition is that a raw path is a **double**
escape hatch: it bypasses the tenant-scoping manager *and* any row-level
security context the ORM path would have carried, so a query that is perfectly
parameterized can still be a cross-tenant read. Audit every hit for isolation
as well as for injection.

The inventory to enumerate during review — each of these reaches the database
without the ORM's guarantees:

- `Manager.raw()`, `QuerySet.extra()`, and `RawSQL` from
  `django.db.models.expressions`;
- `connection.cursor()` followed by `execute()`, `executemany()`, or
  `callproc()`;
- `annotate()`, `aggregate()`, `filter()`, or `order_by()` carrying a `RawSQL`
  or an `extra(select=...)`;
- `Func` and custom `Expression` subclasses whose `template` or `function` is
  built from input;
- any `%`, f-string, `.format()`, or concatenation within reach of the above.

The finding to write on every hit is the same one: **`params` binds values, not
identifiers.** `WHERE col = %s` with parameters is safe; a table name, a column
name, or an `ASC`/`DESC` direction spliced into the string is not, and there is
no placeholder for it — those need an allowlist. Static analysis helps with
discovery: Bandit's `B610` and `B611` flag `.extra()` and `RawSQL` respectively,
as leads to verify rather than findings.

## NoSQL and key-value injection

**Principle: treat *structure* as untrusted, not only values.** Parameterization
answers string injection. Document stores take queries as structured objects, so
the attack is substituting an operator object where the application expected a
scalar — no string concatenation involved, and no amount of escaping helps.

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

Django's own ORM is SQL-only, so this arrives through explicit integrations:

- **MongoDB.** The official `django-mongodb-backend` compiles ordinary ORM
  `filter()` calls into an aggregation pipeline, which is not string-built and
  is the safe path. The exposure is raw PyMongo `find()` and the backend's
  `raw_aggregate()` receiving an attacker-shaped dict. Disable server-side
  JavaScript and never place user input near `$where` or `mapReduce`, which
  evaluate JavaScript on the server and are code execution rather than mere
  injection. A `$regex` built from input is a blind-enumeration oracle even
  where it cannot bypass the check outright.
- **Redis.** The realistic exposures are an unauthenticated or reachable
  instance and untrusted data driving dangerous commands, rather than classical
  injection. Broker and cache exposure, including the Lua sandbox-escape
  advisories, are in `deployment-and-runtime.md`, "Queue and broker exposure".

A wrapper that *handles* operators is not a wrapper that *forbids
attacker-supplied operator structure*; several document-store libraries have
shipped fixes for this class and then shipped a second fix for the same class
reached by a different path. Validate the shape at the boundary and do not rely
on the driver.

## Read replicas and stale authorization

**Principle: an authorization decision must read from a consistent source.
Eventual consistency is a security boundary, not only a user-experience
concern.**

Reading *permission state* — role, group membership, tenant membership, a
revocation or denylist entry, a feature gate that grants access — from a lagging
replica authorizes actions the primary has already denied. The revocation window
is the replication lag, and it is invisible to every test that runs against a
single database.

In Django this is a router decision: pin the models that carry authorization
state, plus session and token models, to the primary alias, and never make a
security decision on a replica read. Django's documented primary/replica router
example is deliberately simple and, as the documentation notes, does not address
replication lag at all — it is a starting point, not a security control.

The same reasoning covers other denormalized copies of authorization-relevant
state; the general treatment is in `authorization-architecture.md`, "Search
indexes and denormalized copies". Severity is typically High, because the
observable effect is access continuing after revocation.

## Transaction isolation and serialization failures

**Principle: raising the isolation level moves an invariant out of application
code and into the database's concurrency control, and it is only a control if
the application retries what the database aborts to hold it.**

Django runs on `READ COMMITTED`. That is PostgreSQL's own default and, on
MySQL, a deliberate override of the server's `REPEATABLE READ` — Django's
databases reference gives the reason, which is that `get_or_create()`'s
`IntegrityError` retry can fail to see the row that just committed under the
server default. Under `READ COMMITTED` every statement sees the latest
committed data, which is also what makes a `select_for_update()` re-read
correct in `a10-exceptional-conditions.md`, "Races, TOCTOU, and adversarial
sequencing".

`SERIALIZABLE` buys the invariants a row lock cannot express. Those are an
aggregate over many rows, or a predicate over rows that do not exist yet and
so cannot be locked. PostgreSQL's `REPEATABLE READ` is snapshot isolation, and it stops
short of that. It aborts a transaction that modifies a row another transaction
already changed. It permits write skew across different rows, so an invariant
over two rows still needs `SERIALIZABLE`. Both levels hold the guarantee by
aborting transactions rather than by blocking them.

Under `SERIALIZABLE`, PostgreSQL raises a serialization failure — SQLSTATE
`40001` — at commit on any transaction whose outcome no serial ordering could
have produced. `REPEATABLE READ` aborts the update conflict it detects. So a
raised isolation level with no retry loop is not a stronger guarantee. It is
the same guarantee plus a new class of runtime error, and it surfaces as a
500 under exactly the concurrency it was introduced to survive.

### Configuring it

Isolation is a property of the connection, so it is set in `DATABASES` and not
chosen by a view:

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

On MySQL and MariaDB the same `OPTIONS` key takes a string — `"read
committed"`, `"repeatable read"`, `"serializable"` — and `None` means "use
whatever the server is configured for", which makes the effective level
invisible to the repository. Prefer naming it.

Django has no per-transaction isolation, which is why the second alias is the
usual shape: `transaction.atomic(using="serializable")` and `.using(...)` on
the queryset put one flow at the higher level while the rest of the
application stays on `READ COMMITTED`. Two aliases onto one database are two
connections and count twice against the pool sizing below.

### The retry loop is not optional

```python
# Correct: the whole transaction re-runs, because a serialization failure
# invalidates everything the aborted attempt read as well as everything it
# wrote. The retry is outside atomic(), since a transaction that has raised
# cannot be used further.
import time

from django.db import DatabaseError, transaction

RETRYABLE_SQLSTATES = {"40001", "40P01"}  # serialization failure, deadlock
MAX_ATTEMPTS = 5


def is_retryable(exc):
    return getattr(exc.__cause__, "sqlstate", None) in RETRYABLE_SQLSTATES


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
            time.sleep(0.05 * 2**attempt)
```

- **Retry from the top, reads included.** Re-running only the write re-applies
  a decision computed from a snapshot the database has just rejected, which is
  the original defect wearing a retry loop.
- **Catch outside the `atomic()` block.** Handling the error inside it leaves
  the transaction marked for rollback, and every subsequent query raises
  `TransactionManagementError`.
- **Everything the block does must be safe to run more than once.** External
  calls, mail, and task dispatch belong in `transaction.on_commit()`;
  `a10-exceptional-conditions.md` owns that ordering and the idempotency it
  implies.
- **Bound the attempts and back off.** An uncapped retry loop under contention
  is a caller-triggered load multiplier of its own
  (`a06-insecure-design.md`, "Algorithmic resource exhaustion").
- **Deadlocks retry on the same path** and occur at every isolation level, so
  the loop is worth having wherever lock ordering is not provably consistent.

### The judgment: constraints before isolation

For most invariants a raised isolation level is an expensive answer to a
question `READ COMMITTED` plus a constraint has already settled. Uniqueness,
value bounds, and non-overlap are properties of the data, so a
`UniqueConstraint`, a `CheckConstraint`, or an `ExclusionConstraint` enforces
them on every path — admin, shell, migration, raw SQL — at no concurrency
cost, and fails deterministically with an `IntegrityError` rather than
load-dependently at commit. That is the ordering
`a10-exceptional-conditions.md` already applies between a constraint and a row
lock, extended by one step: constraint, then lock, then isolation.

`SERIALIZABLE` earns its place where the invariant belongs to a set rather
than to a row — a balance that must hold across many entries, a scheduling
rule over rows not yet inserted, a report that has to be internally consistent
— and where the retry loop will genuinely be written on every path that writes
through that alias. Raising the level globally to fix one flow imposes aborts
on every other flow, and a project that has raised it has also changed what
`get_or_create()` guarantees underneath it.

**Write-time.** When generating code that runs under a raised isolation level,
write the bounded retry loop around the `atomic()` block in the same change,
because a serialization failure is an ordinary outcome of `SERIALIZABLE`
rather than an exceptional one, and code that ships without the loop turns a
routine abort into a 500 the first time two callers overlap. Where the
invariant is uniqueness, a value bound, or non-overlap, generate the database
constraint instead and leave the connection on `READ COMMITTED`.

## Connection exhaustion and query timeouts

**Principle: connections are a bounded, exhaustible resource. Cap concurrency
at a pool you control and time-bound every query, so no single caller can
consume the ceiling.**

The mechanism: every worker and thread holds database connections, and the
server has a hard `max_connections` ceiling where each backend is a real
process with real memory cost. Under load, or with slow queries, held
connections accumulate; once demand exceeds the ceiling, new connections are
refused and the whole application fails at once. Persistent connections
multiply what is held; a long transaction pins a connection for the entire
request.

Controls, in order of leverage:

- **Put a pool between the application and the database and cap it.** On
  Django 5.1+ with psycopg 3 this is built in, and Django 6.0 adds async-aware
  pooling; PgBouncer remains the option for a process-external pool. The pool's
  maximum size is the defense, but Django builds one pool for each process.
  Multiply the maximum size by the processes and by the hosts to get the
  total backends. Only PgBouncer caps that total from outside the processes.
- **Set a server-side statement timeout** so a slow or hostile query cannot pin
  a connection indefinitely.
- **Size deliberately**: hosts × workers × threads × per-worker connections
  must stay under `max_connections`, with headroom left for migrations and
  operator sessions.
- **Use `ATOMIC_REQUESTS` knowingly.** It is good for write consistency and it
  holds a connection and an open transaction for the whole of every view;
  exclude long-running, streaming, and external-call views. Its correctness
  role is in `a10-exceptional-conditions.md`.

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
            "options": "-c statement_timeout=15000",
        },
    }
}
```

Under async and Channels, `CONN_MAX_AGE = 0` is required for a different
reason — Django's own persistent-connection reuse is not safe across the
async boundary — and the two rules agree; see `async-and-channels.md`. Rate and
cost limits at the request layer are in `a06-insecure-design.md`.

## Copies of production data

The backend and the infrastructure team own different halves of this, and the
seam is where it goes wrong. **Infrastructure owns** the backup artifact:
encryption at rest with a key separate from the live data, immutability and
offline copies against ransomware, restore testing, and storage access control.
**The backend owns what is in the copy and where copies are allowed to travel:**

- Sensitive columns are protected *before* they reach a backup. Where field
  encryption is in place, the dump inherits ciphertext; where it is not, the
  dump is plaintext no matter how the bucket is configured.
- Production data is masked, subsetted, or synthetic before it reaches
  development, staging, demo, or analytics environments. A raw production dump
  in a lower environment inherits none of production's access control, and
  breaches in non-production environments are far more common than teams
  assume.
- Application-level export, download, report, and "admin backup" features are
  authorization-checked, rate-limited, and audited. They are a legitimate,
  authenticated exfiltration path and are frequently the only one an attacker
  needs (`a01-broken-access-control.md`, `a09-logging-and-alerting.md`).
- Fixtures, seed data, and anonymization scripts contain no real secrets and no
  real personal data.

Restores deserve their own line: a restore re-materializes rows that erasure or
revocation had removed, so any deletion guarantee has to account for what is in
the backups and for how long. The deletion guarantee itself — the fan-out that
reaches every copy, the per-target completion ledger, and the per-subject key
destruction that covers stores which cannot delete in place — is in
`data-lifecycle-and-privacy.md`.

## Review checklist

### Stack-neutral

- [ ] The application connects as a role that cannot change schema, cannot read
      what it was not granted, and cannot grant; schema changes use a separate
      principal.
- [ ] Any database-enforced isolation is a backstop behind scoped querysets, is
      forced for owners as well as others, and is defined in migrations rather
      than applied by hand.
- [ ] Identity communicated to the database is scoped to the unit of work and
      cannot survive on a pooled connection into the next caller's request.
- [ ] Background workers, scheduled jobs, and operator commands establish the
      same isolation context as the request path, or fail closed.
- [ ] The database connection verifies the server certificate rather than only
      encrypting; the connection string is handled as a secret.
- [ ] Encrypted columns are justified by a threat inside the database's trust
      boundary, and disk-level encryption is not counted as column encryption.
- [ ] Any searchable-encryption scheme states what it leaks; blind-index keys
      are separate from encryption keys.
- [ ] Every path that reaches the store without the application's query layer is
      audited for isolation bypass, not only for injection.
- [ ] Query input is validated for shape as well as value, so a client cannot
      substitute an operator object for a scalar.
- [ ] Authorization state is never read from an eventually consistent copy.
- [ ] Any isolation level above the backend default is paired with a bounded
      retry of the whole transaction, and was chosen only after a database
      constraint was ruled out.
- [ ] Connection concurrency is capped by a pool, and every query is
      time-bounded server-side.
- [ ] No raw production data in lower environments; export and report features
      are authorized, bounded, and audited.

### Django & DRF

- [ ] `migrate` runs under a migration role and the server under a DML-only
      role; `ALTER DEFAULT PRIVILEGES` is set so new migrations' tables stay
      readable; the test runner's `CREATEDB` belongs to a CI role.
- [ ] Row-level security uses `ENABLE` **and** `FORCE`, the application role is
      not the table owner, and `WITH CHECK` covers writes as well as reads.
- [ ] Tenant context is set with `set_config(..., true)` inside
      `transaction.atomic()`, never a session `SET`; schema-per-tenant
      deployments use session-mode pooling.
- [ ] `OPTIONS` sets `sslmode=verify-full` with a pinned root certificate.
- [ ] Field encryption is built on PyCA `cryptography` with keys outside the
      database; no abandoned field-encryption package is relied on.
- [ ] `raw()`, `extra()`, `RawSQL`, and cursor calls pass values through
      `params`, take identifiers from an allowlist, and re-apply tenant scoping.
- [ ] PyMongo and `raw_aggregate()` calls receive serializer-validated scalars;
      server-side JavaScript and `$where` are not reachable from input.
- [ ] A database router pins authorization, session, and token reads to the
      primary.
- [ ] `OPTIONS["isolation_level"]` is named rather than left to the server,
      a raised level is scoped to its own alias rather than applied globally,
      and side effects inside a retried `atomic()` block are deferred to
      `transaction.on_commit()`.
- [ ] `OPTIONS` sets a pool `max_size` and a `statement_timeout`;
      `CONN_MAX_AGE = 0` accompanies pooling; `ATOMIC_REQUESTS` excludes
      long-running and streaming views.
- [ ] Cross-tenant and connection-reuse isolation tests exist and run against a
      pooled configuration, not a single connection.
