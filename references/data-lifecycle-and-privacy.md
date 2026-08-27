# Data Lifecycle and Privacy Engineering

This file covers what happens to a personal-data record after somebody writes
it. It covers how you delete the record, what a "deleted" flag actually hides,
and where copies of it live. It also covers how long you keep it, when
anonymization is real, and how it leaves the system through an export.

The threat model is time and duplication rather than access. The same row stays
readable after the account was closed, or stays present in a copy nobody
listed. Maps primarily to CWE-212, CWE-359, CWE-459, and CWE-532. Relevant
OWASP categories include A01:2025, A06:2025, and A09:2025, and API1:2023 and
API3:2023.

This file owns **the record over time**. That scope is deletion completeness,
what a soft-delete flag fails to hide, and retention with the schedule that has
to be shown to have run. It also covers when anonymization is real, and every
copy an erasure must reach.

The boundary with its neighbors is existence rather than access.
`authorization-architecture.md` owns who may read a denormalized copy, and this
file owns whether that copy still exists once the source row is gone.
`a09-logging-and-alerting.md` owns what must be recorded, and this file owns
the log and the history table as retained personal data. `file-uploads.md` owns
storage and delivery of the files whose deletion belongs here.
`data-layer-and-database.md` owns backups, replicas, and the encryption
substrate that crypto-shredding depends on.

## Contents
- [Principle](#principle)
- [Django & DRF implementation](#django--drf-implementation)
- [Soft delete and what it does not hide](#soft-delete-and-what-it-does-not-hide)
- [Delete paths and what each one runs](#delete-paths-and-what-each-one-runs)
- [Where a record survives](#where-a-record-survives)
- [Erasure as a fan-out with a completion ledger](#erasure-as-a-fan-out-with-a-completion-ledger)
- [Stored files outlive their rows](#stored-files-outlive-their-rows)
- [Anonymization and the reversibility test](#anonymization-and-the-reversibility-test)
- [Retention you can prove ran](#retention-you-can-prove-ran)
- [Export and subject-access endpoints](#export-and-subject-access-endpoints)
- [Audit history against erasure](#audit-history-against-erasure)
- [Marking personal data in the model layer](#marking-personal-data-in-the-model-layer)
- [Lower environments and the copies they inherit](#lower-environments-and-the-copies-they-inherit)
- [Review checklist](#review-checklist)

## Principle

Access control decides who may read a record now. This file covers what the
record does over time. The system copies it into stores with their own query
paths. It outlives the account it belongs to. The deletion that was supposed to
remove it usually removed one instance of it. The invariant is: **every
personal-data record has a known set of locations and a stated lifetime. It has
a deletion path that reaches every location and records that it did.**

Five rules carry most of the weight, and each is stack-agnostic:

- **Logical deletion is a visibility change, not a destruction.** A row flagged
  as deleted is a live row that most query paths can still reach. A control
  that depends on every future query, report, join, and admin screen to
  re-apply a predicate is not a control.
- **Erasure is a fan-out with a completion ledger.** The primary row is one
  target among many. Without a per-target record of success, nobody can
  separate "erased" from "the job failed on target four".
- **Stores that cannot delete in place need a cryptographic answer.** Nobody
  can rewrite backups, write-once archives, and append-only streams per
  subject. Encrypt a subject's fields under a key held only for that subject,
  and destroy the key. That destruction makes the residue unreadable. A claim
  of selective deletion from a backup without such a key is false.
- **Anonymization is a claim about re-identification, not about which columns
  were blanked.** A stable key can survive: a hash of an identifier, a
  surviving foreign key, a high-resolution timestamp, or an unscrubbed
  free-text field. The data is then pseudonymized and still personal.
- **Retention that cannot be shown to have run is indistinguishable from no
  retention.** The policy, the scheduled job, the record of each run, and an
  alert for silence are four separate artifacts. Reviewers routinely find only
  the first.

Regulation makes several of these controls contractually required. Legal
interpretation is out of scope here. Review the data flow.

## Django & DRF implementation

Three Django behaviors decide most outcomes in this area, and all three are
easy to misread from the outside:

1. **A filtered manager does not apply uniformly across relation traversals.**
   A filtered default manager governs some paths, and other paths bypass it by
   design. The table in the next section is the authoritative list for Django
   6.0.x and 5.2.x.
2. **Delete paths differ in what they run.** `Model.delete()`, `QuerySet
   .delete()`, the fast-delete path, `_raw_delete()`, and raw SQL are five
   behaviors, not one.
3. **A delete of a model instance does not delete the file a `FileField` points
   to.** Django removed that behavior in 1.3, and it has not returned. The
   bytes stay in `MEDIA_ROOT` or the bucket.

Behavior in this file was verified against the Django 6.0.7 and 5.2.16 source
on 2 August 2026. The second and third claims above were re-read against the
6.1 source on 9 August 2026, and they are unchanged there. The one addition is
the new database-level delete options recorded with them. The fast-delete path
still declines whenever a delete-signal receiver exists, the bypass set still
bypasses, and `FileField` still connects no `post_delete`. A deleted row
therefore still leaves its bytes in storage.

The first claim, the traversal table, was not re-read against 6.1, and it keeps
its 6.0.x/5.2.x provenance. Re-check it against the project's actual Django
version before you rely on a filtered traversal.

## Soft delete and what it does not hide

Maps to CWE-212 and CWE-359; A01:2025 and API1:2023 where the tombstone is
readable by someone who should not read it.

### Principle layer

Soft delete replaces destruction with a flag. The record remains a live row
with a full set of values and every property it had before. One predicate is
the only difference, and only the paths that remember it apply that predicate.
It is a sound design for an undo or recycle-bin feature, where the requirement
is precisely that the data comes back. It is not a deletion control, because
the tombstone remains readable by anything that reaches the store without the
predicate. Such a reader is a report, an aggregate, a join, an admin screen, a
direct query, an operator, or a backup.

So a soft-delete implementation has to state in the code which of the two it
is. "The account is deleted" is not true of a flagged row for any purpose that
matters: subject erasure, breach scope, or retention.

### Django & DRF implementation layer

The usual implementation is an abstract model with `deleted_at`. It adds a
manager whose `get_queryset()` excludes flagged rows, assigned to `objects`,
and a `delete()` override that sets the flag. That protects `Model.objects`
queries. It does not protect the paths below, and the split is not intuitive:

| Path | Manager used | Filtered by a filtered default manager |
|---|---|---|
| `comment.author` — forward FK or one-to-one | `_base_manager` | No |
| `user.profile` — reverse one-to-one | `_base_manager` | No |
| `prefetch_related("author")` — forward FK or reverse one-to-one | `_base_manager` | No |
| `question.choice_set` — reverse FK, including `prefetch_related` | class of `_default_manager` | Yes |
| `post.tags` — many-to-many, either direction | class of `_default_manager` | Yes |
| `select_related("author")` | none — it is a SQL join | No |
| `refresh_from_db()` without `from_queryset` | `_base_manager` | No |
| `get_object_or_404(Model, ...)` | `_default_manager` | Yes |
| `ModelAdmin.get_queryset()` | `_default_manager` | Yes |
| `.raw()`, `cursor.execute()`, `_raw_delete()` | none | No |

The forward-relation row is the important one. Django deliberately uses the
unfiltered base manager for related-object access, so that a related object
stays retrievable even when the default manager would hide it. A correct
filtered `objects` manager therefore gives false confidence. The object is
absent from lists, and present on every detail page that walks a foreign key to
it.

```python
# Wrong: the filtered default manager is treated as the deletion boundary.
class Comment(models.Model):
    author = models.ForeignKey(User, on_delete=models.PROTECT)

# User.objects.filter(...) hides the deleted author, but comment.author
# traverses User._base_manager and returns the tombstone in full, including
# the email and name the deletion was supposed to remove.

# Correct for the flag option only: re-apply the predicate where the object
# is used, and keep the unfiltered manager under a name that says what it is.
# Every call site is a place to forget, so read the verdict below first.
class User(AbstractUser):
    objects = ActiveUserManager()   # excludes deleted rows
    all_objects = models.Manager()  # every row, for admin and restore paths

def comment_author_or_404(comment):
    author = comment.author
    if author.deleted_at is not None:
        raise Http404
    return author
```

Do not point `Meta.base_manager_name` at the filtered manager. The base manager
exists so that Django internals can reach rows the default manager hides. A
filter on it breaks related-object access, cascade collection, and
`refresh_from_db()`, and those failures surface as missing objects rather than
as errors. Django's own documentation on custom managers says not to filter
results in a base manager. Keep `base_manager_name` unfiltered, and filter in
application code.

The admin is a decision, not a default. `ModelAdmin.get_queryset()` calls
`self.model._default_manager.get_queryset()`. With a filtered default manager,
staff cannot see or restore a soft-deleted row. With an unfiltered one, the
admin becomes a place where staff routinely read deleted personal data. Choose
deliberately, and make the state visible:

```python
# Correct: staff see tombstones as tombstones, and no change form
# resurrects one.
class UserAdmin(admin.ModelAdmin):
    list_display = ("email", "deleted_at")
    readonly_fields = ("deleted_at",)

    def get_queryset(self, request):
        return self.model.all_objects.all()
```

A writable `deleted_at` turns the change form into an undelete. That path runs
no service function, so the children, the credentials, and the audit record are
all skipped. Keep the field read-only. Put restore behind a permission-guarded
admin action that calls the same service function the deletion calls.

On the DRF side, an auto-generated `ModelSerializer` relation uses
`Model.objects` for its writable queryset, so a client cannot select a deleted
object. But a nested or read-only serializer that traverses a forward FK
serializes the tombstone straight over the wire, because that traversal uses
`_base_manager`. Make related-field querysets explicit, and test a nested
representation of a deleted parent.

Unique constraints are the other reliable failure. A column-level `unique=True`
applies across every row, tombstones included. A deleted account therefore
keeps ownership of its email forever. The person cannot re-register, and a
restore fails with `IntegrityError`. The constraint is also the sign that the
identifier was retained indefinitely.

```python
# Wrong: the tombstone owns the address permanently.
email = models.EmailField(unique=True)

# Correct: uniqueness applies to live rows only (PostgreSQL and SQLite
# support partial indexes; on MySQL a generated column is needed).
class Meta:
    constraints = [
        models.UniqueConstraint(
            fields=["email"],
            condition=Q(deleted_at__isnull=True),
            name="uniq_active_email",
        )
    ]
```

The partial constraint moves that failure; it does not remove it. The tombstone
releases the address at the moment of the flag. Anyone can then register it,
and every system keyed on that address resolves to the new account. Those
systems are SSO claims, support tools, mailing lists, and password reset
elsewhere. A restore of the tombstone then fails with `IntegrityError` against
the live row.

So hold the identifier for the length of the tombstone grace period. Release it
as an explicit step of the purge. Record that release as a security event.
State what a restore does when the identifier is already re-issued.

Cascades do not run for a soft delete, because no row was deleted. `on_delete`
never fires, children keep a live foreign key to a tombstoned parent, and
`parent.children` returns them. Decide explicitly whether you delete,
anonymize, or reassign the children. Write that decision into the same service
function that sets the flag, rather than leave it to the database.

Aggregates and reports inherit whichever queryset they start from. A count
built on `all_objects`, a `.raw()` query, or a warehouse extract that reads the
table directly all include tombstones. That is how "deleted" users continue to
appear in totals and exports.

**Verdict.** Three options follow, in priority order. Where undo is a real
requirement, hard-delete the row and move it to a dedicated archive table. The
retained copy is then one explicit object with its own access control, instead
of a predicate every future query must remember. Give that table a retention
period and a leg in the fan-out, or it is the tombstone problem under another
name. Where undo is not a requirement, hard-delete outright.

Use a flag only where neither option is feasible. Then use it only with a
filtered default manager, an unfiltered base manager, and partial unique
constraints. Audit the traversals, and add a scheduled purge that finally
hard-deletes or anonymizes the tombstone. Never report an `is_deleted` row as
erased.

## Delete paths and what each one runs

Django has five delete behaviors, and they differ in what code runs. That
difference matters, because file cleanup, audit records, and cache invalidation
usually attach to one of them:

- `Model.delete()` on an instance runs an overridden `delete()` and sends
  `pre_delete`/`post_delete`.
- `QuerySet.delete()` **does** send `pre_delete` and `post_delete`, cascaded
  objects included. But it does not call each instance's `delete()` method, so
  it skips an override that sets a flag or deletes a file.
- The fast-delete path issues a single DELETE and loads no instances. Django
  only takes it when the model has no delete-signal receivers, no cascading
  relations, and no parents. That receiver test reads the registry of the
  running process, so the answer differs from process to process. A receiver
  connected from `urls.py`, a view module, or a conditional import is absent in
  a Celery worker, a management command, and a shell. Those processes take the
  fast path and run no cleanup, and they raise nothing. Connect every delete
  receiver in `AppConfig.ready()`, which runs in each process that calls
  `django.setup()`. Fast delete also means that a model whose cleanup lives
  only in an overridden `delete()` gets no cleanup at all.
- `_raw_delete()`, `cursor.execute()`, `TRUNCATE`, and database-level
  `ON DELETE CASCADE` bypass model methods and signals entirely. Django 6.1
  makes that last path reachable from the model definition rather than only
  from hand-written DDL. `on_delete=models.DB_CASCADE`, `DB_SET_NULL`, and
  `DB_SET_DEFAULT` push the deletion into the SQL `ON DELETE` clause. The
  related rows are therefore never loaded, and `pre_delete`/`post_delete` are
  never sent for them. All three sit in the collector's skip set, and the
  release notes spell it out for `DB_CASCADE`. A switch to one of these for the
  write performance silently drops every signal-attached side effect on the far
  side of that relation. Those effects are file cleanup, audit rows, and cache
  invalidation. The diff that does it is one keyword long.
- `QuerySet.update()`, `bulk_create()`, and `bulk_update()` skip `save()` and
  the save signals. That is how code scrubs a field without the audit entry
  that was supposed to accompany it.

Cleanup attached to a signal or an override is therefore only as complete as
the set of paths that trigger it. Put erasure side effects in an explicit
service function that every path calls. `a09-logging-and-alerting.md`,
"Lifecycle hooks and audit guarantees" requires the same for audit events.

## Where a record survives

An erasure design is only as good as this inventory, because the failure is
always a location nobody listed. Enumerate for each personal-data model:

**The primary store and its shadows**

- the row itself, any soft-delete tombstone of it, and any archive table it
  was moved to;
- the credentials that still authenticate as the subject: sessions, DRF tokens,
  API keys, OAuth grants, and password-reset tokens. A tombstone and an
  anonymized row both keep them, so a "deleted" principal keeps reading and
  writing as ordinary authenticated traffic. DRF's `TokenAuthentication`
  resolves the account with `select_related` and tests only `is_active`, so
  `deleted_at` never reaches that decision.
  `authorization-architecture.md`, "Identity lifecycle and provisioning
  desynchronization" owns the revocation fan-out. Reuse that fan-out here
  rather than build a second one;
- history, versioning, or audit tables, which hold every prior value of every
  field;
- files behind `FileField` and `ImageField` in local storage or a bucket;
- read replicas, and database backups and point-in-time-recovery archives
  (`data-layer-and-database.md`, "Copies of production data").

**Derived and exported copies**

- search indexes and any denormalized or materialized report table;
- caches, including per-view caches, low-level cache entries, and the session
  store (`a01-broken-access-control.md`, "Caching and authorization");
- CDN edge copies of media and generated exports
  (`deployment-and-runtime.md`, "Caching security" and "Static and media");
- analytics and product-telemetry pipelines, and the warehouse they land in;
- the error tracker, where personal data arrives inside exception locals,
  request bodies, and breadcrumbs. Log aggregation is the same, where it
  arrives in structured log lines (`a09-logging-and-alerting.md`, "Scrub error
  reports" and "Don't log secrets");
- the email or messaging provider, which retains message bodies and
  suppression lists, and any support or CRM tool synchronized with the record;
- queue and event-stream payloads carrying a copy of the record;
- non-production databases seeded from production, and developer machines;
- artifacts already delivered to the subject or a third party — export
  archives, signed tokens, invoices.

Each entry needs an owner, a stated lifetime, and a leg in the fan-out below.
An explicit statement that it is out of scope, with the reason, is the
alternative.

## Erasure as a fan-out with a completion ledger

Maps to CWE-212 and CWE-459; A01:2025 where a surviving copy is reachable.

### Principle layer

Treat an erasure request as a durable object with per-target state, not as a
function call. Record the request. Attempt each target independently and
idempotently (idempotency design: `a10-exceptional-conditions.md`). Each
attempt writes its outcome. The request is complete only when every target
reports success, and a later pass re-reads each one and finds nothing.

Anything that you cannot delete in place takes the cryptographic route instead.
Those stores are backups, write-once storage, and append-only streams. Encrypt
the subject's fields under a key held only for that subject, and let erasure
destroy the key. The ciphertext that remains is no longer readable.

That mechanism depends entirely on key isolation, because a shared key ring
means one key destruction breaks every subject. It also depends on an auditable
destruction. `data-layer-and-database.md`, "Field-level encryption and
searchable lookups" owns the key management it requires.

Crypto-shredding is a decision made at the first write, not at the erasure. A
key destruction cannot reach a payload that entered a stream, an index, or a
backup as plaintext. So decide per store, before anything writes to it, that
the subject's fields go in encrypted. Record every store that already holds
plaintext under an older scheme as unshreddable. Give each of those a migration
date or a purge date instead.

A key inside a restorable backup is not destroyed, because a restore of the key
store makes the ciphertext readable again. Keep per-subject keys out of every
dataset a restore rewrites. Read the key's state at its source before the
target reports `DONE`. A key destruction is also irreversible, and a wrong
subject cannot be repaired afterwards. Hold that one step behind a stated
reversal window that the ledger records. Run every other target inside that
window.

For one erased subject, a reviewer must answer three questions from stored
state. Those questions are which targets were attempted, when each completed,
and what remains. The reviewer must not have to read the task code.

### Django & DRF implementation layer

A ledger is two models and one task per target. The second model exists so that
a partial failure is visible and retryable, rather than lost inside a task that
already returned:

```python
class ErasureRequest(models.Model):
    subject_id = models.CharField(max_length=64)  # opaque, survives the row
    requested_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)


class ErasureTarget(models.Model):
    class State(models.TextChoices):
        PENDING = "pending"
        DONE = "done"
        FAILED = "failed"

    request = models.ForeignKey(
        ErasureRequest, on_delete=models.PROTECT, related_name="targets"
    )
    name = models.CharField(max_length=64)  # "primary_row", "search_index", ...
    state = models.CharField(max_length=16, default=State.PENDING)
    completed_at = models.DateTimeField(null=True, blank=True)
    detail = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["request", "name"], name="uniq_target_per_request"
            )
        ]
```

```python
@transaction.atomic
def request_erasure(*, subject, actor, request_id):
    erasure = ErasureRequest.objects.create(subject_id=subject.erasure_key)
    ErasureTarget.objects.bulk_create(
        [ErasureTarget(request=erasure, name=name) for name in ERASURE_TARGETS]
    )
    SecurityEvent.objects.create(
        actor=actor, action="privacy.erasure_requested",
        object_id=erasure.subject_id, request_id=request_id,
    )
    # Fan out only after the ledger is durable; a task that starts before
    # commit can finish against rows that never existed.
    transaction.on_commit(partial(fan_out_erasure, erasure_id=erasure.pk))
    return erasure


def erase_primary_row(erasure):
    user = User.all_objects.filter(erasure_key=erasure.subject_id).first()
    if user is None:
        return  # a retry of a finished target succeeds rather than raises
    # The parent delete destroys the foreign key that finds the children, so
    # resolve them first. One branch per Privacy.on_erasure.
    resolve_inbound_relations(user)
    # Every FileField on the model, so a field added later needs no edit here.
    stored = [
        (getattr(user, f.name).storage, getattr(user, f.name).name)
        for f in user._meta.local_fields
        if isinstance(f, models.FileField) and getattr(user, f.name)
    ]
    # A queryset delete never calls an overridden Model.delete(). On a
    # soft-delete model, user.delete() writes a tombstone that keeps every
    # value the erasure had to remove.
    User.all_objects.filter(pk=user.pk).delete()
    # The bytes go after the row is committed as gone. A rollback after a file
    # delete leaves a live row that points at destroyed bytes.
    transaction.on_commit(partial(delete_stored_files, stored))
```

Two properties of that function are load-bearing, and each one fails silently:

- **Never let an erasure depend on `Model.delete()`.** A soft-delete model
  overrides that method, so the call writes a flag and the row keeps every
  value. The ledger then reports an erasure that destroyed nothing, and the
  tombstone stays readable through every unfiltered path in the table above.
  `QuerySet.delete()` does not call the override, so it is the path that ends
  the row.
- **Resolve every inbound relation before the parent row goes.** The
  `referenced_by` list in the data map below is that set. A `PROTECT` child
  raises `ProtectedError`, and the target lands in `FAILED`. A `SET_NULL`
  child, or the database-level `DB_SET_NULL`, keeps its own personal fields and
  loses the only key that finds it. That row is then outside every later
  erasure, and outside `referenced_by` as well.

Each target function must be safe to run twice, because retries are how a
distributed fan-out finishes. A delete of an already-deleted search document
must succeed rather than raise. So must an invalidation of an absent cache key,
and a call to a processor's deletion endpoint for an unknown id. Where the
target is the database, mark the target row `DONE` in the same transaction as
the work.

Where the target is not the database, an accepted call is not a completed
deletion. A processor's deletion endpoint usually queues the work, so a 200
means accepted. Mark `DONE` on a verified absence instead. That absence is a
read of the processor's status, or a signed callback that carries the
processor's own deletion reference. Store that reference in the ledger. Treat
an expired processor deadline as `FAILED` rather than as silence.

Completion needs three things that a per-target flag does not give:

- **A driver that survives a crash.** `transaction.on_commit` runs the callback
  in the process that committed. A crash between that commit and the callback
  loses the fan-out, and the request stays `PENDING` with nobody to move it.
  Dispatch through a durable queue. Run a reconciliation job that re-drives
  every non-terminal target.
- **An alert for a request that stopped moving.** Retention below alerts on
  silence, and erasure needs the same artifact. Alert on the age of the oldest
  `PENDING` target, and on any `FAILED` one.
- **A final pass that re-reads rather than trusts the flags.** Nothing freezes
  the subject's writes while the fan-out runs. A profile edit, a late event, or
  a webhook replay writes fresh data into a store that already reported `DONE`.
  So re-run every target as a verification pass. Read the primary row last.
  Set `completed_at` only when that pass finds nothing.

An empty or short `ERASURE_TARGETS` list satisfies the completion rule with no
work at all. Derive the list from the location inventory above. Fail the
request at creation when a listed location has no target.

Keep the subject reference opaque and separate from the user row (`subject_id`
above). Generate `erasure_key` as a random value. Store it only on the user
row. A key derived from an email address or a phone number fails check 1 of the
reversibility test below. An attacker recomputes such a key over an enumerable
domain. `ErasureTarget.detail` is free text that collects processor responses
and database errors, and those strings carry addresses and identifiers. So
sanitize what each target writes there.

The ledger records that erasure happened, not who it happened to in
identifiable terms. It outlives every subject in it, so give it a retention
period and an access model of its own.

A restore is a resurrection path. A backup taken before an erasure still holds
the subject, so a restore undoes the erasure silently. The opaque subject
reference above makes the repair possible, because it outlives the erased rows
and still names what to remove.

That repair fails when the ledger lives only in the database being restored. A
point-in-time recovery to any instant before `requested_at` restores a dataset
that holds no `ErasureRequest` row. The replay then enumerates nothing, reports
success, and the subject is back with no record that it ever left. So write
each completed erasure to a second store that no restore rewrites. Replay from
that store. Keep only the opaque reference and the target names in it.

Make the restore procedure replay every completed erasure against the restored
data before that data serves traffic. Give point-in-time recovery the same
replay step. Test both directions the concrete way: erase a fixture subject,
then restore a backup taken before the request and one taken after it. Prove
the subject stays gone in each case.
`data-layer-and-database.md`, "Copies of production data" owns the backup and
point-in-time-recovery mechanism itself.

DRF endpoints that accept an erasure request need the same treatment as any
destructive endpoint. Authorize the subject against the requester, and
re-authenticate for an account-destroying action. Throttle it. When an operator
triggers it on behalf of someone, log the acting principal separately from the
subject (`privileged-access-and-impersonation.md`).

## Stored files outlive their rows

A delete of a model instance does not delete the file its `FileField` points
to. Django removed the automatic file deletion in 1.3, because it caused data
loss on rolled-back transactions and shared files. Django 6.0 still behaves
this way. An erasure of a user therefore leaves the avatar, the uploaded
identity document, and every attachment in `MEDIA_ROOT` or the bucket. Those
paths are often guessable, and the server delivers them without an
authorization check.

The guarantee comes from an explicit file delete inside the erasure fan-out,
where the ledger records its success. `FieldFile.delete(save=False)` is that
call while the row is still live. Where the row goes first, hold the storage
and the name, and call the storage delete instead. A file that no field
references leaves the storage delete as the only call. Signal-based cleanup
packages are a convenience for ordinary deletes, not an erasure guarantee. They
bind to model signals, so raw SQL, `_raw_delete()`, `TRUNCATE`, and
database-level cascades bypass them entirely. File deletion must also reconcile
with transaction rollback, so that a rolled-back delete does not destroy a live
file.

Two object-store behaviors also make a delete less complete than its return
value suggests. On a versioned bucket, a delete of an object writes a delete
marker and retains every prior version. The erasure therefore has to enumerate
and remove the versions rather than the key. Where delete protection requires
multi-factor authentication, that step cannot be fully automated, and it
belongs in the ledger as a manual one. A replicated copy in another bucket is a
separate object with its own deletion, not a mirror that follows.

`file-uploads.md` owns storage, naming, and authorized delivery of these files.
This file owns only their disappearance.

## Anonymization and the reversibility test

Anonymization is sufficient in place of deletion when nobody can attribute the
result to an individual. That is a property of the whole remaining dataset,
rather than of the columns that were overwritten. Run five checks against the
post-anonymization row and everything that still references it:

1. **Does a stable join key survive?** A hash of an identifier is deterministic
   by construction, so the same input always yields the same token. That token
   joins datasets. An attacker can brute-force it over a small enumerable
   domain such as email addresses or phone numbers. A salt stored beside it
   does not prevent that. If you can recompute the token from the plaintext, it
   is pseudonymization.
2. **Do surviving foreign keys re-identify?** An anonymized user still
   referenced by orders, comments, and audit rows is identifiable from that
   history. Break or blank the references, or anonymize the whole connected
   component.
3. **Do quasi-identifiers still single out a person?** Date of birth with a
   postcode and an employer routinely identifies uniquely with the name gone.
4. **Do timestamps or sequence numbers fingerprint?** A microsecond-resolution
   `created_at`, or a monotonic primary key, correlates with external logs.
   Round or drop them.
5. **Does free text still contain the identity?** Notes, message bodies, and
   bios routinely restate the name the structured fields dropped.

```python
# Wrong: reversible, and still personal data.
user.email = hashlib.sha256(user.email.encode()).hexdigest() + "@example.invalid"
user.save(update_fields=["email"])

# Correct: no derivable link back to the original identity, the row stops
# being a principal, and the free text that restates the identity is gone.
with transaction.atomic():
    user.email = f"erased-{uuid4().hex}@example.invalid"
    user.full_name = ""
    user.phone = ""
    user.date_of_birth = None
    user.set_unusable_password()
    user.is_active = False
    user.save()  # no update_fields, so a history receiver sees every change
    for comment in user.comments.all():
        comment.author_display_name = ""
        comment.body = ""  # check 5: a body restates the name the columns lost
        comment.body_search_vector = None
        comment.save()  # update() would skip save() and every save signal
```

An anonymized row that keeps a usable password and `is_active = True` is still
a live credential holder. Revoke its sessions, tokens, and keys in the same
service function, through the fan-out the inventory above names.

`QuerySet.update()` fires no save signal, so a history receiver never runs and
the anonymization leaves no trace it can audit. It also does not reach the rows
that receiver already wrote. Those rows hold every prior value, so the history
table needs a leg in the fan-out of its own.

A stable key may have to survive for a legitimate reason, such as a
reconciliation of financial records. That is a decision to retain personal data
under a stated basis and a retention period, not an anonymization. Say so in
the code, and put the retained data in the inventory.

## Retention you can prove ran

Maps to CWE-459; A06:2025, since unenforced retention is a missing control
rather than a bug.

A reviewer can confirm retention only when four artifacts exist:

1. **The policy is expressed next to the model**, as an attribute or a small
   registry. The rule is then visible where the code defines the data, and not
   buried in a task file.
2. **A scheduled job enforces it** — a management command invoked by a
   database-backed scheduler or a system timer, deleting or anonymizing rows
   past the period.
3. **Each run writes a durable record**: when it ran, which model, how many
   rows it affected. Without it, a reviewer can confirm the policy exists but
   not that it runs.
4. **Silence is alerted on.** A scheduler that stopped is the common real
   failure, and it is invisible precisely because nothing happens.

```python
class SupportTicket(models.Model):
    RETENTION = timedelta(days=730)  # policy lives with the data
    objects = ActiveTicketManager()  # excludes tombstones
    all_objects = models.Manager()   # the purge has to reach them
    ...


class Command(BaseCommand):
    def handle(self, *args, **options):
        cutoff = timezone.now() - SupportTicket.RETENTION
        # closed_at__lt never matches NULL, so a ticket nobody closed would be
        # kept forever. The policy names its fallback for the open case.
        stale = Q(closed_at__lt=cutoff) | Q(
            closed_at__isnull=True, created_at__lt=cutoff
        )
        deleted, _ = SupportTicket.all_objects.filter(stale).delete()
        # The run record proves that a job ran. This check proves that the rows
        # are gone, which is the claim the policy actually makes.
        survivors = SupportTicket.all_objects.filter(stale).count()
        if survivors:
            raise CommandError(f"{survivors} rows past the cutoff survived")
        # The run record is the artifact a reviewer checks; without it the
        # policy is unfalsifiable.
        RetentionRun.objects.create(
            model_label="support.SupportTicket",
            cutoff=cutoff,
            deleted_count=deleted,
            finished_at=timezone.now(),
        )
```

Three defects hide inside a purge predicate, and each leaves rows in place
while the run record reports success:

- **A comparison never matches NULL.** `closed_at__lt=cutoff` excludes every
  row whose `closed_at` is NULL, so a record nobody closed is retained forever.
  State the fallback the policy uses for the open case.
- **The default manager hides the rows the purge exists for.** On a soft-delete
  model, `Model.objects` excludes the tombstones. The purge that must finally
  hard-delete them therefore reads past them. Purge from the unfiltered
  manager.
- **A subject-writable timestamp chooses the deletion date.** Anyone who can
  set `closed_at` ages a record into the purge. Somebody under investigation
  closes their own dispute and waits out the period, and the deletion looks
  like routine policy. Take the retention timestamp from a field no subject
  writes. Record an operator's edit of one as a security event.

The anti-pattern to flag is a purge command that appears in no scheduler
configuration, timer unit, or crontab. Such a policy exists only as an
unexecuted file. Check the scheduler's own record of the last successful run.
Confirm that a bulk `delete()` here is compatible with the cleanup the model
needs, because it does not call `Model.delete()`.

## Export and subject-access endpoints

Maps to CWE-285 and CWE-639; A01:2025 and API1:2023.

An export endpoint assembles everything the system holds about one subject into
a single downloadable artifact. That is a legitimate feature, and at the same
time the cleanest exfiltration path in the application. A compromised account
can take everything in one authenticated request. An operator export on behalf
of a user is a confused-deputy risk. A reviewer can check each of the controls
below:

- **Two authorization decisions, not one.** Authorize the request, which asks
  whether this principal may export this subject. Authorize retrieval of the
  finished artifact, which asks whether this fetcher owns this export.
  Possession of a result URL is not authorization.
- **Throttle the job, not the request rate.** Exports are expensive and rare;
  bound them per principal per window rather than per second
  (`api-drf-specific.md`, "Throttling as quota, not security (API4)").
- **Signed-URL hygiene.** Use a short expiry, bind the URL to the exact object,
  and make it single-use where the storage supports it. Re-authenticate rather
  than treat the URL as the credential. Keep it out of `Referer` headers,
  access logs, and plaintext email.
- **The archive is itself a personal-data copy.** Private location, enforced
  expiry, and an entry in the inventory and the erasure fan-out. A signed URL's
  expiry ends new fetches and leaves the object in place, so it is not the
  lifetime. Enforce the lifetime on the bytes, with a scheduled delete that
  writes a run record. Invalidate the edge copy in the same step. The delivery
  mechanism is the private-download primitive in `file-uploads.md`, "Private
  downloads".
- **Attribute operator-initiated exports.** Log the acting principal separately
  from the subject and constrain what an admin-initiated export may contain
  (`privileged-access-and-impersonation.md`).
- **Bound the contents deliberately.** An export that serializes every related
  model tends to include internal fields and other people's data in shared
  objects. Define the field set explicitly, as `api-drf-specific.md`,
  "Serializer exposure and mass assignment (API3)" requires of any serialized
  response.

## Audit history against erasure

Security logging requires that events survive. Erasure requires that personal
data does not. The resolution is to separate the identity from the event,
rather than to choose between them. Use this order of preference:

1. **Store the subject reference in a separate identity table**, and keep the
   event row that points at it. Erasure deletes or anonymizes the identity row,
   and the event survives with a dangling or nulled reference. What happened is
   retained, and who it happened to is gone.
2. **Pseudonymize the reference** in the event and destroy the mapping on
   erasure. This is the crypto-shredding pattern applied to a join key and
   carries the same key-isolation requirement.
3. **Retain a minimal defined subset** where a specific obligation requires it.
   Keep it segregated from the general audit store, with its own retention
   period and its own access control.

Model-history and versioning tables are the high-risk instance, because they
retain every prior value of every field. That includes values a subject later
asked to erase, and the values that an anonymization run overwrote. Any history
table over a model with personal fields belongs in the inventory, in the
retention policy, and in the erasure fan-out.

`a09-logging-and-alerting.md` owns what must be logged, and how logs stay
tamper-evident. This file owns the fact that the audit store is itself a
retained copy of personal data that has to reconcile with erasure.

## Marking personal data in the model layer

Nothing above is auditable if nobody can enumerate which fields are personal.
Mark the classification where the code defines the field. Use a small per-model
declaration that names the personal fields, the fields an export includes, and
the erasure action for each. A reviewer can then grep for it, and a management
command can walk the app registry and emit the inventory from the models
themselves.

```python
class Profile(models.Model):
    class Privacy:
        personal_fields = ("full_name", "phone", "date_of_birth")
        export_fields = ("full_name", "phone", "date_of_birth", "created_at")
        on_erasure = "anonymize"  # or "delete", or "retain" with a reason
```

A generated data map is the machine-checkable form of the inventory above. It
holds every model, every field marked personal, and every foreign key into a
model that has any. It is the artifact that makes a new model's missing
classification visible in review. Prefer twenty lines of local convention to a
dependency. The packaged options in this area are unmaintained, as
`security-hardening-libraries.md`, "Data lifecycle and privacy" records.

The command that emits it is **project-side code the audited application
carries**, not tooling a reviewer supplies. It has to run against the
application's own app registry with its own settings loaded. Walk
`apps.get_models()`, read the marker, and emit three lists. Those lists are
what holds personal data, what declares none, and what nobody classified. A
review acts on the third.

```python
# Correct: the inventory is derived from the models themselves, so a model
# or field nobody classified is a visible gap rather than an absence.
import json

from django.apps import apps
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Emit the personal-data map from the model layer."

    def handle(self, *args, **options):
        data_map, unclassified, declared_none = [], [], []
        for model in apps.get_models():
            privacy = getattr(model, "Privacy", None)
            personal = tuple(getattr(privacy, "personal_fields", ()))
            if not personal:
                # Every model lands in exactly one list, so no declaration
                # makes a model disappear from the map.
                if privacy is None:
                    unclassified.append(model._meta.label)
                else:
                    declared_none.append(model._meta.label)
                continue
            exported = tuple(getattr(privacy, "export_fields", ()))
            declared = set(personal) | set(exported)
            data_map.append({
                "model": model._meta.label,
                "personal_fields": sorted(personal),
                "export_fields": sorted(exported),
                "on_erasure": getattr(privacy, "on_erasure", None),
                # Every inbound FK is a path the erasure fan-out must follow.
                "referenced_by": sorted(
                    f"{rel.related_model._meta.label}.{rel.field.name}"
                    for rel in model._meta.related_objects
                ),
                # On the model but absent from the declaration.
                "undeclared_fields": sorted(
                    f.name for f in model._meta.local_fields
                    if not f.primary_key and f.name not in declared
                ),
            })

        self.stdout.write(json.dumps(
            {
                "models": data_map,
                "declared_no_personal_data": sorted(declared_none),
                "unclassified_models": sorted(unclassified),
            },
            indent=2, sort_keys=True,
        ))
```

Three things about the shape are load-bearing. Every model lands in exactly one
of the three lists: a model with no `Privacy` class is unclassified, and one
that declares an empty `personal_fields` is a stated finding of none. The
difference between "nobody looked" and "somebody looked and found none" is the
whole value of the artifact. A model that lands in no list is a place to hide
one, so an empty declaration has to be named rather than skipped.
`related_objects` gives the inbound foreign keys. Those are the paths the
erasure fan-out has to follow, and the paths a reviewer would otherwise have to
find by hand. `undeclared_fields` makes the write-time rule below checkable. A
field added to a classified model but absent from its declaration is the
ordinary way personal data becomes invisible.

Run it in CI and diff the output, on the same terms as any other inventory. The
useful signal is a model or field that moves into the unclassified list, or
into the declared-none list, between one release and the next.

**Write-time.** When you generate a model field that holds personal data, add
it to that model's `Privacy` declaration in the same edit. Add it to
`personal_fields`, to the `export_fields` a subject-access response returns,
and to an `on_erasure` action of delete, anonymize, or retain with its reason.

The erasure fan-out, the retention job, and the export endpoint all run from
that declaration. A field absent from it is invisible to all three, and looks
entirely ordinary on the model. Choose `retain` deliberately rather than by
omission. A field nobody classified is retained by accident and defended by
nobody.

## Lower environments and the copies they inherit

A production dump in staging, a demo environment, or a laptop multiplies every
personal-data copy. Those places have weaker access control, no audit trail,
and broad access. Those copies are invisible to the erasure fan-out, so an
erased subject still exists in last month's staging refresh.
`data-layer-and-database.md`, "Copies of production data" owns the rule. The
pipeline that satisfies it follows:

- **Mask during extraction, never after the load.** If plaintext lands in the
  lower environment first, it was disclosed there, whatever runs next.
- **Preserve referential integrity deterministically.** Mask join keys with a
  per-run secret, so foreign keys still match. Generate fake display values, so
  the environment is usable without real identities.
- **A masked extract is pseudonymized, not anonymized.** The deterministic mask
  is a keyed hash over an enumerable domain, so it fails check 1 above.
  Cardinality, timestamps, and the relation graph all survive it, so checks 3
  and 4 apply as well. Run the five checks against the extract before it loads.
  Protect and rotate the per-run secret as a production key, because it inverts
  every join key it made.
- **Subset rather than copy.** A referentially consistent slice of subjects and
  their related rows is smaller, faster, and a much smaller loss if it leaks.
- **Prefer synthetic data** where realistic-but-fake values suffice; it carries
  no re-identification risk precisely because it is not derived from anyone.
- **Treat the extract as an inventory entry** with a location, a lifetime, and
  an owner, like any other copy. Give it an expiry, or replay completed
  erasures against it after each refresh.

## Review checklist

### Stack-neutral

- [ ] Every personal-data model has an enumerated set of locations, with an
      owner and a stated lifetime for each. Those locations are the primary
      row, history tables, files, caches, indexes, the warehouse, third-party
      processors, and backups.
- [ ] Deletion is a fan-out with per-target completion state that a reviewer can
      read, not a single call whose partial failure is invisible. A durable
      driver re-drives a stalled target, an alert fires on its age, and a
      verification pass closes the request instead of the last flag.
- [ ] The target list is derived from the location inventory, so an absent
      target fails the request rather than completing it silently.
- [ ] Completed erasures are recorded outside every dataset a restore rewrites,
      and the replay reads them from there.
- [ ] Stores that cannot delete in place are handled by destroying a
      per-subject key, not by asserting selective deletion from a backup. That
      choice was made before the first write to each store, and no per-subject
      key sits in a restorable backup.
- [ ] Logical deletion is used for undo, never reported as erasure, and every
      tombstone has a scheduled purge or anonymization.
- [ ] Any anonymization survives the reversibility test. There is no
      recomputable token, no re-identifying foreign key, and no
      quasi-identifier that singles out a person. No timestamp fingerprints,
      and no identity is left in free text.
- [ ] Retention exists as policy, scheduled job, per-run record, and an alert
      for a job that stops running. The job proves the absence itself, because
      a run record proves only that something ran. No subject can edit the
      timestamp that dates a record into the purge.
- [ ] Export endpoints authorize the request and the artifact separately, and
      throttle the job. They expire the artifact, and log operator-initiated
      exports against the acting principal.
- [ ] The audit store retains the event without retaining the identity, and
      history tables are in the retention and erasure paths.
- [ ] Lower environments are masked or subsetted at extraction and are counted
      as copies. Masked extracts pass the reversibility test, and the masking
      secret is held as a production key.

### Django & DRF

- [ ] Soft-delete models keep a filtered default manager, an unfiltered
      `base_manager_name`, and a named unfiltered manager for admin and restore
      paths.
- [ ] The review audits forward FK, reverse one-to-one, `select_related`,
      `refresh_from_db()`, raw SQL, and cursor paths for tombstone leakage.
      Tests exercise nested DRF serializers against a deleted related object.
- [ ] Unique constraints on soft-delete models are partial on the live
      condition, so tombstones neither block re-registration nor retain
      identifiers indefinitely. The released identifier is held for the grace
      period, and a restore states what it does when that identifier is
      re-issued.
- [ ] `ModelAdmin.get_queryset()` states its choice explicitly and surfaces the
      deleted state rather than hiding or silently exposing tombstones.
      `deleted_at` is read-only there, and restore is an audited action that
      calls the deletion's own service function.
- [ ] Erasure of the primary row never calls an overridden `Model.delete()`,
      and it resolves every inbound relation before the row goes. A `PROTECT`
      child raises, and a `SET_NULL` child orphans out of the fan-out's reach.
- [ ] Erasure of a `FileField` drives its field list from the model rather than
      from a hard-coded tuple, and destroys the bytes after the row is
      committed as gone. The review does not treat signal-based cleanup as the
      guarantee.
- [ ] Cleanup does not depend only on an overridden `Model.delete()` or on
      delete signals. `QuerySet.delete()`, `_raw_delete()`, `TRUNCATE`, and
      database-level cascades each behave differently. A `ForeignKey` declared
      with Django 6.1's `DB_CASCADE`, `DB_SET_NULL`, or `DB_SET_DEFAULT` sends
      no delete signal for the rows it removes. Delete receivers are connected
      in `AppConfig.ready()`, so a worker or a management command cannot take
      the fast-delete path that a web process declines.
- [ ] Retention commands are wired into an actual schedule, and they write a
      run record. Their predicate states what happens to a NULL timestamp, and
      reads the unfiltered manager on a soft-delete model. The review checks
      any bulk `delete()` in them against the cleanup the model needs.
- [ ] Personal fields are marked at the model layer so the inventory can be
      generated from the app registry rather than maintained by hand.
- [ ] The restore procedure replays completed erasures against the restored
      data before it serves traffic, and point-in-time recovery carries the
      same step. A fixture subject proves it.
