# Data Lifecycle and Privacy Engineering

What happens to a personal-data record after it is written: how it is deleted,
what a "deleted" flag actually hides, where copies of it live, how long it is
kept, when anonymization is real, and how it leaves the system through an
export. The threat model is time and duplication rather than access — the same
row, still readable after the account was closed, or still present in a copy
nobody listed. Maps primarily to CWE-212, CWE-359, CWE-459, CWE-200, and
CWE-532; relevant OWASP categories include A01:2025, A06:2025, and A09:2025,
and API1:2023 and API3:2023.

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
record does over time: it is copied into stores with their own query paths, it
outlives the account it belongs to, and the deletion that was supposed to remove
it usually removed one instance of it. The invariant is: **every personal-data
record has a known set of locations, a stated lifetime, and a deletion path that
reaches every location and records that it did.**

Five rules carry most of the weight, and each is stack-agnostic:

- **Logical deletion is a visibility change, not a destruction.** A row flagged
  as deleted is a live row that most query paths can still reach. A control that
  depends on every future query, report, join, and admin screen remembering to
  re-apply a predicate is not a control.
- **Erasure is a fan-out with a completion ledger.** The primary row is one
  target among many, and without a per-target record of success nobody can tell
  the difference between "erased" and "the job failed on target four".
- **Stores that cannot delete in place need a cryptographic answer.** Backups,
  write-once archives, and append-only streams cannot be rewritten per subject.
  Encrypting a subject's fields under a key held only for that subject and
  destroying the key is what makes the residue unreadable; asserting selective
  deletion from a backup without one is theatre.
- **Anonymization is a claim about re-identification, not about which columns
  were blanked.** If a stable key survives — a hash of an identifier, a
  surviving foreign key, a high-resolution timestamp, an unscrubbed free-text
  field — the data is pseudonymized and still personal.
- **Retention that cannot be shown to have run is indistinguishable from no
  retention.** The policy, the scheduled job, the record of each run, and an
  alert for silence are four separate artifacts, and reviewers routinely find
  only the first.

Regulation is why several of these controls are contractually required, but
legal interpretation is out of scope here: review the data flow.

## Django & DRF implementation

Three Django behaviors decide most outcomes in this area, and all three are
easy to get wrong from the outside:

1. **Manager filtering is not uniform across relation traversals.** A filtered
   default manager governs some paths and is bypassed by others, by design. The
   table in the next section is the authoritative list for Django 6.0.x and
   5.2.x.
2. **Delete paths differ in what they run.** `Model.delete()`, `QuerySet
   .delete()`, the fast-delete path, `_raw_delete()`, and raw SQL are five
   behaviors, not one.
3. **Deleting a model instance does not delete the file a `FileField` points
   to.** Django removed that behavior in 1.3 and it has not returned; the bytes
   stay in `MEDIA_ROOT` or the bucket.

Behavior in this file was verified against the Django 6.0.7 and 5.2.16 source
on 2 August 2026. Re-check it against the project's actual Django version
before relying on a traversal being filtered.

## Soft delete and what it does not hide

Maps to CWE-212 and CWE-359; A01:2025 and API1:2023 where the tombstone is
readable by someone who should not read it.

### Principle layer

Soft delete replaces destruction with a flag, so the record remains a live row
with a full set of values and every property it had before, minus one predicate
applied by the paths that remember it. It is a sound design for an undo or
recycle-bin feature, where the requirement is precisely that the data comes
back. It is not a deletion control, because the tombstone remains readable by
anything that reaches the store without the predicate: a report, an aggregate,
a join, an admin screen, a direct query, an operator, a backup.

So a soft-delete implementation has to state in the code which of the two it
is, and "the account is deleted" is not true of a flagged row for any purpose
that matters — subject erasure, breach scope, or retention.

### Django & DRF implementation layer

The usual implementation is an abstract model with `deleted_at`, a manager
whose `get_queryset()` excludes flagged rows assigned to `objects`, and a
`delete()` override that sets the flag. That protects `Model.objects` queries.
It does not protect the following, and the split is not intuitive:

| Path | Manager used | Filtered by a filtered default manager |
|---|---|---|
| `comment.author` — forward FK or one-to-one | `_base_manager` | No |
| `user.profile` — reverse one-to-one | `_base_manager` | No |
| `question.choice_set` — reverse FK, including `prefetch_related` | class of `_default_manager` | Yes |
| `post.tags` — many-to-many, either direction | class of `_default_manager` | Yes |
| `select_related("author")` | none — it is a SQL join | No |
| `refresh_from_db()` without `from_queryset` | `_base_manager` | No |
| `get_object_or_404(Model, ...)` | `_default_manager` | Yes |
| `ModelAdmin.get_queryset()` | `_default_manager` | Yes |
| `.raw()`, `cursor.execute()`, `_raw_delete()` | none | No |

The forward-relation row is the important one. Django deliberately uses the
unfiltered base manager for related-object access so that a related object
remains retrievable even when the default manager would hide it. A correct
filtered `objects` manager therefore gives false confidence: the object is
absent from lists and present on every detail page that walks a foreign key to
it.

```python
# Wrong: the filtered default manager is treated as the deletion boundary.
class Comment(models.Model):
    author = models.ForeignKey(User, on_delete=models.PROTECT)

# User.objects.filter(...) hides the deleted author, but comment.author
# traverses User._base_manager and returns the tombstone in full, including
# the email and name the deletion was supposed to remove.

# Correct: re-apply the predicate where the object is used, and keep the
# unfiltered manager available under a name that says what it is.
class User(AbstractUser):
    objects = ActiveUserManager()   # excludes deleted rows
    all_objects = models.Manager()  # every row, for admin and restore paths

def comment_author_or_404(comment):
    author = comment.author
    if author.deleted_at is not None:
        raise Http404
    return author
```

Do not respond to this by pointing `Meta.base_manager_name` at the filtered
manager. The base manager exists so Django internals can reach rows the default
manager hides; filtering it breaks related-object access, cascade collection,
and `refresh_from_db()` in ways that surface as missing objects rather than as
errors. Django's own documentation on custom managers says not to filter
results in a base manager. Keep `base_manager_name` unfiltered and filter in
application code.

The admin is a decision, not a default. `ModelAdmin.get_queryset()` calls
`self.model._default_manager.get_queryset()`, so with a filtered default
manager staff cannot see or restore a soft-deleted row, and with an unfiltered
one the admin becomes a place deleted personal data is routinely read. Choose
deliberately and make the state visible:

```python
# Correct: staff see tombstones as tombstones, not as ordinary rows.
class UserAdmin(admin.ModelAdmin):
    list_display = ("email", "deleted_at")

    def get_queryset(self, request):
        return self.model.all_objects.all()
```

On the DRF side, an auto-generated `ModelSerializer` relation uses
`Model.objects` for its writable queryset, so a client cannot select a deleted
object — but a nested or read-only serializer that traverses a forward FK
serializes the tombstone straight over the wire, because that traversal is
`_base_manager`. Make related-field querysets explicit and test a nested
representation of a deleted parent.

Unique constraints are the other reliable failure. A column-level `unique=True`
is enforced across every row, tombstones included, so a deleted account keeps
ownership of its email forever: the person cannot re-register, and a restore
fails with `IntegrityError`. The constraint is also the tell that the
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

Cascades do not run for a soft delete, because no row was deleted:
`on_delete` never fires, children keep a live foreign key to a tombstoned
parent, and `parent.children` returns them. Decide explicitly whether the
children are deleted, anonymized, or reassigned, and write that into the same
service function that sets the flag rather than leaving it to the database.

Aggregates and reports inherit whichever queryset they start from. A count
built on `all_objects`, a `.raw()` query, or a warehouse extract that reads the
table directly all include tombstones, which is how "deleted" users keep
appearing in totals and exports.

**Verdict.** In priority order: hard-delete the row and move it to a dedicated
archive table when undo is a real requirement, so the retained copy is one
explicit object with its own access control instead of a predicate every future
query must remember; hard-delete outright where undo is not a requirement; use
a flag only where neither is feasible, and then only with a filtered default
manager, an unfiltered base manager, partial unique constraints, audited
traversals, and a scheduled purge that eventually hard-deletes or anonymizes
the tombstone. Never report an `is_deleted` row as erased.

## Delete paths and what each one runs

Django has five delete behaviors and they differ in what code runs, which
matters because file cleanup, audit records, and cache invalidation are usually
attached to one of them:

- `Model.delete()` on an instance runs an overridden `delete()` and sends
  `pre_delete`/`post_delete`.
- `QuerySet.delete()` **does** send `pre_delete` and `post_delete`, including
  for cascaded objects, but it does not call each instance's `delete()` method,
  so an override that sets a flag or deletes a file is skipped.
- The fast-delete path issues a single DELETE without loading instances. Django
  only takes it when the model has no delete-signal receivers, no cascading
  relations, and no parents, so it does not silently skip a signal that exists
  — registering a receiver disables it. It does mean a model whose cleanup
  lives only in an overridden `delete()` gets no cleanup at all.
- `_raw_delete()`, `cursor.execute()`, `TRUNCATE`, and database-level `ON
  DELETE CASCADE` bypass model methods and signals entirely.
- `QuerySet.update()`, `bulk_create()`, and `bulk_update()` skip `save()` and
  the save signals, which is how a field is scrubbed without the audit entry
  that was supposed to accompany it.

Cleanup attached to a signal or an override is therefore only as complete as
the set of paths that trigger it. Put erasure side effects in an explicit
service function called by every path, as `a09-logging-and-alerting.md`,
"Lifecycle hooks and audit guarantees" requires for audit events.

## Where a record survives

An erasure design is only as good as this inventory, because the failure is
always a location nobody listed. Enumerate for each personal-data model:

**The primary store and its shadows**

- the row itself, and any soft-delete tombstone of it;
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
  request bodies, and breadcrumbs, and log aggregation, where it arrives in
  structured log lines (`a09-logging-and-alerting.md`, "Scrub error reports"
  and "Don't log secrets");
- the email or messaging provider, which retains message bodies and
  suppression lists, and any support or CRM tool synchronized with the record;
- queue and event-stream payloads carrying a copy of the record;
- non-production databases seeded from production, and developer machines;
- artifacts already delivered to the subject or a third party — export
  archives, signed tokens, invoices.

Each entry needs an owner, a stated lifetime, and a leg in the fan-out below,
or an explicit statement that it is out of scope and why.

## Erasure as a fan-out with a completion ledger

Maps to CWE-212 and CWE-459; A01:2025 where a surviving copy is reachable.

### Principle layer

Treat an erasure request as a durable object with per-target state, not as a
function call. The request is recorded, each target is attempted
independently and idempotently, each attempt writes its outcome, and the
request is complete only when every target reports success. Anything that
cannot be deleted in place — backups, write-once storage, append-only streams —
gets the cryptographic route instead: the subject's fields are encrypted under
a key that is held only for that subject, and erasure destroys the key, leaving
ciphertext that is no longer readable. That mechanism depends entirely on key
isolation, since a shared key ring means destroying one key breaks every
subject, and on the destruction itself being auditable; the key management it
requires belongs with the encryption substrate in
`data-layer-and-database.md`, "Field-level encryption and searchable lookups".

For one erased subject, a reviewer should be able to answer which targets were
attempted, when each completed, and what remains — from stored state, not by
reading the task code.

### Django & DRF implementation layer

A ledger is two models and one task per target. The point of the second model
is that a partial failure is visible and retryable rather than swallowed by a
task that already returned:

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
    user = User.all_objects.get(erasure_key=erasure.subject_id)
    for field in ("avatar", "id_document"):
        stored = getattr(user, field)
        if stored:
            stored.delete(save=False)  # the row alone leaves the bytes behind
    user.delete()
```

Each target function must be safe to run twice, because retries are how a
distributed fan-out finishes: deleting an already-deleted search document,
invalidating an absent cache key, and calling a processor's deletion endpoint
for an unknown id all have to succeed rather than raise. Mark the target row
`DONE` in the same transaction as the work where the target is the database,
and immediately after the call where it is not.

Keep the subject reference opaque and separate from the user row
(`subject_id` above), so the ledger itself does not become the last surviving
copy of an email address. The ledger records that erasure happened, not who it
happened to in identifiable terms.

DRF endpoints that accept an erasure request need the same treatment as any
destructive endpoint: authorize the subject against the requester, re-
authenticate for an account-destroying action, throttle it, and log the acting
principal separately from the subject when an operator triggers it on someone's
behalf (`privileged-access-and-impersonation.md`).

## Stored files outlive their rows

Deleting a model instance does not delete the file its `FileField` points to.
Django removed the automatic file deletion in 1.3 because it caused data loss
on rolled-back transactions and shared files, and Django 6.0 still behaves this
way. Erasing a user therefore leaves the avatar, the uploaded identity
document, and every attachment in `MEDIA_ROOT` or the bucket, under paths that
are often guessable and served without an authorization check.

The guarantee comes from an explicit `FieldFile.delete(save=False)` — or a
storage-level delete for files not referenced by a field — inside the erasure
fan-out, where its success is recorded. Signal-based cleanup packages are a
convenience for ordinary deletes, not an erasure guarantee: they are bound to
model signals, so raw SQL, `_raw_delete()`, `TRUNCATE`, and database-level
cascades bypass them entirely, and file deletion has to be reconciled with
transaction rollback so a rolled-back delete does not destroy a live file.

Storage, naming, and authorized delivery of these files are in
`file-uploads.md`; this file owns only their disappearance.

## Anonymization and the reversibility test

Anonymization is sufficient in place of deletion when the result can no longer
be attributed to an individual, which is a property of the whole remaining
dataset rather than of the columns that were overwritten. Run five checks
against the post-anonymization row and everything that still references it:

1. **Does a stable join key survive?** A hash of an identifier is deterministic
   by construction, so the same input always yields the same token: it joins
   datasets and is brute-forceable over a small enumerable domain such as email
   addresses or phone numbers, including when the salt is stored beside it. If
   the token can be recomputed from the plaintext, it is pseudonymization.
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

# Correct: no derivable link back to the original identity, and the
# references that would re-identify the row are cleared in the same
# transaction as the values.
with transaction.atomic():
    user.email = f"erased-{uuid4().hex}@example.invalid"
    user.full_name = ""
    user.phone = ""
    user.date_of_birth = None
    user.save(update_fields=["email", "full_name", "phone", "date_of_birth"])
    user.comments.update(author_display_name="", body_search_vector=None)
```

If a stable key must survive for a legitimate reason — reconciling financial
records, for instance — that is a decision to retain personal data under a
stated basis and a retention period, not an anonymization. Say so in the code
and put the retained data in the inventory.

## Retention you can prove ran

Maps to CWE-459; A06:2025, since unenforced retention is a missing control
rather than a bug.

A reviewer can confirm retention only when four artifacts exist:

1. **The policy is expressed next to the model**, as an attribute or a small
   registry, so the rule is visible where the data is defined rather than
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
    ...


class Command(BaseCommand):
    def handle(self, *args, **options):
        cutoff = timezone.now() - SupportTicket.RETENTION
        deleted, _ = SupportTicket.objects.filter(closed_at__lt=cutoff).delete()
        # The run record is the artifact a reviewer checks; without it the
        # policy is unfalsifiable.
        RetentionRun.objects.create(
            model_label="support.SupportTicket",
            deleted_count=deleted,
            finished_at=timezone.now(),
        )
```

The anti-pattern to flag is a purge command that appears in no scheduler
configuration, timer unit, or crontab — a policy that exists only as an
unexecuted file. Check the scheduler's own record of the last successful run,
and confirm that a bulk `delete()` here is compatible with whatever cleanup the
model needs, since it does not call `Model.delete()`.

## Export and subject-access endpoints

Maps to CWE-200 and CWE-639; A01:2025 and API1:2023.

An export endpoint assembles everything the system holds about one subject into
a single downloadable artifact. That is a legitimate feature and simultaneously
the cleanest exfiltration path in the application, because a compromised
account can take everything in one authenticated request, and an operator
export on a user's behalf is a confused-deputy risk. The controls, each of
which a reviewer can check:

- **Two authorization decisions, not one.** Authorize the request (may this
  principal export this subject?) and authorize retrieval of the finished
  artifact (does this fetcher own this export?). Possession of a result URL is
  not authorization.
- **Throttle the job, not the request rate.** Exports are expensive and rare;
  bound them per principal per window rather than per second
  (`api-drf-specific.md`, "Throttling as quota, not security (API4)").
- **Signed-URL hygiene.** Short expiry, bound to the exact object, single-use
  where the storage supports it, and re-authenticated rather than treating the
  URL as the credential. Keep it out of `Referer` headers, access logs, and
  plaintext email.
- **The archive is itself a personal-data copy.** Private location, enforced
  expiry, and an entry in the inventory and the erasure fan-out. The delivery
  mechanism is the private-download primitive in `file-uploads.md`, "Private
  downloads".
- **Attribute operator-initiated exports.** Log the acting principal separately
  from the subject and constrain what an admin-initiated export may contain
  (`privileged-access-and-impersonation.md`).
- **Bound the contents deliberately.** An export that serializes every related
  model tends to include internal fields and other people's data in shared
  objects; define the field set explicitly, as `api-drf-specific.md`,
  "Serializer exposure and mass assignment (API3)" requires of any serialized
  response.

## Audit history against erasure

Security logging requires that events survive; erasure requires that personal
data does not. The resolution is to separate the identity from the event rather
than to choose between them, in this order of preference:

1. **Store the subject reference in a separate identity table** and keep the
   event row pointing at it. Erasure deletes or anonymizes the identity row and
   the event survives with a dangling or nulled reference: what happened is
   retained, who it happened to is gone.
2. **Pseudonymize the reference** in the event and destroy the mapping on
   erasure. This is the crypto-shredding pattern applied to a join key and
   carries the same key-isolation requirement.
3. **Retain a minimal defined subset** where a specific obligation requires it,
   segregated from the general audit store, with its own retention period and
   its own access control.

Model-history and versioning tables are the high-risk instance, because they
retain every prior value of every field — including values a subject later
asked to erase, and including the values that were overwritten by an
anonymization run. Any history table over a model with personal fields belongs
in the inventory, in the retention policy, and in the erasure fan-out.

`a09-logging-and-alerting.md` owns what must be logged and how logs are kept
tamper-evident; this file owns the fact that the audit store is itself a
retained copy of personal data that has to reconcile with erasure.

## Marking personal data in the model layer

Nothing above is auditable if nobody can enumerate which fields are personal.
Mark the classification where the field is defined — a small per-model
declaration listing the personal fields, the fields an export includes, and the
erasure action for each — so that a reviewer can grep for it and a management
command can walk the app registry and emit the inventory from the models
themselves.

```python
class Profile(models.Model):
    class Privacy:
        personal_fields = ("full_name", "phone", "date_of_birth")
        export_fields = ("full_name", "phone", "date_of_birth", "created_at")
        on_erasure = "anonymize"  # or "delete", or "retain" with a reason
```

A generated data map — every model, every field marked personal, every foreign
key into a model that has any — is the machine-checkable form of the inventory
above, and it is the artifact that makes a new model's missing classification
visible in review. Prefer twenty lines of local convention to a dependency: the
packaged options in this area are unmaintained, as recorded in
`security-hardening-libraries.md`, "Data lifecycle and privacy".

## Lower environments and the copies they inherit

A production dump loaded into staging, a demo environment, or a laptop
multiplies every personal-data copy into places with weaker access control, no
audit trail, and broad access — and those copies are invisible to the erasure
fan-out, so an erased subject still exists in last month's staging refresh.
`data-layer-and-database.md`, "Copies of production data" owns the rule; the
pipeline that satisfies it is:

- **Mask during extraction, never after loading.** If plaintext lands in the
  lower environment first, it was disclosed there regardless of what runs next.
- **Preserve referential integrity deterministically.** Mask join keys with a
  per-run secret so foreign keys still line up, and generate fake display
  values, so the environment is usable without holding real identities.
- **Subset rather than copy.** A referentially consistent slice of subjects and
  their related rows is smaller, faster, and a much smaller loss if it leaks.
- **Prefer synthetic data** where realistic-but-fake values suffice; it carries
  no re-identification risk precisely because it is not derived from anyone.
- **Treat the extract as an inventory entry** with a location, a lifetime, and
  an owner, like any other copy.

## Review checklist

### Stack-neutral

- [ ] Every personal-data model has an enumerated set of locations — primary
      row, history tables, files, caches, indexes, warehouse, third-party
      processors, backups — with an owner and a stated lifetime for each.
- [ ] Deletion is a fan-out with per-target completion state that a reviewer can
      read, not a single call whose partial failure is invisible.
- [ ] Stores that cannot delete in place are handled by destroying a
      per-subject key, not by asserting selective deletion from a backup.
- [ ] Logical deletion is used for undo, never reported as erasure, and every
      tombstone has a scheduled purge or anonymization.
- [ ] Any anonymization survives the reversibility test: no recomputable token,
      no re-identifying foreign keys, no singling-out quasi-identifiers, no
      fingerprinting timestamps, no identity left in free text.
- [ ] Retention exists as policy, scheduled job, per-run record, and an alert
      for a job that stops running.
- [ ] Export endpoints authorize the request and the artifact separately,
      throttle the job, expire the artifact, and log operator-initiated exports
      against the acting principal.
- [ ] The audit store retains the event without retaining the identity, and
      history tables are in the retention and erasure paths.
- [ ] Lower environments are masked or subsetted at extraction and are counted
      as copies.

### Django & DRF

- [ ] Soft-delete models keep a filtered default manager, an unfiltered
      `base_manager_name`, and a named unfiltered manager for admin and restore
      paths.
- [ ] Forward FK, reverse one-to-one, `select_related`, `refresh_from_db()`,
      raw SQL, and cursor paths are audited for tombstone leakage; nested DRF
      serializers are tested against a deleted related object.
- [ ] Unique constraints on soft-delete models are partial on the live
      condition, so tombstones neither block re-registration nor retain
      identifiers indefinitely.
- [ ] `ModelAdmin.get_queryset()` states its choice explicitly and surfaces the
      deleted state rather than hiding or silently exposing tombstones.
- [ ] Erasure of a `FileField` calls `FieldFile.delete(save=False)` or a
      storage delete inside the fan-out; signal-based cleanup is not treated as
      the guarantee.
- [ ] Cleanup does not depend only on an overridden `Model.delete()` or on
      delete signals, given `QuerySet.delete()`, `_raw_delete()`, `TRUNCATE`,
      and database-level cascades.
- [ ] Retention commands are wired into an actual schedule and write a run
      record; bulk `delete()` in them is checked against the cleanup the model
      needs.
- [ ] Personal fields are marked at the model layer so the inventory can be
      generated from the app registry rather than maintained by hand.
