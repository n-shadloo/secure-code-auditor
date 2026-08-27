# A09:2025 — Security Logging and Alerting Failures

Enough logging to detect and investigate, without logging the secrets and PII
that turn a log store into a second breach. Also covers lifecycle hooks whose
ordering or bypass can silently omit security events and side effects.

This file owns **what must be recorded and what must never be**. That scope is
the event set and the fields that may not appear in it. It also covers the
order guarantees that decide whether a record exists at all, and whether the
record stays valid afterwards as evidence.

This file does not own the failure that the record describes.
`a10-exceptional-conditions.md` owns fail-closed behavior and the concurrency
mechanics. `data-lifecycle-and-privacy.md` owns the log and the history table
as retained copies of personal data. `a05-injection.md` owns the forged log
line as a sink. `privileged-access-and-impersonation.md` owns the operator
identity an audit record has to carry.

## Contents
- [Principle](#principle)
- [Don't log secrets](#dont-log-secrets)
- [Scrub error reports](#scrub-error-reports)
- [Log the right security events](#log-the-right-security-events)
- [Lifecycle hooks and audit guarantees](#lifecycle-hooks-and-audit-guarantees)
- [Log injection and integrity](#log-injection-and-integrity)
- [Forensic readiness and evidence integrity](#forensic-readiness-and-evidence-integrity)
- [Decoy records and canary tokens](#decoy-records-and-canary-tokens)
- [Review checklist](#review-checklist)

## Principle

You cannot respond to an event that you do not see. A log that captures
credentials, tokens, or personal data becomes a liability of its own. The
principle is **record security-relevant events with enough context to
investigate, redact sensitive values, and make sure something actually watches
the logs**. A log with no alert is only a record that nobody reads. An alert
with no redaction moves the sensitive value into a second store.

## Don't log secrets

- Never log passwords, session/JWT tokens, `Authorization` headers, API keys,
  full card numbers (PAN), or more PII than you need. This is a frequent
  secondary-breach vector (CWE-532).
- The request path and the query string belong in that list. A password-reset
  link, a magic link, and a `?token=` parameter each carry a credential inside
  a URL. Warning: the proxy and the web server record the full request line for
  every request. Those stores sit above Django, so no `LOGGING` entry and no
  filter in the application reaches them. Strip the query string at that tier.
  Keep the credential out of the path. `a07-authentication-failures.md`, "API
  keys" holds the transport rule itself.
- Warning: request and response log middleware and third-party log shippers
  capture headers and bodies by default. Do not answer that with a field
  filter. A filter is a blocklist. It misses `passwd2`, a JWT inside a cookie
  value, and a field that the next release nests one level deeper. Turn header
  capture and body capture off. Then allow the few fields you need by name. The
  body of one login request defeats every blocklist you write.
- A secret that is already in a log store is an incident, not a cleanup task.
  The order is important: rotate first, and scrub last.
  `service-identity-and-secrets.md`, "Responding to a leaked secret" holds the
  full ordered response. If you purge the log lines while the credential still
  works, you invert that order. This inversion is common and costly.

## Scrub error reports

Django's error reports can include local variables and POST data. Redact them:

```python
from django.views.decorators.debug import sensitive_variables, sensitive_post_parameters

@sensitive_variables("password", "token")
def do_login(request, password, token):
    ...

@sensitive_post_parameters("password", "card_number")
def checkout(request):
    ...
```

The two decorators reach Django's own error reports and nothing else. The
`LOGGING` configuration, an APM agent, and an error SDK each need their own
scrub. Prove each one with a canary value that you look for in the rendered
output.

Warning: `sensitive_post_parameters` protects no DRF JSON endpoint. It marks
`request.POST`, and Django fills `request.POST` for a form body only. A JSON
body arrives in `request.data`, so the decorator marks an empty dictionary and
the report keeps the value. `rest_framework.request.Request` is also not an
`HttpRequest`. The decorator on a view method therefore raises `TypeError`, and
it raises the same error below `@api_view`. Signal: `sensitive_post_parameters`
in a file that holds a DRF view.

The value that a JSON body carried also stays in the local variables of the
frame that read it. Put `sensitive_variables` on that function. Scrub
`request.data` in the error SDK and in the APM agent. Then send the canary
through a real JSON request. Read every sink.

Configure `LOGGING` so that handlers do not persist sensitive fields. Set
`DEBUG = False` in production (A10), so that Django does not serve tracebacks
to users.

## Log the right security events

Record authentication successes and failures, lockouts, permission denials,
password and email changes, MFA changes, group and permission grants, and
admin actions. Record who acted, what they did, when they did it, and the
source IP. Derive the source IP correctly behind a proxy.

Django's admin does not satisfy the admin-action requirement on its own. It
writes a `LogEntry` row from the add form, the change form, the delete view,
and the built-in `delete_selected` action. A custom admin action writes none,
unless the code calls `log_change()` or `log_deletions()` itself. The row also
holds a change message rather than the old value and the new value. Signal: an
`@admin.action` function that writes to the database.

Django's auth signals and allauth's audit signals can help. But signals are not
a complete audit boundary; see lifecycle hooks below. Keep logs long enough to
investigate them. Forward them to a monitored store, with alerts on spikes such
as failed logins and 403 storms.

A spike rule detects the fast attack and no other kind. Add two rules beside
it. The first alerts on the single event that decides an incident on its own.
Those events are the first admin login from a new address, the first use of a
new API key, and a bulk export. The second alerts on silence. A source that
goes quiet looks the same as a quiet system. An attacker who stops the shipper
therefore produces no signal at all. Give each source an expected report
interval. Alert when a report does not arrive.

Warning: a threshold that a responder raises to stop noise is a permanent hole,
and an attacker can generate that noise on purpose. Rate-limit the source. Do
not raise the threshold.

Where a backend exposes tools to an agent, each invocation and each denial is a
security event of the same kind. The redaction rules above apply to the
arguments and to the results. See `agent-and-llm-interfaces.md`, "Tool-call
audit records".

## Lifecycle hooks and audit guarantees

Maps primarily to CWE-778 (Insufficient Logging), CWE-223 (Omission of
Security-Relevant Information), and, where the order creates a race, CWE-362.
Permission-changing omissions also map to A01:2025.

### Principle layer

Lifecycle callbacks are implicit control flow. A security invariant fails in
three conditions. One write path skips the callback. A callback runs before the
data is durable. A retry repeats an external side effect. The invariant is:
**every supported state-change path must enforce the security rule and record
its audit event in the same durable boundary. External effects occur only after
commit, and they are safe to retry.**

- Inventory all mutation paths: ordinary writes, bulk operations, direct
  queries, imports, admin tools, jobs, cascades, migrations, and raw database
  access. A callback attached to only one path is not a complete control.
- Keep authorization, validation, state transition, and the durable audit/outbox
  record explicit in one transaction or consistency boundary.
- Never let the state change commit without its audit record. Warning: a
  `try/except` that logs the failure and continues breaks this invariant, and
  the code still reads as if it holds. A failed audit write must roll the
  change back. "Do not break the business flow" is the instinct that produces
  the bug, and it is wrong for this write.
- Publish email, queue messages, cache invalidations, and remote calls only
  after commit. Give each event a stable idempotency key, so that retries do
  not duplicate grants, messages, or audit entries. This file owns the order
  and the outbox. `a10-exceptional-conditions.md`, "Idempotency" owns the key
  design itself.
- Pass actor, tenant, request/correlation id, reason, old state, and new state
  explicitly. Ambient request context is unreliable in jobs and concurrent
  execution.
- Use database constraints or controlled write APIs for invariants that must
  survive every application path. If the complete audit must include privileged
  raw SQL, enforce the rule at the database or platform boundary. If you cannot
  enforce it there, prohibit that bypass.

### Django & DRF implementation layer

Know which Django paths run which hooks:

- `bulk_create()` does not call each model's `save()` and does not send
  `pre_save` or `post_save`.
- `bulk_update()` and `QuerySet.update()` do not call `save()` and do not send
  save signals.
- `QuerySet.delete()` **does send** `pre_delete` and `post_delete` for deleted
  objects, cascades included. But it does not call the `delete()` method of
  each model instance. From Django 6.1 a `ForeignKey` declared with
  `DB_CASCADE` is the exception. The database performs that delete, so Django
  sends no signal for the rows it removes. `DB_SET_NULL` and `DB_SET_DEFAULT`
  skip collection the same way. An audit hook on a delete signal therefore
  records nothing for the far side of that relation. The diff that causes this
  is one keyword long. `data-lifecycle-and-privacy.md`, "Delete paths and what
  each one runs" owns the full path list.
- raw SQL bypasses model methods and ORM signals.
- many-to-many changes have their own `m2m_changed` signal and are not model
  save events. `user.groups.add(group)` gives the user every permission of that
  group, and it sends no save signal for the user. `user_permissions` behaves
  the same way. Both writes are permission grants, so both belong in the event
  set above and in the path test below. Signal: `.add()`, `.remove()`,
  `.set()`, or `.clear()` on `groups`, on `user_permissions`, or on a role
  relation.

Do not repeat the inaccurate claim that `QuerySet.delete()` skips delete
signals. Its distinct risk is that overridden `Model.delete()` methods do not
run, while raw SQL can skip both methods and signals.

Prefer an explicit service function for permission grants, revocations,
security notifications, and audit events:

```python
from functools import partial

from django.core.exceptions import PermissionDenied
from django.db import transaction


def change_membership_role(*, actor, membership_id, new_role, request_id):
    try:
        with transaction.atomic():
            membership = (
                Membership.objects.select_for_update()
                .select_related("tenant")
                .get(pk=membership_id)
            )
            if not membership.tenant.admins.filter(pk=actor.pk).exists():
                raise PermissionDenied

            old_role = membership.role
            membership.role = new_role
            membership.save(update_fields=["role"])

            event = SecurityEvent.objects.create(
                tenant=membership.tenant,
                actor=actor,
                action="membership.role_changed",
                object_id=str(membership.pk),
                old_value=old_role,
                new_value=new_role,
                request_id=request_id,
            )
            transaction.on_commit(
                partial(publish_security_event_once, event_id=event.pk),
            )
    except PermissionDenied:
        # The denial is a required event too, and this record has to survive
        # the rollback. A SecurityEvent row created before the raise above
        # dies with the block, so the refusal leaves no trace at all.
        record_role_change_denied(
            actor=actor,
            membership_id=membership_id,
            new_role=new_role,
            request_id=request_id,
        )
        raise
    return membership
```

The event set above requires permission denials, and this is where they get
lost. The rule: **a denial that a transactional service raises rolls back with
the transaction that denies it.** Write that record outside the transaction.
Signal: a `raise PermissionDenied` inside an `atomic()` block, with the audit
write in the same block. Without the branch above, a probe of the most
privileged endpoint leaves nothing, and the 403 storm alert has no input.

The database audit row commits with the change, on one database. Warning: a
bare `@transaction.atomic` opens on the default alias, and a bare
`transaction.on_commit()` registers on the default connection. A database
router that puts the audit model on another alias therefore breaks the shared
boundary, and no line of this code changes. The audit row then commits on its
own, and it survives a rollback of the change that it describes. Signal:
`DATABASE_ROUTERS` in the settings, beside an audit model. Name the alias in
`atomic(using=)` and in `on_commit(using=)`. Keep the audit model on the alias
of the model that it records.

For stronger delivery guarantees, add a transactional outbox row and let an
idempotent worker publish it. Keep the outbox table and the audit table
separate. The worker marks an outbox row published, so it needs `UPDATE` on
that table. The audit table below holds no `UPDATE` grant at all, so one table
for both makes the append-only rule impossible. Do not grant permissions or
send irreversible mail solely from `post_save`.

Signals stay reasonable for decoupled, non-authoritative reactions when you
understand every write path. If you keep one, obey these rules:

- register it in `AppConfig.ready()`, use `dispatch_uid`, and avoid duplicate
  imports;
- remember that Django holds receivers with weak references by default, unless
  you keep the receiver alive or connect it with `weak=False`;
- handle `raw=True` when Django loads a fixture, and use the supplied database
  alias;
- keep the receiver small and idempotent; and
- defer external work with `transaction.on_commit()`.

If you use the receiver below instead of the explicit `on_commit()`
registration in the service example, do not register the same publication in
both places.

```python
from functools import partial

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver


@receiver(
    post_save,
    sender=SecurityEvent,
    dispatch_uid="security.publish_security_event",
)
def publish_committed_event(sender, instance, created, raw, using, **kwargs):
    if not created or raw:
        return
    transaction.on_commit(
        partial(publish_security_event_once, event_id=instance.pk),
        using=using,
    )
```

A `post_save` receiver runs after the SQL statement, not after the surrounding
transaction commits. Without `on_commit()`, a message may escape for a change
that later rolls back. Also remember that a signal does not know the request
actor. If actor attribution is important, create the audit event in the
explicit service path.

Test the invariant through every supported path. These paths are serializer/API
service, model save, admin action, management command, job, bulk update/create,
many-to-many write, queryset delete, cascade, migration, and any approved raw
SQL. Prove that the path emits the required event, or make the path unavailable
for that model.

### Lifecycle review checklist

#### Stack-neutral

- [ ] Every state-change path enforces the same invariant and writes a durable,
      actor-attributed audit/outbox event in the same consistency boundary.
- [ ] External side effects occur only after commit and are idempotent under
      retries, duplicate delivery, rollback, and worker restart.
- [ ] Tests cover the bulk, import, admin, job, many-to-many, cascade,
  migration, and direct-database paths, or the project prohibits them
  explicitly.
- [ ] A denial is recorded outside the transaction that the denial rolls back.
- [ ] No handler lets a state change commit after its audit write failed.
- [ ] Each caller passes the security context explicitly; the boundary below
  any permitted bypass path enforces the complete audit requirements.

#### Django & DRF

- [ ] Security does not rely solely on `save()`, `delete()`, `post_save`, or
      `pre_delete` where bulk/queryset/raw paths can behave differently,
      database-level cascades on Django 6.1 included.
- [ ] Reviews distinguish correctly between `QuerySet.delete()` signals and
      overridden `Model.delete()` behavior.
- [ ] Critical transitions use explicit transactional services. For external
      work they use `transaction.on_commit()` where the order is enough, or a
      transactional outbox where the record is a guarantee. `on_commit` orders,
      and the outbox survives.
- [ ] Signal registration is single, durable, `raw`/database-aware, small, and
      idempotent; actor attribution does not depend on ambient request state.
- [ ] Where `DATABASE_ROUTERS` is set, the audit model resolves to the alias of
      the model it records, and `atomic()` and `on_commit()` name that alias.

## Log injection and integrity

A log line is an interpreter too. Every reader of the log treats the line as
the record boundary. These readers are a shipper, a SIEM query, and a person at
a terminal. A value that carries CR or LF splits one record into two, and the
attacker writes the second record. This gives a forged authentication success
beside the real failure, a fabricated admin action, or an entry that names
another user.

The attack is against the evidence rather than against the application, which
makes it easy to under-rate. Nothing in production breaks, and the incident
review afterwards reads a false record. Maps to CWE-117, and to CWE-93 for the
injected separator itself.

```python
# Wrong: the submitted username owns the rest of this line and the start of the
# next one, so it can append a whole record of its own.
import logging

logger = logging.getLogger(__name__)

logger.info("login failed for %s", request.POST["username"])
```

Lazy `%s` substitution is the right habit for other reasons, but it does not
help here. The formatter does the substitution, so the newline reaches the
output in both cases. Two fixes follow, in order of preference:

```python
# Correct: a structured record, where the username is a field rather than part
# of the line, and the encoder owns escaping for every field.
import logging

logger = logging.getLogger(__name__)

logger.info("login failed", extra={"username": username})
```

```python
# Correct: or neutralize separators before the value is formatted in. This
# escapes control characters as a class instead of stripping two of them.
import logging

logger = logging.getLogger(__name__)

safe_username = username.encode("unicode_escape").decode("ascii")
logger.info("login failed for %s", safe_username)
```

- Structured (JSON) logs are the durable answer. The encoder does the escape,
  so no call site has to remember it.
- Where lines stay plain text, escape the values in a `logging.Formatter`
  subclass rather than at every call site. One call site that you miss defeats
  the whole control, and that call site is usually in an exception handler.
- Escape control characters as a class, not `\r` and `\n` alone. Terminal
  escape sequences can rewrite what an operator sees in a live tail. Unicode
  line separators and paragraph separators split records for some parsers, even
  after you remove CR and LF. Put the Unicode format characters in the same
  class. A right-to-left override or a zero-width character forges the name
  that a person reads, and it splits no line at all.
- The escape stops the split, and it does not stop the forgery. A value shaped
  like `user=admin action=login_success` stays on one line, and a key-value
  parser in the SIEM reads it as fields. Those forged fields then replace the
  real ones for a detection rule and for an investigator's query. This is the
  reason the structured record comes first above. There the field boundary is
  the encoder, and not a convention inside the text.
- Sanitize the values that the request supplied and the values that you read
  back from storage equally. A username that the database holds with a newline
  forges a line the first time that any code logs it.
- Protect integrity and retention. Ship logs to a store the application's own
  credentials cannot rewrite, so the record survives the compromise it
  documents. A local file between the process and that store is inside the
  compromise. The application user can rewrite the buffer before the shipper
  reads it, and the store then keeps the edited version faithfully. Send to the
  collector directly, or give the buffer to a user that the application cannot
  write as. Personal data in that store is a retained copy with a lifetime —
  see `data-lifecycle-and-privacy.md`.

**Write-time.** When you generate a log call or an audit call, pass the values
as structured fields through `extra=`. Do not interpolate them into the
message. This hands the escape to the encoder once instead of to every call
site forever. The call site that you miss is the one in an exception handler.
`extra=` populates the `LogRecord`, and the configured formatter decides what
it renders. Name the JSON formatter that the pipeline uses, and test its
output.

Decide at that same call what may appear in the record. Use identifiers rather
than objects, and write no password, no token, no `Authorization` header, and
no personal data. A redaction filter that you add afterwards covers only the
shipper that somebody remembered to configure. Where the lines of the project
stay plain text, put the control-character escape in a `logging.Formatter`
subclass in the same change. The rule then also holds for the calls that nobody
has written yet.

`a05-injection.md`, "Tracing input to a sink" holds every other interpreter
that a request can reach, and the method to trace a source to one.

## Forensic readiness and evidence integrity

Maps to CWE-778 and CWE-223 where the record is missing, and to CWE-345
where what survives cannot be trusted to be what was written.

### Principle layer

Two questions decide whether a log store is evidence. The first is whether you
can prove what happened after an incident. The second is whether you can prove
that nobody changed the record afterwards. Most projects can answer neither
question, and they learn this in the week when the cost is highest.

**Append-only sinks.** A store that the application can delete from is not
evidence. The credential that writes the record is the credential that an
intruder holds after they compromise the application. Separate the write
identity from the delete identity. The writing principal appends records and
holds no delete grant and no update grant, and removal happens under a
different principal on a different schedule. This is the requirement stated
above for shipped logs, applied to the audit table that a project keeps in its
own database. The control is usually missing there, because the ORM writes the
table with the same role that serves requests. A second principal is real only
when the application cannot reach its credential. A retention password in the
environment that the web process reads gives one principal two names.

**Sequence integrity.** A hash chain over audit records makes an alteration
detectable. Each row carries a digest of its own fields and of the digest of
the previous row. A signed, monotonically increasing sequence number does the
same. State precisely what this control gives, because projects routinely
oversell it. It proves that nobody modified a record that is present in the
chain. It also proves that nobody removed a record from the middle without a
break in every link after it. It does not prove that a record for a given event
ever existed.

An event that never reached the sink leaves a chain that verifies perfectly. A
chain is evidence of integrity and never evidence of completeness.

The chain does not prove that a record inside it describes a real event. The
writing principal holds `INSERT`, so it can append a false record with a
correct digest. The chain then verifies because the record is well formed, and
not because the event happened.

Removal from the end is the same gap in the other direction. Removal from the
middle breaks every later link, and removal of the last rows breaks nothing at
all. Only a published head digest detects that removal. The publication
interval is therefore the length of the window that an attacker gets.

The chain also proves nothing against a principal who can recompute it. A
principal who can rewrite a row can also rewrite the digests after it. The
chain therefore binds only an attacker who is weaker than the writer. To close
that gap, put one element outside the reach of that attacker. Publish the head
digest periodically to a store that the application cannot rewrite. As the
alternative, compute the digest as a MAC under a key that the writing process
does not hold. Without one of these two measures, report the chain as a control
against accidental and after-the-fact edits rather than against a compromised
application.

**Clock discipline.** To correlate the web tier, the worker tier, and the
database, you need one time source and one recorded zone. A tier that drifts
produces a reconstruction in which effects precede causes. Nothing in the
record separates drift from a real order. For a record in the chain below, the
`sequence` column is the order evidence, and the timestamp is one clock's
assertion. Read the sequence where the two disagree. The same disagreement
decides whether a service accepts a credential.
`service-identity-and-secrets.md`, "Validating an inbound machine token" holds
the skew tolerance that an `exp`/`nbf` check allows.

**Correlation identity.** One request identifier turns three logs into one
narrative. The edge mints that identifier, and the view, the task, and the
outbound call propagate it. The edge must replace a client-supplied
`X-Request-ID` with its own value. The service above already takes `request_id`
as an explicit argument. That value must be the same across the tiers rather
than one value per tier.

**Record the decision, not only the event.** The line "user opened record 41"
is weaker than a line that names four facts. These facts are which principal
acted, which permission the code consulted, which object it resolved to, and
what the outcome was. The first line says that a request happened. The second
line says whether the authorization system did its job. An incident asks the
second question.

**Record the state at the time.** An audit row that points at a mutable row
proves nothing about what the actor saw. The target changed afterwards,
possibly during the incident that you now investigate. Capture the values that
the decision used, or a digest of them, in the record itself.

**Who may delete a log.** Name the principal, and review that grant on the same
cadence as any other privileged permission
(`privileged-access-and-impersonation.md`). A retention job that deletes audit
rows on a schedule is legitimate. An attacker prefers that path to a manual
delete. The runs of the job therefore belong in the record that it prunes.

A retention obligation and an erasure obligation land on the same record, and
that conflict is real rather than a drafting error. The resolution is to
separate the identity from the event instead of a choice between the two.
`data-lifecycle-and-privacy.md`, "Audit history against erasure" sets that
resolution out as an ordered set of patterns. Take it from there. This file
does not restate it, and it offers no legal reading of which obligation wins.

The chain gives that resolution one more reason. Keep the subject identity out
of the chained payload. A redaction inside a chained record breaks every link
after it, and it breaks them permanently. An erasure request is a normal reason
to redact, so the verification then reports a tamper forever. A real break
hides inside that expected one.

### Django & DRF implementation layer

By default, the database role of the application can delete the audit table
that a project writes through the ORM. That default is the whole problem in one
sentence. Grant that role `INSERT` and `SELECT` on the audit table and nothing
further. Put deletion under the separate role that the retention job uses.
`data-layer-and-database.md` owns role separation and the grants themselves.

A chain is a small model plus one serialized append:

```python
# Correct: each row commits carrying the digest of its own fields and of the
# row before it, so an edit to any row breaks every link after it. The lock
# serializes appends -- without it two writers read the same predecessor and
# the chain forks, which verifies later as tampering that never happened.
import hashlib
import json

from django.db import models, transaction
from django.utils import timezone


class AuditRecord(models.Model):
    sequence = models.PositiveBigIntegerField(unique=True)
    recorded_at = models.DateTimeField()
    payload = models.JSONField()
    previous_digest = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)


@transaction.atomic
def append_audit_record(payload):
    previous = (
        AuditRecord.objects.select_for_update().order_by("-sequence").first()
    )
    sequence = previous.sequence + 1 if previous else 1
    previous_digest = previous.digest if previous else "0" * 64
    recorded_at = timezone.now()
    body = json.dumps(
        {
            "sequence": sequence,
            "recorded_at": recorded_at.isoformat(),
            "payload": payload,
            "previous_digest": previous_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return AuditRecord.objects.create(
        sequence=sequence,
        recorded_at=recorded_at,
        payload=payload,
        previous_digest=previous_digest,
        digest=hashlib.sha256(body.encode()).hexdigest(),
    )
```

The lock is not incidental, and the `unique=True` on `sequence` covers the case
that the lock cannot. An empty table has no row to lock, so the constraint is
the backstop for the first two concurrent appends. Serial appends are a
throughput cost that you pay deliberately. That cost is the reason a chain
belongs on security events rather than on request logs.
`a10-exceptional-conditions.md`, "Races, TOCTOU, and adversarial sequencing"
owns the concurrency mechanics.

`allow_nan=False` is not decoration either. By default `json.dumps` writes
`NaN` and `Infinity`, and neither one is valid JSON. A request body that
carries `1e999` parses to a float that Python accepts and a strict parser in
another language rejects. One such row makes the chain unreadable from that
point. Fail the append instead.

This model is not a second audit system beside the `SecurityEvent` rows above.
Put the chain fields on the model that already holds the security events, and
let the service function call the append instead of `create()`. Route every
event that the event set requires through that one path, inside the transaction
that makes the change. A chain over the rows that one engineer remembered to
append protects nothing that an incident asks about.

Make the append the only writer of the table. A fixture, a `RunPython`
migration, or a management command that inserts rows directly computes no
digest. Such a write forks the chain, and the next verification reports a
tamper that nobody did.

A chain that nobody verifies detects nothing. Run the verification on a
schedule. Alert on a broken link, and alert on a head digest that no job
published. Report a chain with no verification job as an absent control.

Keep `USE_TZ = True`, so that Django stores instants in UTC. The zone is then a
presentation concern rather than a property of the row. Propagate the request
id into the worker as an explicit task argument rather than generate a new one
there. The lifecycle section gives the same reason for the actor and the
tenant: ambient context does not survive the hop.

**Write-time.** When you generate an audit record, write the principal, the
permission the code consulted, the object, the outcome, and the values the
decision read. Do not write the action name alone. An investigator needs the
fields that nobody thinks to add while the code still makes sense to its
author. Pass the request id in as an argument in the same edit. Where the
project keeps its audit rows in the application database, say in the review
that the writing role also holds `DELETE` on that table. Say this unless you
have seen the grant that says otherwise.

## Decoy records and canary tokens

### Principle layer

A decoy is a record, a credential, a file, or a route with no legitimate
reader. Nothing in the product reaches it, so any read is a signal. Keep the
claim that size. A decoy is a detection control, and it detects a reader who is
already inside. It never replaces the access control that should have stopped
them. A review that finds a decoy in the place of authorization has found the
authorization finding instead.

The value is signal quality. Most detection rules fire on behavior that also
has innocent explanations. Such a rule therefore arrives with a triage cost,
and finally with a threshold that someone raised to stop the noise. A decoy has
no innocent reader by construction, so its alert carries almost no false
positive rate. Nobody argues with such an alert, and somebody therefore acts on
it at once. That is the whole argument for the control, and it is enough.

These placements work: a decoy user row, a decoy API key in a configuration
store, and a decoy object in a storage bucket. A decoy row inside a real tenant
and a decoy route with the shape of an operational endpoint also work. The
decoy row inside a real tenant is the one that catches cross-tenant reads
specifically.

Three failure modes follow. Each one has been the reason that a project
abandoned a deployment:

- A decoy that a legitimate query path touches produces noise, and an operator
  mutes a noisy alert. The decoy then stays in place with the appearance of a
  control, but it detects nothing. That result is worse than no decoy at all.
- An export, a backup, an analytics job, or an erasure fan-out can touch a
  decoy. That job then either breaks, or carries the decoy to a place where it
  becomes visible. The fan-out is the most severe case, because
  `data-lifecycle-and-privacy.md`, "Where a record survives" is precisely the
  list of jobs that a decoy row meets.
- An undocumented decoy sends a responder after it during a real incident. That
  responder spends the hours that the control was bought to save.

One rule prevents all three failures. Register every decoy in one place, with
an owner, an expected reader set, and an alert route. A decoy that nobody can
find in that register is a liability rather than a control.

The expected reader set is empty for most placements. It is not empty for the
decoy row inside a real tenant. The admins of that tenant read it, and so do
the list endpoints of that tenant. State the signal for that placement
precisely: a read by a principal outside the tenant. A reader count of zero on
that row fires the alert on the tenant's own traffic, and the mute in the first
failure above then closes it.

### Django & DRF implementation layer

Mark a decoy row with an explicit field rather than hide it behind a filtered
default manager. A hidden row disappears from the query paths where you want it
visible, which are the paths an intruder uses. The paths that must skip it are
the batch jobs. A filtered manager also does not govern every relation
traversal (`data-lifecycle-and-privacy.md`, "Soft delete and what it does not
hide" holds that traversal table). Filter on the flag explicitly in each job,
and let ordinary read paths see the row.

A decoy credential signals only if the code that rejects it can separate it
from the invalid values that it rejects all day. Recognize the canary in the
authentication path, and alert on the attempt. A verifier that returns the same
failure it returns for a typo has placed a decoy that nothing watches. A decoy
route belongs in the endpoint inventory for the same reason. Without that
entry, the next review reports it as an undocumented endpoint
(`api-drf-specific.md`, "Endpoint inventory (API9)").

Warning: a decoy credential must authenticate nothing. A decoy that a copy of
the real provisioning path mints is a live credential with no owner, which is a
backdoor rather than a control. Prove with a test that the value fails every
real authorization check. Give the caller the same failure that any other
invalid credential gets, and raise the alert off the response path. A different
status, a different message, or a slower answer tells an attacker which values
to avoid.

**Write-time.** When you generate a decoy, write its register entry in the same
change. That entry holds the owner, the placement, the expected reader set,
and the alert route. The register and its alert route are security-relevant
records, so a change to either one is an event in the set above. A responder
who finds an unregistered decoy cannot separate it from a real record, and
neither can the job that breaks on it. Add
the exclusion to the batch paths in that same change, rather than wait for the
first false alert to identify them for you.

## Review checklist

- [ ] No passwords/tokens/`Authorization`/PANs/excess PII in logs or log
      middleware.
- [ ] `sensitive_variables`/`sensitive_post_parameters` on auth/payment paths.
- [ ] Auth, authz-denial, and admin events logged with source IP, admin actions
  covered beyond Django's own `LogEntry`; logs monitored, with alerts on
  volume, on the single decisive event, and on the silence of a source.
- [ ] Security-relevant lifecycle events cover save, bulk, many-to-many,
      delete, admin, job, migration, and approved raw paths; effects occur
      after commit and are idempotent.
- [ ] User input that reaches a log line has control characters escaped as a
      class, or appears as a structured field. A formatter does that escape
      rather than each call site. Logs ship to a tamper-resistant store.
- [ ] Personal data that reaches logs, error reports, and history tables counts
      as a retained copy with a stated lifetime. The audit store retains the
      event without the identity (`data-lifecycle-and-privacy.md`).
- [ ] The audit sink is append-only for the writing principal, and deletion
      sits under a separate identity whose credential the application cannot
      reach. The review reports what any integrity chain proves — not
      completeness, not a record it holds, not a removal at the end, and not
      resistance to a principal who can recompute it. A scheduled job verifies
      the chain and publishes the head digest.
- [ ] Records name the principal, the permission, the object, the outcome, and
      the state read. One request id crosses the web, worker, and database
      tiers against a single time source.
- [ ] Any decoy has a register entry with an owner, an expected reader set, and
      an alert route. A decoy credential authenticates nothing. It stays
      excluded from export, backup, analytics, and erasure paths, and it does
      not replace an access control.
