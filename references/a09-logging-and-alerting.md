# A09:2025 — Security Logging and Alerting Failures

Enough logging to detect and investigate, without logging the secrets and PII
that turn a log store into a second breach. Also covers lifecycle hooks whose
ordering or bypass can silently omit security events and side effects.

This file owns **what must be recorded and what must never be** — the event
set, the fields that may not appear in it, the ordering guarantees that
decide whether a record exists at all, and whether the record holds up
afterwards as evidence. It does not own the failure being
recorded: `a10-exceptional-conditions.md` owns fail-closed behavior and the
concurrency mechanics, `data-lifecycle-and-privacy.md` owns the log and the
history table as retained copies of personal data, `a05-injection.md` owns the
forged log line as a sink, and `privileged-access-and-impersonation.md` owns
the operator identity an audit record has to carry.

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

You can't respond to what you can't see, but logs that capture credentials,
tokens, or personal data become a liability of their own. The principle is
**record security-relevant events with enough context to investigate, redact
sensitive values, and make sure something actually watches the logs**. Logging
without alerting is a diary; alerting without redaction is a leak.

## Don't log secrets

- Never log passwords, session/JWT tokens, `Authorization` headers, API keys,
  full card numbers (PAN), or more PII than you need. This is a frequent
  secondary-breach vector (CWE-532).
- Be careful with request/response logging middleware and third-party log
  shippers — they capture headers and bodies by default; filter them.
- A secret already written to a log store is an incident rather than a cleanup
  task, and the order matters: rotate first, scrub last. The full ordered
  response is in `service-identity-and-secrets.md`, "Responding to a leaked
  secret"; purging the log lines while the credential still works is the
  common and costly inversion.

## Scrub error reports

Django's error reporting can include local variables and POST data. Redact them:

```python
from django.views.decorators.debug import sensitive_variables, sensitive_post_parameters

@sensitive_variables("password", "token")
def do_login(request, password, token):
    ...

@sensitive_post_parameters("password", "card_number")
def checkout(request):
    ...
```

Configure `LOGGING` so handlers don't persist sensitive fields, and ensure
`DEBUG = False` in production (A10) so tracebacks aren't served to users.

## Log the right security events

Record authentication successes/failures, lockouts, permission denials,
password/email changes, MFA changes, and admin actions — with who, what, when,
and source IP (derived correctly behind a proxy). Django's auth signals and
allauth's audit signals can help, but signals are not a complete audit boundary;
see lifecycle hooks below. Keep logs long enough to investigate, and forward
them somewhere monitored with alerts on spikes (failed logins, 403 storms).

Where a backend exposes tools to an agent, each invocation and each denial is a
security event of the same kind, with the redaction rules above applying to
arguments and results; see `agent-and-llm-interfaces.md`, "Tool-call audit
records".

## Lifecycle hooks and audit guarantees

Maps primarily to CWE-778 (Insufficient Logging), CWE-223 (Omission of
Security-Relevant Information), and, where ordering creates a race, CWE-362.
Permission-changing omissions also map to A01:2025.

### Principle layer

Lifecycle callbacks are implicit control flow. A security invariant fails when
one write path skips the callback, a callback runs before the data is durable,
or a retry repeats an external side effect. The invariant is: **every supported
state-change path must enforce the security rule and record its audit event in
the same durable boundary, while external effects occur only after commit and
are safe to retry.**

- Inventory all mutation paths: ordinary writes, bulk operations, direct
  queries, imports, admin tools, jobs, cascades, migrations, and raw database
  access. A callback attached to only one path is not a complete control.
- Keep authorization, validation, state transition, and the durable audit/outbox
  record explicit in one transaction or consistency boundary.
- Publish email, queue messages, cache invalidations, and remote calls only
  after commit. Give each event a stable idempotency key so retries do not
  duplicate grants, messages, or audit entries; this file owns the ordering and
  the outbox, while the key design itself is in
  `a10-exceptional-conditions.md`, "Idempotency".
- Pass actor, tenant, request/correlation id, reason, old state, and new state
  explicitly. Ambient request context is unreliable in jobs and concurrent
  execution.
- Use database constraints or controlled write APIs for invariants that must
  survive every application path. If complete auditing includes privileged raw
  SQL, enforce it at the database/platform boundary or prohibit that bypass.

### Django & DRF implementation layer

Know which Django paths run which hooks:

- `bulk_create()` does not call each model's `save()` and does not send
  `pre_save` or `post_save`.
- `bulk_update()` and `QuerySet.update()` do not call `save()` and do not send
  save signals.
- `QuerySet.delete()` **does send** `pre_delete` and `post_delete` for deleted
  objects, including cascades, but it does not call each model instance's
  `delete()` method.
- raw SQL bypasses model methods and ORM signals.
- many-to-many changes have their own `m2m_changed` signal and are not model
  save events.

Do not repeat the inaccurate claim that `QuerySet.delete()` skips delete
signals. Its distinct risk is that overridden `Model.delete()` methods do not
run, while raw SQL can skip both methods and signals.

Prefer an explicit service function for permission grants, revocations,
security notifications, and audit events:

```python
from functools import partial

from django.core.exceptions import PermissionDenied
from django.db import transaction


@transaction.atomic
def change_membership_role(*, actor, membership_id, new_role, request_id):
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
    return membership
```

The database audit row commits with the change. For stronger delivery
guarantees, make it a transactional outbox row and let an idempotent worker
publish it. Do not grant permissions or send irreversible mail solely from
`post_save`.

Signals remain reasonable for decoupled, non-authoritative reactions when every
write path is understood. If one is retained:

- register it in `AppConfig.ready()`, use `dispatch_uid`, and avoid duplicate
  imports;
- remember receivers are weak-referenced by default unless kept alive or
  connected with `weak=False`;
- handle `raw=True` during fixture loading and use the provided database alias;
- keep the receiver small and idempotent; and
- defer external work with `transaction.on_commit()`.

If the receiver below is used instead of the explicit `on_commit()` registration
in the service example, do not register the same publication in both places.

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
that later rolls back. Also remember that a signal does not naturally know the
request actor; if actor attribution matters, create the audit event in the
explicit service path.

Test the invariant through every supported path: serializer/API service, model
save, admin action, management command, job, bulk update/create, queryset
delete, cascade, migration, and any approved raw SQL. Either prove the path
emits the required event or make the path unavailable for that model.

### Lifecycle review checklist

#### Stack-neutral

- [ ] Every state-change path enforces the same invariant and writes a durable,
      actor-attributed audit/outbox event in the same consistency boundary.
- [ ] External side effects occur only after commit and are idempotent under
      retries, duplicate delivery, rollback, and worker restart.
- [ ] Bulk, import, admin, job, cascade, migration, and direct-database paths are
      tested or explicitly prohibited.
- [ ] Security context is passed explicitly; complete audit requirements are
      enforced below any permitted bypass path.

#### Django & DRF

- [ ] Security does not rely solely on `save()`, `delete()`, `post_save`, or
      `pre_delete` where bulk/queryset/raw paths can behave differently.
- [ ] Reviews distinguish correctly between `QuerySet.delete()` signals and
      overridden `Model.delete()` behavior.
- [ ] Critical transitions use explicit transactional services and
      `transaction.on_commit()` or a transactional outbox for external work.
- [ ] Signal registration is single, durable, `raw`/database-aware, small, and
      idempotent; actor attribution does not depend on ambient request state.

## Log injection and integrity

A log line is an interpreter too. Whatever reads the log — a shipper, a SIEM
query, a person in a terminal — treats the line as the record boundary, so a
value carrying CR or LF splits one record into two and the second record is
whatever the attacker wrote. That buys a forged authentication success beside
the real failure, a fabricated admin action, or an entry attributed to another
user. It is an attack on the evidence rather than on the application, which is
what makes it easy to under-rate: nothing in production breaks, and the
incident review afterwards is reading fiction. Maps to CWE-117, and to CWE-93
for the injected separator itself.

```python
# Wrong: the submitted username owns the rest of this line and the start of the
# next one, so it can append a whole record of its own.
import logging

logger = logging.getLogger(__name__)

logger.info("login failed for %s", request.POST["username"])
```

Lazy `%s` formatting is the right habit for other reasons and does not help
here: the substitution happens inside the formatter, so the newline reaches the
output either way. Two fixes, in order of preference:

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

- Structured (JSON) logging is the durable answer, because escaping stops being
  a thing each call site has to remember.
- Where lines stay plain text, do the escaping in a `logging.Formatter`
  subclass rather than at every call site. One missed call site is the whole
  control, and the missed one is usually in an exception handler.
- Escape control characters as a class, not `\r` and `\n` alone. Terminal
  escape sequences can rewrite what an operator sees in a live tail, and
  Unicode line
  and paragraph separators split records for some parsers even after CR and LF
  are gone.
- Sanitize values the request supplied and values read back from storage
  equally: a username saved with a newline last week forges a line the first
  time anything logs it.
- Protect integrity and retention. Ship logs to a store the application's own
  credentials cannot rewrite, so the record survives the compromise it
  documents. Personal data in that store is a retained copy with a lifetime —
  see `data-lifecycle-and-privacy.md`.

**Write-time.** When generating a log or an audit call, pass the values as
structured fields through `extra=` rather than interpolating them into the
message, because that hands escaping to the encoder once instead of to every
call site forever, and the call site that gets missed is the one in an
exception handler. Decide at that same call what may appear in the record —
identifiers rather than objects, and no password, token, `Authorization`
header, or personal data — because a redaction filter added afterwards covers
only the shipper somebody remembered to configure. Where the project's lines
stay plain text, put the control-character escaping in a `logging.Formatter`
subclass in the same change, so the rule also holds for the calls nobody has
written yet.

Every other interpreter a request can reach, and the method for tracing a
source to one, is in `a05-injection.md`, "Tracing input to a sink".

## Forensic readiness and evidence integrity

Maps to CWE-778 and CWE-223 where the record is missing, and to CWE-345
where what survives cannot be trusted to be what was written.

### Principle layer

Two questions decide whether a log store is evidence: after an incident, can
you prove what happened, and can you prove the record was not changed
afterwards. Most projects can answer neither, and find that out in the week
they can least afford to.

**Append-only sinks.** A store the application can delete from is not
evidence, because the credential that writes the record is the credential an
intruder holds once the application is compromised. Separate the write
identity from the delete identity: the writing principal appends and holds no
delete or update grant, and removal happens under a different principal on a
different schedule. This is the requirement stated above for shipped logs,
applied to the audit table a project keeps in its own database — where it is
usually missing, because the ORM writes it with the same role that serves
requests.

**Sequence integrity.** A hash chain over audit records — each row carrying a
digest of its own fields and of the previous row's digest — or a signed,
monotonically increasing sequence number makes alteration detectable. State
what that buys precisely, because it is routinely oversold. It proves that a
record present in the chain was not modified after it was written, and that
nothing was removed from the middle without breaking every link after it. It
does not prove that any particular record was ever written: an event that
never reached the sink leaves a chain that verifies perfectly. A chain is
evidence of integrity and never evidence of completeness.

It also proves nothing against a principal who can recompute it. Whoever can
rewrite a row can rewrite the digests after it, so the chain only binds an
attacker weaker than the writer. What closes that gap is putting something
outside their reach: publish the head digest periodically to a store the
application cannot rewrite, or compute the digest as a MAC under a key the
writing process does not hold. Without one of those, report the chain as a
control against accidental and after-the-fact edits rather than against a
compromised application.

**Clock discipline.** Correlating the web tier, the worker tier, and the
database needs one time source and one recorded zone. A tier that drifts
produces a reconstruction in which effects precede causes, and nothing in the
record distinguishes drift from a real ordering. The same disagreement
decides whether a credential is accepted — the skew tolerance an `exp`/`nbf`
check allows is in `service-identity-and-secrets.md`, "Validating an inbound
machine token".

**Correlation identity.** One request identifier, minted at the edge and
propagated through the view, the task, and the outbound call, is what turns
three logs into one narrative. The service above already takes `request_id`
as an explicit argument; the point here is that it must be the same value
across tiers rather than one generated per tier.

**Record the decision, not only the event.** "user opened record 41" is
weaker than a line naming which principal acted, which permission was
consulted, which object it resolved to, and what the outcome was. The first
says a request happened. The second says whether the authorization system did
its job, which is the question an incident actually asks.

**Record the state at the time.** An audit row that points at a mutable row
proves nothing about what the actor saw, because the target changed
afterwards — possibly during the incident being investigated. Capture the
values the decision was made on, or a digest of them, in the record itself.

**Who may delete a log.** Name the principal and review that grant on the
cadence any other privileged permission gets
(`privileged-access-and-impersonation.md`). A retention job deleting audit
rows on schedule is legitimate and is exactly the path an attacker would
rather use than a manual delete, so the job's own runs belong in the record
it prunes.

A retention obligation and an erasure obligation land on the same record, and
that conflict is real rather than a drafting error. The resolution is to
separate the identity from the event instead of choosing between them, which
`data-lifecycle-and-privacy.md`, "Audit history against erasure" sets out as
an ordered set of patterns. Take it from there; this file neither restates it
nor offers a legal reading of which obligation wins.

### Django & DRF implementation layer

The audit table a project writes through the ORM is deletable by the
application's own database role by default, which is the whole problem in one
sentence. Grant that role `INSERT` and `SELECT` on the audit table and
nothing further, and put deletion under the separate role the retention job
uses; role separation and the grants themselves are
`data-layer-and-database.md`'s.

A chain is a small model plus one serialized append:

```python
# Correct: each row commits carrying the digest of its own fields and of the
# row before it, so an edit to any row breaks every link after it. The lock
# serializes appends -- without it two writers read the same predecessor and
# the chain forks, which verifies later as tampering that never happened.
import hashlib
import json

from django.db import models, transaction


class AuditRecord(models.Model):
    sequence = models.PositiveBigIntegerField(unique=True)
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
    body = json.dumps(
        {
            "sequence": sequence,
            "payload": payload,
            "previous_digest": previous_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return AuditRecord.objects.create(
        sequence=sequence,
        payload=payload,
        previous_digest=previous_digest,
        digest=hashlib.sha256(body.encode()).hexdigest(),
    )
```

The lock is not incidental, and the `unique=True` on `sequence` is what
covers the case the lock cannot: an empty table has no row to lock, so the
constraint is the backstop for the first two concurrent appends. Serializing
appends is a throughput cost paid deliberately, and it is the reason a chain
belongs on security events rather than on request logs. The concurrency
mechanics are `a10-exceptional-conditions.md`, "Races, TOCTOU, and
adversarial sequencing".

Keep `USE_TZ = True` so stored instants are UTC and the zone is a
presentation concern rather than a property of the row. Propagate the request
id into the worker as an explicit task argument rather than regenerating one
there, on the same reasoning the lifecycle section gives for passing actor
and tenant explicitly: ambient context does not survive the hop.

**Write-time.** When generating an audit record, write the principal, the
permission consulted, the object, the outcome, and the values the decision
read — not just the action name — because the fields an investigator needs
are the ones nobody thinks to add while the code still makes sense to its
author. Pass the request id in as an argument in the same edit, and where the
project keeps its audit rows in the application database, say in the review
that the writing role also holds `DELETE` on that table unless you have seen
the grant that says otherwise.

## Decoy records and canary tokens

### Principle layer

A decoy is a record, a credential, a file, or a route with no legitimate
reader. Nothing in the product reaches it, so any read is a signal. Keep the
claim that size: it is a detection control, it detects a reader who is
already inside, and it is never a substitute for the access control that
should have stopped them. A review that finds decoys standing in for
authorization has found the authorization finding instead.

The value is signal quality. Most detection rules fire on behavior that also
has innocent explanations, so they arrive with a triage cost and eventually
with a threshold someone raised to stop the noise. A decoy has no innocent
reader by construction, so its alert carries almost no false positive rate,
and an alert nobody argues with is one somebody acts on at three in the
morning. That is the whole argument for the control, and it is enough.

Placements that work: a decoy user row, a decoy API key in a configuration
store, a decoy object in a storage bucket, a decoy row inside a real tenant —
which is the one that catches cross-tenant reads specifically — and a decoy
route shaped like an operational endpoint.

Three failure modes, each of which has been the reason a deployment was
abandoned:

- A decoy that a legitimate query path touches produces noise, and a noisy
  alert gets muted. The decoy then stays in place looking like a control
  while detecting nothing, which is worse than never having placed it.
- A decoy that an export, a backup, an analytics job, or an erasure fan-out
  touches either breaks that job or carries the decoy somewhere it becomes
  visible. The fan-out is the sharpest case, because
  `data-lifecycle-and-privacy.md`, "Where a record survives" is precisely the
  list of jobs a decoy row will meet.
- An undocumented decoy sends a responder chasing it during a real incident,
  spending the hours the control was bought to save.

One rule prevents all three: register every decoy in one place, with an
owner, an expected reader count of zero, and an alert route. A decoy nobody
can look up is a liability rather than a control.

### Django & DRF implementation layer

Mark a decoy row with an explicit field rather than hiding it behind a
filtered default manager. Hiding it removes it from the query paths you
wanted it visible to — the ones an intruder uses — while the paths that must
skip it are the batch jobs, and a filtered manager does not govern every
relation traversal anyway (`data-lifecycle-and-privacy.md`, "Soft delete and
what it does not hide" holds that traversal table). Filter on the flag
explicitly in each job, and let ordinary read paths see the row.

A decoy credential only signals if the code that rejects it can tell it apart
from the invalid values it rejects all day. Recognize the canary in the
authentication path and alert on the attempt; a verifier that returns the
same failure it returns for a typo has placed a decoy nothing is watching. A
decoy route belongs in the endpoint inventory for the same reason — otherwise
the next review reports it as an undocumented endpoint
(`api-drf-specific.md`, "Endpoint inventory (API9)").

**Write-time.** When generating a decoy, write its register entry — owner,
placement, expected reader count of zero, alert route — in the same change,
because an unregistered decoy is indistinguishable from a real record to the
responder who finds it and to the job that breaks on it. Add the exclusion to
the batch paths in that change too, rather than waiting for the first
false alert to identify them for you.

## Review checklist

- [ ] No passwords/tokens/`Authorization`/PANs/excess PII in logs or log
      middleware.
- [ ] `sensitive_variables`/`sensitive_post_parameters` on auth/payment paths.
- [ ] Auth, authz-denial, and admin events logged with source IP; logs monitored
      and alerting.
- [ ] Security-relevant lifecycle events cover save, bulk, delete, admin, job,
      migration, and approved raw paths; effects occur after commit and are
      idempotent.
- [ ] User input reaching a log line has control characters escaped as a class,
      in a formatter rather than per call site, or is emitted as a structured
      field; logs shipped to a tamper-resistant store.
- [ ] Personal data reaching logs, error reports, and history tables is counted
      as a retained copy with a stated lifetime, and the audit store retains the
      event without retaining the identity
      (`data-lifecycle-and-privacy.md`).
- [ ] The audit sink is append-only for the writing principal, deletion sits
      under a separate identity whose grant is reviewed, and any integrity
      chain is reported for what it proves — not completeness, and not
      resistance to a principal who can recompute it.
- [ ] Records name the principal, the permission, the object, the outcome,
      and the state read, and one request id crosses the web, worker, and
      database tiers against a single time source.
- [ ] Any decoy is registered with an owner, an expected reader count of
      zero, and an alert route, is excluded from export, backup, analytics,
      and erasure paths, and is not standing in for an access control.
