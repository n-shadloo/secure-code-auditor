# A09:2025 — Security Logging and Alerting Failures

Enough logging to detect and investigate, without logging the secrets and PII
that turn a log store into a second breach. Also covers lifecycle hooks whose
ordering or bypass can silently omit security events and side effects.

## Contents
- [Principle](#principle)
- [Don't log secrets](#dont-log-secrets)
- [Scrub error reports](#scrub-error-reports)
- [Log the right security events](#log-the-right-security-events)
- [Lifecycle hooks and audit guarantees](#lifecycle-hooks-and-audit-guarantees)
- [Log injection and integrity](#log-injection-and-integrity)
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
  duplicate grants, messages, or audit entries.
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

- Neutralize newlines/control characters in user-supplied values before logging
  so an attacker can't forge log lines.
- Protect log integrity/retention; ship to a store the app can't rewrite.

## Review checklist

- [ ] No passwords/tokens/`Authorization`/PANs/excess PII in logs or log
      middleware.
- [ ] `sensitive_variables`/`sensitive_post_parameters` on auth/payment paths.
- [ ] Auth, authz-denial, and admin events logged with source IP; logs monitored
      and alerting.
- [ ] Security-relevant lifecycle events cover save, bulk, delete, admin, job,
      migration, and approved raw paths; effects occur after commit and are
      idempotent.
- [ ] User input sanitized before logging; logs shipped to a tamper-resistant
      store.
