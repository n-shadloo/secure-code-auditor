# Privileged Access, Impersonation, and Break-Glass

This file covers operator-facing privilege. That is "log in as this user"
tooling, emergency elevation, and the audit guarantees that both require. A
team builds these features for support and incident response. They also decide
what a compromised internal account reaches. Impersonation tooling makes one
phished employee into access to every customer.

Read this file with four others. `authorization-architecture.md` owns the
privilege model, and `a01-broken-access-control.md` owns admin exposure.
`a09-logging-and-alerting.md` owns audit durability.
`agent-and-llm-interfaces.md` applies the same invariant to a machine delegate
that acts for a user.

Maps to OWASP A01:2025 and A09:2025. Maps also to CWE-269 (Improper Privilege
Management) and CWE-250 (Execution with Unnecessary Privileges). Maps to the
CWE-266/CWE-268 privilege escalation family, where you match the sub-ID to the
specific finding. Maps to CWE-778 (Insufficient Logging).

## Contents
- [Principle](#principle)
- [Why this surface gets attacked](#why-this-surface-gets-attacked)
- [Impersonation: design requirements](#impersonation-design-requirements)
- [Django implementation: django-hijack](#django-implementation-django-hijack)
- [Reviewing home-grown impersonation](#reviewing-home-grown-impersonation)
- [Break-glass and emergency elevation](#break-glass-and-emergency-elevation)
- [Telling legitimate use from abuse](#telling-legitimate-use-from-abuse)
- [Review checklist](#review-checklist)

## Principle

The normal rule is that the privileges of a session belong to the person who
authenticated. Impersonation and emergency elevation break that rule on
purpose. One invariant replaces it. **The acting operator remains the
accountable identity. The elevated capability is narrower than the operator's
own account, and it expires on its own. The whole episode can be reconstructed
afterwards, from records the operator cannot edit.**

Three failures follow from dropping any part of that:

- **Attribution loss.** The system records each action as the target user. The
  audit log therefore says that a customer did what an employee did. Incident
  response cannot tell support activity from account takeover.
- **Privilege inheritance.** The impersonated session carries the privileges
  of the operator, or a standing elevation never expires. A single stolen
  session is then permanent access with no bound.
- **Unbounded scope.** Nothing restricts which accounts a person may
  impersonate. Support tooling therefore reaches administrators, other
  operators, and the highest-value tenants.

If a session cannot be reconstructed afterwards, the control is too weak for
enterprise use, regardless of how the elevation is gated.

## Why this surface gets attacked

Three documented incidents, useful for justifying the controls below:

- **Twitter, July 2020.** The New York State DFS *Report on the Twitter Hack*
  of 14 Oct 2020 records this incident. Attackers took credentials from four
  employees by social engineering. They reached internal account-management
  tooling, and took over 130 accounts. They used 45 of those accounts to send
  the scam, and gained at least $118,000 in bitcoin fraud. The report notes
  that Twitter had no chief information security officer at the time. The
  tooling decided the reach of the attack, and the login did not.
- **Okta support system, late 2023.** Okta reported that a threat actor read
  support-case files for 134 customers between 28 September and 17 October
  2023. The actor used session tokens from uploaded HAR files to hijack
        legitimate sessions for 5 customers. Those customers include
        1Password, BeyondTrust, and Cloudflare. A session artifact in a
        support system is impersonation capability.
- **Cox Communications.** An attacker acted as a support agent and reached
  customer account data. That data holds the name, address, phone, account
  number, PIN, and security questions. An impersonation feature exposes the
  same data.

## Impersonation: design requirements

- **A separate audit identity.** Attribute every action during the session to
  the **operator**, and not to the target. Carry both identities in a token or
  session that holds the operator and the target. Write both into every audit
  record.
- **Explicit time-boxing.** The session expires on its own. Make it long
  enough for an investigation, and short enough to bound a theft. 30 minutes
  is a common, defensible default. After that the token is invalid. Do not
  depend on the operator to select "release".
- **Do not inherit the operator's privileges.** Give the impersonated session
  the least scope that solves the support case, which is frequently read-only.
  Embed that scope in the token. Do not infer it from the operator who started
  the session. An admin who impersonates a customer must not get admin rights
  over that customer.
- **A visible in-app indicator** for the duration of the session, so an
  operator cannot forget which identity they are acting as.
- **Restrictions on the target set.** Impersonating higher-privileged
  accounts, other operators, or administrators is refused, not merely
  discouraged.
- **Session rotation on both edges.** Flush the session on entering and on
  leaving so data does not leak between operator and target in either
  direction.
- **A tamper-resistant audit trail.** It captures the operator identity and
  role, the target identity, the reason, and the granted scope. It also
  captures the start and stop timestamps, and the actions taken. Store it per
  identity, where the operator cannot rewrite it.
- **Require a reason at grant time,** validated server-side. A free-text
  reason is untrusted input. Store it, and neutralize it before you log it.
  See `a09-logging-and-alerting.md`. Never let it drive a decision.

**Write-time.** When you generate an impersonation or break-glass path, use
`django-hijack` at its own defaults before you write one. Those defaults are
superusers only, POST with CSRF, and a session flush on both edges. They
implement several of the requirements above, and a reviewer has already read
them.

Sometimes the flow must be home-grown. Write five controls in the change that
introduces the feature. Write the dual-identity token, and the expiry that
does not depend on a release action by the operator. Write the reduced scope,
embedded in the token rather than inherited from the operator who started the
session. Write the server-validated reason, and the audit record that names
both identities. Each control is load-bearing on its own, and this tooling
decides the reach of an attack rather than the login in front of it.

## Django implementation: django-hijack

`django-hijack` (3.7.8, Apr 2026; see `security-hardening-libraries.md`) is the
vetted choice. v3 is a security-focused rewrite — all v2 APIs changed. What it
gives you and what it does not:

- **Default permission is `hijack.permissions.superusers_only`** — only
  superusers may hijack. Staff hijacking is opt-in. Point
  `HIJACK_PERMISSION_CHECK` at `hijack.permissions.superusers_and_staff` for
  it. The v2-era `HIJACK_AUTHORIZE_STAFF` setting is gone with the rest of the
  v2 API. There is deliberately **no built-in option for staff to hijack
  superusers**, because that would remove the distinction. Preserve both
  defaults.
- **Views are POST-only with CSRF** by default, and the bundled admin
  integration submits a POST form, so nothing needs GET. A project can enable
  GET acquisition again, which is a v2 habit. That change gives up CSRF
  protection for convenience. Treat any such configuration or fork as a
  finding, unless a separate control mitigates the exposure.
- **Session flush on acquire and release**, via Django's login utility, so
  session data does not leak between operator and target.
- **`hijack_started` and `hijack_ended` signals** — the intended audit hook.
- The docs warn that custom permission functions are highly dangerous and a
  common source of privilege escalation. Any project-supplied replacement for
  `superusers_only` deserves direct review: check it cannot return `True` for
  a target with equal or greater privilege.

It does **not** re-authenticate the operator at hijack time, does not time-box
the session, and does not scope down what the impersonated session may do. Those
remain yours to add.

Wire the signals to a durable audit record rather than logging alone:

```python
from django.dispatch import receiver
from hijack.signals import hijack_ended, hijack_started


@receiver(hijack_started)
def record_hijack_started(sender, hijacker, hijacked, request, **kwargs):
    ImpersonationEvent.objects.create(
        operator=hijacker,
        operator_role=hijacker.groups.values_list("name", flat=True).first(),
        target=hijacked,
        event="started",
        reason=request.POST.get("reason", ""),  # validated, stored raw
        request_id=getattr(request, "id", ""),
    )


@receiver(hijack_ended)
def record_hijack_ended(sender, hijacker, hijacked, request, **kwargs):
    ImpersonationEvent.objects.create(
        operator=hijacker,
        target=hijacked,
        event="ended",
        request_id=getattr(request, "id", ""),
    )
```

Stock hijack posts only `user_pk` and `next`. A reason field therefore exists
only where you override its form and `AcquireUserView`. `hijack_started` is
sent with `Signal.send()`. An exception in any receiver therefore leaves the
view and breaks the acquire request. That happens *after* `login()` has
already switched the session. Put the audit write in a receiver that cannot
raise on missing or malformed input.

`hijack_ended` fires only on an explicit release. Enforce the expiry
separately. Store the start time in the session. Then reject or release an
impersonated request past the limit, in middleware. An episode with a
`started` row and no `ended` row is worth an alert on its own.

## Reviewing home-grown impersonation

Hand-rolled "log in as user" is common and usually wrong in the same ways. Look
for:

- `login(request, target_user)` or a session-key swap **without** flushing, so
  the target's session inherits the operator's cart, tenant, or CSRF state (or
  the reverse).
- middleware that sets `request.user = target` based on a header or query
  parameter — the client controls the identity, and nothing is recorded.
- a JWT reissued with the `sub` of the target and **no operator claim**.
  Attribution is then impossible for the whole lifetime of the token. Such a
  token also usually inherits the normal long expiry.
- no expiry, no release path, or release that only clears a UI flag.
- audit rows written as the target user, or written only to application logs
  the operator's team can edit.
- the impersonation endpoint gated by `IsAuthenticated`, `is_staff`, or a role
  check that does not compare the operator's privilege to the target's.

## Break-glass and emergency elevation

The pattern, drawn from cloud IAM and SRE practice (Google's SRE book for the
incident-response and blameless-post-mortem discipline; cloud IAM documentation
for the mechanics):

- **Zero standing privilege.** Nobody holds the elevated role in normal
  operation; it is granted just in time and revoked automatically.
- **Time-boxed grants**, typically 15–60 minutes, expiring without action.
- **Two-person rule** for the highest tiers. The requester cannot approve
  themselves. The convention comes from nuclear-surety controls. The property
  that matters is that one compromised account is insufficient.
- **Mandatory reason capture.** Capture the rationale, the incident or ticket
  reference, and the approvers. Capture the start and stop, the scope, and the
  actions that the grant permits.
- **Dedicated break-glass accounts** held in a hardened vault or PAM system,
  with credentials rotated even when unused.
- **Out-of-band alerting** on every request and grant — a channel the elevated
  privilege itself cannot suppress.
- Route all privileged activity into SIEM/SOAR rather than only application
  logs.

In Django terms, this argues against a permanent `is_superuser` on a staff
account. The superuser short-circuit means that such an account bypasses every
check you wrote, at every moment. See `authorization-architecture.md`. Grant
the elevated role for the window, and then remove it. Note that a user object
cached during the request does not see the revocation.

## Telling legitimate use from abuse

A declared incident comes before legitimate break-glass. Legitimate
break-glass ties to an approver, and it is scoped and time-boxed. It also
*leaves deliberate evidence*. These signals are worth an alert:

- elevation with **no matching incident or ticket**;
- out-of-hours use with no corresponding incident;
- scope or commands beyond the fix path, such as a data export, a permission
  grant, or an account change during a "read the logs" elevation;
- missing out-of-band approval, or approver and requester being the same
  person;
- impersonation sessions that never end, or cluster on high-value accounts;
- a spike in impersonation of accounts with no open support case.

## Review checklist

### Stack-neutral

- [ ] Every action during impersonation or elevation is attributed to the
      operator, with the target recorded separately, in a store the operator
      cannot rewrite.
- [ ] Sessions and grants expire automatically. The expiry does not depend on
      a release action by the operator.
- [ ] Elevated scope is least-privilege and explicit, not inherited from the
      operator's own account.
- [ ] Higher-privileged, administrative, and peer-operator accounts cannot be
      impersonated.
- [ ] The reason, the approver, the scope, and the start and stop are captured
      at grant time. The highest tier requires a second person.
- [ ] Requests and grants alert out of band, into a channel the privilege
      cannot suppress.

### Django & DRF

- [ ] `django-hijack` keeps `superusers_only`, or a reviewed replacement that
      cannot target equal or greater privilege. It also keeps POST with CSRF.
      GET acquisition stays disabled, or a separate justification covers it.
- [ ] `hijack_started` and `hijack_ended` write durable, actor-attributed
      audit rows. Middleware detects and time-boxes a session that never
      ended.
- [ ] Home-grown impersonation flushes the session on both edges. It never
      takes the identity from a client-supplied header or parameter. It embeds
      the operator in any reissued token.
- [ ] No staff account carries a standing `is_superuser`. Elevation is granted
      for a window and then revoked, and the permission cache is read again
      after the change.
- [ ] Impersonation and elevation endpoints are excluded from any permissive
      default and covered by the URLconf audit test.
