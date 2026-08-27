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
accountable identity. The capability is explicit, and it expires on its own.
The whole episode can be reconstructed afterwards, from records the operator
cannot edit.**

The invariant bounds the two mechanisms differently, and one sentence for both
misstates it. Impersonation stays *below* the operator's own privileges,
because the operator already holds them. Elevation goes *above* them on
purpose, so the declared scope and the time box are its bound. Write the bound
per mechanism. A reader who applies the impersonation half to break-glass
treats the invariant as aspirational, and then enforces neither half.

Four failures follow from dropping any part of that:

- **Attribution loss.** The system records each action as the target user. The
  audit log therefore says that a customer did what an employee did. Incident
  response cannot tell support activity from account takeover.
- **Privilege inheritance.** The impersonated session carries the privileges
  of the operator, or a standing elevation never expires. A single stolen
  session is then permanent access with no bound.
- **Unbounded scope.** Nothing restricts which accounts a person may
  impersonate. Support tooling therefore reaches administrators, other
  operators, and the highest-value tenants.
- **Persistence made inside the window.** The episode expires, and what it
  created does not. A password, a second factor, an API token, or a new
  administrator outlives the grant that produced it. The time box then bounds
  the session and nothing else.

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
  the least scope that solves the support case. Embed that scope in the token.
  Do not infer it from the operator who started the session. An admin who
  impersonates a customer must not get admin rights over that customer. The
  reverse holds too: a target who administers a tenant carries rights over that
  tenant, and the operator gets them unless the scope removes them. Enforce the
  scope at one place that every route passes, because a route added later
  inherits an allowlist and misses a decorator.
- **Deny the credential surface to an impersonated session, on read and on
  write.** That surface holds the password, the recovery email and phone,
  second-factor enrollment and removal, recovery codes, API tokens, and device
  or session management. It also holds the support PIN and the security
  answers. A write mints access that outlives the time box. A read harvests
  credentials that still work on the phone channel, and the Cox incident above
  is that read. Re-authentication does not guard this surface, because an
  impersonated session answers "the account owner" by construction. See
  `a07-authentication-failures.md` for each credential's own rules.
- **Fresh re-authentication at grant time.** The operator proves a factor
  before the episode starts, and the proof binds to this target and this scope.
  A stolen session cookie otherwise acquires any account with no second
  challenge. Both incidents above are session and credential theft rather than
  password guessing. Give the proof a short life, so a captured one does not
  open a later episode.
- **A server-side episode record is the authority.** Give the episode a row
  with an identifier, the operator, the target, the scope, and the end time.
  The session carries the identifier and nothing else. A check that reads only
  session keys fails open, because a session with no start time reads as not
  impersonated rather than as expired. Treat an authenticated session with no
  live episode row as an episode to end, and never as a normal session.
- **The time box covers the work the episode starts,** and not only its HTTP
  requests. A queued task, an open connection, and a scheduled job each outlive
  the middleware that enforces the limit. Carry the episode identifier into the
  task message and the connection scope. Read the episode row again when the
  work runs, and refuse the work when the episode has ended.
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
  identity, where the operator cannot rewrite it. A model in the application
  database does not meet that bar here, because the accounts that may
  impersonate reach every model through the admin and the shell. Send the rows
  to a sink whose write credential the application does not hold, and see
  `a09-logging-and-alerting.md` for what that sink has to prove.
- **Require a reason at grant time,** validated server-side. A free-text
  reason is untrusted input. Store it, and neutralize it before you log it.
  See `a09-logging-and-alerting.md`. Never let it drive a decision. Validate it
  in the overridden form, and keep a second check on the audit path that
  refuses an empty reason.

**Write-time.** When you generate an impersonation or break-glass path, use
`django-hijack` before you write one. Its defaults are superusers only, POST
with CSRF, and a session flush on both edges. They implement several of the
requirements above, and a reviewer has already read them. They do not implement
the time box, the re-authentication, the reduced scope, or the target test.
Generate those four in the same change.

Sometimes the flow must be home-grown. Write seven controls in the change that
introduces the feature. Write the dual-identity token, and the expiry that
does not depend on a release action by the operator. Write the episode record
that the expiry reads, and the re-authentication at grant time. Write the
reduced scope, embedded in the token rather than inherited from the operator
who started the session. Write the server-validated reason, and the audit
record that names both identities. Each control is load-bearing on its own,
and this tooling decides the reach of an attack rather than the login in front
of it.

## Django implementation: django-hijack

`django-hijack` (3.7.8, Apr 2026; see `security-hardening-libraries.md`) is the
vetted choice. v3 is a security-focused rewrite — all v2 APIs changed. What it
gives you and what it does not:

- **Default permission is `hijack.permissions.superusers_only`** — only
  superusers may hijack. Staff hijacking is opt-in. Point
  `HIJACK_PERMISSION_CHECK` at `hijack.permissions.superusers_and_staff` for
  it. The v2-era `HIJACK_AUTHORIZE_STAFF` setting is gone with the rest of the
  v2 API.
- **Neither built-in gate meets the target-set requirement, and the looser
  name meets more of it.** In 3.7.8 `superusers_only` returns
  `hijacked.is_active and hijacker.is_superuser`. It reads the target for
  `is_active` alone, so a superuser may acquire another superuser and any staff
  member. `superusers_and_staff` refuses a staff hijacker any target that is
  staff or superuser. That refusal is the deliberate block on a staff account
  that acquires a superuser, because the alternative removes the distinction.
  Read the function rather than its name.
- **`HIJACK_PERMISSION_CHECK` is the one enforcement point, so put the target
  test there.** The docs warn that custom permission functions are highly
  dangerous and a common source of privilege escalation. That warning argues
  for review of the replacement, and not for a default that the checklist below
  fails. Have the replacement call `superusers_only` first and then compare
  privilege, so it keeps the `is_active` test that a rewrite drops without
  notice. Refuse an equal or greater target. Prove it with a test that
  enumerates the privilege pairs and asserts a refusal for each.
- **Reconcile the gate with the zero-standing-privilege rule below.** The
  Django checklist forbids a standing `is_superuser` on a staff account, and
  the stock gate admits superusers alone. Together they mean that each routine
  support case needs a break-glass elevation first. Record the resolution the
  project chose: routine support goes through elevation, or the gate becomes a
  reviewed replacement that reads a dedicated permission. A team that leaves
  the contradiction unstated keeps one standing superuser for support, and that
  account is the Twitter-2020 target.
- **Views are POST-only with CSRF** by default, and the bundled admin
  integration submits a POST form, so nothing needs GET. A project can enable
  GET acquisition again, which is a v2 habit. That change gives up CSRF
  protection for convenience. Treat any such configuration or fork as a
  finding, unless a separate control mitigates the exposure.
- **Session flush on acquire and release**, via Django's login utility, so
  session data does not leak between operator and target.
- **`hijack_started` and `hijack_ended` signals** — the intended audit hook.

It does **not** re-authenticate the operator at hijack time, does not time-box
the session, and does not scope down what the impersonated session may do. Those
remain yours to add.

Wire the signals to a durable audit record rather than logging alone:

```python
import uuid

from django.dispatch import receiver
from hijack.signals import hijack_ended, hijack_started


class ImpersonationAuditError(Exception):
    """Not a Django exception, so the response is 500 and the session is lost.

    A 400 or a 403 would save the session and complete the acquire.
    """


@receiver(hijack_started)
def record_hijack_started(sender, hijacker, hijacked, request, **kwargs):
    reason = (request.POST.get("reason") or "").strip()
    if not reason:
        raise ImpersonationAuditError("impersonation needs a reason")
    episode_id = str(uuid.uuid4())
    request.session["impersonation_episode"] = episode_id
    ImpersonationEvent.objects.create(
        episode_id=episode_id,
        operator=hijacker,
        # hijack_history[0] is the operator who started the chain.
        root_operator_id=request.session["hijack_history"][0],
        operator_roles=list(
            hijacker.groups.order_by("pk").values_list("name", flat=True)
        ),
        target=hijacked,
        event="started",
        reason=reason,  # stored raw, neutralized at render
    )


@receiver(hijack_ended)
def record_hijack_ended(sender, hijacker, hijacked, request, **kwargs):
    ImpersonationEvent.objects.create(
        # login() flushed the session, so middleware stashes the id here.
        episode_id=request.impersonation_episode,
        operator=hijacker,
        target=hijacked,
        event="ended",
    )
```

`hijack_history` is a list, and an acquire appends to it, so an operator may
acquire a second target from inside an episode. The `hijacker` argument is
`request.user` at acquire time, which in that chain is the intermediate
identity rather than the person. Record `hijack_history[0]` as well, or the
audit names the framed account as the actor.

Stock hijack posts only `user_pk` and `next`. A reason field therefore exists
only where you override its form and `AcquireUserView`. `hijack_started` is
sent with `Signal.send()`, after `login()` has already switched the session.
That ordering reads as a fail-open audit, and in 3.7.8 it is not one. Let the
receiver raise.

`AcquireUserView` inherits `LockUserTableMixin`, which wraps `dispatch()` in
`transaction.atomic()`. Django's `SessionMiddleware` skips the session save and
the cookie for a response of 500 or above. A receiver that raises therefore
rolls the audit row and the session switch back together, and the operator
keeps their own session.

A receiver written so that it "cannot raise" is the fail-open version, because
the acquire then succeeds with a missing or empty row. Three conditions break
the guarantee, and the first is the one a reviewer writes by accident.

Raise an exception that Django does not map to a status below 500. Django
answers 400 for `SuspiciousOperation` and 403 for `PermissionDenied`, and both
are the instinctive choice here. Either one saves the session and completes the
acquire with no audit row. Only an exception that reaches the uncaught handler
gives the 500 that discards the session. A custom exception class in the
project is the safe choice, and a project exception handler must not answer it
below 500 either.

The other two conditions are narrower. A session backend in another database is
outside that rolled-back transaction. The same mechanism blocks a release when
the `hijack_ended` receiver raises, so give that receiver its inputs on the
request rather than in the flushed session.

**`request.user` is the target for every record you did not write.** The rows
above are the project's own. Django's admin history calls
`LogEntry.objects.log_actions(user_id=request.user.pk, ...)`, so an admin
change during an episode names the customer as the actor. Every receiver of
`user_logged_in` fires with the target too, so a login-alert receiver mails the
customer and a device rule reads the wrong identity.

Hijack 3.7.8 disconnects one receiver, `update_last_login`, around both
`login()` calls, so `last_login` is the exception rather than the pattern.
Check each receiver of `user_logged_in` and each admin action for the identity
it records. State in the report that reconstruction stops at the records the
project stamps itself.

`hijack_ended` fires only on an explicit release. Enforce the expiry
separately, in middleware, and **release rather than reject**. A rejection
answers 403 and leaves the hijack state in the session. It writes no terminal
row, and it can block the release route itself, which strands the session until
the cookie expires. A release drives the same path the operator would, so
`hijack_ended` fires and the episode closes.

Middleware that reads `request.session` alone fails open. A session with
`hijack_history` set and no start time reads as unbounded rather than as
expired. Treat a live `hijack_history` with no open episode row as an episode
to release now. Have the middleware re-check the preconditions and not the
clock alone: the operator is still active and still holds the permission, and
the target is still inside the permitted set. A disable of a compromised
operator must end their live episodes in the same action, and
`authorization-architecture.md` owns the rest of that lifecycle.

Write the episode identifier on the `started` row and on every terminal row,
and pair the rows on it. Nested acquires and a per-tab retry both give one
operator two open episodes, so a pair matched on operator and target closes the
wrong one. An episode with a `started` row and no terminal row is worth an
alert on its own, and it means something only once every end cause writes one.

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
  token also usually inherits the normal long expiry. The operator claim alone
  is not enough. A resource server that reads `sub` and ignores an unknown
  claim grants the target's full privileges, so give the impersonation token
  its own audience and refuse it on every other path.
- an expiry check that reads a start time from the session and treats a missing
  key as "not impersonating", so a session without the key never expires.
- a scope allowlist applied by a decorator on each view, so a route added later
  carries the target's full privileges.
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
  that matters is that one compromised account is insufficient. Bind the
  approval to the grant, so that it names the target, the scope, and the
  duration. The executor refuses a grant whose parameters differ from the
  approved ones, because an approval that names none of them approves whatever
  the requester asks for later.
- **Mandatory reason capture.** Capture the rationale, the incident or ticket
  reference, and the approvers. Capture the start and stop, the scope, and the
  actions that the grant permits. Validate the reference server-side: it
  exists, it is open, and it names the target. An unvalidated reference is an
  assertion by the requester, and the signals below then read it as evidence.
- **Scopes that a window must never include.** A grant expires, and what it
  changed does not. Keep the auth model out of every break-glass scope, meaning
  users, groups, and permissions. Keep the approval configuration and the audit
  and alerting configuration out as well. A window that reaches them creates a
  standing administrator, approves its own successors, or stops the channel
  that reports it. Route a genuine change to any of them through a separate
  path that always needs two people.
- **A comparison after the window closes.** Record the auth model, the group
  memberships, the scheduled jobs, and the credentials that exist before the
  grant opens. Compare after it closes, and alert on each difference the
  incident does not explain. Automatic revocation proves that the grant ended,
  and proves nothing about what the grant left behind.
- **Dedicated break-glass accounts** held in a hardened vault or PAM system,
  with credentials rotated even when unused. A shared account is not an
  accountable identity, which contradicts the principle above. Close the gap at
  the checkout: the vault records the human who took the credential, and the
  audit record names that human. Without that record, every action in the
  window belongs to an account that nobody is.
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

Every signal above is internal, and an operator who files a plausible case
first and stays under each threshold trips none of them. One check does not
depend on the operator's own systems. Notify the target after the episode, out
of band, with the operator identity, the duration, and the scope. The
impersonated person is the one party who knows whether they asked for support.
Give the notification a documented exception for an active investigation, and
give that exception an expiry.

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
      cannot suppress. A break-glass scope reaches neither that channel nor
      the auth model, and a comparison after the window reports what the grant
      left behind.
- [ ] The operator re-authenticates at grant time, and the proof binds to this
      target and this scope. The approver is bound to the same parameters.
- [ ] An impersonated session reaches no credential, on read or on write. That
      covers the password, recovery contacts, second factors, recovery codes,
      tokens, the support PIN, and the security answers.
- [ ] A server-side episode record is the authority, and the session holds only
      its identifier. Work started inside the episode reads that record again
      when it runs.

### Django & DRF

- [ ] `HIJACK_PERMISSION_CHECK` refuses an equal or greater target, and keeps
      the `hijacked.is_active` test that `superusers_only` performs. A test
      enumerates the privilege pairs. The stock gate alone does not pass this.
- [ ] Acquisition keeps POST with CSRF. GET acquisition stays disabled, or a
      separate justification covers it.
- [ ] `hijack_started` and `hijack_ended` write durable, actor-attributed
      audit rows carrying the episode identifier and the root operator from
      `hijack_history`. The audit receiver raises rather than swallows.
- [ ] Middleware releases an expired episode rather than rejecting it, writes a
      terminal row for every end cause, and fails closed on a session whose
      episode record is missing.
- [ ] Every receiver of `user_logged_in` and every admin action is checked for
      the identity it records during an episode.
- [ ] Home-grown impersonation flushes the session on both edges. It never
      takes the identity from a client-supplied header or parameter. It embeds
      the operator in any reissued token.
- [ ] No staff account carries a standing `is_superuser`. Elevation is granted
      for a window and then revoked, and the permission cache is read again
      after the change.
- [ ] Impersonation and elevation endpoints are excluded from any permissive
      default and covered by the URLconf audit test.
