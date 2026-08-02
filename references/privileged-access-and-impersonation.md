# Privileged Access, Impersonation, and Break-Glass

Operator-facing privilege: "log in as this user" tooling, emergency elevation,
and the audit guarantees both require. These features are built for support and
incident response, and they define the blast radius of a compromised internal
account — impersonation tooling turns one phished employee into access to every
customer. Read alongside `authorization-architecture.md` (the privilege model),
`a01-broken-access-control.md` (admin exposure),
`a09-logging-and-alerting.md` (audit durability), and
`agent-and-llm-interfaces.md`, which applies the same invariant to a machine
delegate acting on a user's behalf. Maps to OWASP A01:2025 and
A09:2025, and to CWE-269 (Improper Privilege Management), CWE-250 (Execution
with Unnecessary Privileges), CWE-266/CWE-268 (privilege escalation family —
match the sub-ID to the specific finding), and CWE-778 (Insufficient Logging).

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

Impersonation and emergency elevation deliberately break the normal rule that a
session's privileges belong to the person who authenticated. The invariant that
replaces it: **the acting operator remains the accountable identity, the
elevated capability is narrower than the operator's own account and expires on
its own, and the whole episode can be reconstructed afterwards from records the
operator cannot edit.**

Three failures follow from dropping any part of that:

- **Attribution loss.** Actions are recorded as the target user, so the audit
  log says a customer did something an employee did. Incident response cannot
  distinguish support activity from account takeover.
- **Privilege inheritance.** The impersonated session carries the operator's
  own privileges, or standing elevation never expires, so a single stolen
  session is permanent, unbounded access.
- **Unbounded scope.** Nothing restricts which accounts may be impersonated, so
  support tooling reaches administrators, other operators, or the highest-value
  tenants.

If a session cannot be reconstructed afterwards, the control is too weak for
enterprise use, regardless of how the elevation is gated.

## Why this surface gets attacked

Three documented incidents, useful for justifying the controls below:

- **Twitter, July 2020.** Per the New York State DFS *Report on the Twitter
  Hack* (14 Oct 2020), attackers social-engineered credentials from four
  employees, reached internal account-management tooling, and took over 130
  accounts (45 used to tweet the scam), netting at least $118,000 in bitcoin
  fraud. The report notes Twitter had no chief information security officer at
  the time. The tooling, not the login, defined the blast radius.
- **Okta support system, late 2023.** Okta reported that between 28 September
  and 17 October 2023 a threat actor accessed support-case files for 134
  customers; session tokens in uploaded HAR files were used to hijack legitimate
  sessions for 5 customers, including 1Password, BeyondTrust, and Cloudflare.
  Session artifacts in a support system are impersonation capability.
- **Cox Communications.** An attacker posing as a support agent reached customer
  account data including name, address, phone, account number, PIN, and security
  questions — the same data an impersonation feature exposes.

## Impersonation: design requirements

- **A separate audit identity.** Every action during the session is attributed
  to the **operator**, not the target. Carry both identities (a token or session
  holding operator and target), and write both into every audit record.
- **Explicit time-boxing.** The session expires on its own — long enough to
  investigate, short enough to bound a theft. 30 minutes is a common,
  defensible default; after that the token is simply invalid. Do not rely on the
  operator clicking "release".
- **Do not inherit the operator's privileges.** The impersonated session gets
  the least scope that solves the support case, frequently read-only, and that
  scope is embedded in the token rather than inferred from whoever started it.
  An admin impersonating a customer must not get admin-over-that-customer.
- **A visible in-app indicator** for the duration of the session, so an operator
  cannot forget which identity they are acting as.
- **Restrictions on the target set.** Impersonating higher-privileged accounts,
  other operators, or administrators is refused, not merely discouraged.
- **Session rotation on both edges.** Flush the session on entering and on
  leaving so data does not leak between operator and target in either direction.
- **A tamper-resistant audit trail** capturing operator identity and role,
  target identity, reason, granted scope, start and stop timestamps, and the
  actions taken — stored per identity, where the operator cannot rewrite it.
- **Require a reason at grant time,** validated server-side. A free-text reason
  is untrusted input: store it, neutralize it before logging
  (`a09-logging-and-alerting.md`), and never let it drive a decision.

## Django implementation: django-hijack

`django-hijack` (3.7.8, Apr 2026; see `security-hardening-libraries.md`) is the
vetted choice. v3 is a security-focused rewrite — all v2 APIs changed. What it
gives you and what it does not:

- **Default permission is `hijack.permissions.superusers_only`** — only
  superusers may hijack. Staff hijacking is opt-in via `HIJACK_AUTHORIZE_STAFF`,
  and there is deliberately **no built-in option for staff to hijack
  superusers**, since that would erase the distinction. Preserve both defaults.
- **Views are POST-only with CSRF** by default. `HIJACK_ALLOW_GET_REQUESTS`
  exists for the admin button and trades CSRF protection for convenience —
  treat enabling it as a finding unless the exposure is separately mitigated.
- **Session flush on acquire and release**, via Django's login utility, so
  session data does not leak between operator and target.
- **`hijack_started` and `hijack_ended` signals** — the intended audit hook.
- The docs warn that custom permission functions are highly dangerous and a
  common source of privilege escalation. Any project-supplied replacement for
  `superusers_only` deserves direct review: check it cannot return `True` for a
  target with equal or greater privilege.

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

Stock hijack posts only `user_pk` and `next`, so a reason field exists only if
you override its form and `AcquireUserView`; and because `hijack_started` is
sent with `Signal.send()`, an exception in any receiver propagates out of the
view and breaks the acquire request *after* `login()` has already switched the
session — so the audit write belongs in a receiver that cannot raise on missing
or malformed input.

Because `hijack_ended` only fires on an explicit release, expiry must be
enforced independently — store the start time in the session and reject or
release impersonated requests past the limit in middleware. An episode with a
`started` row and no `ended` row is itself worth alerting on.

## Reviewing home-grown impersonation

Hand-rolled "log in as user" is common and usually wrong in the same ways. Look
for:

- `login(request, target_user)` or a session-key swap **without** flushing, so
  the target's session inherits the operator's cart, tenant, or CSRF state (or
  the reverse).
- middleware that sets `request.user = target` based on a header or query
  parameter — the client controls the identity, and nothing is recorded.
- a JWT reissued with the target's `sub` and **no operator claim**, which makes
  attribution impossible for the token's whole lifetime and typically inherits
  the normal (long) expiry.
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
- **Two-person rule** for the highest tiers — the requester cannot approve
  themselves. (The convention originates in nuclear-surety controls; the
  property that matters is that one compromised account is insufficient.)
- **Mandatory reason capture**: rationale, incident or ticket reference,
  approvers, start and stop, scope, and the actions the grant permits.
- **Dedicated break-glass accounts** held in a hardened vault or PAM system,
  with credentials rotated even when unused.
- **Out-of-band alerting** on every request and grant — a channel the elevated
  privilege itself cannot suppress.
- Route all privileged activity into SIEM/SOAR rather than only application
  logs.

In Django terms, this argues against permanently-set `is_superuser` on staff
accounts: the superuser short-circuit
(`authorization-architecture.md`) means such an account bypasses every check
you wrote, all the time. Grant the elevated role for the window and remove it,
and remember that a user object cached mid-request will not see the revocation.

## Telling legitimate use from abuse

Legitimate break-glass is preceded by a declared incident, tied to an approver,
scoped, time-boxed, and *leaves deliberate evidence*. Signals worth alerting on:

- elevation with **no matching incident or ticket**;
- out-of-hours use with no corresponding incident;
- scope or commands beyond the fix path — data exports, permission grants, or
  account changes during a "read the logs" elevation;
- missing out-of-band approval, or approver and requester being the same person;
- impersonation sessions that never end, or cluster on high-value accounts;
- a spike in impersonation of accounts with no open support case.

## Review checklist

### Stack-neutral

- [ ] Every action during impersonation or elevation is attributed to the
      operator, with the target recorded separately, in a store the operator
      cannot rewrite.
- [ ] Sessions and grants expire automatically; expiry does not depend on the
      operator releasing them.
- [ ] Elevated scope is least-privilege and explicit, not inherited from the
      operator's own account.
- [ ] Higher-privileged, administrative, and peer-operator accounts cannot be
      impersonated.
- [ ] Reason, approver, scope, and start/stop are captured at grant time; the
      highest tier requires a second person.
- [ ] Requests and grants alert out of band, into a channel the privilege
      cannot suppress.

### Django & DRF

- [ ] `django-hijack` keeps `superusers_only` (or a reviewed replacement that
      cannot target equal-or-greater privilege) and POST + CSRF;
      `HIJACK_ALLOW_GET_REQUESTS` is off or separately justified.
- [ ] `hijack_started` / `hijack_ended` write durable, actor-attributed audit
      rows; unterminated sessions are detectable and time-boxed in middleware.
- [ ] Home-grown impersonation flushes the session on both edges, never takes
      the identity from a client-supplied header or parameter, and embeds the
      operator in any reissued token.
- [ ] Staff accounts do not carry standing `is_superuser`; elevation is granted
      for a window and revoked, with the permission cache re-read after change.
- [ ] Impersonation and elevation endpoints are excluded from any permissive
      default and covered by the URLconf audit test.
