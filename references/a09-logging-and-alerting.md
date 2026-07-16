# A09:2025 — Security Logging and Alerting Failures

Enough logging to detect and investigate, without logging the secrets and PII
that turn a log store into a second breach.

## Contents
- [Principle](#principle)
- [Don't log secrets](#dont-log-secrets)
- [Scrub error reports](#scrub-error-reports)
- [Log the right security events](#log-the-right-security-events)
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
allauth's audit signals help. Keep logs long enough to investigate, and forward
them somewhere monitored with alerts on spikes (failed logins, 403 storms).

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
- [ ] User input sanitized before logging; logs shipped to a tamper-resistant
      store.
