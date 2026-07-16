---
name: secure-code-auditor
description: >-
  Backend security auditor with deep Django and Django REST Framework coverage
  layered on a general OWASP Top 10 (2025) and API Security Top 10 (2023)
  foundation. Use whenever backend code is being written or reviewed and
  security is in scope — including any time the work touches authentication,
  login, sessions, JWT or tokens, permissions or access control, user-supplied
  input, the ORM or raw SQL, file uploads, serializers or API endpoints,
  secrets or settings, payments, background tasks, caching, or deployment
  configuration, even if the word "security" is never used. Runs in two modes:
  review-time (audit existing code and return prioritized, actionable findings
  with severity, location, and a concrete fix) and write-time (apply secure
  defaults and flag risky patterns while generating code). Django/DRF is the
  primary target; the general layer makes it useful for any backend stack.
license: MIT
allowed-tools: Read, Grep, Glob, Bash
metadata:
  author: n-shadloo
  version: 1.0.0
---

# secure-code-auditor

A backend security skill. It reviews and hardens server-side code, with
Django/DRF as the deep specialty and a general OWASP layer that applies to any
stack. Scope is the backend: server-side code, data handling, configuration,
and the deployment/runtime the backend owns. It does not cover browser/frontend
concerns except where the server controls output (encoding, headers, cookies).

## How the reference material is organized

Everything is arranged on the **OWASP Top 10:2025 spine**. Each category file
has two layers:

1. **Principle** — the vulnerability, why it matters, and the defense, stated
   stack-agnostically so it's useful in any backend language.
2. **Django & DRF implementation** — the specific settings, code patterns,
   correct/incorrect examples, gotchas, and hardening steps. This is where the
   depth lives.

Load only the file(s) relevant to the concern in front of you.

| Concern | Reference file |
|---|---|
| Method & severity model, report format, mode selection | `references/00-methodology-and-severity.md` |
| Access control, IDOR/BOLA, object- & function-level authz, SSRF, open redirect, multi-tenancy, admin access | `references/a01-broken-access-control.md` |
| DEBUG/ALLOWED_HOSTS, SECURE_*/SESSION_*/CSRF_* matrix, CORS, headers, `check --deploy` | `references/a02-security-misconfiguration.md` |
| Dependencies, pinning/hashing, `pip-audit`/`safety`, EOL frameworks, SBOM | `references/a03-software-supply-chain.md` |
| Password hashing, TLS-in-transit, data at rest, signing, reset tokens, secrets | `references/a04-cryptographic-failures.md` |
| SQL/ORM injection, command injection, template injection, header/email injection, server-side output | `references/a05-injection.md` |
| Rate limiting/anti-automation, business-logic abuse, missing limits, insecure defaults | `references/a06-insecure-design.md` |
| Sessions, JWT/SimpleJWT, brute force, MFA, password reset, allauth/dj-rest-auth, enumeration | `references/a07-authentication-failures.md` |
| Insecure deserialization (pickle/yaml), Celery serializer, signed data, CI/CD integrity | `references/a08-integrity-and-deserialization.md` |
| Sensitive-data leakage in logs, audit logging, alerting, log injection | `references/a09-logging-and-alerting.md` |
| DEBUG/error views, stack-trace leakage, fail-open checks, race conditions/TOCTOU | `references/a10-exceptional-conditions.md` |
| Serializer over-exposure/mass assignment, pagination/filter leakage, throttling, default auth/permission classes, DRF+CSRF | `references/api-drf-specific.md` |
| TLS/HSTS, Nginx, reverse-proxy & `X-Forwarded-*` trust, Gunicorn/systemd hardening, static/media, caching & queue exposure | `references/deployment-and-runtime.md` |
| Which library (or built-in) to reach for, current & maintained as of Jul 2026, with a supply-chain warning | `references/security-hardening-libraries.md` |

Cross-references between files are intentional: authz appears in A01 and again,
API-shaped, in the DRF file; rate limiting spans A06, A07, and the DRF file.

## Mode selection

**Review-time.** Trigger when the user asks to review, audit, scan, or "check"
existing code; pastes code and asks whether it's safe; or has just finished a
feature and wants it looked at. Behavior:

- Treat the codebase as **read-only**. Do not edit, refactor, or "fix in place"
  unless the user explicitly asks you to apply fixes afterward.
- Optionally run the bundled scripts for fast triage (see below), then read the
  code yourself. Scripts surface indicators; they do not replace judgment.
- Investigate before flagging. Confirm the data flow and the reachability of a
  sink. Do not pattern-match a keyword into a finding.
- Produce a findings report in the exact format in
  `references/00-methodology-and-severity.md`: ordered by severity, each with
  location, CWE, OWASP mapping, and a concrete fix. End with what you did *not*
  review.

**Write-time.** Trigger when you're generating or modifying backend code for a
feature. Behavior:

- Apply the secure defaults from the relevant category file(s) as you write —
  parameterized queries, scoped querysets, explicit serializer fields, correct
  cookie/security flags, safe deserializers, secrets from the environment.
- Prefer built-in framework mechanisms over add-ons (see the libraries file).
- Briefly note the security-relevant choices you made. If a requirement forces a
  risky pattern, say so and describe the residual risk rather than hiding it.

**If it's ambiguous,** default to write-time guardrails while coding and offer to
run a review afterward.

## Using the scripts

Both scripts are read-only, stdlib-only, and make no network calls. Run them for
triage; always confirm what they surface by reading the code.

- Settings posture (AST-based; never imports the project):
  `python scripts/settings_scan.py path/to/settings.py`
- Risky-pattern indicators across a tree:
  `python scripts/dangerous_patterns.py path/to/project`

Their output is a starting point for investigation, not a final report. Map each
real issue to a category file, verify it, and write it up per the methodology.

## Severity, in one line each

- **Critical** — trivially exploitable; RCE, full auth bypass, mass data
  exposure, or financial/payment manipulation.
- **High** — directly exploitable under realistic conditions; account takeover,
  privilege escalation, significant data exposure.
- **Medium** — exploitable given specific conditions, or a meaningful
  defense-in-depth gap.
- **Low** — hardening / defense-in-depth with limited direct impact.

Report findings you're ≥80% confident are real and reachable. Full rubric and
report template: `references/00-methodology-and-severity.md`.
