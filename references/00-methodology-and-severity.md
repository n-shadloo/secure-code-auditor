# Methodology, Severity, and Report Format

## Contents
- [Operating principles](#operating-principles)
- [Choosing the mode](#choosing-the-mode)
- [Severity rubric](#severity-rubric)
- [Confidence](#confidence)
- [Finding schema](#finding-schema)
- [Report structure](#report-structure)
- [What to exclude](#what-to-exclude)
- [Worked example](#worked-example)

## Operating principles

1. **Investigate, don't pattern-match.** A keyword (`raw`, `mark_safe`,
   `pickle`) is a lead, not a finding. Trace whether attacker-controlled data
   actually reaches the sink and whether the path is reachable in the deployed
   configuration. If you can't establish reachability, downgrade confidence or
   move it to "worth checking".
2. **Prefer confirmed over comprehensive.** A short list of real, exploitable
   issues with concrete fixes is worth more than a long list of maybes.
3. **Read-only by default in review mode.** Don't rewrite the project unless the
   user asks. Findings describe the fix; they don't silently apply it.
4. **Every finding is actionable.** Location, why it matters, and code the
   developer can apply. No vague "consider reviewing your auth".
5. **State the boundary.** Say what you reviewed and what you didn't. Silence
   reads as false assurance.

## Choosing the mode

- **Review-time** when asked to review/audit/scan, when code is pasted for a
  security opinion, or right after a feature is built. Output: a findings report.
- **Write-time** when generating or editing backend code. Output: secure code
  plus a short note on the security choices.
- Ambiguous → guardrails while coding, then offer a review.

## Severity rubric

| Severity | Test |
|---|---|
| **Critical** | Trivially or remotely exploitable with severe impact: RCE, authentication bypass, mass PII/credential exposure, or manipulation of money/orders/balances. Little or no precondition. |
| **High** | Directly exploitable under realistic conditions: horizontal/vertical privilege escalation, account takeover, IDOR exposing another user's data, injection with real impact. |
| **Medium** | Requires specific conditions, a chained precondition, or is a meaningful defense-in-depth failure (e.g., missing lockout on login, overly broad CORS without credentials, verbose errors leaking internals). |
| **Low** | Hardening and defense-in-depth with limited direct impact (missing header, non-rotating token with short TTL, minor info disclosure). |

When severity is borderline, decide on **realistic impact × ease of
exploitation** and say which way you leaned.

## Confidence

Score how sure you are the issue is real and reachable:

- **High (report it):** you traced the path and it holds. ≥80%.
- **Medium:** plausible but you couldn't fully confirm reachability. Put in
  "worth checking" with the specific thing to verify.
- **Low:** speculative. Omit, or mention once as a caveat.

Do not inflate severity to compensate for low confidence, or vice versa.

## Finding schema

Each finding uses this shape:

```
### [SEVERITY] Short title
- Location: path/to/file.py:LINE (and any related lines)
- Category: <e.g. Broken Object Level Authorization>  |  CWE-XXX  |  OWASP A0X:2025 (and APIX:2023 if relevant)
- Confidence: High | Medium
- Problem: one or two sentences on exactly what is wrong.
- Impact: the concrete attack or exposure this enables.
- Fix: the specific change, with a minimal code snippet.
```

## Report structure

1. **Summary** — one paragraph: scope (what was reviewed), how it was reviewed
   (read + which scripts), and counts by severity.
2. **Findings** — ordered Critical → Low, using the schema above.
3. **Worth checking** — medium-confidence items with the exact thing to verify.
4. **Not reviewed / limitations** — files, flows, or layers you didn't cover
   (e.g., "runtime Nginx/systemd config not provided", "no tests reviewed").

## What to exclude

Keep the signal high. Don't report:

- Pure denial-of-service theory, resource-exhaustion speculation, or
  rate-limit-tuning opinions (note anti-automation gaps only where they're a
  real authz/abuse issue).
- Secrets that are correctly loaded from the environment (flag secrets only when
  **hardcoded** or committed).
- Framework internals you can't see configured, unless the code clearly
  misconfigures them.
- Client/browser-only concerns with no server component.
- Style or performance issues with no security impact.

## Worked example

```
### [High] Object endpoint returns any user's invoice (IDOR)
- Location: billing/views.py:42
- Category: Broken Object Level Authorization | CWE-639 | OWASP A01:2025, API1:2023
- Confidence: High
- Problem: InvoiceDetail uses Invoice.objects.all() as the queryset and looks up
  by pk from the URL, with permission_classes = [IsAuthenticated]. Authentication
  is checked but ownership is not, so any logged-in user can read /invoices/<id>/
  for any id.
- Impact: Authenticated horizontal privilege escalation; full read access to
  other tenants' billing records by incrementing the id.
- Fix: scope the queryset to the requester.

    class InvoiceDetail(RetrieveAPIView):
        serializer_class = InvoiceSerializer
        permission_classes = [IsAuthenticated]

        def get_queryset(self):
            return Invoice.objects.filter(account=self.request.user.account)
```
