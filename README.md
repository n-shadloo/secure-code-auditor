# secure-code-auditor

A Claude Agent Skill for backend security work. It reviews existing code for
vulnerabilities and applies secure defaults while new code is written. The
deep specialty is Django and Django REST Framework; underneath that sits a
general OWASP layer that applies to any backend stack, so the same skill is
useful whether or not you're on Django.

## Why this exists

Backend security review is repetitive and easy to do inconsistently. The high-
risk areas — access control, injection, auth and tokens, serializer exposure,
secrets, deployment settings — are well understood, but they're spread across a
lot of documentation and they change (Django ships security releases regularly).
This skill packages that knowledge so an agent applies it the same way every
time, and points a reviewer straight at the parts that matter.

It's organized on the OWASP Top 10 (2025) as a spine. Each category has two
layers: a short, stack-agnostic explanation of the vulnerability and its defense,
then a deep Django/DRF section with the actual settings, code, and gotchas.

## What it covers

- Access control: object- and function-level authorization, IDOR/BOLA,
  cache-mediated data leaks, SSRF, open redirect, multi-tenancy, admin exposure.
- File uploads: type/content validation, safe names and inert storage/serving,
  SVG, image/archive bombs, size/count limits, quotas, private downloads.
- Injection: SQL/ORM (including the recent column-alias class), command,
  template, and header injection; server-side output handling.
- Auth: sessions, JWT/SimpleJWT, brute-force lockout, MFA, password reset,
  account enumeration, allauth/dj-rest-auth.
- API/DRF: serializer over-exposure and mass assignment, pagination/filter
  leakage, throttling, default permission classes, CSRF interaction, payments.
- Async/ASGI and Channels: safe ORM boundaries, request-context isolation,
  origin checks, and per-connection authentication, authorization, and limits.
- Abuse-resistant notifications: reset/magic-link, invite/share throttling,
  idempotency, anti-enumeration, and SSRF-safe previews.
- Configuration and crypto: the `SECURE_*`/`SESSION_*`/`CSRF_*` matrix, CORS,
  password hashing, secrets, signing.
- Integrity: insecure deserialization, Celery serializers, webhook verification,
  and safe schema/data migrations.
- Logging and lifecycle: secret-safe audit logs, complete lifecycle coverage,
  post-commit side effects, error handling, and alerting.
- Deployment/runtime: TLS, headers, reverse-proxy trust, Gunicorn/systemd,
  origin-isolated media, caching, and brokers.
- Supply chain: pinning, hashing, scanning, EOL frameworks.

Version baseline is kept current (Django 6.0.7 / 5.2.16 LTS; DRF 3.17.1;
SimpleJWT 5.5.1; Channels 4.3.2, as of 16 Jul 2026), and it flags projects on
end-of-life Django.

## Install

The repository is a plain-Markdown Agent Skill. The canonical instructions live
in the root `SKILL.md`, which routes to the files under `references/`. Claude
reads the skill directly. Cursor and OpenAI Codex CLI reuse the same canonical
content through their native discovery mechanisms, while Gemini CLI reads a
`GEMINI.md` context file. Nothing needs to be built; there are no dependencies
beyond `git`.

### Claude

One project:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  .claude/skills/secure-code-auditor
```

All your projects:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  ~/.claude/skills/secure-code-auditor
```

For claude.ai or the API, upload the folder as a custom skill in Settings.

### Codex CLI

Codex CLI discovers Agent Skills from the `.agents/skills/` directory and uses
the bundled pointer skill to load the canonical `SKILL.md`.

One project:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  .agents/skills/secure-code-auditor
```

All your projects:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  ~/.agents/skills/secure-code-auditor
```

`AGENTS.md` provides project-wide context, while the pointer skill forwards to
the canonical instructions in the repository root.

### Cursor

Cursor natively supports Agent Skills, so the same repository works:

```bash
git clone https://github.com/n-shadloo/secure-code-auditor.git \
  .cursor/skills/secure-code-auditor
```

The included `.cursor/rules/secure-code-auditor.mdc` file is optional
reinforcement that points back to the canonical `SKILL.md`.

### Gemini CLI

Gemini CLI doesn't read Agent Skills directly; it reads `GEMINI.md`.

- **Per project:** copy `GEMINI.md` into the repository root.
- **All projects:** copy it to `~/.gemini/GEMINI.md`.

`GEMINI.md` points Gemini to the canonical `SKILL.md` and `references/`
instead of duplicating the content.

The only requirement is `git` and a Git repository to run in.

## Use

Two modes, chosen from context.

Review an existing codebase — ask for a security review, or point it at code:

```
Review this Django app for security issues before we ship.
```

You'll get findings ordered by severity, each with a location, a CWE and OWASP
mapping, the concrete problem, the impact, and a fix. For fast triage there are
two read-only helper scripts (no network access, they don't run your project):

```
python scripts/settings_scan.py config/settings/production.py
python scripts/dangerous_patterns.py .
```

Write new code — it applies secure defaults as it goes (parameterized queries,
scoped querysets, explicit serializer fields, correct cookie flags, secrets from
the environment) and notes the security-relevant choices it made.

## Example finding

```
### [High] Object endpoint returns any user's invoice (IDOR)
- Location: billing/views.py:42
- Category: Broken Object Level Authorization | CWE-639 | OWASP A01:2025, API1:2023
- Confidence: High
- Problem: InvoiceDetail uses Invoice.objects.all() and looks up by pk from the
  URL with permission_classes = [IsAuthenticated]. Authentication is checked but
  ownership is not, so any logged-in user can read /invoices/<id>/ for any id.
- Impact: Authenticated horizontal privilege escalation; read access to other
  accounts' billing records by incrementing the id.
- Fix: scope the queryset to the requester.

    def get_queryset(self):
        return Invoice.objects.filter(account=self.request.user.account)
```

## Notes

The scripts need only the Python standard library (3.9+). Findings from the
scripts are indicators to verify, not confirmed vulnerabilities. Security is not
a checklist you finish; treat this as a strong, current baseline, not a guarantee.
The skill version is recorded in SKILL.md frontmatter (`metadata.version`); releases are tagged in git.

## Layout

```text
secure-code-auditor/
├── SKILL.md                            # canonical skill and router
├── AGENTS.md                           # always-on project context
├── GEMINI.md                           # Gemini CLI context
├── .cursor/
│   └── rules/
│       └── secure-code-auditor.mdc     # Cursor reinforcement rule
├── references/
│   ├── 00-methodology-and-severity.md  # methodology and findings format
│   ├── a01-broken-access-control.md
│   ├── a02-security-misconfiguration.md
│   ├── a03-software-supply-chain.md
│   ├── a04-cryptographic-failures.md
│   ├── a05-injection.md
│   ├── a06-insecure-design.md
│   ├── a07-authentication-failures.md
│   ├── a08-integrity-and-deserialization.md
│   ├── a09-logging-and-alerting.md
│   ├── a10-exceptional-conditions.md
│   ├── api-drf-specific.md
│   ├── async-and-channels.md
│   ├── deployment-and-runtime.md
│   ├── file-uploads.md
│   └── security-hardening-libraries.md
├── scripts/
│   ├── dangerous_patterns.py           # read-only project scanner
│   ├── settings_scan.py                # read-only Django settings scanner
│   └── README.md
├── README.md
├── LICENSE
└── .gitignore
```

## License

MIT. See `LICENSE`.
