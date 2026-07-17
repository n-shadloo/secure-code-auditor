# A05:2025 — Injection

SQL/ORM, OS command, template, header/email injection, and server-side output
handling (XSS from server-rendered content).

## Contents
- [Principle](#principle)
- [SQL and the ORM](#sql-and-the-orm)
- [The dictionary-expansion column-alias class](#the-dictionary-expansion-column-alias-class)
- [OS command injection](#os-command-injection)
- [Template injection and server-side output](#template-injection-and-server-side-output)
- [Header and email injection](#header-and-email-injection)
- [XML / deserialization pointers](#xml--deserialization-pointers)
- [Review checklist](#review-checklist)

## Principle

Injection happens when untrusted input is interpreted as code — SQL, a shell
command, a template, a header, a query language. The universal defense is to
**keep data and code separate**: use parameterized/prepared statements and safe
APIs so input is always a value, never syntax. Where an API can't parameterize
(dynamic identifiers, table/column names), constrain input to a strict allowlist.
Validate input for shape, but never rely on validation *instead of*
parameterization.

## SQL and the ORM

Django's ORM parameterizes by default and is safe for normal queries. The risk
is in the escape hatches. Investigate these:

```python
# Wrong: string-built SQL
User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % name)
cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")
Model.objects.extra(where=[f"name = '{name}'"])
```

```python
# Correct: parameters, never interpolation
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
cursor.execute("SELECT * FROM t WHERE id = %s", [user_id])
Model.objects.filter(name=name)  # prefer the ORM
```

- `.raw()`, `RawSQL`, `cursor.execute`, and `.extra()` are the danger zone; treat
  any Python string formatting (`%`, f-string, `.format`) that reaches them as a
  lead. Parameter placeholders are `%s` for all backends here (the DB-API driver
  binds them safely).
- `.extra()` is legacy and easy to misuse; prefer expressions
  (`Func`, `Value`, `annotate`) which parameterize.

## The dictionary-expansion column-alias class

Django's recent CVE history is dominated by one pattern worth encoding as a
first-class check regardless of version: **user-controlled keys/aliases expanded
into ORM calls**. The stream runs from CVE-2022-28346 through 2025 (CVE-2025-64459,
CVE-2025-13372) and into 2026 (CVE-2026-1287, CVE-2026-1312) — control characters
or crafted keys in column aliases reaching `annotate()`, `aggregate()`, `alias()`,
`extra()`, `values()`, `values_list()`, `order_by()`, and dict-expansion into
`filter()`/`Q()`.

Flag code that lets a user name an aggregate/column or supplies the keys here:

```python
# Wrong: user controls the alias/column keys
qs.annotate(**{request.GET["label"]: Count("id")})
qs.order_by(request.GET["sort"])            # unvalidated column name
Model.objects.filter(**request.data)         # dict expansion from the client
```

```python
# Correct: allowlist the identifiers
ALLOWED_SORT = {"created", "-created", "name", "-name"}
sort = request.GET.get("sort", "created")
if sort not in ALLOWED_SORT:
    sort = "created"
qs.order_by(sort)
```

Keeping Django patched matters (the framework hardens these), but the durable fix
is to never route client-controlled identifiers into these methods.

## OS command injection

```python
# Wrong
subprocess.run(f"convert {filename} out.png", shell=True)
os.system("ping " + host)
```

```python
# Correct: no shell, arguments as a list
subprocess.run(["convert", filename, "out.png"], shell=False, check=True)
```

Avoid `shell=True` with any dynamic content; pass an argument list so the OS
never re-parses a string. Treat `os.system`, `eval`, and `exec` on
request-influenced data as high-severity leads.

## Template injection and server-side output

- Django templates **autoescape HTML by default**. The bypasses are `|safe`,
  `mark_safe()`, `{% autoescape off %}`, and misuse of `format_html`. Never pass
  attacker-controlled content through them. Use `format_html("{}", value)` (it
  escapes args) rather than `mark_safe(f"...{value}...")`.
- **Jinja2 does not autoescape unless configured.** If the project uses Jinja2,
  confirm `autoescape=True`. Never build a template string from user input and
  render it — that's server-side template injection (SSTI), which can reach RCE.
- Autoescaping does not cover unquoted HTML attributes, `javascript:` URLs, or
  data injected into `<script>`; emit JSON to templates with
  `json_script` rather than interpolating it.

## Header and email injection

- Build emails with Django's mail classes; never interpolate user data into
  headers (To/From/Subject) — newline injection lets an attacker add headers.
- Don't reflect unvalidated input into response headers (`Location`, custom
  headers). Django validates header values, but user-derived redirect targets
  still need the open-redirect check from A01.
- For reset, magic-link, invite/share, mailbox-flooding, and preview-fetch abuse,
  see the email and notification design controls in A06.

## XML / deserialization pointers

Parsing untrusted XML with the stdlib is XXE/entity-expansion-prone; use
`defusedxml`. Untrusted `pickle`/`yaml.load` is remote code execution — that's
covered in A08 (Integrity and Deserialization); cross-check there.

## Review checklist

- [ ] No string-formatted SQL in `.raw()`/`extra()`/`RawSQL`/`cursor.execute`;
      parameters used throughout.
- [ ] No client-controlled column names/aliases/keys into
      `order_by/annotate/aggregate/values/filter(**...)`.
- [ ] No `shell=True`, `os.system`, `eval`, or `exec` on request data.
- [ ] Autoescaping intact; `mark_safe`/`|safe`/Jinja2 autoescape verified; no
      template built from user input.
- [ ] Email/response headers not built from raw user input; XML via `defusedxml`.
