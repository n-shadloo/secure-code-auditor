# A05:2025 — Injection

This file is the sink inventory for the whole skill. It covers SQL and the
ORM, including the GeoDjango lookup positions the ORM does not parameterize.
It covers OS command, template, directory, and header and email injection. It
covers server-side output handling, which is XSS from server-rendered content.
It covers the exported file whose interpreter runs on the reader's machine. It
also gives the method that traces a source to any of them.

The inventory is exhaustive. Thus a file that defers to it can rely on a
complete list rather than keep a partial copy. This file owns four sinks
outright, and duplicates them nowhere: SQL, the shell, server-side output, and
the spreadsheet reader an export writes for. The rest point outward to the
file that owns the rules.

`data-layer-and-database.md` owns the raw-path enumeration and document-store
shape validation. `file-uploads.md` owns the storage key an upload lands
under. `a01-broken-access-control.md` owns SSRF and the filesystem path a
request names. `a08-integrity-and-deserialization.md` owns deserialization.
`a09-logging-and-alerting.md` owns the log line.

## Contents
- [Principle](#principle)
- [Tracing input to a sink](#tracing-input-to-a-sink)
- [SQL and the ORM](#sql-and-the-orm)
- [The dictionary-expansion column-alias class](#the-dictionary-expansion-column-alias-class)
- [GeoDjango raster and spatial lookups](#geodjango-raster-and-spatial-lookups)
- [OS command injection](#os-command-injection)
- [Template injection and server-side output](#template-injection-and-server-side-output)
- [Directory and LDAP injection](#directory-and-ldap-injection)
- [Header and email injection](#header-and-email-injection)
- [Export channels and formula injection](#export-channels-and-formula-injection)
- [XML / deserialization pointers](#xml--deserialization-pointers)
- [Review checklist](#review-checklist)

## Principle

Injection happens when an interpreter reads untrusted input as code. That
interpreter is SQL, a shell command, a template, a header, or a query
language. The universal defense is to **keep data and code separate**. Use
parameterized or prepared statements and safe APIs, so that input is always a
value and never syntax. Where an API cannot parameterize, such as for a
dynamic identifier or a table or column name, constrain the input to a strict
allowlist. Validate input for shape, but never rely on validation *instead of*
parameterization.

Untrusted means untrusted, whatever the origin. Text a model generated is the
same input class as a request body once it reaches any sink below. Text a
model retrieved from a document or a web page is the same class. See
`agent-and-llm-interfaces.md`, "Model output as an injection source".

## Tracing input to a sink

### Principle layer

A **sink** is any call where data leaves the application's own semantics and
goes to something that interprets it. That interpreter is a SQL engine, a
shell, a template compiler, or a directory server. It is also a path resolver,
an HTTP client, a deserializer, a log line, or a response header. Injection is
the same defect at every one of them. Attacker-influenced content changes what
the operation *means*, not only what it operates on. That is why the defense is
one discipline and not a dozen.

A finding needs three things established, in this order.

**Sources.** Untrusted input is more than the request body. It includes
`request.GET`, `request.POST`, `request.data`, `request.query_params`,
`request.FILES`, headers, cookies, and URL keyword arguments. It also includes
any free-text field in DRF's `validated_data`, and WebSocket and consumer
messages. It includes model fields populated from any of those earlier, and
text a model generated or retrieved. Validation upstream narrows what a source
can contain. It does not make the source trusted, because the sink is where the
interpreter assigns meaning.

A source is anything that crosses the process boundary. Four of them sit
outside the request. The first is the body of a response the application
fetched from another system. A webhook, an identity provider, and a partner API
all send one, and a signature on it proves only the sender. The second is the
content of a file the application parses. The third is an environment or
settings value, and the fourth is the output of another program.

**Sinks.** Enumerate every interpreter the request can reach. The inventory
below is that list. One location for it is the point. A reference that defers
here relies on a complete list rather than restates a partial copy.

**The path between them.** Follow each source through assignment, function
parameters, and every construction that joins it to text the developer wrote.
Those constructions are f-strings, `%`, `.format()`, `+`, `join()`, and
dictionary expansion (`**`). A value that arrives at a sink as one of those
constructions is the vulnerability. A value that arrives as a bound parameter,
an element of an argument vector, a template context value, or an escaped term
is not. That distinction, not the presence of the sink, separates a lead from
a finding.

Reviews miss the second-order paths, because the source and the sink sit in
different requests. A name is stored today, and rendered, logged, fetched, or
compiled tomorrow. A stored field is as tainted as its worst writer, not as
the handler you happen to be reading.

### Django & DRF implementation layer

Each row gives a sink family, what reaches it, the form that keeps the input
as data, and where this skill keeps the rules. This table lists a sink whose
rules live elsewhere as well, so that a reviewer has to consult only this
inventory.

| Interpreter or effect | Reached through | Form that stays data | Rules |
|---|---|---|---|
| SQL | `Manager.raw()`, `QuerySet.extra()`, `RawSQL`, `cursor.execute()`/`executemany()`/`callproc()`, and `Func`/`Expression` subclasses whose `template` or `function` is built from input | a `%s` placeholder plus a `params` sequence | "SQL and the ORM"; the raw-path list to enumerate during review is in `data-layer-and-database.md`, "Raw SQL as an isolation bypass" |
| SQL identifiers | keyword names and dictionary keys expanded into `annotate()`, `aggregate()`, `alias()`, `values()`, `values_list()`, `filter()`, `exclude()`, `get()`, `Q()`, `order_by()` | a fixed server-side allowlist; identifiers cannot be parameterized | "The dictionary-expansion column-alias class" |
| A spatial lookup's non-value positions | a band index spliced into a `RasterField` lookup path or into the tuple on its right-hand side, and a `str`, `pathlib.Path`, or `dict` given as a spatial lookup value | an `int` band index taken from a server-side set, and a raster source wrapped in `GDALRaster` explicitly | "GeoDjango raster and spatial lookups" |
| Document-store query | a JSON value that arrives as a dict where a scalar was expected, becoming an operator | validate shape and type, not characters | `data-layer-and-database.md`, "NoSQL and key-value injection" |
| Shell | `os.system`, `os.popen`, `subprocess` with `shell=True`, any command assembled as a string | an argument list with `shell=False` | "OS command injection" |
| A program's own option parser | a value that reaches `argv` and begins with `-` | `--` before the positional arguments | "OS command injection" |
| Python | `eval`, `exec`, `compile` on request-influenced text | none; remove the call | "OS command injection" |
| HTML | `mark_safe()`, `SafeString`, `\|safe`, `\|safeseq`, `{% autoescape off %}`, misused `format_html`, a string handed to `HttpResponse` | autoescaped template output, or `format_html("{}", value)` | "Template injection and server-side output" |
| Markdown | a renderer that permits raw HTML, and its rendered result handed on as trusted markup | a renderer with raw HTML off, and `nh3` over the result where rich text is the feature | "Template injection and server-side output" |
| Template compiler | `Template(...)` or `Engine.from_string(...)` on a string the user supplied | a template file in the repository, with user data in the context | "Template injection and server-side output" |
| Template loader | a template name a request chooses, in `render()`, `get_template()`, `render_to_string()`, or `{% include %}` with a variable | a name resolved through a server-side mapping | "Template injection and server-side output" |
| Directory server | an LDAP filter string built by interpolation | `escape_filter_chars` on every assertion value | "Directory and LDAP injection" |
| Response and mail headers | `response[name] = value`, `EmailMessage` header fields, `send_mail` arguments, and a value a bare `DomainNameValidator` call cleared below 6.0.7 or 5.2.16 | reject CR and LF before construction, and take the cleaning from a form or serializer field rather than from the validator | "Header and email injection" |
| A spreadsheet reader, off the server | a cell an export writes whose value begins with `=`, `+`, `-`, `@`, a tab, or a carriage return | the value rejected where it is written, or a cell given an explicit text type — quoting is not it | "Export channels and formula injection" |
| Log line | any value interpolated into a log message | structured fields, or control characters escaped in a formatter | `a09-logging-and-alerting.md`, "Log injection and integrity" |
| Filesystem path | `open()`, `os.path.join(base, value)`, `pathlib` joins, and storage names taken from the client | a server-chosen identifier resolved against a fixed base, by an API that rejects an escape rather than normalizing it | `a01-broken-access-control.md`, "Path traversal"; the name and key an upload brings are in `file-uploads.md`, "Filenames and storage keys" |
| Outbound HTTP | `requests`, `urllib`, `httpx`, `aiohttp` on a user-influenced URL | an allowlisted destination checked after DNS resolution, not a validated string | `a01-broken-access-control.md`, "SSRF" |
| Object deserializer | `pickle.loads`, `yaml.load`, `jsonpickle`, `marshal`, the model artifact `torch.load`, `joblib.load`, or `numpy.load` with `allow_pickle=True` unpickles, the cache, session, and fixture paths Django runs without being asked, and the task message a worker turns back into arguments | a format that cannot construct objects | `a08-integrity-and-deserialization.md`, "Insecure deserialization" and "Celery and task queues" |
| XML parser | DTDs, external entities, and entity expansion in submitted documents | a maintained parser with those features off, behind input limits | "XML / deserialization pointers" |

Two grep passes make this tractable on a real codebase. Search for the sink
names above. Then search near each hit for what carries input to them:
`request.`, `.data`, `validated_data`, `kwargs[`, `**`, `f"`, `.format(`, and
`%`. A sink with no source that reaches it is not a finding. A source that
reaches a sink through string construction almost always is.

The word "near" fails where a project wraps its sinks. Put `subprocess.run`
inside `utils/shell.py`, and every call site reads as `run_tool(...)`. The
first pass then finds the wrapper with no request near it. The second pass
finds the call sites with no sink name near them. Therefore search for the name
of each first-party wrapper as a sink name. An import alias and a `getattr`
dispatch hide a sink in the same way.

Walk the second-order path once in full, because the grep passes above find it
as two unrelated hits. A single stored field carries it, and that field is the
only thing the two halves have in common:

```python
# Wrong: three moments, one bug. The serializer that writes `label` contains no
# sink, and the job that reads it back contains no request, so each half
# reviews clean on its own and neither reviewer sees the path between them.
import subprocess

from django.db import models
from rest_framework import serializers


class Report(models.Model):
    label = models.CharField(max_length=200)


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ["id", "label"]


def render_nightly(report):
    subprocess.run(f"wkhtmltopdf --title {report.label} out.pdf", shell=True)
```

```python
# Correct: the stored field is treated as the source it is, at both ends. The
# validator constrains what the serializer writes, and the argument list holds
# whatever the column already contains -- because the writer and the reader
# change on different days, and the reader cannot see which writer ran.
import subprocess

from django.core.validators import RegexValidator
from django.db import models
from rest_framework import serializers


class Report(models.Model):
    label = models.CharField(
        max_length=200,
        validators=[RegexValidator(r"\A[\w .-]+\Z")],
    )


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ["id", "label"]


def render_nightly(report):
    subprocess.run(
        ["/usr/bin/wkhtmltopdf", "--title", report.label, "out.pdf"],
        shell=False,
        check=True,
        timeout=60,
    )
```

Read the fix as two independent controls, rather than as one control applied
twice. The validator reaches the paths that call `full_clean()`, which are a
form, the admin, and a serializer that DRF builds from the model. The argument
list holds when a later migration, a management command, an admin edit, or a
data import writes the same column without the serializer. Neither one is
sufficient. A stored field is as tainted as its worst writer, and the worst
writer is rarely the one in front of you.

**A model validator is not a control on the column.** `Model.save()` does not
call it. Neither does `bulk_create()`, `QuerySet.update()`, `get_or_create()`,
a data migration, or raw SQL. Checked against Django 6.0.7 on 27 August 2026.
Therefore never close a sink finding because the model field carries a
`validators` argument. A `CheckConstraint` on the model is the control the
database applies to every writer, and the sink-side control has to hold in any
case.

The worst writer can also sit outside this repository. Another service, a
data-import job, or an operator with a database client writes the same table.
No grep in this working tree finds any of them. Ask whether another writer
shares the database, rather than assume this repository holds them all.
`01-audit-workflow.md`, "Phase 0 — scope, mode, and what the repository cannot
tell you" holds that rule.

One property of the source itself breaks the trace before it reaches any sink.
**A parameter can arrive more than once, and which value a reader sees depends
on how it reads.** `request.GET`, `request.POST`, and DRF's `query_params` are
`QueryDict` instances. Subscripting and `.get()` return the **last**
occurrence, and `.getlist()` returns all of them. A request that carries
`?next=/dashboard&next=//attacker.example` therefore presents two different
values to two pieces of code that both look correct in isolation. The defect
is that the value which was checked is not the value that was used:

```python
# Wrong: the guard and the redirect each read the parameter on their own line,
# and getlist() and subscripting do not agree about which occurrence they mean.
# The guard passes if any value is allowed; the redirect then goes to the last
# one. Reversing which side calls getlist() is the same bug mirrored.
from django.utils.http import url_has_allowed_host_and_scheme

if any(
    url_has_allowed_host_and_scheme(candidate, allowed_hosts={request.get_host()})
    for candidate in request.GET.getlist("next")
):
    return redirect(request.GET["next"])
```

```python
# Correct: one read, bound to a name, and every later use is that name. Where a
# parameter is genuinely single-valued, rejecting the duplicate is better than
# silently picking an occurrence, because a caller sending two never meant one.
from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.utils.http import url_has_allowed_host_and_scheme

values = request.GET.getlist("next")
if len(values) > 1:
    raise SuspiciousOperation("duplicate 'next' parameter")
target = values.pop() if values else settings.LOGIN_REDIRECT_URL
if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
    target = settings.LOGIN_REDIRECT_URL
return redirect(target)
```

The pattern generalizes past redirects to any parameter a security decision
reads: a tenant identifier, an object id, an amount, or a scope. It also
reaches outward. Where a gateway, a WAF, or a proxy inspects a request before
Django does, that component picks an occurrence by its own rule. Nothing
guarantees it is the one Django will read. This repository does not show which
occurrence the edge chooses. Carry it as a question to whoever operates the
edge, rather than assume an answer. `01-audit-workflow.md`, "Phase 0 — scope,
mode, and what the repository cannot tell you" holds that rule.

**Write-time.** When you generate a handler that reads a query or form
parameter a security decision depends on, read it once into a local name. Use
that name everywhere. Reject a duplicate outright where the parameter is
single-valued. A check and a use can each read the `QueryDict` on their own
line. They then read two different values the moment a caller sends the
parameter twice.

### Tracing review checklist

#### Stack-neutral

- [ ] Sources are enumerated beyond the request body, including stored fields
      and model-generated text, before any sink is judged.
- [ ] Each source is followed to every sink it reaches, and the construction
      that joins it to developer-written text is named in the finding.
- [ ] A first-party wrapper around a sink is searched under its own name, so
      that the sink and its callers are not judged as two clean halves.
- [ ] Stored-then-used paths are traced across requests, not only within the
      handler under review. A writer outside this repository was asked about,
      rather than assumed absent.

#### Django & DRF

- [ ] The inventory above was walked, rather than only the sink family the
      feature obviously uses.
- [ ] Sinks whose rules live in another reference were followed there rather
      than judged locally against a partial rule.
- [ ] DRF `validated_data` is treated as a source: serializer validation
      constrains shape, and does not make a value safe at a sink.
- [ ] No sink finding is closed because the model field carries a `validators`
      argument. That validator does not reach `save()`, `bulk_create()`,
      `QuerySet.update()`, a data migration, or raw SQL.
- [ ] A parameter a security decision reads is read once from the `QueryDict`
      and reused by name. Thus nobody can validate one occurrence of a
      duplicated parameter and act on another.

## SQL and the ORM

Django's ORM parameterizes **values** by default, and it is safe for normal
queries. State the guarantee that precisely, because readers routinely stretch
it two ways it does not cover. It does not reach identifiers, where a column,
alias, or sort key goes into the statement as syntax rather than binds as a
value. That is the next section, and it is where Django's own recent
SQL-injection history sits. The guarantee also stops entirely at the escape
hatches. Investigate these:

```python
# Wrong: the value is spliced into the statement, so a quote in `name` ends the
# string literal and everything after it is parsed as SQL.
from django.contrib.auth.models import User
from django.db import connection

from .models import Model

User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % name)
with connection.cursor() as cursor:
    cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")
Model.objects.extra(where=[f"name = '{name}'"])
```

```python
# Correct: the driver binds each value after the statement is parsed, so no
# input can add syntax. Note the placeholder is unquoted -- '%s' inside quotes
# is string formatting again, not a bind parameter.
from django.contrib.auth.models import User
from django.db import connection

from .models import Model

User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM t WHERE id = %s", [user_id])
Model.objects.filter(name=name)  # prefer the ORM
```

- `.raw()`, `RawSQL`, `cursor.execute`, and `.extra()` are the escape hatches.
  Treat any Python string formatting (`%`, f-string, `.format`) that reaches
  them as a lead. Parameter placeholders are `%s` for all backends here, and
  the DB-API driver binds them safely.
- `.extra()` is worse than legacy. Django's own queryset reference calls it an
  old API to use as a last resort, aimed for deprecation. It states that the
  project no longer improves it or fixes bugs in it. Thus even a correctly
  parameterized `extra(where=["headline=%s"], params=[value])` builds on a SQL
  layer nobody maintains. Prefer expressions (`Func`, `Value`, `annotate`),
  which parameterize. Treat a newly written `.extra()` call as a finding of
  its own, rather than wait for the interpolation bug in it.
- A raw path is a **double** escape hatch. Beside injection, it bypasses the
  tenant-scoping manager and any row-level-security context the ORM path would
  have carried. Thus a perfectly parameterized raw query can still return
  another tenant's rows. Audit every hit for isolation as well as for
  injection. See `data-layer-and-database.md`, "Raw SQL as an isolation
  bypass".

**Write-time.** When you generate a query, express it with ORM methods, and
let the ORM bind the values. Where raw SQL is genuinely required, write the
statement with unquoted `%s` placeholders, and pass the separate `params`
sequence in the same edit. A placeholder added later to a string that already
interpolates is a rewrite nobody schedules. Do not use `.extra()` at all, on
the reasoning above: a new call there starts life on a SQL layer Django has
stopped fixing.

Injection is not SQL-only. A document store takes its query as a structured
object. Thus a JSON body value that arrives as a dict rather than as a scalar
becomes a query *operator*. There is no string concatenation, and nothing for
escaping to correct. Validate shape, not only characters
(`data-layer-and-database.md`, "NoSQL and key-value injection").

### Commonly mistaken for a finding

**`cursor.execute("... WHERE id = %s", [value])`, and `Manager.raw(sql,
params)` in the same shape.** It looks like the wrong example above, because
`%s` is the same two characters Python's `%` operator uses. A reviewer who
scans for interpolation lands on both. It is the opposite. `%s` is the
placeholder the DB-API requires. The driver binds the separate `params`
sequence after the statement is already parsed, which is exactly the control
this section asks for.

The deciding question is never whether the string contains `%s`. The question
is whether the code *builds* the SQL string. It builds it by an f-string, `%`
interpolation, `.format()`, or concatenation with anything that is not a
literal constant. A static statement with a params argument is the correct form
of the call. A report of it is the highest-volume false positive available in a
Django codebase.

## The dictionary-expansion column-alias class

One pattern dominates Django's recent CVE history, and it is worth a
first-class check whatever the version: **user-controlled keys and aliases
expanded into ORM calls**. The stream runs from CVE-2022-28346 through 2025
(CVE-2025-64459, CVE-2025-13372) and into 2026 (CVE-2026-1287, CVE-2026-1312).
In each one, control characters or crafted keys in column aliases reach
`annotate()`, `aggregate()`, `alias()`, `extra()`, `values()`,
`values_list()`, `order_by()`, or dict-expansion into `filter()` and `Q()`.

Flag code that lets a user name an aggregate or a column, or that lets a user
supply the keys here:

```python
# Wrong: the client names the identifier, and an identifier is syntax -- there
# is no placeholder that can bind it.
from django.db.models import Count

from .models import Model

qs.annotate(**{request.GET["label"]: Count("id")})
qs.order_by(request.GET["sort"])            # unvalidated column name
Model.objects.filter(**request.data)         # dict expansion from the client
```

```python
# Correct: the client picks from a set the server wrote, so the value that
# reaches the ORM was never attacker-authored in the first place.
ALLOWED_SORT = {"created", "-created", "name", "-name"}
sort = request.GET.get("sort", "created")
if sort not in ALLOWED_SORT:
    sort = "created"
qs.order_by(sort)
```

A patched Django matters, because the framework hardens these methods. The
durable fix is to never route a client-controlled identifier into them.

### Commonly mistaken for a finding

**`.filter(**data)` where `data` is a serializer's `validated_data`.** The
double asterisk is the signature of the class above, so the call reads as the
wrong example on sight. Client-controlled *keys* are what make this class
dangerous, and a serializer with a declared field set supplies the keys
itself. `validated_data` can carry only the top-level names the serializer
declared, whatever the request body contained.

The deciding question is therefore where the keys come from, not where the
values come from. A serializer with `fields = "__all__"`, a bare
`request.data`, and a dictionary assembled from query parameters all fail it.
A declared field set passes, and it closes the top-level names only.

**A declared name can still hold client-authored keys.** `DictField`,
`JSONField`, and `HStoreField` accept whatever keys the body carried, inside a
field the serializer declared. Checked against DRF 3.17.1 on 27 August 2026.
Therefore the carve-out applies only where every value that reaches the
expansion is a scalar. A `filter(**validated_data["filters"])` over a declared
`DictField` is the wrong example again, with one more level between the client
and the call.

**Write-time.** When you generate a filter, an update, or an aggregate from
`**`-expansion, declare the serializer's `fields` explicitly in the same edit
that writes the expansion. The expansion is safe exactly as far as the key set
is closed, and nothing at the call site shows whether it is.

## GeoDjango raster and spatial lookups

In GeoDjango the ORM's parameterization guarantee stops being a question about
escape hatches. It becomes a question about positions inside an ordinary
`filter()` call. Two positions in a spatial lookup do not take a bound value,
and Django's 2026 record has one CVE for each of them.

**A band index is syntax, not a value.** Raster lookups on a `RasterField` are
implemented only on the PostGIS backend. They take a band index on the left of
the lookup (`rast__1__contains=geom`), or as the second element of a tuple on
the right (`rast__contains=(rst, 1)`). Django inlined that index into the
generated SQL instead of binding it. Thus an index derived from a request was
a SQL-injection sink. That is CVE-2026-1207, rated high, fixed in Django
6.0.2, 5.2.11, and 4.2.28 on 3 February 2026.

The patch closes the framework's half. The durable half is that a band index
sits in an identifier position exactly as a column alias does. Coerce it to an
`int`, or choose it from a server-side set, before it reaches the lookup,
under the same rule as the section above.

**A lookup value can be a raster source rather than a value.** Spatial lookups
also accepted `str`, `pathlib.Path`, and `dict` on the right-hand side, and
passed them to `GDALRaster`. `GDALRaster` opens or creates a datasource
through a GDAL driver. A `dict`, or a JSON string that Django parses into one
first, creates a new raster. That write puts a file with an attacker-chosen
name and contents on disk. It reaches remote code execution where that file
lands somewhere the application later loads.

Django opens a bare `str` as a datasource, so a GDAL virtual-filesystem path
such as `/vsicurl/...` issues an outbound request as the Django process user.
That is CVE-2026-15307, rated high, fixed in Django 6.0.8 and 5.2.17 on 4
August 2026.

The write is a side effect of the driver that opens the datasource, rather
than of a flag somebody left on. `GDALRaster` always opens a new raster in
write mode. The constructor's `write=False` default never governed the open at
all, so there was nothing to disable.

Reachability is wider than "a view that accepts a raster". The admin
changelist takes lookups from query parameters, subject only to
`ModelAdmin.lookup_allowed()`. Thus on any model registered with the admin
that carries a spatial field, a staff user with nothing beyond *view*
permission could reach the lookup. Treat a spatial field on a registered model
as reachable by every staff account, rather than by whoever wrote the view.

The fix is an opt-in signal rather than a sanitizer. Django now rejects `str`,
`Path`, and `dict` in a lookup with `DisallowedRasterLookup`, a
`SuspiciousOperation` subclass, which Django renders as a 400. A value wrapped
in `GDALRaster(...)` is how a project states that this particular source is
trusted. Django still accepts `bytes` unwrapped, because they open through
GDAL's in-memory virtual filesystem rather than through the disk or the
network.

Django leaves assignment deliberately unchanged. A `dict` assigned to a
`RasterField` still opens a new raster, and a `str` or `Path` assigned to one
still fetches the referenced raster. Thus an upgrade closes the lookup path
and leaves every assignment from untrusted input exactly as dangerous as it
was. The `GeometryField` form field rejects rasters rather than validates them.

The assignment therefore needs a control the project writes. The signal is a
serializer field, a form field, or an admin form that binds a request value to
a `RasterField`. Reject `str`, `Path`, and `dict` in that field. Accept only a
source the server names. Then build the `GDALRaster` from that name, rather
than from the request.

Raw `bytes` are not a safe class either. They reach the same GDAL driver, and a
staff account reaches that driver through the changelist. GDAL's own guidance
on restricting the available drivers is the defense-in-depth layer under all of
it.

```python
# Wrong: the band index is spliced into the lookup path, where PostGIS raster
# lookups inline it as SQL rather than binding it. The right-hand value is a
# client-supplied string the lookup reads as a raster source -- opened through
# a GDAL driver before the fix, a 400 after it, and in both cases a request
# value the code is treating as trusted.
from .models import Elevation

band = request.GET["band"]
Elevation.objects.filter(**{f"rast__{band}__contains": geom})
Elevation.objects.filter(rast__contains=request.data["source"])
```

```python
# Correct: the band index is one of a set the server wrote, so nothing the
# client sends reaches the statement as syntax; the raster source is named by
# configuration and wrapped in GDALRaster, which is the wrap that says trusted
# rather than a wrap that makes an untrusted value safe.
from django.conf import settings
from django.contrib.gis.gdal import GDALRaster

from .models import Elevation

ALLOWED_BANDS = {"0", "1", "2"}

band = request.GET.get("band", "0")
if band not in ALLOWED_BANDS:
    band = "0"
Elevation.objects.filter(**{f"rast__{band}__contains": geom})
Elevation.objects.filter(
    rast__contains=GDALRaster(settings.REFERENCE_RASTER_PATH)
)
```

**Write-time.** When you generate a GeoDjango lookup, decide for each position
whether the ORM binds it or splices it. The two look identical at the call
site. Bind the geometry. Take the band index from a server-side set as an
`int`.

Where a raster genuinely has to come from outside the code, wrap it in
`GDALRaster(...)` in the same edit. The trust decision is then written down
where the value enters, rather than inferred later from the absence of an
exception. Where the feature does not actually need a caller-chosen band,
write the literal, and the whole position stops being an input.

## OS command injection

```python
# Wrong: the shell parses the assembled string, so `;`, `|`, backticks, and
# `$( )` in either variable are operators rather than characters.
import os
import subprocess

subprocess.run(f"convert {filename} out.png", shell=True)
os.system("ping " + host)
```

```python
# Correct: no shell exists to re-parse anything, and each element arrives at
# the program as exactly one argument however it is spelled.
import subprocess

subprocess.run(["convert", filename, "out.png"], shell=False, check=True)
```

Avoid `shell=True` with any dynamic content. Pass an argument list, so that
the OS never re-parses a string. Treat `os.system`, `eval`, and `exec` on
request-influenced data as high-severity leads.

An argument list closes the shell, not the program behind it. A value that
reaches `argv` is still read as an option if it begins with a dash, which
turns a filename into a flag. In a tool that can write files, load a config,
or run a helper from a flag, that reaches the same place a shell would. Where
the program supports it, end the option list before the untrusted arguments:

```python
# Wrong: a `pattern` of "--include=*" or a `name` of "-r" is an option here,
# because the program parses flags wherever they appear.
import subprocess

subprocess.run(["grep", pattern, name], shell=False, check=True)
```

```python
# Correct: everything after `--` is positional, whatever it starts with.
import subprocess

subprocess.run(
    ["/usr/bin/grep", "--", pattern, name],
    shell=False,
    check=True,
    timeout=30,
)
```

An argument list closes the shell. It does not close a program that is itself
an interpreter. `sh -c`, `bash -c`, and `python -c` read one argument and run
it as a program. `ssh host command` runs its argument on the far side. `find
-exec`, `xargs`, `psql -c`, and `mysql -e` each do it for their own language.
A call of that shape passes `shell=False`, an argument list, and `--` together,
and it is still complete command injection.

Therefore ask what the program does with each argument, rather than whether a
shell is present. The signal is an argument position that the program parses as
code. `-c`, `-e`, `--eval`, and a command that follows a host name are the
common spellings. Never put an untrusted value in one of them. Where a feature
needs a caller-named program, take the name from a server-side mapping, and
pass the untrusted value to it as data.

Bound the call as well as its arguments. Pass `timeout=`, so that a hostile
input cannot hold a worker. Name the binary by absolute path, rather than
inherit whatever `PATH` resolves to in the deployed environment. The
environment is a second argument channel, and the child reads names out of it
that no argument list shows. Pass an explicit `env=`. Never build the
environment from keys a request supplied.

**Write-time.** When you generate a call into another program, write the
argument list, `shell=False`, the `timeout`, the absolute path, the explicit
`env=`, and the `--` separator together. Each of them is a line a team adds
after an incident rather than during a refactor.

Apply the same discipline where there is no request in front of the code. A
management command's parsed arguments and a data migration's inputs reach
these same interpreters. That context usually carries more database privilege
than a view does. Bind and validate them as you would a request body. Do not
trust the value because an operator supplied it.

### Commonly mistaken for a finding

**`subprocess` with `shell=True` where every argument is a literal.** Every
scanner keys on the flag, and this section spends its length on a warning
about it. Thus a hit reads as confirmed before the reviewer reads the
arguments. Nothing varies here, so there is no input for the shell to re-parse
and no injection to report. The deciding question is whether any element of
the command comes from outside the source file. That element is a request, a
model field, an environment value, or a filename discovered on disk.

Where no element does, keep it as a hygiene note. The shell is still present
for the next edit to hand something to. Drop the injection claim, and the
severity that came with it.

**Write-time.** When you generate a call into another program whose arguments
are all literal today, still write the argument list with `shell=False`. Do
not write the string form. The argument that becomes dynamic arrives in a
later edit that changes what is passed, and not how it is passed.

## Template injection and server-side output

- Django templates **autoescape HTML by default**. The bypasses are `|safe`,
  `mark_safe()`, `{% autoescape off %}`, and misuse of `format_html`. Never
  pass attacker-controlled content through them. Use `format_html("{}",
  value)`, which escapes its arguments, rather than
  `mark_safe(f"...{value}...")`.
- **The Jinja2 library does not autoescape unless you configure it. Django's
  own Jinja2 template backend enables it**, and defaults `autoescape` to
  `True` in its options. Thus on a project that uses
  `django.template.backends.jinja2`, the finding is an explicit `"autoescape":
  False` in `OPTIONS`, or a bare `jinja2.Environment()` constructed outside
  the backend. The absence of the option is not the finding. Never build a
  template string from user input and render it, because that is server-side
  template injection (SSTI), which can reach RCE.
- Autoescaping does not cover an unquoted HTML attribute, a `javascript:` URL,
  or data injected into `<script>`. Emit JSON to a template with
  `json_script`, rather than interpolate it.
- **A template name is an input position too.** A request that chooses the name
  reaches every template the configured loaders can find, and it renders that
  template with the context of the view it landed in. Django's loaders reject a
  traversal outside their own directories, so the reach is the search path
  rather than the filesystem. Resolve the name through a server-side mapping,
  rather than build a path from the value.

When a product genuinely requires user-authored rich HTML, use an explicit
allowlist sanitizer, and still apply output-context encoding. `nh3==0.3.6`
passes the maintained-package gate as of 9 Aug 2026. Centralize its tag,
attribute, and URL-scheme policy. Test bypass payloads against it. Sanitize
again when the policy changes. A plain-text or structured-markup design stays
safer than accepted HTML.

Markdown is an output context too, and a renderer that permits raw HTML turns
user text into DOM. `markdown-it-py` permits it by default. The `commonmark`
preset that its constructor selects sets `html` to `True`, and `gfm-like` and
`gfm-like2` do the same. Construct it as `MarkdownIt("js-default")`, or pass
`{"html": False}` beside the preset the project needs.
`mistune.create_markdown()` escapes raw HTML by default, but the module-level
`mistune.html` renderer carries `escape=False`. Python-Markdown has no such
switch at all. `markdown.markdown()` passes raw HTML through, and the
`safe_mode` argument that once limited it went away at 3.0. Checked against
Python-Markdown 3.10.3 on 27 August 2026.

Escaping is not sanitization. Where rich text is the feature, render with raw
HTML off, and put the sanitizer above over the result. Where the renderer has
no such switch, the sanitizer over the output is the only control, and it
becomes load-bearing rather than defense in depth. Each claim here comes
from the project's own source, read on 20 Aug 2026.

### Commonly mistaken for a finding

**`mark_safe` over a string assembled only from constants, and `mark_safe` or
`|safe` applied to what `format_html` returned.** Both are escape-hatch
identifiers on the list above, and both are frequently correct. A string built
from literals the source file contains carries nothing a request authored.
`format_html` escapes each of its arguments through `conditional_escape`, so a
mark of its result as safe asserts what the call already did.

**`format_html` escapes an argument, unless the argument is already safe.**
`conditional_escape` returns any value that carries `__html__` unchanged, and a
`SafeString` carries it. Checked against Django 6.0.7 on 27 August 2026.
Therefore a `mark_safe()` further up the call chain travels through
`format_html` intact. The carve-out above then dismisses the `|safe` at the end
of that chain. It holds only where no argument reached the call as a
`SafeString`.

The deciding question is whether any value in the marked string reached it
from outside the source file. That includes a request, a model field, a
model's output, and any other outside source. One interpolated value is the
whole finding, and none of them is no finding at all.

**Write-time.** When you generate markup that mixes a fixed fragment with a
value, write `format_html("...{}...", value)` rather than `mark_safe` over an
assembled string. `format_html` escapes each argument at the call, and it
leaves the constant half visibly separate from the half that came from
somewhere else.

## Directory and LDAP injection

An LDAP filter is a query language with its own metacharacters. A directory is
one of the few interpreters a Django project reaches with no framework layer
in between. Code almost always assembles a filter as a string, which makes
this string concatenation in the oldest sense. A `*` in a username turns an
equality test into a wildcard match, which authenticates against the first
matching entry. A `)(` closes the current term, so an attacker can supply
their own. Maps to CWE-90.

```python
# Wrong: the value is part of the filter grammar, so it can add terms.
filterstr = f"(uid={username})"
```

```python
# Correct: escaped for the grammar first, so the value can only be a value.
import ldap.filter

filterstr = "(uid=%s)" % ldap.filter.escape_filter_chars(username)
```

- Escape every assertion value, including a value that came back from the
  directory rather than from a request. A group name read from LDAP and
  interpolated into the next filter is the second-order case.
- `escape_filter_chars` has a minimum safe version of its own. In
  `python-ldap` before 3.4.5, a `list` or `dict` passed as the assertion value
  under the non-default `escape_mode=1` could make it skip escaping
  (CVE-2025-61911, moderate). The fix type-checks the argument. Require
  `python-ldap>=3.4.5` even on the default escape mode, which was never
  affected, and pass a string.
- Prefer the maintained integration over a hand-built filter.
  `django-auth-ldap` escapes filter arguments through the same function, with
  escaping on by default. It does not install a patched `python-ldap` for you,
  because its own floor is `python-ldap>=3.1`. Pin that dependency separately.
  See `security-hardening-libraries.md`, "Recommended or conditional choices".
- A distinguished name is not a filter, and `escape_filter_chars` is the wrong
  function for one. Where code assembles a DN from input, escape for DN syntax
  with `ldap.dn.escape_dn_chars` instead. Prefer a DN found by a searched,
  escaped filter over a DN the code builds.

## Header and email injection

- Build emails with Django's mail classes. Never interpolate user data into a
  header such as To, From, or Subject, because newline injection lets an
  attacker add headers.
- Do not reflect unvalidated input into a response header such as `Location`
  or a custom header. Django does reject CR and LF on both paths, so the
  framework is not the gap. The exception is not the same object in each path,
  which is worth knowing before you write a handler for it. In `django.http`,
  `BadHeaderError` is a subclass of `ValueError`, raised when code sets a
  response header. In `django.core.mail`, the name is bound directly to
  `ValueError` itself, for compatibility with the error Python's email API
  already raises.

  A catch of `ValueError` covers both. A catch of `django.http.BadHeaderError`
  around mail code does not. In both paths an unhandled rejection is a 500.
  Therefore validate before you construct, rather than rely on the exception
  as the control.
- An HTML mail body is server-rendered output, and no autoescape reaches a body
  built by interpolation. `send_mail(html_message=...)` and
  `attach_alternative()` take the string as it is. Render the body from a
  template, or build it with `format_html`.
- A user-derived redirect target still needs the open-redirect check from A01.
  A rejection of newlines says nothing about where the `Location` points.
- For reset, magic-link, invite and share, mailbox-flooding, and preview-fetch
  abuse, see the email and notification design controls in A06.
- **A validator that returns without a raise is not a header-safety check.**
  `DomainNameValidator` accepted values that contain newlines below 6.0.7 and
  5.2.16. That is CVE-2026-53878, fixed 7 July 2026. Ordinary Django usage was
  never exposed. A `CharField` strips the leading and trailing whitespace that
  carried the newline, and `HttpResponse` rejects a newline on the way out.
  Both ends held even while the validator did not. That strip reaches the edges
  of the value only, and a CR or an LF inside it survives into `cleaned_data`.

  The exposure was code that called the validator directly on a raw request
  value. That code then treated the result as clean enough to build a header
  or an address from. That is the shape to look for. The validator is invoked
  outside a form or serializer field, on a value that came off the request.
  The header or `EmailMessage` construction is downstream of it, and nothing
  rejects CR and LF in between.

**Write-time.** When you generate validation for a hostname, domain, or
address a request supplies, put it behind a form or serializer field. Do not
call the validator on the raw value. The field's own cleaning removes the
leading and trailing whitespace a validator is not specified to reject, and a
bare call skips that cleaning. A strip does not reach a CR or an LF inside the
value. Therefore reject CR and LF explicitly wherever the value reaches a
header or an address, and not only where the call is direct. Do not infer their
absence from a validator that returned.

## Export channels and formula injection

Maps to CWE-1236. This is the one sink in the inventory that does not run on
the server.

### Principle layer

Every other row above names an interpreter inside the request's own process.
This one names a program on somebody else's machine. The application writes a
cell. A spreadsheet reader parses that cell and evaluates it. Nothing in the
server misbehaves, the file is well formed, and the code that produced it
reads as serialization rather than as a sink. That is why the class survives
reviews that catch everything else in this file.

The common spreadsheet readers read a cell whose first character is `=`, `+`,
`-`, or `@` as a formula rather than as text. A leading tab or carriage return
reaches the same state in some readers, which strip it and treat the next
character as the first one.

The payload does not need a macro. A formula can address a remote location,
and it can carry the contents of neighboring cells into the request it makes.
Thus the row leaves as a query string. Score that as data exfiltration from
the reader's machine. It runs with the reader's credentials, on the reader's
network, which is routinely a network the application itself cannot reach.
Where the reader is an administrator or an analyst, that network is the
interesting one.

Quoting is not the control. A CSV writer quotes a field to keep the file
parseable. The reader's CSV parser consumes those quotes before the value
reaches the formula engine. `csv.QUOTE_ALL` produces a valid file and an
unchanged exposure.

Three controls follow, strongest first. Each one has a cost that belongs in
the finding:

- **Reject the value where it is written.** This is the strongest control,
  because it keeps the character out of the column rather than out of one
  export. Every later export inherits it. It costs a legitimate value. A note
  that opens with a minus sign is text somebody meant to store.
- **Write the cell with an explicit text type.** This costs the data nothing,
  and it is unavailable in the format most exports use. CSV carries no types
  at all, so there is nothing to declare. This control exists only where a
  workbook writer produces a typed cell.
- **Prefix the value with a single quote.** This is the fallback, and it is
  the one that changes the stored data. The prefix is a byte in the file, so a
  machine consumer downstream reads a value that is not the one in the
  database. An export-then-import round trip shifts it again. Apply it per
  column, to text a caller authored rather than to a column the server renders
  as a number. Otherwise a negative amount arrives as a string.

The absence of the middle control from CSV is the practical shape of this
finding. A CSV export chooses between a rejection of values and a mutation of
them. A review that recommends "escape it" has not made the choice. Rejection
at the write is also the discipline "Tracing input to a sink" already asks
for, and for the same reason. Whoever wrote the column rarely writes the
export.

### Django & DRF implementation layer

The export is usually not a view, which is why a grep for `HttpResponse`
misses most of it. Walk each of these:

- an admin export action, including one registered through
  `ModelAdmin.actions`;
- a management command that writes a report to disk or to a bucket;
- a renderer that produces CSV or TSV. DRF ships none in core, so this is the
  project's own renderer class or a third-party package. Content negotiation
  is what makes it selectable by a query parameter or an `Accept` header. Where
  that renderer sits in `DEFAULT_RENDERER_CLASSES`, every endpoint is an export
  location, and no walk of export views finds them. Neutralize the cell in the
  renderer itself in that case, rather than at each place that builds a row;
- a Celery task that builds a file for later download
  (`a08-integrity-and-deserialization.md`, "Celery and task queues");
- a subject-access export, which by construction carries free text from every
  model attached to the subject
  (`data-lifecycle-and-privacy.md`, "Export and subject-access endpoints");
- any writer library used in text mode, where the value goes out as a string
  and the reader infers the cell type.

```python
# Wrong: the writer quotes the field, which keeps the file valid and does
# nothing about what opens it. `csv` has no cell type to declare, so a note
# of "=WEBSERVICE(...)&A1" is written as a formula and runs on the machine
# of whoever opens the file. The filename is the caller's as well.
import csv

from django.http import HttpResponse

from .models import Contact


def export_contacts(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        f'attachment; filename="{request.GET["label"]}.csv"'
    )
    writer = csv.writer(response, quoting=csv.QUOTE_ALL)
    for contact in Contact.objects.values_list("name", "note"):
        writer.writerow(contact)
    return response
```

```python
# Correct: each text cell is neutralized for the reader's formula engine
# before it is written, the columns it applies to are chosen deliberately,
# and the filename is the server's. The prefix is the fallback control -- it
# changes the byte a downstream consumer reads, which is the trade named
# above and the reason rejection at the write is better where it is possible.
import csv

from django.http import HttpResponse
from django.utils.http import content_disposition_header

from .models import Contact

FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def as_text_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_TRIGGERS) else text


def export_contacts(request):
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Disposition"] = content_disposition_header(
        as_attachment=True, filename="contacts.csv"
    )
    writer = csv.writer(response)
    for name, note in Contact.objects.values_list("name", "note"):
        writer.writerow([as_text_cell(name), as_text_cell(note)])
    return response
```

The response headers are a control separate from the cell contents, and teams
skip them most often on the export. Set the content type. Set
`X-Content-Type-Options: nosniff`, so that a reader cannot sniff the bytes
into a renderable type. Build the `Content-Disposition` filename from a
server-controlled value.

The stack-neutral reason for that last rule is header injection, and Django
closes it on both paths rather than leaves it to the caller. Checked against
6.0.7 on 14 August 2026. `HttpResponse.__setitem__` raises `BadHeaderError`
for a value that contains CR or LF.
`django.utils.http.content_disposition_header()` escapes `"` and `\` inside
the quoted form, and percent-encodes anything outside it. Thus a filename that
carries CRLF comes back as an RFC 6266 `filename*=utf-8''` parameter rather
than as a second header.

What remains on Django is therefore not a smuggled header. It is a 500 from
the unhandled `BadHeaderError` (`a10-exceptional-conditions.md`, "Don't leak
on error"), and a caller who chooses the name the file is saved under. The
general rule for values bound into headers stays in "Header and email
injection" above.

**Write-time.** When you generate anything that writes a cell, neutralize the
first character of every text cell in the same edit that writes the row. A CSV
response, an admin export action, a report command, and a workbook are the
cases. The writer is the only place the class is visible, and the reader is
somebody else's program six weeks later. Decide it per column rather than per
file, so that numbers stay numbers. Write the content type, the `nosniff`
header, and a server-side filename through `content_disposition_header()` at
the same time. Each of those is a line a team adds after an incident rather
than during a refactor.

## XML / deserialization pointers

Disable XML when the application does not need it. Where it is required, use a
maintained format-specific parser configured to reject DTDs, external
entities, network access, and unbounded entity expansion. Enforce input and
expansion limits before the parse. Those settings have names worth a place in
a report.

The first two close **XML external entity** injection, XXE. In XXE a declared
entity makes the parser read a local file, or issue a request on the server's
behalf. The expansion limit closes **entity expansion**, in which a few
hundred bytes of self-referential entities expand into gigabytes during the
parse.

Maps to CWE-611 and CWE-776. Do not newly recommend `defusedxml` from
historical guidance alone, because its latest release and maintenance signals
do not pass the dated dependency gate. An existing installation needs an
explicit maintenance and runtime compatibility review. An untrusted `pickle`
or `yaml.load` is remote code execution. A08 (Integrity and Deserialization)
covers that, and you should cross-check there.

## Review checklist

- [ ] Every untrusted source is traced to each sink it reaches, including a
      sink reached in a later request. The sources are the body, the query,
      headers, cookies, URL kwargs, DRF `validated_data`, stored fields, and
      model output.
- [ ] No string-formatted SQL reaches `.raw()`, `extra()`, `RawSQL`, or
      `cursor.execute`. Parameters are used throughout, and placeholders are
      unquoted. Every raw path is checked for tenant or row-level-security
      bypass as well as for injection.
- [ ] No newly written `.extra()` call, on the basis that Django no longer
      fixes bugs in it, independent of whether this one interpolates.
- [ ] Document-store queries validate the *shape* of input, so a client cannot
      substitute an operator object where a scalar was expected.
- [ ] No client-controlled column names/aliases/keys into
      `order_by/annotate/aggregate/values/filter(**...)`. A declared
      `DictField`, `JSONField`, or `HStoreField` carries client-authored keys
      inside a declared name, and does not pass the carve-out.
- [ ] A raster band index that reaches a PostGIS lookup is an `int` from a
      server-side set. No spatial lookup takes a `str`, `Path`, or `dict` from
      a request. A `GDALRaster` wrap over a request value is the same finding,
      because the wrap states trust rather than creates it. A field that assigns
      a request value to a `RasterField` rejects `str`, `Path`, and `dict`,
      because the fix left assignment unchanged. Spatial fields on
      admin-registered models are judged as staff-reachable.
- [ ] No `shell=True`, `os.system`, `eval`, or `exec` acts on request data.
      Argument lists pass `shell=False`, a `timeout`, and `--` ahead of any
      value a program could otherwise read as an option.
- [ ] No untrusted value sits in an argument position the program runs as
      code, such as after `-c` or `-e`, or after a host name. An argument list
      does not make that call safe. The environment passed with `env=` is
      judged as a second argument channel.
- [ ] Management commands and data migrations hold to the same parameter and
      argument discipline as request handlers. They reach the same
      interpreters with more privilege and no request to blame.
- [ ] Autoescaping is intact. `mark_safe`, `|safe`, and Jinja2 autoescape are
      verified. No template is built from user input, and no template name is
      chosen by a request outside a server-side mapping.
- [ ] No argument reaches `format_html` already marked safe, because
      `conditional_escape` passes such an argument through unescaped.
- [ ] Any Markdown renderer over untrusted text has raw HTML off. Where the
      renderer carries no such switch, the sanitizer over its output is
      present. Rich-text output is sanitized after the render, rather than
      trusted from it.
- [ ] LDAP filters escape every assertion value with `escape_filter_chars`.
      DNs use `escape_dn_chars`. `python-ldap` is 3.4.5 or later.
- [ ] A value bound for a response or mail header is rejected for CR and LF
      before the header is constructed. The framework rejection afterwards is
      not the only check. No bare validator call stands in for that rejection,
      and neither does a field strip, which reaches the edges of the value only.
      An HTML mail body is judged as server-rendered output.
- [ ] Every text cell an export writes is neutralized against a leading `=`,
      `+`, `-`, `@`, tab, or carriage return. The control is a rejection where
      the value is written, or an explicit cell type, and quoting does not
      count. Admin actions, report commands, CSV renderers, file-building
      tasks, and subject-access exports were all walked, rather than only the
      endpoint that returns one. A CSV or TSV renderer in
      `DEFAULT_RENDERER_CLASSES` makes every endpoint an export location, and
      the neutralization then belongs in the renderer.
- [ ] An export response sets its content type, `X-Content-Type-Options`, and
      a `Content-Disposition` filename the server chose.
- [ ] Unneeded XML is disabled. Required XML uses a maintained parser with
      DTD, external-entity, network, and expansion controls. Deserialization
      is cross-checked against A08.
- [ ] Model-generated or model-retrieved text that reaches a query, shell,
      template, path, URL, or deserializer is treated as untrusted input.
