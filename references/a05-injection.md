# A05:2025 — Injection

The sink inventory for the whole skill: SQL/ORM including the GeoDjango lookup
positions the ORM does not parameterize, OS command, template, directory,
header/email injection, and server-side output handling (XSS from
server-rendered content), plus the method for tracing a source to any of them.

The inventory is meant to be exhaustive, so a file that defers to it can rely
on the list being complete instead of keeping a partial copy. Three sinks are
owned here outright and duplicated nowhere: SQL, the shell, and server-side
output. The rest point outward to the file that owns the rules —
`data-layer-and-database.md` for the raw-path enumeration and document-store
shape validation, `file-uploads.md` for the storage key an upload lands under,
`a01-broken-access-control.md` for SSRF and for the filesystem path a request
names, `a08-integrity-and-deserialization.md` for deserialization, and
`a09-logging-and-alerting.md` for the log line.

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

Untrusted means untrusted regardless of origin. Text a model generated, or text
a model retrieved from a document or web page, is the same input class as a
request body once it reaches any sink below — see
`agent-and-llm-interfaces.md`, "Model output as an injection source".

## Tracing input to a sink

### Principle layer

A **sink** is any call where data leaves the application's own semantics and is
handed to something that interprets it: a SQL engine, a shell, a template
compiler, a directory server, a path resolver, an HTTP client, a deserializer,
a log line, a response header. Injection is the same bug at every one of them —
attacker-influenced content changes what the operation *means*, not just what
it operates on — which is why the defense is one discipline and not a dozen.

A finding needs three things established, in this order.

**Sources.** Untrusted input is more than the request body: `request.GET`,
`request.POST`, `request.data`, `request.query_params`, `request.FILES`,
headers, cookies, URL keyword arguments, any free-text field in DRF's
`validated_data`, WebSocket and consumer messages, model fields populated from
any of those earlier, and text a model generated or retrieved. Validation
upstream narrows what a source can contain; it does not turn it into a trusted
one, because the sink is where meaning is assigned.

**Sinks.** Enumerate every interpreter the request can reach. The inventory
below is that list. Keeping it in one place is the point: a reference that
defers here relies on it being complete rather than restating a partial copy.

**The path between them.** Follow each source through assignment, function
parameters, and every construction that joins it to text the developer wrote —
f-strings, `%`, `.format()`, `+`, `join()`, and dictionary expansion (`**`).
Arriving at a sink as one of those constructions is the vulnerability. Arriving
as a bound parameter, an element of an argument vector, a template context
value, or an escaped term is not. That distinction, not the presence of the
sink, is what separates a lead from a finding.

Second-order paths are the ones reviews miss, because source and sink sit in
different requests: a name stored today and rendered, logged, fetched, or
compiled tomorrow. A stored field is as tainted as its worst writer, not as the
handler you happen to be reading.

### Django & DRF implementation layer

Each row is a sink family, what reaches it, the form that keeps the input as
data, and where this skill keeps the rules. Sinks whose rules live elsewhere
are listed here anyway, so that the inventory is the one place a reviewer has
to consult.

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
| Template compiler | `Template(...)` or `Engine.from_string(...)` on a string the user supplied | a template file in the repository, with user data in the context | "Template injection and server-side output" |
| Directory server | an LDAP filter string built by interpolation | `escape_filter_chars` on every assertion value | "Directory and LDAP injection" |
| Response and mail headers | `response[name] = value`, `EmailMessage` header fields, `send_mail` arguments, and a value a bare `DomainNameValidator` call cleared below 6.0.7 or 5.2.16 | reject CR and LF before construction, and take the cleaning from a form or serializer field rather than from the validator | "Header and email injection" |
| Log line | any value interpolated into a log message | structured fields, or control characters escaped in a formatter | `a09-logging-and-alerting.md`, "Log injection and integrity" |
| Filesystem path | `open()`, `os.path.join(base, value)`, `pathlib` joins, and storage names taken from the client | a server-chosen identifier resolved against a fixed base, by an API that rejects an escape rather than normalizing it | `a01-broken-access-control.md`, "Path traversal"; the name and key an upload brings are in `file-uploads.md`, "Filenames and storage keys" |
| Outbound HTTP | `requests`, `urllib`, `httpx`, `aiohttp` on a user-influenced URL | an allowlisted destination checked after DNS resolution, not a validated string | `a01-broken-access-control.md`, "SSRF" |
| Object deserializer | `pickle.loads`, `yaml.load`, `jsonpickle`, `marshal`, the cache, session, and fixture paths Django runs without being asked, and the task message a worker turns back into arguments | a format that cannot construct objects | `a08-integrity-and-deserialization.md`, "Insecure deserialization" and "Celery and task queues" |
| XML parser | DTDs, external entities, and entity expansion in submitted documents | a maintained parser with those features off, behind input limits | "XML / deserialization pointers" |

Two grep passes make this tractable on a real codebase. Search for the sink
names above, then search for what carries input to them: `request.`, `.data`,
`validated_data`, `kwargs[`, `**`, `f"`, `.format(`, and `%` near any hit. A
sink with no source reaching it is not a finding; a source reaching a sink
through string construction almost always is.

The second-order path is worth walking once in full, because it is the one the
grep passes above find as two unrelated hits. A single stored field carries it,
and the field is the only thing the two halves have in common:

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
# Correct: the stored field is treated as the source it is, at both ends. It is
# constrained where it is written, so the column cannot hold shell syntax in
# the first place, and it still arrives at the sink as one argument rather than
# as text a shell re-parses -- because the writer and the reader change on
# different days.
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

Read the fix as two independent controls rather than one applied twice. The
validator is what makes the column's contents describable; the argument list is
what holds when a later migration, a management command, an admin edit, or a
data import writes the same column without passing through the serializer at
all. Neither is sufficient, because a stored field is as tainted as its worst
writer and the worst writer is rarely the one in front of you.

One property of the source itself breaks the trace before any sink is reached:
**a parameter can arrive more than once, and which value a reader sees depends
on how it reads.** `request.GET`, `request.POST`, and DRF's `query_params` are
`QueryDict` instances, where subscripting and `.get()` return the **last**
occurrence while `.getlist()` returns all of them. A request carrying
`?next=/dashboard&next=//attacker.example` therefore presents two different
values to two pieces of code that both look correct in isolation, and the
defect is that the value which was checked is not the value that was used:

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
reads — a tenant identifier, an object id, an amount, a scope. It also reaches
outward: where a gateway, a WAF, or a proxy inspects a request before Django
does, that component picks an occurrence by its own rule, and nothing
guarantees it is the one Django will read. Which occurrence the edge chooses is
not visible in this repository, so it is carried as a question to whoever
operates it under `01-audit-workflow.md`, "Phase 0 — scope, mode, and what the
repository cannot tell you" rather than assumed.

**Write-time.** When generating a handler that reads a query or form parameter
a security decision depends on, read it once into a local name and use that
name everywhere, and reject a duplicate outright where the parameter is
single-valued, because a check and a use that each read the `QueryDict` on
their own line are reading two different values the moment a caller sends the
parameter twice.

### Tracing review checklist

#### Stack-neutral

- [ ] Sources are enumerated beyond the request body, including stored fields
      and model-generated text, before any sink is judged.
- [ ] Each source is followed to every sink it reaches, and the construction
      that joins it to developer-written text is named in the finding.
- [ ] Stored-then-used paths are traced across requests, not only within the
      handler under review.

#### Django & DRF

- [ ] The inventory above was walked, rather than only the sink family the
      feature obviously uses.
- [ ] Sinks whose rules live in another reference were followed there rather
      than judged locally against a partial rule.
- [ ] DRF `validated_data` is treated as a source: serializer validation
      constrains shape, and does not make a value safe at a sink.
- [ ] A parameter a security decision reads is read once from the `QueryDict`
      and reused by name, so a duplicated parameter cannot be validated on one
      occurrence and acted on with another.

## SQL and the ORM

Django's ORM parameterizes **values** by default and is safe for normal
queries. State the guarantee that precisely, because it is routinely stretched
two ways it does not cover. It does not reach identifiers, where a column,
alias, or sort key is spliced into the statement as syntax rather than bound as
a value — that is the next section, and where Django's own recent
SQL-injection history sits. And it stops entirely at the escape hatches.
Investigate these:

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

- `.raw()`, `RawSQL`, `cursor.execute`, and `.extra()` are the danger zone; treat
  any Python string formatting (`%`, f-string, `.format`) that reaches them as a
  lead. Parameter placeholders are `%s` for all backends here (the DB-API driver
  binds them safely).
- `.extra()` is worse than legacy. Django's own queryset reference calls it an
  old API to use as a last resort, aimed for deprecation, and states that the
  project is no longer improving or fixing bugs in it — so even a correctly
  parameterized `extra(where=["headline=%s"], params=[value])` builds on a SQL
  layer nobody is maintaining. Prefer expressions (`Func`, `Value`,
  `annotate`), which parameterize, and treat a newly written `.extra()` call as
  a finding of its own rather than waiting for the interpolation bug in it.
- A raw path is a **double** escape hatch. Besides injection, it bypasses the
  tenant-scoping manager and any row-level-security context the ORM path would
  have carried, so a perfectly parameterized raw query can still return another
  tenant's rows. Audit every hit for isolation as well as injection — see
  `data-layer-and-database.md`, "Raw SQL as an isolation bypass".

**Write-time.** When generating a query, express it with ORM methods and let
the ORM bind the values. Where raw SQL is genuinely required, write the
statement with unquoted `%s` placeholders and pass the separate `params`
sequence in the same edit, because a placeholder retrofitted onto a string that
already interpolates is a rewrite nobody schedules. Do not reach for `.extra()`
at all, on the reasoning above: a new call there starts life on a SQL layer
Django has stopped fixing.

Injection is not SQL-only. A document store takes its query as a structured
object, so a JSON body value that arrives as a dict rather than a scalar becomes
a query *operator* — no string concatenation and nothing for escaping to fix.
Validate shape, not only characters (`data-layer-and-database.md`, "NoSQL and
key-value injection").

### Commonly mistaken for a finding

**`cursor.execute("... WHERE id = %s", [value])`, and `Manager.raw(sql,
params)` in the same shape.** It looks like the wrong example above because
`%s` is the same two characters Python's `%` operator uses, and a reviewer
scanning for interpolation lands on both. It is the opposite: `%s` is the
placeholder the DB-API requires, and the driver binds the separate `params`
sequence after the statement has already been parsed, which is exactly the
control this section asks for. The deciding question is never whether the
string contains `%s` — it is whether the SQL string is *built*, by an
f-string, `%` interpolation, `.format()`, or concatenation with anything that
is not a literal constant. A static statement with a params argument is the
correct form of the call, and reporting it is the single highest-volume false
positive available in a Django codebase.

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

Keeping Django patched matters (the framework hardens these), but the durable fix
is to never route client-controlled identifiers into these methods.

### Commonly mistaken for a finding

**`.filter(**data)` where `data` is a serializer's `validated_data`.** The
double asterisk is the signature of the class above, so the call reads as the
wrong example on sight. What makes this class dangerous is client-controlled
*keys*, and a serializer with a declared field set supplies the keys itself:
`validated_data` can only carry the names the serializer declared, whatever
the request body contained. The deciding question is therefore where the keys
come from, not where the values do — a serializer with `fields = "__all__"`,
a bare `request.data`, or a dictionary assembled from query parameters all
fail it, and a declared field set passes.

**Write-time.** When generating a filter, an update, or an aggregate from
`**`-expansion, declare the serializer's `fields` explicitly in the same edit
that writes the expansion, because the expansion is safe exactly as far as the
key set is closed and nothing at the call site shows whether it is.

## GeoDjango raster and spatial lookups

GeoDjango is where the ORM's parameterization guarantee stops being a question
about escape hatches and becomes a question about positions inside an ordinary
`filter()` call. Two positions in a spatial lookup do not take a bound value,
and Django's 2026 record has one CVE for each of them.

**A band index is syntax, not a value.** Raster lookups on a `RasterField` —
implemented only on the PostGIS backend — take a band index either on the left
of the lookup (`rast__1__contains=geom`) or as the second element of a tuple on
the right (`rast__contains=(rst, 1)`). Django inlined that index into the
generated SQL instead of binding it, so an index derived from a request was a
SQL-injection sink. That is CVE-2026-1207, rated high, fixed in Django 6.0.2,
5.2.11, and 4.2.28 on 3 February 2026. The patch closes the framework's half.
The durable half is that a band index sits in an identifier position exactly
as a column alias does, so it has to be coerced to an `int` or chosen from a
server-side set before it reaches the lookup, under the same rule as the
section above.

**A lookup value can be a raster source rather than a value.** Spatial lookups
also accepted `str`, `pathlib.Path`, and `dict` on the right-hand side and
handed them to `GDALRaster`, which opens or creates a datasource through a GDAL
driver. A `dict` — or a JSON string, which is parsed into one first — creates a
new raster, which writes a file with an attacker-chosen name and contents and
reaches remote code execution where that file lands somewhere the application
later loads. A bare `str` is opened as a datasource, so a GDAL
virtual-filesystem path such as `/vsicurl/...` issues an outbound request as
the Django process user. That is CVE-2026-15307, rated high, fixed in Django
6.0.8 and 5.2.17 on 4 August 2026.

The write is a side effect of the driver opening the datasource rather than of
a flag someone left on. `GDALRaster` always opens new rasters in write mode,
and the constructor's `write=False` default never governed the open at all, so
there was nothing to switch off.

Reachability is wider than "a view that accepts a raster". The admin changelist
takes lookups from query parameters, subject only to
`ModelAdmin.lookup_allowed()`, so on any model registered with the admin that
carries a spatial field the lookup was reachable by a staff user holding
nothing beyond *view* permission. Treat a spatial field on a registered model
as reachable by every staff account rather than by whoever wrote the view.

The fix is an opt-in signal rather than a sanitizer. `str`, `Path`, and `dict`
are now rejected in a lookup with `DisallowedRasterLookup`, a
`SuspiciousOperation` subclass, which Django renders as a 400; wrapping the
value in `GDALRaster(...)` is how a project states that this particular source
is trusted. `bytes` are still accepted unwrapped, because they open through
GDAL's in-memory virtual filesystem rather than through the disk or the
network. Assignment is deliberately unchanged: assigning a `dict` to a
`RasterField` still opens a new raster and assigning a `str` or `Path` still
fetches the referenced one, so upgrading closes the lookup path and leaves
every assignment from untrusted input exactly as dangerous as it was. Validate
raster input yourself — the `GeometryField` form field rejects rasters rather
than validating them, and GDAL's own guidance on restricting the available
drivers is the defense-in-depth layer under all of it.

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

**Write-time.** When generating a GeoDjango lookup, decide for each position
whether the ORM will bind it or splice it, because the two look identical at
the call site: bind the geometry, take the band index from a server-side set as
an `int`, and if a raster genuinely has to come from outside the code, wrap it
in `GDALRaster(...)` in the same edit so the trust decision is written down
where the value enters rather than inferred later from the absence of an
exception. Where the feature does not actually need a caller-chosen band, write
the literal and the whole position stops being an input.

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

Avoid `shell=True` with any dynamic content; pass an argument list so the OS
never re-parses a string. Treat `os.system`, `eval`, and `exec` on
request-influenced data as high-severity leads.

An argument list closes the shell, not the program behind it. A value that
reaches `argv` is still read as an option if it begins with a dash, which turns
a filename into a flag — and in tools that can write files, load a config, or
run a helper from a flag, that reaches the same place a shell would. Where the
program supports it, end the option list before the untrusted arguments:

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

Bound the call as well as its arguments: pass `timeout=` so a hostile input
cannot hold a worker, and name the binary by absolute path rather than
inheriting whatever `PATH` resolves to in the deployed environment.

**Write-time.** When generating a call into another program, write the argument
list, `shell=False`, the `timeout`, the absolute path, and the `--` separator
together, because each of them is a thing that gets added after an incident
rather than during a refactor. Apply the same discipline where there is no
request in front of the code: a management command's parsed arguments and a
data migration's inputs reach these same interpreters from a context that
usually carries more database privilege than a view does, so bind and validate
them as you would a request body rather than trusting the value because an
operator supplied it.

### Commonly mistaken for a finding

**`subprocess` with `shell=True` where every argument is a literal.** The flag
is the thing every scanner keys on and the thing this section spends its
length warning about, so a hit reads as confirmed before the arguments are
looked at. Nothing varies here, so there is no input for the shell to
re-parse and no injection to report. The deciding question is whether any
element of the command comes from outside the source file — a request, a
model field, an environment value, a filename discovered on disk. Where none
does, keep it as a hygiene note: the shell is still present for the next edit
to hand something to. Drop the injection claim and the severity that came with
it.

**Write-time.** When generating a call into another program whose arguments
are all literal today, still write the argument list with `shell=False` rather
than the string form, because the argument that becomes dynamic arrives in a
later edit that changes what is passed and not how it is passed.

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

When a product genuinely requires user-authored rich HTML, use an explicit
allowlist sanitizer and still apply output-context encoding. `nh3==0.3.6` passes
the maintained-package gate as of 9 Aug 2026; centralize its tag/attribute/URL-
scheme policy, test bypass payloads, and sanitize again when policy changes.
Plain-text or structured-markup designs remain safer than accepting HTML.

### Commonly mistaken for a finding

**`mark_safe` over a string assembled only from constants, and `mark_safe` or
`|safe` applied to what `format_html` returned.** Both are escape-hatch
identifiers on the list above, and both are frequently correct. A string built
from literals the source file contains carries nothing a request authored, and
`format_html` has already escaped each of its arguments, so marking its result
safe asserts something that is by then true. The deciding question is whether
any value in the marked string reached it from a request, a model field, a
model's output, or any other source outside the source file — one interpolated
value is the whole finding, and none of them is no finding at all.

**Write-time.** When generating markup that mixes a fixed fragment with a
value, write `format_html("...{}...", value)` rather than `mark_safe` over an
assembled string, because `format_html` escapes each argument at the call and
leaves the constant half visibly separate from the half that came from
somewhere else.

## Directory and LDAP injection

An LDAP filter is a query language with its own metacharacters, and a directory
is one of the few interpreters a Django project reaches with no framework layer
in between. Filters are almost always assembled as strings, which makes this
string concatenation in the oldest sense: `*` in a username turns an equality
test into a wildcard match that authenticates against the first matching entry,
and `)(` closes the current term so an attacker can supply their own. Maps to
CWE-90.

```python
# Wrong: the value is part of the filter grammar, so it can add terms.
filterstr = f"(uid={username})"
```

```python
# Correct: escaped for the grammar first, so the value can only be a value.
import ldap.filter

filterstr = "(uid=%s)" % ldap.filter.escape_filter_chars(username)
```

- Escape every assertion value, including values that came back from the
  directory rather than from a request: a group name read from LDAP and
  interpolated into the next filter is the second-order case.
- `escape_filter_chars` has a minimum safe version of its own. In `python-ldap`
  before 3.4.5 it could be made to skip escaping when a `list` or `dict` was
  passed as the assertion value under the non-default `escape_mode=1`
  (CVE-2025-61911, moderate); the fix type-checks the argument. Require
  `python-ldap>=3.4.5` even on the default escape mode, which was never
  affected, and pass a string.
- Prefer the maintained integration over hand-built filters: `django-auth-ldap`
  escapes filter arguments through the same function with escaping on by
  default. It does not pull a patched `python-ldap` for you — its own floor is
  `python-ldap>=3.1` — so pin that dependency separately. See
  `security-hardening-libraries.md`, "Recommended or conditional choices".
- A distinguished name is not a filter, and `escape_filter_chars` is the wrong
  function for one. Where a DN is assembled from input, escape for DN syntax
  (`ldap.dn.escape_dn_chars`) instead, and prefer looking the DN up by a
  searched, escaped filter over building it.

## Header and email injection

- Build emails with Django's mail classes; never interpolate user data into
  headers (To/From/Subject) — newline injection lets an attacker add headers.
- Don't reflect unvalidated input into response headers (`Location`, custom
  headers). Django does reject CR and LF on both paths, so the framework is not
  the gap — but the exception is not the same object in each, which is worth
  knowing before writing a handler for it. In `django.http`, `BadHeaderError`
  is a subclass of `ValueError`, raised when a response header is set. In
  `django.core.mail`, the name is bound directly to `ValueError` itself, for
  compatibility with the error Python's email API already raises. Catching
  `ValueError` covers both; catching `django.http.BadHeaderError` around mail
  code does not. Either way an unhandled rejection is a 500, so validate before
  constructing rather than relying on the exception as the control.
- User-derived redirect targets still need the open-redirect check from A01;
  rejecting newlines says nothing about where the `Location` points.
- For reset, magic-link, invite/share, mailbox-flooding, and preview-fetch abuse,
  see the email and notification design controls in A06.
- **A validator returning without raising is not a header-safety check.**
  `DomainNameValidator` accepted values containing newlines below 6.0.7 and
  5.2.16 — CVE-2026-53878, fixed 7 July 2026. Ordinary Django usage was never
  exposed: a `CharField` strips newlines before the validator runs, and
  `HttpResponse` rejects them on the way out, so both ends held even while the
  validator did not. The exposure was code calling the validator directly on a
  raw request value and then treating the result as clean enough to build a
  header or an address from. That is the shape to look for — a validator
  invoked outside a form or serializer field, on a value that came off the
  request, with the header or `EmailMessage` construction downstream of it and
  nothing rejecting CR and LF in between.

**Write-time.** When generating validation for a hostname, domain, or address a
request supplies, put it behind a form or serializer field rather than calling
the validator on the raw value, because the field's own cleaning is what removes
the control characters a validator is not specified to reject and a bare call
skips. Where a direct call genuinely is the right shape, reject CR and LF
explicitly in the same function instead of inferring their absence from the
validator having returned.

## XML / deserialization pointers

Disable XML when the application does not need it. When it is required, use a
maintained format-specific parser configured to reject DTDs, external entities,
network access, and unbounded entity expansion; enforce input and expansion
limits before parsing. Do not newly recommend `defusedxml` solely from historical
guidance: its latest release and maintenance signals do not pass the dated
dependency gate. Existing installations need an explicit maintenance and runtime
compatibility review. Untrusted `pickle`/`yaml.load` is remote code execution —
that is covered in A08 (Integrity and Deserialization); cross-check there.

## Review checklist

- [ ] Every untrusted source — body, query, headers, cookies, URL kwargs, DRF
      `validated_data`, stored fields, and model output — is traced to each
      sink it reaches, including sinks reached in a later request.
- [ ] No string-formatted SQL in `.raw()`/`extra()`/`RawSQL`/`cursor.execute`;
      parameters used throughout, placeholders unquoted, and every raw path is
      checked for tenant or row-level-security bypass as well as for injection.
- [ ] No newly written `.extra()` call, on the basis that Django no longer
      fixes bugs in it, independent of whether this one interpolates.
- [ ] Document-store queries validate the *shape* of input, so a client cannot
      substitute an operator object where a scalar was expected.
- [ ] No client-controlled column names/aliases/keys into
      `order_by/annotate/aggregate/values/filter(**...)`.
- [ ] A raster band index reaching a PostGIS lookup is an `int` from a
      server-side set, and no spatial lookup takes a `str`, `Path`, or `dict`
      from a request rather than a value wrapped in `GDALRaster`; spatial
      fields on admin-registered models are judged as staff-reachable.
- [ ] No `shell=True`, `os.system`, `eval`, or `exec` on request data; argument
      lists pass `shell=False`, a `timeout`, and `--` ahead of any value that
      could otherwise be read as an option.
- [ ] Management commands and data migrations hold to the same parameter and
      argument discipline as request handlers, since they reach the same
      interpreters with more privilege and no request to blame.
- [ ] Autoescaping intact; `mark_safe`/`|safe`/Jinja2 autoescape verified; no
      template built from user input.
- [ ] LDAP filters escape every assertion value with `escape_filter_chars`, DNs
      use `escape_dn_chars`, and `python-ldap` is 3.4.5 or later.
- [ ] Values bound for a response or mail header are rejected for CR and LF
      before the header is constructed, not only by the framework afterwards,
      and no bare validator call is standing in for that rejection.
- [ ] unneeded XML is disabled; required XML uses a maintained parser with DTD,
      external-entity, network, and expansion controls; deserialization is
      cross-checked against A08;
- [ ] model-generated or model-retrieved text reaching a query, shell, template,
      path, URL, or deserializer is treated as untrusted input.
