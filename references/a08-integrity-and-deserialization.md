# A08:2025 — Software and Data Integrity Failures

Insecure deserialization, unsafe task serializers, unsigned or unauthenticated
data crossing a system boundary, and integrity of the pipeline that ships code.
This file owns the receiving end of cross-system trust: the webhook a provider
sends you, the message a worker takes off a broker, and every layer that turns
stored or transmitted bytes back into live objects. Payment webhook integrity
lives here and in the DRF file.

## Contents
- [Principle](#principle)
- [Insecure deserialization](#insecure-deserialization)
- [Celery and task queues](#celery-and-task-queues)
- [Django's built-in tasks framework](#djangos-built-in-tasks-framework)
- [Signed cookies and data](#signed-cookies-and-data)
- [Webhook and callback integrity](#webhook-and-callback-integrity)
- [Pipeline and artifact integrity](#pipeline-and-artifact-integrity)
- [Review checklist](#review-checklist)

## Principle

Integrity failures occur when your system trusts data or code whose authenticity
it never verified — a serialized object from the network, an unsigned update, a
webhook that anyone could forge. The principle is **verify before you trust**:
sign and check data you round-trip, never deserialize untrusted input into live
objects, and authenticate the source of anything that drives a state change.

## Insecure deserialization

Maps to CWE-502 (Deserialization of Untrusted Data). Severity is Critical
wherever an attacker controls the bytes, because the outcome is code execution
rather than data corruption.

### Principle layer

A format that produces only strings, numbers, lists, and maps is data. A format
that can name a class or a callable and have the parser construct it is a
program, and deserializing untrusted input in such a format runs an attacker's
program with your process's privileges. The defense is a format choice, not a
filter: no allowlist of permitted types makes an object-constructing format
safe, because the attack lives in the construction itself.

The useful review question is therefore not "where did someone call `loads()`"
but **"where does any layer turn stored or transmitted bytes back into
objects"**. The developer's own calls are the ones already under suspicion. The
framework's calls — the cache, the session, the queue — are the ones nobody
reads, and they are where the reachable instances usually are.

That reframes the threat model. An object-constructing deserializer turns *any*
write primitive into code execution: a store the application trusts becomes a
place to leave a payload, and the application itself loads and runs it. So the
question after finding one is always "who can write to what this reads from",
and a "we only read our own data back" argument is only as strong as the write
controls on that store.

### Django & DRF implementation layer

#### The paths a developer writes

- **`pickle.loads` / `pickle.load`** on anything that crossed a trust boundary.
  Construction runs `__reduce__` on the attacker's terms; there is no safe
  subset and no safe loader option.
- **`yaml.load` with the default loader, `FullLoader`, or `UnsafeLoader`**, plus
  `yaml.unsafe_load` and `yaml.full_load`. Only `yaml.safe_load` (equivalently,
  `SafeLoader`) is data-only.
- **`marshal`, `dill`, `jsonpickle`** reconstruct arbitrary objects and belong
  in the same class as `pickle`, including where they arrive as a machine
  learning model file or a cached computation.
- **`django.core.serializers.deserialize`** on input an attacker can influence —
  see fixtures below.

```python
# Wrong: the loader decides what to build from bytes the caller supplied, so
# the request body chooses which constructor runs.
import pickle

import yaml


def restore(request):
    state = pickle.loads(request.body)
    config = yaml.load(request.POST["config"])
    return state, config
```

```python
# Correct: both parsers can now only produce strings, numbers, lists, and
# maps, so the worst a hostile payload yields is bad data for validation to
# reject.
import json

import yaml


def restore(request):
    state = json.loads(request.body)
    config = yaml.safe_load(request.POST["config"])
    return state, config
```

**Protobuf sits on the data side of that line, with two caveats.** A protobuf
message is schema-bound — the parser can fill only the fields the compiled
descriptor declares, so it cannot name a class or reach a constructor the way
pickle can — and unlike JSON it arrives bounded: grpcio caps a received
message at 4 MB, protobuf's pure-Python decoder carries
`DEFAULT_RECURSION_LIMIT = 100`, and `json_format.Parse` and `ParseDict`
default `max_recursion_depth=100`, all read from grpcio 1.83.0 and protobuf
7.35.1 on 9 Aug 2026. What keeps it out of the safe column is that both
recursion guards have been bypassed. CVE-2025-4565 exhausts the interpreter's
own limit through nested groups and recursive messages in the pure-Python
decoder, fixed in 4.25.8, 5.29.5, and 6.31.1; CVE-2026-0994 bypasses the JSON
guard through nested `google.protobuf.Any` messages, fixed in 5.29.6 and
6.33.5. Both are denial of service rather than execution, and the current 7.x
line is outside the affected range of each. Two behaviors stay reviewable on
any version: unpacking an `Any` instantiates whichever message type the sender
named, so allow-list the acceptable type URLs before unpacking, and proto3
preserves unknown fields through a binary parse and re-serialize, so a message
relayed onward carries fields this service never validated. The surface that
receives them is in `graphql-and-alternative-api-surfaces.md`, "gRPC: nothing
from the DRF request cycle applies".

#### The paths the framework runs for you

**The cache framework pickles by default, on every built-in backend.**
`RedisCache`, `LocMemCache`, `FileBasedCache`, `DatabaseCache`, and the
memcached backends all serialize with `pickle` at the highest protocol —
`PyMemcacheCache` by defaulting `serde` to pymemcache's pickle serde, and
`PyLibMCCache` through pylibmc's native serialization. **Django ships no
built-in JSON serializer for the cache**, so moving off pickle means supplying a
custom serializer or a third-party backend that provides one; there is no
setting to flip.

The consequence is the write-primitive rule above, made concrete: anyone who can
write to the cache store gets code execution the next time the application calls
`cache.get()`. Treat each of these as a finding in its own right — a
world-writable file-cache directory, a Redis or memcached instance reachable
without authentication, a cache table exposed to SQL injection, or a cache
shared across environments so a lower-trust deployment can write what production
reads. Django's own documentation warns that the file-cache directory is a
code-execution path if it is attacker-writable. The service-level controls are
in `deployment-and-runtime.md`, "Caching security"; the key-scoping and
authorization side is in `a01-broken-access-control.md`.

**Sessions no longer offer a pickle option.**
`django.contrib.sessions.serializers.PickleSerializer` was deprecated in Django
4.1 and removed in 5.0, so on the supported lines `JSONSerializer` is the only
built-in session serializer and stock configuration cannot select pickle. The
live findings are a *custom* or third-party pickle-based session serializer, and
a leaked or weak `SECRET_KEY` — which, combined with any pickle-capable
serializer, is a direct route from signing-key disclosure to code execution.
Rotation and leak response are in `service-identity-and-secrets.md`.

**`django.core.signing` is JSON by default.** `dumps` and `loads` default to
`JSONSerializer`, so the built-in signing helpers are data-only unless a
`serializer=` argument replaces that. A pickle-based serializer passed there is
the same finding as a pickle session.

Message-queue payloads are the fourth implicit path; they are in the Celery
section below.

#### Fixtures: `loaddata` and `dumpdata`

Fixtures are a bulk write that bypasses the layer that normally enforces
invariants. Loading one calls `Model.save_base` with `raw=True`: a model's
overridden `save()` never runs, `full_clean()` is never called, and `pre_save`
and `post_save` fire with `raw=True` set, which correct handlers are expected to
skip on. A fixture can therefore set `is_staff`, `is_superuser`, a price, or a
tenant to values no code path would ever permit — a privilege-escalation route
that exists in the safe JSON format, with no deserialization bug required.

- Any code path that runs `loaddata` or `serializers.deserialize` on content an
  attacker can influence is a trust boundary: a user-facing "import" feature, a
  backup-restore endpoint, or fixtures read from a writable location. Validate
  and authorize the contents as request input, or do not accept them.
- Django's built-in formats are `json`, `jsonl`, `xml`, and `yaml`; the YAML
  serializer exists only when PyYAML is installed. Keep fixtures on `json` or
  `xml` and treat a YAML fixture path fed by anything untrusted as the
  `yaml.load` finding above.
- `dumpdata` output is a concentrated copy of model data and needs the handling
  a database backup gets. Review-time check: is it written under a web-served
  path, committed to version control, or baked into a container image? Retention
  and copies of personal data are in `data-lifecycle-and-privacy.md`.

### Commonly mistaken for a finding

**`pickle` on bytes the application itself wrote to a location no other
principal can write.** Severity in this section is Critical wherever an
attacker controls the bytes, and `pickle.loads` is the most recognizable
identifier in the file, so the call is often written up as remote code
execution before the store behind it is looked at. The deciding question is
who can write the bytes, not which module reads them — a memoization file
under a directory only this process owns, a cached computation in a Redis
instance nothing else can reach, a blob in a table no untrusted path writes.
Keep the design objection, because that answer is a property of the deployment
rather than of the code and the write controls are exactly what the review
before this one cannot see; drop the RCE claim, which asserts an attacker who
was never shown to exist. This is the same question the write-primitive rule
above asks, read in the other direction: where any second principal can reach
that store, the finding is live and it is Critical.

**Write-time.** When generating code that persists application state for the
application itself to read back later, write it in a data-only format even
though nothing untrusted writes that store today, because the property making
`pickle` safe there belongs to the deployment — a directory's permissions, a
broker's network position — and it is changed by people who will never read
this call.

## Celery and task queues

Maps to CWE-502 where the serializer constructs objects, and CWE-306 (Missing
Authentication for Critical Function) for the enqueue path itself.

### Principle layer

**A worker authenticates the message, not the producer.** A task is a serialized
message sitting on a broker, and a worker executes any well-formed message on a
queue it consumes. Nothing in the protocol records who put it there, and no
client library is needed to put one there — speaking the broker's wire protocol
is enough. So the set of principals who can invoke your tasks is exactly the set
who can reach the broker, which is rarely the set the code was written for.

Two consequences follow, and the second is the one usually missed:

- If the serializer can construct objects, broker reachability is remote code
  execution outright.
- **Even with a data-only serializer, reaching the broker means invoking any
  registered task with any arguments.** That is an authorization bypass on every
  task, and it is frequently an indirect route to code execution through a task
  that shells out, writes a file, or processes input it believes is internal.

**Therefore task arguments are a trust boundary, not internal data.** Validate
them inside the task as though they arrived from an anonymous client, and never
pass a secret or an already-authorized capability token as an argument on the
reasoning that only your own code enqueues this task.

### Django & DRF implementation layer

Celery has defaulted to JSON since 4.0 — `task_serializer` and
`result_serializer` are `json` and `accept_content` is `{'json'}` — so the
finding is almost never the default. It is a project that *widened*
`accept_content` to admit `pickle` or `yaml`, usually to move a non-serializable
argument, and left it wide afterwards. Set the three explicitly so the intent is
visible and a dependency's default cannot change it:

```python
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
```

`accept_content` is the one that decides what a worker will execute; the other
two only decide what it emits. A single `"pickle"` entry there re-opens the hole
regardless of what the producers are configured to send.

**Write-time.** When generating Celery configuration, write those three
settings explicitly even though the defaults already match them, because the
finding here is always a later widening and an explicit `["json"]` is the line
a reviewer can watch being changed. When generating a task, validate its
arguments inside the task body and pass identifiers rather than objects,
secrets, or an already-authorized token, because whatever can reach the broker
can call that task with arguments of its own choosing. Where a sensitive value
genuinely has to travel in the message, encrypt it in the producer and decrypt
it in the task rather than relying on the signed serializer, which
authenticates the message without concealing it.

- **The result backend is a second exposure with the same reach.** Results are
  written to the broker or an equivalent store and are readable and writable by
  whatever can reach it, so a task returning personal data or a token publishes
  it there. Task arguments and results are also routinely logged; keep both free
  of secrets, and see `a09-logging-and-alerting.md`.
- **Celery's `auth` serializer signs messages so a worker rejects any message
  not signed by a trusted key**, which is the mechanism that actually
  authenticates the producer. Its own documentation is explicit that it does not
  encrypt the contents, so it addresses forgery and not disclosure; a broker
  that can read the payload still reads it.
- **Confidentiality is therefore a separate decision, and Celery ships no
  option that makes it.** A message sits on the broker in the clear for as long
  as it is queued and the result sits in the backend for as long as it is
  retained, so anything sensitive in either is readable by whatever reaches
  that store — its operator, its snapshots, and its own logs included. Two
  answers exist and they defend against different things. TLS to the broker
  and the result backend plus at-rest encryption of their storage covers the
  network and the disk, and is the right default; it does not cover the broker
  itself. Where the broker is outside the trust boundary — a managed service, a
  shared cluster — encrypt the sensitive argument in the producer and decrypt
  it in the task, so the message carries ciphertext, with the key handled per
  `a04-cryptographic-failures.md`, "Key lifecycle and envelope encryption".
  Neither is needed for an argument that is only an identifier the task
  resolves for itself, which is why that remains the default.
- Broker authentication, network placement, and the standing severity of a
  reachable unauthenticated Redis are in `deployment-and-runtime.md`, "Queue and
  broker exposure". A worker's own database and network privileges are part of
  the blast radius: a task queue is a second, unauthenticated front door to
  every capability the worker holds.
- Dispatch belongs after the commit, not inside the transaction — see
  `a10-exceptional-conditions.md`, which owns the side-effect ordering and the
  redelivery semantics that make a task's own handling need to be idempotent.

## Django's built-in tasks framework

Maps to CWE-306 (Missing Authentication for Critical Function) for the task
body, and CWE-863 (Incorrect Authorization) where a task re-derives a
permission it has no principal to derive.

Django gained a built-in tasks framework in the 6.0 line: `django.tasks`, a
`@task` decorator, `Task.enqueue()` and `aenqueue()`, a `TaskResult`, and a
`TASKS` setting shaped like `DATABASES` and `CACHES`. Every behavior below was
read from the Django 6.0.7 source and exercised against it on 14 August 2026.
Django 6.1 was not available to check, so treat each claim as scoped to the
6.0 line and re-verify before relying on it against a later release.

### Principle layer

**A task function runs with no request and no authenticated user.** There is
no `request.user`, no session, and no DRF permission class between the caller
and the body. So the authorization decision has to be resolved *before* the
enqueue, by the code that still holds a principal, and carried into the task
as data — a decision already made, not an identifier to be judged later.

That reframes a common shape. A task that receives an object id and re-derives
permission from it inside itself re-derives it **with no principal**: there is
nobody for the id to be checked against, so the check either compares the
object to nothing or silently becomes a check that everyone passes. Pass the
identifiers the task needs to do its work, and pass the authorization outcome
separately as a fact the caller established.

**A project with two task systems has two authorization boundaries and
usually reviews one.** Where the built-in framework lands in a codebase that
already runs Celery, expect them to coexist rather than replace: new code
takes the built-in, existing tasks stay. Both are execution entry points, they
carry different defaults, and an inventory that stops at `@shared_task` misses
half the surface. Enumerate both — `01-audit-workflow.md`, "Phase 1 —
entry-point inventory" carries the row.

### Django & DRF implementation layer

**The default backend runs tasks inline, in the request cycle.** Django's
`global_settings` names the immediate backend as the shipped default:

```python
# django/conf/global_settings.py, Django 6.0.7
TASKS = {
    "default": {"BACKEND": "django.tasks.backends.immediate.ImmediateBackend"}
}
```

A project that adds `@task` and never configures `TASKS` therefore gets
synchronous execution rather than a background job. Core ships two backends on
the 6.0 line — `ImmediateBackend` and `DummyBackend`, the latter for tests —
and no durable one; a real worker comes from a third-party backend. Three
review consequences follow, and none looks like a task-queue finding:

- The work inherits the request timeout and the worker process, so a job sized
  for a background queue becomes a denial of service against the web tier.
  Whatever bound `a06-insecure-design.md` assigns the operation has to hold at
  request latency, because that is where it now runs.
- `ImmediateBackend._execute_task` catches `BaseException` —
  `KeyboardInterrupt` excepted — records it on the result, and returns
  normally. **The caller sees no exception.** A task that fails in production
  fails silently unless something inspects the result, and neither shipped
  backend supports retrieving one: `supports_get_result` is `False` on both,
  and `ImmediateBackend.get_result` raises `NotImplementedError`.
- Neither shipped backend supports `run_after` (`supports_defer` is `False`),
  so a scheduled task is a third-party backend's feature, not the framework's.

**Enqueue belongs after the commit, and the backend decides which way it goes
wrong.** Nothing in `django.tasks` integrates with `transaction.on_commit`.
With a durable backend the familiar failure holds — the worker claims the
message before the producer commits and reads a row that does not exist yet.
With `ImmediateBackend` the failure inverts: the task body runs *inside*
`enqueue()`, on the caller's thread, within the open atomic block, so it reads
uncommitted state and its own writes and side effects roll back with the
transaction that enclosed them. Verified on 6.0.7: a task enqueued inside
`transaction.atomic()` observed the uncommitted row, and the rollback took
both back. `transaction.on_commit` is the answer under either backend;
`a10-exceptional-conditions.md`, "Side effects and the commit boundary" owns
the ordering rule, and its "Idempotency" section owns the duplicate delivery
any retrying backend will produce, which the framework does not make idempotent
for you.

**Argument serialization is JSON-only and refuses at enqueue time.**
`TaskResult.__post_init__` runs `django.utils.json.normalize_json` over `args`
and `kwargs`, which admits `Mapping`, `Sequence`, `str`, `int`, `float`,
`bool`, and `None`, and raises `TypeError` on anything else. Confirmed
rejected on 6.0.7: a model instance, `datetime`, `Decimal`, `set`, and `UUID`.
This is the good news, and it is worth stating plainly: **there is no
serializer setting to widen, so the Celery pickle finding above has no
equivalent here** — see "Celery and task queues" for that case rather than
looking for it in `TASKS`. Two normalizations are silent rather than refusing,
and both belong in a review:

- A `tuple` becomes a `list`, so a task annotated for a tuple receives a list.
- `bytes` are decoded as UTF-8 and arrive as `str`; bytes that are not valid
  UTF-8 raise `ValueError`. A task that believes it received binary receives
  text.

Everything else the Celery section says about arguments still applies, because
it is a property of the queue and not of the serializer: **arguments are a
trust boundary wherever the task store is reachable by anything but your
producers**, and a secret or an already-authorized capability token does not
belong in one.

**A task path is an import path.** `Task.module_path` is
`f"{func.__module__}.{func.__qualname__}"`, and a durable backend resolves that
string to a callable at execution time. Never build it from request data:
selecting a task by a user-supplied name is arbitrary-import, in the same class
as every other dynamic-import sink in `a05-injection.md`. Keep the mapping from
input to task in a literal dict in the code. The same rule reaches one place
that is easy to miss — `TaskError.exception_class` calls `import_string` on the
`exception_class_path` recorded on a stored result, and it validates that the
target is a `BaseException` subclass only *after* the import has run. Reading
`.exception_class` on results from a store a lower-trust party can write is
therefore an import of their choosing.

**The result holds the arguments, and the traceback holds the message.**
`TaskResult` retains `args` and `kwargs` as stored, and each `TaskError` keeps
a formatted traceback string. Confirmed on 6.0.7: a task enqueued with
`{"password": "hunter2"}` keeps that value on its result, and an exception
message appears in full in the stored traceback. The framework also logs to the
`django.tasks` logger — id, `module_path`, and backend on enqueue and start,
and the finish record with `exc_info` attached. So a result row is a store of
personal data and, when a task is called carelessly, of secrets: it takes the
retention and scrubbing rules in `data-lifecycle-and-privacy.md`, "Retention
you can prove ran", and the never-log list in `a09-logging-and-alerting.md`.
Result ids are random 32-character strings and `Task.get_result` raises
`TaskResultMismatch` when the id belongs to a different task function — that is
a type guard, not an authorization check, so exposing a result id to a client
exposes the result.

Two constraints the framework does enforce, worth knowing so they are not
mistaken for protections. `validate_task` requires a module-level function,
rejecting a nested function, a bound method, and a builtin; and it raises
`InvalidTask` for a coroutine, a non-default priority, or a `run_after` on a
backend whose capability flags do not declare support, and for a `queue_name`
missing from the backend's configured `QUEUES`. Neither is an authorization
control.

**Write-time.** When generating a `@task` function, resolve the authorization
decision in the caller before the enqueue and pass the outcome as an argument,
because the body has no principal to re-derive it from. Enqueue inside
`transaction.on_commit` even when the configured backend is immediate, since
that is the one placement correct under both. When generating the first task in
a project, write the `TASKS` setting explicitly rather than inheriting the
default, because the default is inline execution in the request cycle and the
difference is invisible at the call site. Never assemble a task's import path
from request data, and keep secrets and personal data out of task arguments,
because both are retained on the result and reproduced in logs.

## Signed cookies and data

- Django's signed-cookie session backend stores data in a signed (not encrypted)
  cookie — clients can read it. Don't put secrets there; prefer server-side
  sessions for sensitive data.
- Use Django `signing`/`TimestampSigner` for any value you hand out and expect
  back; check the signature on return. Note the 2026 signed-cookie salt-namespace
  fix — keep Django patched and review custom `get_signed_cookie` salts.

## Webhook and callback integrity

Maps to CWE-345 (Insufficient Verification of Data Authenticity) and CWE-347
(Improper Verification of Cryptographic Signature), with CWE-294 (Authentication
Bypass by Capture-replay) for the replay half and CWE-208 (Observable Timing
Discrepancy) for the comparison. OWASP API2:2023 also applies, because the
signature *is* the authentication for this endpoint. Severity is High to
Critical on any route that moves money, grants entitlement, or changes identity
state.

### Principle layer

A webhook endpoint is an unauthenticated public route that performs privileged
work on behalf of a system you do not control. Seven steps make it safe, and
each one is a distinct place implementations fail:

1. **Verify a MAC over the exact received bytes**, using a secret scoped to that
   one endpoint.
2. **Compare in constant time.** A byte-by-byte early-exit comparison leaks how
   much of a guess was right, which turns forgery into a search.
3. **Bind a timestamp into the signed material** and reject anything outside a
   tolerance. A timestamp the sender can alter without breaking the MAC is
   decoration.
4. **De-duplicate on the provider's event identifier**, because the timestamp
   check alone still permits replay inside the window.
5. **Make the effect idempotent**, because legitimate retries are routine and
   arrive long after any tolerance window has closed.
6. **Acknowledge fast and do the work asynchronously**, because a slow handler
   is recorded as a delivery failure and re-sent.
7. **Fail closed.** Any doubt is a rejection, and the rejection carries no
   detail about why.

Steps 4 and 5 are the same store seen from two sides. Replay defense needs the
identifier retained for at least the tolerance window; idempotency needs it
retained for as long as the provider will retry, which is hours to days —
Stripe retries for up to three days with exponential backoff, and Shopify
retries up to eight times over four hours before removing the subscription. Size
the retention for the longer of the two. The design of the store itself,
including why a durable unique constraint rather than an `exists()` check
arbitrates it, is in `a10-exceptional-conditions.md`, "Idempotency", and is not
restated here.

### Django & DRF implementation layer

#### The receiver, end to end

The failure that survives review is the raw body. Django's `HttpRequest.body`
reads and caches the stream on first access, so whichever layer touches it first
wins: once a parser has consumed the stream, `request.body` raises
`RawPostDataException`. The tempting repair is to sign the parsed data instead,
and that silently breaks verification, because re-serializing will not reproduce
the provider's key order, separators, or escaping. Engineers who hit this often
"fix" it by weakening the check.

```python
# Wrong: DRF's parser consumed the stream before this line, so the digest is
# computed over Django's re-serialization rather than the bytes that were
# signed, and it will never match a real payload. `!=` then compares what is
# left in non-constant time, and nothing bounds age or duplication.
import hashlib
import hmac
import json

from rest_framework.response import Response
from rest_framework.views import APIView


class WebhookView(APIView):
    def post(self, request):
        event = request.data
        expected = hmac.new(
            SECRET, json.dumps(event).encode(), hashlib.sha256
        ).hexdigest()
        if expected != request.headers["X-Sig"]:
            return Response(status=400)
        process(event)
        return Response(status=200)
```

```python
# Correct: a plain function view, so nothing parses ahead of the handler. Each
# step below is one of the seven, in the only order that works: bytes first,
# signature before parse, parse before use.
import hashlib
import hmac
import json
import time

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

TOLERANCE_SECONDS = 300


@csrf_exempt                      # server-to-server; the MAC is the auth
@require_POST
def stripe_webhook(request):
    payload = request.body        # raw bytes, before anything parses them
    header = request.headers.get("Stripe-Signature", "")
    pairs = [p.split("=", 1) for p in header.split(",") if "=" in p]
    timestamp = next((v for k, v in pairs if k == "t"), None)
    # Rolling a secret leaves two live at once, so the header carries one v1
    # per active secret. Collect them all; a dict here would keep only the
    # last and reject deliveries signed with the other valid secret.
    signatures = [v for k, v in pairs if k == "v1"]
    if not timestamp or not signatures:
        return HttpResponse(status=400)

    try:
        skew = abs(time.time() - int(timestamp))
    except ValueError:
        return HttpResponse(status=400)
    if skew > TOLERANCE_SECONDS:
        return HttpResponse(status=400)

    # The timestamp is inside the signed material, so it cannot be moved
    # forward without invalidating the signature.
    signed = timestamp.encode() + b"." + payload
    expected = hmac.new(SECRET, signed, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, s) for s in signatures):
        return HttpResponse(status=401)

    event = json.loads(payload)   # parse only after the bytes are trusted
    # The unique constraint arbitrates, so a duplicate loses the insert rather
    # than being screened out by a prior read. An already-seen event is
    # acknowledged, not re-processed: the provider needs a 2xx to stop.
    _, created = ProcessedEvent.objects.get_or_create(event_id=event["id"])
    if not created:
        return HttpResponse(status=200)

    process_event.delay(event["id"])   # fast ack, work off the request path
    return HttpResponse(status=200)
```

`csrf_exempt` belongs on this route and nowhere else, and it is only safe
because the MAC replaces what CSRF was protecting. A CSRF-exempt webhook route
with no signature check is an unauthenticated write endpoint. Where the sender
is first-party or the provider supports client certificates, requiring mutual
TLS at the proxy narrows who can reach this route at all without changing any
step above it (`service-identity-and-secrets.md`, "Client-certificate identity
behind a proxy").

In DRF the same ordering has to be won against the parsers rather than assumed;
that mechanic, and the DRF-shaped correct form, are in `api-drf-specific.md`,
"Payments and webhook bodies". Prefer a plain function view for a webhook.

#### What each provider signs

The scheme differs per provider, and copying one provider's comparison to
another is a common, exploitable bug — the encoding difference in particular,
because a hex comparison against a base64 digest fails closed in testing and
gets "fixed" by removing the check.

| Provider | Header | Signed material | Encoding |
|---|---|---|---|
| Stripe | `Stripe-Signature: t=<unix>,v1=<sig>` | `"{t}." + raw body` | hex |
| GitHub | `X-Hub-Signature-256: sha256=<sig>` | raw body | hex |
| Shopify | `X-Shopify-Hmac-SHA256: <sig>` | raw body | **base64** |
| Standard Webhooks | `webhook-signature: v1,<sig>` | `"{webhook-id}.{webhook-timestamp}." + raw body` | **base64** |

All four are HMAC-SHA256. Details that change the code:

- **Stripe** scopes the secret per endpoint, and rolling a secret leaves both
  active for up to 24 hours with one signature per secret in the header — so a
  verifier must accept *any* matching `v1` value, not the first one. Ignore
  schemes other than `v1`; the `v0` value present on test events exists to be
  ignored, and treating unknown schemes as acceptable is a downgrade path.
- **GitHub** sends no timestamp, so recency cannot be enforced and replay
  defense rests entirely on de-duplicating `X-GitHub-Delivery`. The legacy
  `X-Hub-Signature` header is HMAC-SHA1 and exists only for compatibility;
  verifying it instead of the SHA-256 header is a finding.
- **Shopify** keys the HMAC with the app's client secret and identifies a
  delivery with `X-Shopify-Webhook-Id`.
- **Standard Webhooks** base64-encodes the secret after its `whsec_` prefix, and
  carries a space-delimited list of signatures so rotation can sign with the old
  and new keys at once; accept the message if any entry verifies.

#### Keying the replay store

Key on **the provider's event or delivery identifier** — `event.id`,
`X-GitHub-Delivery`, `X-Shopify-Webhook-Id`, `webhook-id`. It is stable across
retries, it is meaningful in a log, and it is already the idempotency key, so
one row serves both jobs.

The alternatives do not work. **Keying on the signature** fails on the
provider's own retries: Stripe generates a fresh timestamp and signature for
each delivery attempt, so the same event re-signed reads as a new one and gets
processed twice — the exact duplicate the store exists to prevent. **Keying on a
nonce** requires the provider to issue a single-use one, which most do not, and
where one exists it is the event identifier under another name.

Where the handler does the work inline, put the receipt row and the effect in
one transaction, so a receipt can only exist if its effect committed. Where the
handler acknowledges and defers — the shape above, and the one the fast-ack rule
pushes you toward — the receipt records only that the event was *accepted*, and
the worker still needs an idempotent effect of its own. A receipt row is not
evidence that anything happened. Decide which of the two shapes you are
building; the common failure is to write the deferred one while reasoning about
the guarantees of the inline one.

A Redis `SET` with a TTL is adequate for the recency check alone, but it is not
durable under eviction and must not be the only thing standing between a retry
and a second payment.

Two rules survive from the payment case and are absolute: **never take an
amount, price, or currency from the callback payload as authoritative** —
reconcile against your own record — and never treat the payload's assertion
about who the actor is as authorization. A verified signature proves the message
came from the provider. It proves nothing about what the message is entitled to
do.

#### Sending webhooks of your own

An outbound-delivery worker is an HTTP client whose destinations are supplied by
users, which makes it an SSRF vector and a potential amplifier. The controls
specific to webhook delivery:

- **Address destinations by a registered identifier, not a free-form URL at call
  time**, and re-validate the stored URL at every delivery rather than only at
  registration.
- **Resolve the host and check every resolved address immediately before
  connecting**, so DNS rebinding cannot move the target between the check and
  the request; disable redirects or re-validate each hop. The allowlisting
  mechanics, the private and link-local ranges, and the cloud metadata endpoint
  are owned by `a01-broken-access-control.md`, "SSRF".
- **Isolate the delivery worker's egress** so it cannot reach internal services
  or the metadata endpoint even if the application-level check is wrong. This is
  the layer most implementations skip, and it is the one that holds when the
  others fail.
- **Bound the retry machinery** — a maximum attempt count, exponential backoff,
  a per-destination rate limit, and a delivery timeout. Without them, an
  attacker who registers a victim's URL and triggers events turns your retry
  logic into an amplifier pointed at a third party (CWE-770).
- **Sign what you send**, over the raw body with a timestamp bound in, so
  consumers can verify you; support rotation by signing with the old and new
  keys during an overlap window and sending both. Where the signing secrets live
  and how they rotate is `service-identity-and-secrets.md`.

## Pipeline and artifact integrity

Maps to CWE-494 (Download of Code Without Integrity Check) and CWE-829.
`a03-software-supply-chain.md` owns which dependencies you are entitled to
install and how they are pinned and scanned. This section owns the narrower
question A08 asks: **can you prove that what you shipped is what you built, and
that what you consumed is what its publisher produced.**

What a backend repository owns, and can be reviewed for:

- Installs verify artifact integrity, not just version numbers — a committed
  lockfile plus hash checking, so a swapped artifact fails the install rather
  than running. The commands are in A03, "Pin and verify"; the finding here is
  a Dockerfile or deploy script that installs unpinned or unhashed while the
  lockfile sits unused beside it.
- Base images and critical build tools you consume are signature- or
  provenance-verified before use, rather than pulled by mutable tag.
- Artifacts you publish carry provenance. SLSA's Build track sets the floor:
  **L1 is "package has provenance showing how it was built"**, and it is a
  repository-level opt-in that generated attestations satisfy. Treat its own
  caveat as part of the finding — L1 provenance is trivial to forge, so it
  establishes a record, not a guarantee. The current specification version,
  what a build on hosted runners may honestly claim above that floor, and the
  consumer-side verification without which none of it means anything are in
  `a03-software-supply-chain.md`, "SBOM, scan gate, and provenance".
- Deploy credentials and CI secrets are protected, because a compromised
  pipeline ships attacker code under your signature. Prefer short-lived
  federated credentials over long-lived deploy keys; A03 and
  `service-identity-and-secrets.md` carry that decision.
- For signed data your own application hands out and takes back, use
  `django.core.signing` with `TimestampSigner` and `max_age` rather than a
  hand-rolled token or anything pickle-based.

**Out of scope, and worth naming as such** so it is not mistaken for an
unaddressed gap: hardened or hermetic isolated builders (SLSA Build L3),
the CI platform's key custody, two-person review, and organization-wide registry
admission control are platform work rather than repository work. Report them as
platform recommendations, not as repository findings.

## Review checklist

### Stack-neutral

- [ ] No object-constructing deserializer (`pickle`, unsafe YAML, `marshal`,
      `dill`, `jsonpickle`) reads bytes from any store an attacker can write to;
      interchange formats are data-only.
- [ ] Every store the application deserializes from — cache, queue, session,
      file, database column — has been checked for who can write to it, not only
      for who can read it.
- [ ] Where protobuf crosses a trust boundary, the runtime is outside the
      affected range of both recursion advisories, no `Any` is unpacked without
      an allow-list of type URLs, and no message is relayed onward carrying
      unknown fields this service never validated.
- [ ] Task-queue messages are treated as unauthenticated input: arguments are
      validated inside the task, and no secret or capability token is passed as
      an argument.
- [ ] A signed task serializer is credited with integrity only; anything
      sensitive that has to travel in a message or a result is protected by
      transport and at-rest encryption, or encrypted at the application layer
      where the broker is outside the trust boundary.
- [ ] Webhook receivers verify a MAC over the exact received bytes with a
      per-endpoint secret, using a constant-time comparison and the provider's
      own encoding.
- [ ] A timestamp is inside the signed material and a tolerance is enforced —
      neither zero nor open-ended; five minutes is the industry default.
- [ ] A durable store keyed on the provider's event or delivery identifier
      de-duplicates, retained for as long as the provider will retry rather than
      only for the tolerance window.
- [ ] Receivers acknowledge with a 2xx quickly and defer the work; rejections
      return an error without detail, a stack trace, or a hint about which check
      failed.
- [ ] Payload amounts, prices, and actor claims are reconciled server-side; a
      valid signature is treated as proof of origin only.
- [ ] Outbound deliveries go to registered destinations re-validated at send
      time, with redirects bounded, egress isolated, retries capped with backoff
      and a per-destination limit, and payloads signed with overlapping keys
      across a rotation.
- [ ] Published artifacts have provenance and installs verify hashes; build
      inputs are pinned and consumed by digest rather than by mutable tag.

### Django & DRF

- [ ] The cache store is not attacker-writable, given that every built-in Django
      cache backend deserializes with `pickle`: the file-cache directory is not
      world-writable, Redis and memcached are authenticated and private, the
      database cache table is not reachable by injection, and no lower
      environment writes a cache production reads.
- [ ] No custom or third-party pickle-based session or signing serializer; the
      stock `JSONSerializer` is in use and `SECRET_KEY` is neither weak, shared
      across environments, nor committed.
- [ ] `CELERY_ACCEPT_CONTENT` is JSON-only — the setting that decides what a
      worker will execute — with the task and result serializers set explicitly;
      the broker is authenticated and unreachable from the internet, and the
      result backend holds no secrets.
- [ ] Where `django.tasks` is used, `TASKS` is set explicitly rather than
      inherited, since the default backend executes tasks inline in the request
      cycle, swallows the exception, and gives the operation the request
      timeout it was moved off the request path to escape.
- [ ] Every `@task` body receives its authorization outcome as an argument
      resolved by the caller, rather than re-deriving permission from an
      identifier with no principal to check it against; secrets and personal
      data stay out of arguments, which are retained on the result and logged.
- [ ] Enqueues are wrapped in `transaction.on_commit`, no task import path is
      built from request data, and where both `django.tasks` and Celery are
      present the inventory covers both.
- [ ] `loaddata` and `serializers.deserialize` never run on attacker-influenced
      fixtures; fixtures are `json` or `xml`, and the privilege fields a fixture
      can set while bypassing `save()` and `full_clean()` are accounted for.
- [ ] `dumpdata` output is not written to a web-served path, committed, or baked
      into an image.
- [ ] The webhook view reads `request.body` before anything touches
      `request.data` or `request.POST`, and no middleware consumes the stream
      ahead of it; the HMAC input is the raw bytes, never `json.dumps` of parsed
      data.
- [ ] Comparison uses `hmac.compare_digest`, never `==`.
- [ ] `csrf_exempt` appears on the webhook route only, and that route verifies a
      signature.
- [ ] The de-duplication insert is arbitrated by a unique constraint, not by an
      `exists()` check; it shares a transaction with an inline effect, and where
      the work is deferred the worker carries its own idempotency.
