# A08:2025 — Software and Data Integrity Failures

This file covers insecure deserialization, unsafe task serializers, and
unsigned or unauthenticated data that crosses a system boundary. It also covers
the integrity of the pipeline that ships code. It owns the receiving end of
cross-system trust. That end is the webhook a provider sends you, and the
message a worker takes off a broker. It is also every layer that turns stored
or transmitted bytes back into live objects. Payment webhook integrity lives
here and in the DRF file.

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

An integrity failure occurs when your system trusts data or code whose
authenticity it never verified. The examples are a serialized object from the
network, an unsigned update, and a webhook that anyone could forge. The
principle is **verify before you trust**. Sign and check the data you
round-trip. Never deserialize untrusted input into live objects. Authenticate
the source of anything that drives a state change.

## Insecure deserialization

Maps to CWE-502 (Deserialization of Untrusted Data). Severity is Critical
wherever an attacker controls the bytes, because the outcome is code execution
rather than data corruption.

### Principle layer

A format that produces only strings, numbers, lists, and maps is data. A
format that can name a class or a callable, and have the parser construct it,
is a program. A deserializer that reads untrusted input in such a format runs
an attacker's program with your process's privileges. The defense is a format
choice, not a filter. No allowlist of permitted types makes an
object-constructing format safe, because the attack lives in the construction
itself.

The useful review question is therefore not "where did someone call
`loads()`". It is **"where does any layer turn stored or transmitted bytes
back into objects"**. The developer's own calls are already under suspicion.
The framework's calls are the ones nobody reads: the cache, the session, and
the queue. They are where the reachable instances usually are.

That changes the threat model. An object-constructing deserializer turns *any*
write primitive into code execution. A store the application trusts becomes a
place to leave a payload, and the application itself loads and runs it. Thus
the question after you find one is always "who can write to what this reads
from". A "we only read our own data back" argument is only as strong as the
write controls on that store.

### Django & DRF implementation layer

#### The paths a developer writes

- **`pickle.loads` and `pickle.load`** on anything that crossed a trust
  boundary. Construction runs `__reduce__` on the attacker's terms. There is
  no safe subset and no safe loader option.
- **`yaml.load` with no `Loader` argument or with `UnsafeLoader`**, plus
  `yaml.unsafe_load`. Each one constructs arbitrary Python objects.
  `FullLoader` and `yaml.full_load` construct a wider object set than
  `safe_load`, and they are the lower-severity sibling. Only `yaml.safe_load`,
  or equivalently `SafeLoader`, is data-only.
- **`marshal`, `dill`, and `jsonpickle`** reconstruct arbitrary objects, and
  they belong in the same class as `pickle`. That includes where they arrive
  as a machine learning model file or a cached computation.
- **`django.core.serializers.deserialize`** on input an attacker can
  influence. See the fixtures section below.

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
message is schema-bound. The parser can fill only the fields the compiled
descriptor declares, so it cannot name a class or reach a constructor the way
pickle can. Unlike JSON it also arrives bounded. grpcio caps a received
message at 4 MB, protobuf's pure-Python decoder carries
`DEFAULT_RECURSION_LIMIT = 100`, and `json_format.Parse` and `ParseDict`
default `max_recursion_depth=100`. All of those come from grpcio 1.83.0 and
protobuf 7.35.1, read on 9 Aug 2026.

What keeps it out of the safe column is that attackers have bypassed both
recursion guards. CVE-2025-4565 exhausts the interpreter's own limit through
nested groups and recursive messages in the pure-Python decoder, fixed in
4.25.8, 5.29.5, and 6.31.1. CVE-2026-0994 bypasses the JSON guard through
nested `google.protobuf.Any` messages, fixed in 5.29.6 and 6.33.5. Both are
denial of service rather than execution, and the current 7.x line is outside
the affected range of each.

Two behaviors stay reviewable on any version. An unpacked `Any` instantiates
whichever message type the sender named. Allow-list the acceptable type URLs
before you unpack. proto3 preserves unknown fields through a binary parse and
re-serialize. A message relayed onward therefore carries fields this service
never validated. `graphql-and-alternative-api-surfaces.md`, "gRPC: nothing from
the DRF request cycle applies", owns the surface that receives them.

#### The paths the framework runs for you

**The cache framework pickles by default, on every built-in backend.**
`RedisCache`, `LocMemCache`, `FileBasedCache`, `DatabaseCache`, and the
memcached backends all serialize with `pickle` at the highest protocol.
`PyMemcacheCache` does so by a `serde` default of pymemcache's pickle serde,
and `PyLibMCCache` through pylibmc's native serialization. **Django ships no
built-in JSON serializer for the cache.** Thus a move off pickle needs a
custom serializer, or a third-party backend that provides one. There is no
setting to change.

The consequence is the write-primitive rule above, made concrete. Anyone who
can write to the cache store gets code execution the next time the application
calls `cache.get()`. Treat each of these as a finding in its own right. The
first is a world-writable file-cache directory, and the second a Redis or
memcached instance reachable without authentication. The third is a cache table
exposed to SQL injection. The fourth is a cache shared across environments, so
that a lower-trust deployment can write what production reads.

Django's own documentation warns that the file-cache directory is a
code-execution path where an attacker can write to it.
`deployment-and-runtime.md`, "Caching security", owns the service-level
controls. `a01-broken-access-control.md` owns the key-scoping and
authorization side.

**Sessions no longer offer a pickle option.**
`django.contrib.sessions.serializers.PickleSerializer` was deprecated in
Django 4.1 and removed in 5.0. Thus on the supported lines `JSONSerializer` is
the only built-in session serializer, and stock configuration cannot select
pickle. The live findings are a *custom* or third-party pickle-based session
serializer, and a leaked or weak `SECRET_KEY`. A weak key with any
pickle-capable serializer is a direct route from signing-key disclosure to
code execution. `service-identity-and-secrets.md` owns rotation and leak
response.

**`django.core.signing` is JSON by default.** `dumps` and `loads` default to
`JSONSerializer`, so the built-in signing helpers are data-only unless a
`serializer=` argument replaces that default. A pickle-based serializer passed
there is the same finding as a pickle session.

Message-queue payloads are the fourth implicit path; they are in the Celery
section below.

#### Fixtures: `loaddata` and `dumpdata`

Fixtures are a bulk write that bypasses the layer that normally enforces
invariants. A load calls `Model.save_base` with `raw=True`. Thus a model's
overridden `save()` never runs, nothing calls `full_clean()`, and `pre_save`
and `post_save` fire with `raw=True` set, which a correct handler skips on. A
fixture can therefore set `is_staff`, `is_superuser`, a price, or a tenant to
values no code path would ever permit. That is a privilege-escalation route in
the safe JSON format, and it needs no deserialization bug.

- Any code path that runs `loaddata` or `serializers.deserialize` on content
  an attacker can influence is a trust boundary. The cases are a user-facing
  "import" feature, a backup-restore endpoint, and fixtures read from a
  writable location. Validate and authorize the contents as request input, or
  do not accept them.
- Django's built-in formats are `json`, `jsonl`, `xml`, and `yaml`. The YAML
  serializer exists only where PyYAML is installed, and it loads with
  `SafeLoader` (`django/core/serializers/pyyaml.py`, read on Django 6.0.7).
  Thus a YAML fixture is not the `yaml.load` finding above. Its risk is the
  same unvalidated bulk write, and the same authorization question, as every
  other format. Keep fixtures on `json` or `xml`, because the extra dependency
  gives nothing here. Django 6.1 hardens the XML path, where the deserializer
  now raises `SuspiciousOperation` on an unexpected nested tag.
- `dumpdata` output is a concentrated copy of model data, and it needs the
  handling a database backup gets. At review time, check three places. Confirm
  that nothing writes it under a web-served path, commits it to version
  control, or bakes it into a container image. `data-lifecycle-and-privacy.md`
  owns retention and copies of personal data.

### Commonly mistaken for a finding

**`pickle` on bytes the application itself wrote to a location no other
principal can write.** Severity in this section is Critical wherever an
attacker controls the bytes, and `pickle.loads` is the most recognizable
identifier in the file. Thus a reviewer often reports the call as remote code
execution before they read the store behind it. The deciding question is who
can write the bytes, not which module reads them. The safe cases are a
memoization file under a directory only this process owns. The second is a
cached computation in a Redis instance nothing else can reach. The third is a
blob in a table no untrusted path writes.

Keep the design objection, because that answer is a property of the deployment
rather than of the code. The write controls are exactly what the review before
this one cannot see. Drop the RCE claim, which asserts an attacker nobody has
shown to exist. This is the same question the write-primitive rule above asks,
read in the other direction. Where any second principal can reach that store,
the finding is live and it is Critical.

**Write-time.** When you generate code that persists application state for the
application itself to read back later, write it in a data-only format. Do this
even though nothing untrusted writes that store today. The property that makes
`pickle` safe there belongs to the deployment, such as a directory's
permissions or a broker's network position. People who will never read this
call change that property.

## Celery and task queues

Maps to CWE-502 where the serializer constructs objects, and CWE-306 (Missing
Authentication for Critical Function) for the enqueue path itself.

### Principle layer

**A worker authenticates the message, not the producer.** A task is a
serialized message on a broker, and a worker executes any well-formed message
on a queue it consumes. Nothing in the protocol records who put it there. No
client library is necessary to put one there, because the broker's wire
protocol is enough. Thus the set of principals who can invoke your tasks is
exactly the set who can reach the broker. That is rarely the set the code was
written for.

Two consequences follow, and the second is the one usually missed:

- If the serializer can construct objects, broker reachability is remote code
  execution outright.
- **Even with a data-only serializer, a principal that reaches the broker can
  invoke any registered task with any arguments.** That is an authorization
  bypass on every task. It is frequently an indirect route to code execution.
  The route is a task that calls another program, writes a file, or processes
  input it believes is internal.

**Therefore task arguments are a trust boundary, not internal data.** Validate
them inside the task as though they arrived from an anonymous client. Never
pass a secret or an already-authorized capability token as an argument, on the
reasoning that only your own code enqueues this task.

### Django & DRF implementation layer

Celery has defaulted to JSON since 4.0. `task_serializer` and
`result_serializer` are `json`, and `accept_content` is `{'json'}`. Thus the
finding is almost never the default. It is a project that *widened*
`accept_content` to admit `pickle` or `yaml`, usually to move a
non-serializable argument, and left it wide afterwards. Set the three
explicitly, so that the intent is visible and a dependency's default cannot
change it:

```python
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
```

`accept_content` is the one that decides what a worker will execute. The other
two only decide what it emits. A single `"pickle"` entry there re-opens the
hole, whatever the producers are configured to send.

`result_accept_content` is the separate allowlist for the result-reading side.
It defaults to `None`, which means it follows `accept_content`. Thus a project
that widens that one setting alone re-opens the hole on the result backend,
while `accept_content` still reads as narrow.

**Write-time.** When you generate Celery configuration, write those three
settings explicitly, even though the defaults already match them. The finding
here is always a later widening, and an explicit `["json"]` is the line a
reviewer can watch for a change.

When you generate a task, validate its arguments inside the task body. Pass
identifiers rather than objects, secrets, or an already-authorized token.
Whatever can reach the broker can call that task with arguments of its own
choosing. Where a sensitive value genuinely has to travel in the message,
encrypt it in the producer and decrypt it in the task. Do not rely on the
signed serializer, which authenticates the message without concealment of it.

- **The result backend is a second exposure with the same reach.** Celery
  writes results to the broker or an equivalent store, and whatever can reach
  that store can read and write them. Thus a task that returns personal data
  or a token publishes it there. Projects also routinely log task arguments
  and results. Keep both free of secrets, and see
  `a09-logging-and-alerting.md`.
- **Celery's `auth` serializer signs messages, so a worker rejects any message
  a trusted key did not sign.** That is the mechanism that actually
  authenticates the producer. Its own documentation is explicit that it does
  not encrypt the contents. Thus it addresses forgery and not disclosure, and
  a broker that can read the payload still reads it.
- **Confidentiality is therefore a separate decision, and Celery ships no
  option that makes it.** A message sits on the broker in the clear for as
  long as it is queued. The result sits in the backend for as long as the
  project retains it. Thus whatever reaches that store can read anything
  sensitive in either. That includes its operator, its snapshots, and its own
  logs.

  Two answers exist, and they defend against different things. TLS to the
  broker and the result backend, plus at-rest encryption of their storage,
  covers the network and the disk. That is the right default, and it does not
  cover the broker itself. The broker can also sit outside the trust boundary,
  as a managed service or a shared cluster does. Encrypt the sensitive
  argument in the producer there, and decrypt it in the task. The message then
  carries ciphertext, with the key handled per
  `a04-cryptographic-failures.md`, "Key lifecycle and envelope encryption".

  Neither answer is necessary for an argument that is only an identifier the
  task resolves for itself, which is why that remains the default.
- `deployment-and-runtime.md`, "Queue and broker exposure", owns broker
  authentication, network placement, and the standing severity of a reachable
  unauthenticated Redis. A worker's own database and network privileges are
  part of the blast radius. A task queue is a second, unauthenticated front
  door to every capability the worker holds.
- Dispatch belongs after the commit, not inside the transaction. See
  `a10-exceptional-conditions.md`, which owns the side-effect ordering and the
  redelivery semantics that make a task's own handling need to be idempotent.

## Django's built-in tasks framework

Maps to CWE-306 (Missing Authentication for Critical Function) for the task
body. It maps to CWE-863 (Incorrect Authorization) where a task re-derives a
permission it has no principal to derive.

Django gained a built-in tasks framework in the 6.0 line. It holds
`django.tasks`, a `@task` decorator, `Task.enqueue()` and `aenqueue()`, a
`TaskResult`, and a `TASKS` setting shaped like `DATABASES` and `CACHES`.
Every behavior below comes from the Django 6.0.7 source, exercised against it
on 14 August 2026. Django 6.1 adds to this framework, and the 6.1 items below
name their release. Treat each unnamed claim as scoped to the 6.0 line.

### Principle layer

**A task function runs with no request and no authenticated user.** There is
no `request.user`, no session, and no DRF permission class between the caller
and the body. Thus the code that still holds a principal has to resolve the
authorization decision *before* the enqueue. It then carries the decision into
the task as data. The task receives a decision already made, not an identifier
to judge later.

That changes a common shape. A task that receives an object id and re-derives
permission from it inside itself re-derives it **with no principal**. There is
nobody to check the id against. Thus the check either compares the object to
nothing, or silently becomes a check that everyone passes. Pass the
identifiers the task needs to do its work, and pass the authorization outcome
separately, as a fact the caller established.

**A project with two task systems has two authorization boundaries, and
usually reviews one.** Where the built-in framework lands in a codebase that
already runs Celery, expect the two to coexist rather than replace each other.
New code takes the built-in framework, and existing tasks stay. Both are
execution entry points, and they carry different defaults. An inventory that
stops at `@shared_task` misses half the surface. Enumerate both.
`01-audit-workflow.md`, "Phase 1 — entry-point inventory" carries the row.

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
the 6.0 line: `ImmediateBackend`, and `DummyBackend` for tests. It ships no
durable one, so a real worker comes from a third-party backend. Three review
consequences follow, and none of them looks like a task-queue finding:

- The work inherits the request timeout and the worker process. Thus a job
  sized for a background queue becomes a denial of service against the web
  tier. Whatever bound `a06-insecure-design.md` assigns the operation has to
  hold at request latency, because that is where it now runs.
- `ImmediateBackend._execute_task` catches `BaseException`, with
  `KeyboardInterrupt` excepted. It records the exception on the result, and
  returns normally. **The caller sees no exception.** A task that fails in
  production fails silently unless something inspects the result. Neither
  shipped backend supports a read of one: `supports_get_result` is `False` on
  both, and `ImmediateBackend.get_result` raises `NotImplementedError`.
- Neither shipped backend supports `run_after`, because `supports_defer` is
  `False`. Thus a scheduled task is a third-party backend's feature, and not
  the framework's.

**Enqueue belongs after the commit, and the backend decides which way it goes
wrong.** Nothing in `django.tasks` integrates with `transaction.on_commit`.
With a durable backend the familiar failure holds. The worker claims the
message before the producer commits, and reads a row that does not exist yet.
With `ImmediateBackend` the failure inverts. The task body runs *inside*
`enqueue()`, on the caller's thread, within the open atomic block. Thus it
reads uncommitted state, and its own writes and side effects roll back with
the transaction that enclosed them.

Verified on 6.0.7: a task enqueued inside `transaction.atomic()` observed the
uncommitted row, and the rollback took both back. `transaction.on_commit` is
the answer under either backend. `a10-exceptional-conditions.md`, "Side
effects and the commit boundary" owns the ordering rule. Its "Idempotency"
section owns the duplicate delivery any retrying backend will produce, which
the framework does not make idempotent for you.

**Argument serialization is JSON-only, and it refuses at enqueue time.**
`TaskResult.__post_init__` runs `django.utils.json.normalize_json` over `args`
and `kwargs`. That function admits `Mapping`, `Sequence`, `str`, `int`,
`float`, `bool`, and `None`, and it raises `TypeError` on anything else.
Confirmed rejected on 6.0.7: a model instance, `datetime`, `Decimal`, `set`,
and `UUID`.

This is the good news, and it is worth a plain statement. **There is no
serializer setting to widen, so the Celery pickle finding above has no
equivalent here.** See "Celery and task queues" for that case, rather than
search for it in `TASKS`. Two normalizations are silent rather than refuse,
and both belong in a review:

- A `tuple` becomes a `list`, so a task annotated for a tuple receives a list.
- Django decodes `bytes` as UTF-8, and they arrive as `str`. Bytes that are
  not valid UTF-8 raise `ValueError`. A task that believes it received binary
  receives text.

Everything else the Celery section says about arguments still applies, because
it is a property of the queue and not of the serializer. **Arguments are a
trust boundary wherever anything but your producers can reach the task
store.** A secret or an already-authorized capability token does not belong in
one.

**A task path is an import path.** `Task.module_path` is
`f"{func.__module__}.{func.__qualname__}"`, and a durable backend resolves
that string to a callable at execution time. Never build it from request data.
A task selected by a user-supplied name is arbitrary-import, in the same class
as every other dynamic-import sink in `a05-injection.md`. Keep the mapping
from input to task in a literal dict in the code.

The same rule reaches one place that is easy to miss.
`TaskError.exception_class` calls `import_string` on the
`exception_class_path` recorded on a stored result. It validates that the
target is a `BaseException` subclass only *after* the import has run. Thus a
read of `.exception_class` on results from a store a lower-trust party can
write is an import of their choosing.

**The result holds the arguments, and the traceback holds the message.**
`TaskResult` retains `args` and `kwargs` as stored, and each `TaskError` keeps
a formatted traceback string. Confirmed on 6.0.7: a task enqueued with
`{"password": "hunter2"}` keeps that value on its result, and an exception
message appears in full in the stored traceback. The framework also logs to
the `django.tasks` logger. It logs the id, the `module_path`, and the backend
on enqueue and start, and the finish record with `exc_info` attached.

Thus a result row is a store of personal data, and, where a task is called
carelessly, of secrets. It takes the retention and scrubbing rules in
`data-lifecycle-and-privacy.md`, "Retention you can prove ran", and the
never-log list in `a09-logging-and-alerting.md`. Result ids are random
32-character strings, and `Task.get_result` raises `TaskResultMismatch` where
the id belongs to a different task function. That is a type guard, not an
authorization check. Thus an exposed result id exposes the result.

The framework does enforce two constraints. Know them, so that nobody mistakes
them for protections. `validate_task` requires a module-level function, and
rejects a nested function, a bound method, and a builtin. It also raises
`InvalidTask` for a coroutine, a non-default priority, or a `run_after` on a
backend whose capability flags do not declare support. It raises the same error
for a `queue_name` missing from the backend's configured `QUEUES`. Neither
constraint is an authorization control.

Django 6.1 makes `Task` and `TaskResult` picklable, which moves them into
stores this file already rules on. A `TaskResult` holds the arguments and the
traceback verbatim, so a pickle-serialized cache or session now carries that
payload too. `Task.__reduce__` records `module_path`, and Django calls
`import_string` on that value when it rebuilds the object. That is the
import-driven path `TaskError.exception_class` takes above.

Neither fact is a new risk in a pickle store an attacker can already write,
because pickle runs code by design. The rule is unchanged, and it now reaches
further. Unpickle only from a store no lower-trust party can write. Verified
against the 6.1 source of `django/tasks/base.py` on 20 Aug 2026.

**Write-time.** When you generate a `@task` function, resolve the
authorization decision in the caller before the enqueue, and pass the outcome
as an argument. The body has no principal to re-derive it from. Enqueue inside
`transaction.on_commit`, even where the configured backend is immediate,
because that is the one placement correct under both.

When you generate the first task in a project, write the `TASKS` setting
explicitly rather than inherit the default. The default is inline execution in
the request cycle, and the difference is invisible at the call site. Never
assemble a task's import path from request data. Keep secrets and personal
data out of task arguments, because the result retains both and the logs
reproduce them.

## Signed cookies and data

- Django's signed-cookie session backend stores data in a signed cookie, and
  not in an encrypted one, so a client can read it. Do not put a secret there.
  Prefer server-side sessions for sensitive data.
- Use Django `signing` or `TimestampSigner` for any value you give out and
  expect back. Check the signature on return. Note the 2026 signed-cookie
  salt-namespace fix. Keep Django patched, and review custom
  `get_signed_cookie` salts.

## Webhook and callback integrity

Maps to CWE-345 (Insufficient Verification of Data Authenticity) and CWE-347
(Improper Verification of Cryptographic Signature). CWE-294 (Authentication
Bypass by Capture-replay) covers the replay half, and CWE-208 (Observable
Timing Discrepancy) covers the comparison. OWASP API2:2023 also applies,
because the signature *is* the authentication for this endpoint. Severity is
High to Critical on any route that moves money, grants entitlement, or changes
identity state.

### Principle layer

A webhook endpoint is an unauthenticated public route that performs privileged
work on behalf of a system you do not control. Seven steps make it safe, and
each one is a distinct place where an implementation fails:

1. **Verify a MAC over the exact received bytes**, using a secret scoped to that
   one endpoint.
2. **Compare in constant time.** A byte-by-byte early-exit comparison leaks
   how much of a guess was right, which turns forgery into a search.
3. **Bind a timestamp into the signed material**, and reject anything outside
   a tolerance. A timestamp the sender can alter without a break of the MAC is
   decoration.
4. **De-duplicate on the provider's event identifier**, because the timestamp
   check alone still permits replay inside the window.
5. **Make the effect idempotent**, because legitimate retries are routine and
   arrive long after any tolerance window has closed.
6. **Acknowledge fast, and do the work asynchronously.** The provider records
   a slow handler as a delivery failure, and sends the event again.
7. **Fail closed.** Any doubt is a rejection, and the rejection carries no
   detail about why.

Steps 4 and 5 are the same store seen from two sides. Replay defense needs the
identifier retained for at least the tolerance window. Idempotency needs it
retained for as long as the provider will retry, which is hours to days.
Stripe retries for up to three days with exponential backoff, and Shopify
retries up to eight times over four hours before it removes the subscription.
Size the retention for the longer of the two. `a10-exceptional-conditions.md`,
"Idempotency", owns the design of the store itself, including why a durable
unique constraint rather than an `exists()` check arbitrates it.

### Django & DRF implementation layer

#### The receiver, end to end

The failure that survives review is the raw body. Django's `HttpRequest.body`
reads and caches the stream on first access, so whichever layer touches it
first wins. Once a parser has consumed the stream, `request.body` raises
`RawPostDataException`. The tempting repair is to sign the parsed data
instead, and that silently breaks verification. A re-serialization will not
reproduce the provider's key order, separators, or escaping. An engineer who
meets this often "corrects" it by a weakening of the check.

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

from django.db import transaction
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
    # acknowledged, not re-processed: the provider needs a 2xx to stop. The
    # row records that the event was RECEIVED; the worker transitions it.
    _, created = ReceivedEvent.objects.get_or_create(
        event_id=event["id"],
        defaults={"payload": event, "status": ReceivedEvent.RECEIVED},
    )
    if not created:
        return HttpResponse(status=200)

    # The committed row is the durable fact and the enqueue is only a wake-up,
    # so it runs after the commit. Enqueuing before the commit races the
    # worker against a row it cannot read yet; enqueuing outside on_commit
    # loses the work when the process dies here.
    transaction.on_commit(lambda: process_event.delay(event["id"]))
    return HttpResponse(status=200)
```

The record is the durable fact, and the enqueue is only a wake-up. A crash
between the commit and the enqueue, or a broker outage at `.delay`, leaves a
`RECEIVED` row that no worker claimed. A periodic sweep enqueues the
`RECEIVED` records older than a small threshold again, so a lost wake-up
delays the work instead of drops it. The lease, the retry, and the dead-letter
design of that worker belong to queue delivery and retry mechanics, which this
file does not cover. This file owns one thing only: the verified event
survives the acknowledgment.

`csrf_exempt` belongs on this route and nowhere else. It is safe only because
the MAC replaces what CSRF was protecting. A CSRF-exempt webhook route with no
signature check is an unauthenticated write endpoint. Where the sender is
first-party, or the provider supports client certificates, mutual TLS required
at the proxy narrows who can reach this route at all. It changes no step above
it (`service-identity-and-secrets.md`, "Client-certificate identity behind a
proxy").

In DRF you have to win the same ordering against the parsers, rather than
assume it. `api-drf-specific.md`, "Payments and webhook bodies", holds that
mechanic and the DRF-shaped correct form. Prefer a plain function view for a
webhook.

#### What each provider signs

The scheme differs per provider, and a copy of one provider's comparison to
another is a common, exploitable defect. The encoding difference is the worst
case. A hex comparison against a base64 digest fails closed in testing, and a
developer "corrects" it by a removal of the check.

| Provider | Header | Signed material | Encoding |
|---|---|---|---|
| Stripe | `Stripe-Signature: t=<unix>,v1=<sig>` | `"{t}." + raw body` | hex |
| GitHub | `X-Hub-Signature-256: sha256=<sig>` | raw body | hex |
| Shopify | `X-Shopify-Hmac-SHA256: <sig>` | raw body | **base64** |
| Standard Webhooks | `webhook-signature: v1,<sig>` | `"{webhook-id}.{webhook-timestamp}." + raw body` | **base64** |

All four are HMAC-SHA256. These details change the code:

- **Stripe** scopes the secret per endpoint. A rolled secret leaves both
  active for up to 24 hours, with one signature per secret in the header. Thus
  a verifier must accept *any* matching `v1` value, and not the first one.
  Ignore schemes other than `v1`. The `v0` value present on test events exists
  to be ignored, and an acceptance of unknown schemes is a downgrade path.
- **GitHub** sends no timestamp, so you cannot enforce recency. Replay defense
  rests entirely on de-duplication of `X-GitHub-Delivery`. The legacy
  `X-Hub-Signature` header is HMAC-SHA1, and it exists only for compatibility.
  A verifier that checks it instead of the SHA-256 header is a finding.
- **Shopify** keys the HMAC with the app's client secret and identifies a
  delivery with `X-Shopify-Webhook-Id`.
- **Standard Webhooks** base64-encodes the secret after its `whsec_` prefix.
  It carries a space-delimited list of signatures, so a rotation can sign with
  the old and new keys at once. Accept the message if any entry verifies.

#### Keying the replay store

Key on **the provider's event or delivery identifier**: `event.id`,
`X-GitHub-Delivery`, `X-Shopify-Webhook-Id`, or `webhook-id`. It is stable
across retries, it is meaningful in a log, and it is already the idempotency
key. Thus one row serves both jobs.

The alternatives do not work. **A key on the signature** fails on the
provider's own retries. Stripe generates a fresh timestamp and signature for
each delivery attempt. Thus the same event re-signed reads as a new one, and
the handler processes it twice. That is the exact duplicate the store exists
to prevent. **A key on a nonce** requires the provider to issue a single-use
one, which most do not. Where one exists, it is the event identifier under
another name.

Where the handler does the work inline, put the receipt row and the effect in
one transaction. A receipt can then exist only if its effect committed. Where
the handler acknowledges and defers, the receipt records only that the event
was *accepted*. The worker there still needs an idempotent effect of its own.
That is the shape above, and the one the fast-ack rule leads you toward. A
receipt row is not evidence that anything happened.

Decide which of the two shapes you are building. The common failure is to
write the deferred one while you reason about the guarantees of the inline
one.

A Redis `SET` with a TTL is adequate for the recency check alone. It is not
durable under eviction, and it must not be the only control between a retry
and a second payment.

Two rules survive from the payment case, and both are absolute. **Never take
an amount, price, or currency from the callback payload as authoritative.**
Reconcile against your own record. Never treat the payload's assertion about
who the actor is as authorization. A verified signature proves the message
came from the provider. It proves nothing about what the message is entitled
to do.

#### Sending webhooks of your own

An outbound-delivery worker is an HTTP client whose destinations users supply.
That makes it an SSRF vector and a potential amplifier. These controls are
specific to webhook delivery:

- **Address a destination by a registered identifier, and not by a free-form
  URL at call time.** Validate the stored URL again at every delivery, rather
  than only at registration.
- **Resolve the host and check every resolved address immediately before the
  connection.** DNS rebinding then cannot move the target between the check
  and the request. Disable redirects, or validate each hop again.
  `a01-broken-access-control.md`, "SSRF", owns the allowlist mechanics, the
  private and link-local ranges, and the cloud metadata endpoint.
- **Isolate the delivery worker's egress**, so that it cannot reach an
  internal service or the metadata endpoint even where the application-level
  check is wrong. Most implementations skip this layer, and it is the one that
  holds when the others fail.
- **Bound the retry machinery** with a maximum attempt count, exponential
  backoff, a per-destination rate limit, and a delivery timeout. Without them,
  an attacker who registers a victim's URL and triggers events turns your
  retry logic into an amplifier pointed at a third party (CWE-770).
- **Sign what you send**, over the raw body with a timestamp bound in, so that
  a consumer can verify you. Support rotation: sign with the old and the new
  key during an overlap window, and send both.
  `service-identity-and-secrets.md` owns where the signing secrets live and
  how they rotate.

## Pipeline and artifact integrity

Maps to CWE-494 (Download of Code Without Integrity Check) and CWE-829.
`a03-software-supply-chain.md` owns which dependencies you are entitled to
install, and how the project pins and scans them. This section owns the
narrower question A08 asks. **Can you prove that what you shipped is what you
built, and that what you consumed is what its publisher produced.**

What a backend repository owns, and can be reviewed for:

- Installs verify artifact integrity, and not only version numbers. A
  committed lockfile plus hash checking makes a swapped artifact fail the
  install rather than run. A03, "Pin and verify", holds the commands. The
  finding here is a Dockerfile or deploy script that installs unpinned or
  unhashed, while the lockfile sits unused beside it.
- Base images and critical build tools you consume are signature-verified or
  provenance-verified before use, rather than fetched by a mutable tag.
- Artifacts you publish carry provenance. SLSA's Build track sets the floor.
  **L1 is "package has provenance showing how it was built"**, and it is a
  repository-level opt-in that generated attestations satisfy. Treat its own
  caveat as part of the finding. L1 provenance is trivial to forge, so it
  establishes a record, and not a guarantee. `a03-software-supply-chain.md`,
  "SBOM, scan gate, and provenance", holds the current specification version.
  It also holds what a build on hosted runners may honestly claim above that
  floor. It holds the consumer-side verification without which none of it means
  anything.
- Deploy credentials and CI secrets are protected, because a compromised
  pipeline ships attacker code under your signature. Prefer short-lived
  federated credentials over long-lived deploy keys. A03 and
  `service-identity-and-secrets.md` carry that decision.
- For signed data your own application gives out and takes back, use
  `django.core.signing` with `TimestampSigner` and `max_age`. Do not use a
  hand-rolled token or anything pickle-based.

**Name these as out of scope**, so that nobody mistakes them for an unaddressed
gap. Hardened or hermetic isolated builders (SLSA Build L3) and the CI
platform's key custody are platform work rather than repository work. So are
two-person review and organization-wide registry admission control. Report them
as platform recommendations, and not as repository findings.

## Review checklist

### Stack-neutral

- [ ] No object-constructing deserializer (`pickle`, unsafe YAML, `marshal`,
      `dill`, `jsonpickle`) reads bytes from any store an attacker can write
      to. The interchange formats are data-only.
- [ ] Every store the application deserializes from has been checked for who
      can write to it, and not only for who can read it. The stores are the
      cache, the queue, the session, a file, and a database column.
- [ ] Where protobuf crosses a trust boundary, the runtime is outside the
      affected range of both recursion advisories. No `Any` is unpacked
      without an allow-list of type URLs. No message is relayed onward
      carrying unknown fields this service never validated.
- [ ] Task-queue messages are treated as unauthenticated input. The arguments
      are validated inside the task, and no secret or capability token is
      passed as an argument.
- [ ] A signed task serializer is credited with integrity only. Anything
      sensitive that has to travel in a message or a result is protected by
      transport and at-rest encryption. Where the broker is outside the trust
      boundary, it is encrypted at the application layer.
- [ ] Webhook receivers verify a MAC over the exact received bytes with a
      per-endpoint secret, using a constant-time comparison and the provider's
      own encoding.
- [ ] A timestamp is inside the signed material, and a tolerance is enforced.
      The tolerance is neither zero nor open-ended, and five minutes is the
      industry default.
- [ ] A durable store keyed on the provider's event or delivery identifier
      de-duplicates. It is retained for as long as the provider will retry,
      rather than only for the tolerance window.
- [ ] Receivers acknowledge with a 2xx quickly, and defer the work. A
      rejection returns an error without detail, a stack trace, or a hint
      about which check failed.
- [ ] Payload amounts, prices, and actor claims are reconciled server-side. A
      valid signature is treated as proof of origin only.
- [ ] Outbound deliveries go to registered destinations, validated again at
      send time. The redirects are bounded, the egress is isolated, and the
      retries are capped with backoff and a per-destination limit. The
      payloads are signed with overlapping keys across a rotation.
- [ ] Published artifacts have provenance, and installs verify hashes. Build
      inputs are pinned, and consumed by digest rather than by a mutable tag.

### Django & DRF

- [ ] The cache store is not attacker-writable, because every built-in Django
      cache backend deserializes with `pickle`. The file-cache directory is
      not world-writable. Redis and memcached are authenticated and private.
      The database cache table is not reachable by injection. No lower
      environment writes a cache production reads.
- [ ] There is no custom or third-party pickle-based session or signing
      serializer. The stock `JSONSerializer` is in use, and `SECRET_KEY` is
      not weak, not shared across environments, and not committed.
- [ ] `CELERY_ACCEPT_CONTENT` is JSON-only, and it is the setting that decides
      what a worker will execute. The task and result serializers are set
      explicitly. The broker is authenticated and unreachable from the
      internet, and the result backend holds no secrets.
- [ ] Where a project uses `django.tasks`, `TASKS` is set explicitly rather
      than inherited. The default backend executes tasks inline in the request
      cycle, and hides the exception. It gives the operation the request
      timeout it was moved off the request path to escape.
- [ ] Every `@task` body receives its authorization outcome as an argument the
      caller resolved. It does not re-derive permission from an identifier
      with no principal to check it against. Secrets and personal data stay
      out of the arguments, which the result retains and the logs reproduce.
- [ ] Enqueues are wrapped in `transaction.on_commit`. No task import path is
      built from request data. Where both `django.tasks` and Celery are
      present, the inventory covers both.
- [ ] `loaddata` and `serializers.deserialize` never run on
      attacker-influenced fixtures. The fixtures are `json` or `xml`. The
      privilege fields a fixture can set while it bypasses `save()` and
      `full_clean()` are accounted for.
- [ ] `dumpdata` output is not written to a web-served path, committed, or
      baked into an image.
- [ ] The webhook view reads `request.body` before anything touches
      `request.data` or `request.POST`, and no middleware consumes the stream
      ahead of it. The HMAC input is the raw bytes, and never `json.dumps` of
      parsed data.
- [ ] Comparison uses `hmac.compare_digest`, never `==`.
- [ ] `csrf_exempt` appears on the webhook route only, and that route verifies
      a signature.
- [ ] A unique constraint arbitrates the de-duplication insert, and not an
      `exists()` check. It shares a transaction with an inline effect. Where
      the work is deferred, the worker carries its own idempotency.
