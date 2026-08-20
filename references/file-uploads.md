# File Upload Handling

Untrusted file ingestion from request to storage to download, including the
architecture where the bytes never transit the application at all. Covers
spoofed types, unsafe names, active content, parser and decompression hazards,
quotas, object-store configuration, delegated upload and download URLs, and
authorization for private files. Maps primarily to CWE-434, CWE-22, CWE-79,
CWE-400, CWE-409, CWE-284, and CWE-770; relevant OWASP categories include
A01:2025, A02:2025, A05:2025, A06:2025, A08:2025, and API4:2023.

This file owns **the file from the request to the reader**, including the
architecture where the bytes never reach the application at all: what a
delegated upload URL binds, the quarantine prefix an object waits in until the
server has verified it against the store rather than against the uploader's
claims, and the choice between proxying a private download and signing a URL
for it. `a08-integrity-and-deserialization.md` owns the signature, timestamp,
and replay rules a storage callback has to satisfy;
`a01-broken-access-control.md` owns import-from-URL SSRF, the
cache-mediated leak that a CDN cache key dropping its signing parameters is
one case of, and path traversal on a read whose path the request named, which
leaves this file the name an upload brings and the key it lands under;
`a05-injection.md` owns the sink a storage key or a filename
reaches; and `data-lifecycle-and-privacy.md` owns whether the bytes are gone,
leaving this file only the fact that an already-issued signed URL is beyond
the reach of any erasure.

## Contents
- [Principle](#principle)
- [Django & DRF implementation](#django--drf-implementation)
- [Type and content validation](#type-and-content-validation)
- [Filenames and storage keys](#filenames-and-storage-keys)
- [Storage and serving](#storage-and-serving)
- [Object storage configuration](#object-storage-configuration)
- [Direct-to-storage uploads](#direct-to-storage-uploads)
- [SVG and other active content](#svg-and-other-active-content)
- [Images and archives](#images-and-archives)
- [Size, count, and quota limits](#size-count-and-quota-limits)
- [Private downloads](#private-downloads)
- [Review checklist](#review-checklist)

## Principle

An uploaded file is attacker-controlled input in several forms at once: its
bytes, filename, extension, declared media type, structure, size, and eventual
serving behavior. A check of only one signal cannot establish safety. The
security invariant is: **accept only formats the feature needs, establish the
type from the content with a real parser, generate the storage identity on the
server, keep untrusted bytes non-executable, and apply authorization again when
the file is retrieved.**

Design the full lifecycle, not just the upload endpoint:

- Allowlist the minimum formats needed. Compare extension, declared media type,
  detected signature, and parser result; reject contradictions. Signatures
  identify a container, not whether the entire document is well-formed or safe.
- Replace client filenames with server-generated opaque keys. A display name
  may be retained as metadata after removing path and control characters, but it
  must never decide a filesystem or object-store path.
- Store new files in a quarantined, non-executable location. Scan, parse, or
  transform before promotion. Serve untrusted content from an isolated origin
  or as a download, not from the application's authenticated origin.
- Bound work before expensive parsing: request bytes, bytes per file, number of
  files, decoded dimensions, archive entries, total expanded bytes, nesting,
  processing time, and per-principal storage or processing quota.
- Treat archives as collections of hostile paths and payloads. Every extracted
  entry must stay under a fresh destination, and links or special files must not
  escape it.
- Keep private-file identifiers unguessable, but never use unguessability as
  authorization. Resolve an allowed object for the current principal before
  returning bytes or a short-lived delegated download.

## Django & DRF implementation

`UploadedFile.name`, `UploadedFile.content_type`, and a DRF parser's media type
come from the request and are untrusted. Django's `FileExtensionValidator`
checks the filename extension only; it is a useful allowlist signal, not content
validation. DRF's `MultiPartParser` and `FileUploadParser` use Django's upload
handlers but do not make the content safe. With `FileUploadParser`, both the URL
filename and `Content-Disposition` filename remain attacker-controlled.

Process large uploads through `UploadedFile.chunks()` rather than an unbounded
`read()`. A bounded prefix may support signature detection, provided the file
position is reset before later parsing or storage. Validate with multiple
independent signals and a maintained format-specific parser, then decode the
complete bounded file; canonical re-encoding is stronger than a magic-byte match.
Do not newly recommend `python-magic` or `filetype`: their release/maintenance
signals do not pass the 9 Aug 2026 dependency gate. Existing use must be re-vetted.

## Type and content validation

Use independent checks and fail closed. A safe ingestion gate should:

1. enforce request, file, decompressed, pixel/page/object-count, and tenant quota
   limits before expensive parsing;
2. normalize and allowlist the declared extension and media type, but never trust
   browser-supplied `Content-Type` or a filename as proof;
3. compare a bounded signature/prefix with the expected family and reject
   mismatches or polyglot/ambiguous content;
4. decode the complete bounded object with a maintained parser for the allowed
   format, with external resources, macros, scripts, DTDs, and network access off;
5. canonicalize or re-encode where practical and discard attacker metadata;
6. quarantine and scan asynchronously when the threat model requires malware/CDR,
   exposing nothing until the verdict is complete; and
7. reset streams deliberately and test truncated, oversized, decompression-bomb,
   malformed, parser-differential, and active-content samples.

No single detector proves a file safe. Select a maintained parser for each format
the product actually accepts and run it through the A03 package gate; otherwise
remove that format from the allowlist.

**Write-time.** When generating an upload field or handler, write the format
allowlist, the size cap, and the server-generated storage key in the same edit
as the field itself, because each is separately load-bearing and the one
deferred is the one that ships. `FileExtensionValidator` belongs in that first
edit as the cheapest of the signals rather than as the whole gate — it reads
the name the client chose. Never assemble the stored path from `upload.name`,
and settle where the bytes will be served from before the first file arrives,
since changing that afterwards means moving every object already stored.

## Filenames and storage keys

Do not join `upload.name` to `MEDIA_ROOT`, pass it to `open()`, or reuse it as an
object-store key. Generate a name after validation:

```python
from pathlib import Path
from uuid import uuid4


def generated_upload_name(*, detected_type):
    extension = {
        "application/pdf": ".pdf",
        "image/jpeg": ".jpg",
        "image/png": ".png",
    }[detected_type]
    return f"{uuid4().hex}{extension}"
```

If custom storage or archive extraction performs path joins, resolve the final
path and verify it remains below the intended root. Reject absolute paths,
drive-qualified paths, `..` traversal, NUL/control characters, alternate path
separators, links, devices, and other special entries. Sanitizing a display name
does not make it a safe storage path.

A key has to be **unguessable and inert**. `uuid4().hex` carries 122 bits of
randomness — a 128-bit value with six bits fixed for version and variant —
which settles the guessing question for any bucket that does not let the world
list its contents. The threat is someone guessing a key, not someone
exhausting the space. Unguessability still is not authorization: it decides
how bad the other failures are. A predictable key combined with an object
readable without credentials is a mass-exposure primitive, because the whole
corpus can be walked; either one alone is a far smaller finding.

Inert means the key discloses nothing by being seen. Keys travel further than
the objects they name — into access logs, referrer headers, support tickets,
and analytics — so treat the key itself as published text. Customer and tenant
names, email addresses, sequential identifiers, original filenames, document
titles, and dates in a key path all leak (CWE-201): a sequential
identifier discloses volume and invites enumeration, and a retained filename
such as `redundancy-letter-2026.pdf` discloses the content of a file nobody
was authorized to read.

A tenant prefix is worth adding on top of the random component, not instead of
it. Its value is that it can be enforced *below* the application: a storage
credential restricted to one prefix keeps an application bug from writing or
reading across tenants, which a check in view code cannot promise. Keep the
prefix a surrogate identifier rather than a name.

Finally, a key is an identity, so two writes to the same key are one object.
Object stores overwrite by default rather than deduplicating — S3 replaces the
existing object on a PUT to an existing key, and `FileSystemStorage` is the
outlier in appending a suffix instead. Under a server-generated key that is
irrelevant; under a user-influenced key it is silent data loss and, across a
tenant boundary, an unauthorized write (CWE-639).

## Storage and serving

- Keep uploads out of application code, templates, and static roots. The web
  server and object store must never interpret them as scripts or configuration.
- Prefer a separate object store or a distinct registrable-domain origin for
  public user content. A sibling subdomain can still share some browser trust
  boundaries; do not send application cookies to the upload origin.
- Return `X-Content-Type-Options: nosniff`, an allowlisted `Content-Type`, and
  usually `Content-Disposition: attachment`. Do not reflect the supplied media
  type into the response.
- Use a quarantine state until validation or scanning completes. Make state
  transitions explicit so an unapproved object cannot be fetched through a
  predictable media URL.
- Keep permissions non-executable and credentials least-privileged. The upload
  worker may write quarantine; the serving tier should not be able to modify
  application code.

- Use Django's Storage API with an official, maintained provider SDK or a freshly
  vetted backend. Do not newly recommend `django-storages==1.14.6` for the Django 6
  baseline: `1.14.6` was released in April 2025 and its own Django classifiers
  stop at 5.1, so it declares support for neither 5.2 LTS nor 6.0. Existing
  deployments need a compatibility and credential/URL-signing review before
  framework upgrades; the settings that decide whether that review passes are
  in "Object storage configuration" below.

See `deployment-and-runtime.md` for edge and serving configuration. Serving an
upload outside the web root is useful only if the separate serving path is also
configured to be inert.

### Metadata the store echoes back

An object store persists metadata the uploader influenced and returns it on
retrieval, which makes stored metadata an input to the response rather than a
record about it. Custom metadata lives under `x-amz-meta-*` on S3,
`x-goog-meta-*` on GCS, and `x-ms-meta-*` on Azure, and all three come back as
response headers on a read. Those are the obvious half. The dangerous half is
the content-type and content-disposition pair, because that is what decides
whether a browser renders the bytes or saves them, and every provider offers a
route by which it is chosen somewhere other than your serving code:

- **S3** stores `Content-Type` at upload and returns it on a read, and a
  signed request can override it for that request through the
  `response-content-type` and `response-content-disposition` query
  parameters, which take precedence over the stored value.
- **GCS** stores `Content-Type`, `Content-Disposition`, `Content-Encoding`,
  `Cache-Control`, and `Content-Language` as object metadata and serves them
  back as given.
- **Azure** stores the blob content-type and content-disposition system
  properties and serves them as the corresponding response headers, unless
  the SAS carries an `rsct` or `rscd` override, which wins for that request.

So whoever controlled the upload controls how the object is later
interpreted, and a filename that reaches a disposition header unescaped
controls the header itself: `text/html` served from an origin holding session
cookies is stored XSS (CWE-79), and an unsanitized filename in a disposition
is header injection (CWE-116). Neither needs a second bug — a stored value
being trusted is the whole of it.

The serving rules above are the answer, applied one layer earlier: the content
type and disposition belong to the server's validated verdict at serve time,
not to anything the upload supplied, so set them explicitly on the response
and let the stored copy be a record rather than an instruction. Where a
display name has to survive into a disposition, encode it as `filename*`
rather than interpolating it, and treat every `*-meta-*` value as untrusted
text wherever it is rendered.

**Write-time.** When writing the code that serves an upload back, pass the
content type from the server's own record of what the file was found to be and
set the disposition explicitly, in the same edit as the read. The default in
every one of these APIs is to hand back what was stored, so the value that was
never chosen is the uploader's.

## Object storage configuration

Storage configuration decides whether any of the controls above are reachable:
an object that can be read without going through the application has no
authorization on it at all. Maps to CWE-284 (Improper Access Control),
CWE-668 (Exposure of Resource to Wrong Sphere), and CWE-732 (Incorrect
Permission Assignment), under A01:2025 and A02:2025.

### Principle layer

Two questions decide exposure, and a code review can only answer the first:

1. **Does the application hand out a URL that grants access by itself?** A URL
   built from a bucket or CDN hostname with no signature is a bearer
   capability — whoever holds it reads the object, and it can be logged,
   forwarded, and indexed. This is visible in the repository.
2. **Would the object be readable without that URL?** Public-access blocking,
   the bucket policy, and object ownership answer that, and none of them lives
   in the codebase.

Report the first, name the second as an open question, and do not collapse the
two. A signal of the first kind is Critical only when the second turns out
badly; against a bucket that blocks public access the same signal is a
hardening finding.

Application-visible signals worth raising:

- one storage backend serving both public assets and private user content, or
  no separate private backend at all;
- storage URLs rendered into templates, serializers, or emails with no signing
  step between the object and the reader;
- a media base URL pointing at a bare bucket or CDN hostname;
- default object permissions set to a public grant;
- URL signing switched off for content the application treats as private,
  which is itself a statement that the bucket is expected to be public;
- one credential used to upload, to serve, and to administer, so a narrowly
  scoped URL still carries broad authority.

Name these as requiring out-of-band verification rather than asserting them
from code: public-access blocking, the bucket policy and object-ownership
setting, versioning and delete protection, the permissions actually attached
to the signing principal, bucket-level CORS, and lifecycle rules.
Infrastructure code in the same repository brings some of them back into
scope — read it when it is there, and say which findings came from it.

Two platform defaults are worth knowing so a review does not raise something
the platform already closed. On S3, public access has been blocked and ACLs
disabled on new buckets since April 2023, and server-side encryption with
S3-managed keys has applied to every new object since January 2023 and cannot
be turned off. Encryption at rest is therefore not the finding; which key
protects it, and who may use that key, still is.

**A bucket per tenant, or one bucket with a prefix per tenant.** Both are
defensible, the choice is an architecture decision rather than a security
verdict, and it is made once and is expensive to undo — so it is worth making
deliberately rather than by default:

| Dimension | Bucket per tenant | Shared bucket, prefix per tenant |
| --- | --- | --- |
| Blast radius | A wrong policy exposes one tenant | A wrong policy exposes every tenant at once |
| Policy granularity | Public-access blocking, versioning, retention, and the encryption key are all set per tenant | Those are bucket-level, so every tenant gets one setting: the strictest tenant's cost or the weakest tenant's risk |
| Credential scoping | A credential cannot name a bucket it was not given; the boundary is structural | The boundary is a prefix condition in the policy, which holds only if it was written correctly and is absent silently |
| Operational cost | Provisioning, per-account bucket limits, and per-bucket configuration drift become the scaling constraint | One bucket to configure, monitor, and reason about |

The failure that decides most cases is the third row meeting the second: a
shared bucket is sound when the prefix condition on the upload and download
credentials is real and tested, and is a cross-tenant read the moment it is
merely intended. A per-tenant bucket makes that failure structurally
unavailable, which is what makes it the stronger default for
high-sensitivity content and the wrong default at high tenant counts, where
the bucket limit and the configuration drift become the larger risk. Either
way the tenant component of the key stays a surrogate identifier rather than a
name, for the reasons in "Filenames and storage keys" above, and either way
the prefix or bucket restriction on the signing credential is the control that
a check in view code cannot promise.

### Django & DRF implementation layer

`STORAGES` is the configuration form — `DEFAULT_FILE_STORAGE` and
`STATICFILES_STORAGE` were removed in Django 5.1 — and a second named alias is
the built-in way to keep private user content off the backend that serves
public assets:

```python
# Wrong: one backend for everything, so a private document inherits whatever
# URL and permission policy the public asset bucket was given.
STORAGES = {
    "default": {"BACKEND": "myapp.storage.PublicMediaStorage"},
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
    },
}

# Correct: a private alias with its own bucket, credentials, and URL policy.
# Each FileField then names the storage it belongs to, so the public/private
# decision is reviewable per field instead of being a property of the project.
STORAGES = {
    "default": {"BACKEND": "myapp.storage.PublicMediaStorage"},
    "private": {"BACKEND": "myapp.storage.PrivateDocumentStorage"},
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
    },
}
```

`FILE_UPLOAD_PERMISSIONS` (`0o644` since Django 3.0) and
`FILE_UPLOAD_DIRECTORY_PERMISSIONS` (`None`, leaving it to the process umask)
govern `FileSystemStorage` only. An object store ignores both, so a clean
local-storage review says nothing about the bucket.

Where `django-storages` is already installed, four of its S3 defaults decide
whether a private object is private. Read them off the backend's own source
rather than off documentation:

- `AWS_DEFAULT_ACL` defaults to `None`, which means the object inherits the
  bucket's permissions — not that it is explicitly private. On a bucket with
  public access blocked and ACLs disabled that is safe. On an older bucket it
  is not, and an install carried across the version where the default was
  `public-read` may still be setting it.
- `AWS_QUERYSTRING_AUTH` defaults to `True`, with `AWS_QUERYSTRING_EXPIRE` at
  3600 seconds. Setting it to `False` on private media publishes unsigned URLs
  that work only if the object is public, so finding it there is a strong
  indication that the bucket is.
- `AWS_S3_CUSTOM_DOMAIN` silently overrides both of those. With a custom
  domain set, `url()` returns a signed URL only when a CloudFront signer is
  *also* configured; with no signer it returns the plain domain-and-key URL,
  and `AWS_QUERYSTRING_AUTH = True` has no effect on that path. A custom
  domain on private media without `AWS_CLOUDFRONT_KEY_ID` and
  `AWS_CLOUDFRONT_KEY` is a permanent, unsigned URL for every private object,
  and nothing in the settings file looks wrong.
- `AWS_S3_FILE_OVERWRITE` defaults to `True`, so `get_available_name()`
  returns the key unchanged and a second save replaces the first, which is the
  opposite of the deduplicating behavior a `FileSystemStorage` habit expects.

That last pair is the reason to review the *combination* of settings rather
than each one. Grep for `AWS_S3_CUSTOM_DOMAIN`, `AWS_QUERYSTRING_AUTH`,
`AWS_DEFAULT_ACL`, and `MEDIA_URL` together, and read them against which
storage alias the sensitive `FileField`s actually use.

## Direct-to-storage uploads

When the client uploads straight to the object store, every synchronous
control above is bypassed: the bytes never reach the application, so nothing
validates a type, counts a byte, or rejects an archive before the object
exists. The controls do not disappear — they move to either side of the
transfer, and an architecture that omits the second half never applies them at
all. Maps to CWE-770, CWE-434, CWE-639, CWE-345, and CWE-306, under A01:2025,
A08:2025, and API4:2023.

### Principle layer

A delegated upload URL is the issuer's authority compressed into a link.
Whatever the signing principal may do, the holder of the link may do, within
the signed constraints and for as long as it lives. It is a bearer token that
survives being copied, so the question is never whether the URL stays secret —
it is what the URL permits.

Bind all seven of these, because each unbound one is a specific attack:

- **The operation.** An upload URL that also reads is a read primitive.
- **The key**, server-generated, or at minimum pinned to a tenant prefix. An
  unconstrained key writes over another tenant's object (CWE-22, CWE-639).
- **A maximum size**, and a minimum. Without one the URL is an unmetered write
  into your storage bill (CWE-770, CWE-400; API4:2023).
- **The content type**, so the object cannot later be served as something
  active (CWE-79, CWE-116).
- **The shortest workable lifetime.** A long-lived URL outlives the session
  that justified it and is still valid wherever it was logged, shared, or
  captured (CWE-524, CWE-613).
- **Server-side encryption terms**, where a specific key rather than the
  platform default is required.
- **A least-privileged signing principal.** The URL cannot be narrower than
  the credential behind it, so a signer that can also read and list the bucket
  makes every scoping decision above advisory (CWE-269, CWE-732).

Severity turns on combinations. An unbounded size on a private bucket is a
cost and availability finding; a predictable key plus an unsigned public URL
is a mass-exposure primitive.

The size bound is where the three major stores diverge, so what to look for
depends on which one is behind the URL rather than on one rule generalized
from S3:

- **S3** — a presigned PUT binds no size at all. The enforced form is a
  presigned POST whose policy carries a `content-length-range` condition.
- **GCS** — a V4 signed PUT *can* bind one, by signing an
  `x-goog-content-length-range` header of `MIN,MAX` bytes into the URL. Cloud
  Storage rejects a body outside that inclusive range with `400`, and the POST
  policy supports a `content-length-range` condition as well.
- **Azure** — a SAS binds no size in any form. Its whole signed field set is
  the permission, the resource, the window, an IP range, the protocol, a
  stored-policy identifier, and five response-header overrides; none of them
  is a length. The ceiling has to be applied after the object exists, which
  makes the verification step the only thing between a SAS and an unmetered
  write.

**No delegated URL can be recalled one at a time, and not within its lifetime.
What differs by provider is how much else you have to break to withdraw one
early** — and on that, the rule the rest of this section is written around
holds for S3 and GCS but is too strong for Azure. On S3 and GCS the only lever
is the signing credential, so the URL dies when it does. Signing with a
short-lived session credential rather than a long-lived key is therefore the
real control — on S3 an assumed-role session lasts one hour by default and an
instance-profile credential roughly six, against the seven days a long-lived
key permits, and the URL expires with the credential even when a longer expiry
was requested. Rotating or deactivating that credential invalidates every URL
it signed, which is blunt but works. And an object that is still in quarantine
grants a URL holder access to nothing that is served.

Azure's shared access signature comes in three forms, and which one was issued
decides how blunt the withdrawal is. A **user-delegation SAS** is signed with a
user-delegation key obtained through Entra credentials, so the signing identity
is a security principal and no account key is involved; it is Blob-only. A
**service SAS** is signed with the storage account key and scoped to one
service. An **account SAS** is signed with the account key and spans services
and service-level operations. Only Azure offers a withdrawal that leaves the
signing credential in place:

| Form | Withdrawn before expiry by | Granularity, and on what timeline |
| --- | --- | --- |
| S3 presigned URL or POST policy | Rotating or deactivating the signing credential | Immediate, and takes every URL that credential signed with it |
| GCS V4 signed URL | Rotating the signing service account's key, or removing its IAM permission | Immediate, and takes every URL that key signed with it |
| Azure account SAS, or a service SAS with no stored policy | Regenerating the storage account key | Immediate, and takes every SAS in the account with it |
| Azure service SAS bound to a stored access policy | Deleting the policy, renaming it, or moving its expiry into the past | Per policy, so one grant goes without touching the account key; timeline not published |
| Azure user-delegation SAS | Revoking the user-delegation key, or removing the signing principal's role assignment | Per key or per principal, still not per URL; timeline not published, and both the key and the role assignments are cached |

Those two are worth preferring on Azure for that reason, and the
user-delegation SAS additionally keeps the account key out of the process.
Neither is a recall button: the granularity is a policy or a key rather than a
URL, and Azure publishes no number for how long a revocation takes to land,
stating only that there may be a delay. Treat any specific latency you are
told as unverified.

So the lifetime cap remains the control that does not depend on anyone
noticing, and every provider tops out in the same place — 604800 seconds,
seven days, on a GCS V4 signature, an S3 SigV4 presigned URL, and an Azure
user-delegation key regardless of the expiry requested. An upload URL has no
business near that ceiling; minutes is the right order of magnitude. Where the
platform can cap it centrally instead of trusting the issuer it should, and
that control is provider-specific rather than the S3 one generalized: an S3
bucket policy can refuse requests whose signature is older than a chosen age,
and an Azure storage account can carry a SAS expiration policy. GCS has no
server-side equivalent, so there the bound the signer chose is the only one
there is. Design for expiry, not for recall.

The flow that keeps the controls attached:

1. authorize the request against the tenant *before* issuing anything;
2. generate an opaque key under a quarantine prefix;
3. issue a narrowly scoped, short-lived URL for that key, signed by a
   credential that can write the quarantine prefix and nothing else;
4. record a row in a `PENDING` state;
5. the client uploads directly;
6. verification begins on an authenticated server-side confirmation or an
   authenticated event notification — never on an unauthenticated "done" ping;
7. the server reads size and type back from the *store*, then runs the same
   validation the synchronous path runs;
8. only then does the object move to the served prefix and the row become
   `AVAILABLE`.

The prefix that is served must not be writable by the upload credential.
Otherwise the client writes straight into it and steps six through eight
decide nothing.

That state machine needs a terminal `REJECTED` state, and a sweeper for
objects that are uploaded and never confirmed — without one, abandoned
quarantine objects accumulate as unreviewed content and unbilled-for storage.
Where scanning is part of the verdict it must be asynchronous and must fail
closed. Four failure modes let unscanned content reach a reader: a scanner
timeout treated as clean; the object copied to the served prefix before the
verdict is recorded; a scan run against the type in the database rather than
the bytes in the store; and an object that can still be overwritten between
the scan and the serve. The last is why the served prefix is write-denied to
the uploader and why object versioning is worth having. Selecting a scanning
engine is a separate decision and belongs to the dependency gate in
`a03-software-supply-chain.md`.

A verdict is a fact about bytes, not about a row, so cache it under a hash of
the content rather than under the object key or the filename. Keyed that way,
identical content uploaded twice reuses the existing verdict, a rename cannot
launder a rejected object into a fresh scan, and two different objects can
never share one. A verdict is also only as good as the signatures that
produced it, so record the engine and signature version beside it and treat a
version advance as invalidating — content admitted before a signature existed
stays admitted otherwise, and that window is exactly the one a novel sample
occupies. Re-scanning lazily on next access is usually enough; the requirement
is that a stale "clean" cannot become permanent.

Where a detection gap is not tolerable at all, content disarm and
reconstruction is the other shape of the control. Rather than deciding whether
a file is malicious, CDR decomposes it, discards every component outside an
allowlist — macros, embedded scripts, other active content — and rebuilds a
functionally equivalent file from what is left. Depending on no signature, it
is unaffected by novel or polymorphic content; rewriting the file, it can
break what the file was for, and editability, embedded logic, and fidelity all
move. That trade is why it is a control to choose deliberately rather than a
default, and it sits alongside scanning rather than replacing it.

Confirmations and event notifications are the weak point, because they are the
step that grants availability. An unauthenticated callback that moves a row
from `PENDING` to `AVAILABLE` lets an attacker approve their own object
(CWE-306). A callback that takes the object key from the request body without
checking it against the row lets one user confirm another's upload. And a
confirmation that believes a client-supplied size or content type has undone
the entire verification. Verify the message's authenticity, then re-derive
every fact from the store. The signature, timestamp, and replay rules for
doing that are in `a08-integrity-and-deserialization.md`, "Webhook and
callback integrity", which owns them; the SSRF rules that an "import from a
URL" upload path must satisfy are in `a01-broken-access-control.md`, "SSRF".

### Django & DRF implementation layer

On S3 the two delegated-upload forms are not interchangeable. A presigned
`put_object` URL binds only what was signed into it, and there is no signed
element for a maximum body size — so a presigned PUT cannot bound how much is
uploaded at all. A presigned POST carries a policy document that S3 itself
evaluates, and `content-length-range` is the only mechanism either form offers
for capping object size. Re-checked against `boto3` 1.43.67 on 9 Aug 2026 and
still true: `generate_presigned_url` accepts an operation, its parameters, and
an expiry, and admits no condition of any kind, while the POST policy carries
`content-length-range` as a first-class condition. Prefer POST wherever size,
key, or type has to be enforced rather than merely expected:

```python
from uuid import uuid4

import boto3

QUARANTINE_PREFIX = "quarantine"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def quarantine_key(tenant_id):
    return f"{QUARANTINE_PREFIX}/{tenant_id}/{uuid4().hex}.jpg"


# Wrong: the signature covers the key and nothing else, so the holder may send
# any number of bytes of any type for the whole hour. The only ceiling is S3's
# own 5 GB limit on a single PUT.
def presign_upload_unbounded(*, tenant_id):
    return boto3.client("s3").generate_presigned_url(
        "put_object",
        Params={"Bucket": "uploads", "Key": quarantine_key(tenant_id)},
        ExpiresIn=3600,
    )


# Correct: S3 evaluates every condition below before it stores anything.
# starts-with pins the key to this tenant's quarantine prefix even though the
# client submits the key field itself, and content-length-range is what makes
# the size limit real rather than expected.
def presign_upload(*, tenant_id):
    return boto3.client("s3").generate_presigned_post(
        "uploads",
        quarantine_key(tenant_id),
        Fields={"Content-Type": "image/jpeg"},
        Conditions=[
            {"Content-Type": "image/jpeg"},
            ["content-length-range", 1, MAX_UPLOAD_BYTES],
            ["starts-with", "$key", f"{QUARANTINE_PREFIX}/{tenant_id}/"],
        ],
        ExpiresIn=120,
    )
```

Two mechanics of that call are easy to get wrong. A condition and its field
are separate arguments and neither implies the other, so a `Content-Type`
condition with no matching `Fields` entry rejects every upload; and S3 requires
every form field the client sends to appear in the conditions, apart from the
signature, the file, the policy itself, and any `x-ignore-` prefixed field — a
field the client can add freely is a field you did not constrain.

After the upload, `head_object` returns the size and content type the store
recorded, which is what verification runs against. Read them there, never from
the confirmation request; then apply "Type and content validation" above to
the bytes themselves, because a store-reported content type is only what the
uploader declared at PUT time. S3 has been strongly read-after-write consistent
for writes, overwrites, and deletes since 2020, so an immediate read back is
correct and the retry loops that older guidance recommends are obsolete —
bucket-level configuration is still eventually consistent, and other
S3-compatible stores may not offer the same guarantee.

Model the states as a field with an explicit transition, not as a boolean, and
keep the promotion — copy to the served prefix, then mark `AVAILABLE` — in
that order, so a crash leaves an object that is present but unreachable rather
than reachable but unverified. Enforcing the transition itself against
concurrent confirmations is in `a10-exceptional-conditions.md`.

#### GCS: the signed PUT that does bound size

`google-cloud-storage` expresses the binding through the `headers` argument of
`generate_signed_url`. Anything passed there is folded into the canonical
headers that the V4 string-to-sign covers and is named in the URL's
`X-Goog-SignedHeaders`, so the client must send each one, unaltered, or the
signature fails. That is what makes an `x-goog-content-length-range` header a
constraint rather than a suggestion:

```python
from datetime import timedelta

from google.cloud.storage import Client

MAX_UPLOAD_BYTES = 5 * 1024 * 1024


# Wrong: the same shape as the unbounded S3 PUT above and wrong for the same
# reason — the signature covers the key and the method, so the holder may send
# anything of any size for the whole hour.
def gcs_presign_upload_unbounded(*, tenant_id):
    blob = Client().bucket("uploads").blob(quarantine_key(tenant_id))
    return blob.generate_signed_url(
        version="v4",
        expiration=timedelta(hours=1),
        method="PUT",
    )


# Correct: both constraints are signed, so neither can be dropped or edited by
# the holder. The range is MIN,MAX in bytes and is inclusive at both ends;
# Cloud Storage answers an out-of-range body with 400.
def gcs_presign_upload(*, tenant_id):
    blob = Client().bucket("uploads").blob(quarantine_key(tenant_id))
    return blob.generate_signed_url(
        version="v4",
        expiration=timedelta(minutes=2),
        method="PUT",
        content_type="image/jpeg",
        headers={"x-goog-content-length-range": f"1,{MAX_UPLOAD_BYTES}"},
    )
```

Verified against `google-cloud-storage` 3.13.1 on 9 Aug 2026: signing that
call puts `x-goog-content-length-range` into `X-Goog-SignedHeaders`, and the
seven-day ceiling is enforced by the library itself — an expiration over
604800 seconds raises `ValueError` rather than producing a URL. That check is
specific to V4; a `version="v2"` signature accepts a longer expiration without
complaint, which is one more reason to sign V4.

Two bucket-level settings that sound like they would interfere do not. Uniform
bucket-level access, which disables object ACLs and leaves IAM as the only
grant, is the posture to want and does not restrict signed URLs. Neither does
public access prevention: a signed URL derives its authority from the signing
service account's own IAM permissions rather than from any public grant, so it
keeps working under both. The corollary is the one that matters for review —
under UBLA the signing service account's IAM role *is* the ceiling on every
URL it issues, so that role is the thing to scope down.

#### Azure: a SAS binds less than you would expect

Two things about `generate_blob_sas` have to be read off the source, because
its own docstring is wrong about the first. `protocol` is not defaulted: pass
nothing and no `spr` field is emitted at all, which leaves the SAS usable over
plain HTTP — while the docstring states that the default is HTTPS. State it.
The second is that `permission` and `expiry`, ordinarily required, are both
waived by supplying a `policy_id`: the resulting token carries only `si`, `sr`,
`sv`, and the signature, and takes its permission and its expiry from a stored
access policy on the container that no amount of reading the codebase will
show you. That is one of the two forms the revocation table above prefers, so
the trade is explicit — the withdrawable SAS is also the one whose grant is
invisible in code, and reviewing it means reading the container's policy.

```python
from datetime import datetime, timedelta, timezone

from azure.storage.blob import (
    BlobSasPermissions,
    BlobServiceClient,
    generate_blob_sas,
)


# Wrong: signed with the account key, so the only way to withdraw it is to
# regenerate that key and break every other SAS in the account; no protocol is
# stated, so the token is valid over HTTP.
def sas_upload_url_account_key(*, tenant_id, account_key):
    return generate_blob_sas(
        account_name="acct",
        container_name="uploads",
        blob_name=quarantine_key(tenant_id),
        account_key=account_key,
        permission=BlobSasPermissions(create=True, write=True),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )


# Correct: signed with a user-delegation key, which can be revoked without
# regenerating the account key and never brings that key into the process;
# HTTPS is stated rather than assumed; the window is minutes. There is no
# size argument to add, because Azure has no SAS field for one — the byte
# ceiling belongs to the verification step that follows.
def sas_upload_url(*, tenant_id, service: BlobServiceClient):
    start = datetime.now(timezone.utc)
    expiry = start + timedelta(minutes=2)
    return generate_blob_sas(
        account_name=service.account_name,
        container_name="uploads",
        blob_name=quarantine_key(tenant_id),
        user_delegation_key=service.get_user_delegation_key(start, expiry),
        permission=BlobSasPermissions(create=True, write=True),
        expiry=expiry,
        start=start,
        protocol="https",
    )
```

Verified against `azure-storage-blob` 12.30.0 on 9 Aug 2026. The delegation
key carries its own seven-day maximum, so the `expiry` above is bounded by the
key as well as by the argument.

**Write-time.** When generating a delegated upload URL, settle the provider
before the constraints, because the provider decides which of them can be
signed at all: on GCS write the `x-goog-content-length-range` header into the
same call as the key and the expiry, on S3 reach for the presigned POST rather
than the PUT the moment a size matters, and on Azure write the verification
step in the same change as the SAS, since nothing in the token will bound the
bytes. State the protocol and the expiry explicitly on every provider rather
than inheriting a default, and sign with the narrowest credential the platform
offers — a session credential on S3, a scoped service account on GCS, a
user-delegation key on Azure.

## SVG and other active content

SVG is XML-based active content, not a passive image. It can contain scripts,
event handlers, links, external resource loads, and `foreignObject` HTML.
Reject SVG by default for image uploads. If the product genuinely requires it,
use a dedicated, maintained allowlist sanitizer; remove scripts, event
attributes, external references, animation where unnecessary, and
`foreignObject`; then reserialize and serve it from an isolated origin or as an
attachment. A CSP header is defense in depth, not a substitute for sanitization
and origin isolation. Apply the same scrutiny to HTML, XML, and office/document
containers that can carry active content.

## Images and archives

For images, open and decode under limits, verify the reported format, cap width,
height, total pixels, frames, and metadata, and re-encode to an approved format.
Keep Pillow's decompression-bomb protection enabled; treat its warning as a
rejection for untrusted uploads rather than disabling `MAX_IMAGE_PIXELS`.

For ZIP, tar, and similar archives:

- inspect the central directory before extraction;
- cap entry count, per-entry size, total uncompressed size, compression ratio,
  nesting depth, and processing time;
- reject absolute/traversing names, duplicate/conflicting destinations,
  symlinks, devices, and special files;
- resolve every destination beneath a fresh extraction root; and
- extract and process in a low-privilege, resource-constrained worker.

The Python `zipfile` module does not make an untrusted archive safe merely
because it normalizes some names. Validate the policy explicitly and do not use
`extractall()` as the policy boundary.

The same boundary exists for tar, and tar has a supported answer.
`TarFile.extractall()` without a filter obeys the archive's own metadata:
absolute names, `..` components, symlinks, hardlinks, device nodes, and setuid
modes. Python 3.12 adds extraction filters. Call
`extractall(path, filter="data")` for a data archive. The `"data"` filter
rejects absolute names, parent-directory escapes, links that point outside the
destination, device nodes, and dangerous modes.

The filter API is backported to Python 3.9.17, 3.10.12, and 3.11.4. Python 3.12
warns when the caller gives no filter. Python 3.14 makes `"data"` the default.
Pass the filter explicitly, and do not depend on the version default. An older
micro version has no filter API, so test with `hasattr(tarfile, "data_filter")`
before you call it. For a user upload, reject a tar member that is a symlink or
a hardlink.

**Write-time.** When you generate tar extraction code, pass `filter="data"` in
the same call. When you generate ZIP extraction code, write the member checks
before the extraction call. The library enforces no policy of its own.

## Size, count, and quota limits

Put a hard request-body limit at the reverse proxy, CDN, or gateway so oversized
requests are rejected before the application reads or spools them. Add
endpoint-specific limits for each file, aggregate bytes and file count per
request, and rolling quotas per authenticated user, tenant, destination, and
time window. Expensive scanning or conversion should run under worker CPU,
memory, wall-clock, and concurrency limits.

Django settings have narrower meanings than their names suggest:

- `DATA_UPLOAD_MAX_MEMORY_SIZE` limits request data Django reads into memory and
  excludes uploaded-file content; it is not a hard upload-size cap.
- `FILE_UPLOAD_MAX_MEMORY_SIZE` chooses when an upload moves from memory to a
  temporary file; it is a spooling threshold, not a rejection limit.
- `DATA_UPLOAD_MAX_NUMBER_FIELDS` and `DATA_UPLOAD_MAX_NUMBER_FILES` (the
  latter defaulting to 100) constrain multipart complexity and should not be
  raised casually.
- From Django 6.1 `HttpRequest.multipart_parser_class` selects the parser that
  reads the request body. A replacement parser owns every bound above, because
  the settings are read by the parser rather than applied around it. Review a
  custom value as request-handling code, not as configuration.
- Django 6.1 validates Base64 strictly where it decodes request and stored
  data. `django.http.multipartparser.MultiPartParser` raises
  `MultiPartParserError` on invalid Base64, where earlier versions could ignore
  it or produce an empty value. `django.db.models.BinaryField` raises
  `ValidationError`, and `django.core.cache.backends.db.DatabaseCache` raises
  on a corrupt entry rather than skipping it. Each is a fail-closed change:
  confirm the handler around these paths returns a 400 rather than a 500.
- A custom upload handler can stop a stream early, but an edge limit is still
  required. Under ASGI, request data may already have been received or spooled
  before application-level handling rejects it — and CVE-2026-5766, fixed in
  Django 6.0.5 and 5.2.14, was that failure exactly: an ASGI request with a
  missing or understated `Content-Length` bypassed
  `FILE_UPLOAD_MAX_MEMORY_SIZE` and was read into memory. Its severity is
  recorded by two bodies that disagree — low under Django's own security
  policy, medium in the GitHub Advisory Database — and both belong in a report,
  because a scanner keyed to the second and a reviewer quoting the first will
  otherwise describe the same install in different words. Patching closes that
  instance, but the size ceiling belongs at the web server either way.

A direct-to-storage upload has no reverse proxy in its path, so none of the
above applies to it. The equivalent ceiling is a `content-length-range`
condition in the signed policy, and it is the only one there is.

Keep application checks even with an edge limit because different endpoints and
principals need different policies. Use `upload.size` only as an early signal;
enforce a counted byte limit while streaming when the storage or transport does
not guarantee it.

Size, count, and expansion ratio are this file's instances of a rule that runs
across every surface — every caller-controlled value that multiplies work
carries a server-enforced ceiling. The design rule and the table of surfaces
are in `a06-insecure-design.md`, "Algorithmic resource exhaustion".

## Private downloads

Resolve the file through a requester-scoped queryset before opening storage:

```python
from django.contrib.auth.decorators import login_required
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.cache import never_cache


@never_cache
@login_required
def download_document(request, document_id):
    document = get_object_or_404(
        Document.objects.visible_to(request.user),
        pk=document_id,
        status=Document.Status.APPROVED,
    )
    stream = document.file.open("rb")
    return FileResponse(
        stream,
        as_attachment=True,
        filename=document.download_name,
        content_type=document.detected_content_type,
    )
```

Passing `content_type` there is not decoration. `FileResponse` sets the header
from the filename when it is not given, so a stored display name would choose
the response's media type; the validated type is the one that belongs in the
header, and `as_attachment=True` supplies the `attachment` disposition.

### Proxy or signed URL

If Nginx, a CDN, or object storage sends the bytes, perform the same
authorization first and issue an internal redirect or short-lived,
single-purpose signed URL. Bind delegated URLs to the exact object and
disposition, use a short expiry, and prevent shared caching of private
responses. Do not expose a permanent public media URL for a private object.

The two arrangements fail differently, so choose deliberately:

- **Proxying through the application** authorizes every request, logs every
  access, and revokes the moment the permission changes. It costs application
  bandwidth and, under WSGI, occupies a worker for the whole transfer, so a
  slow reader on a large file is an availability concern of its own.
- **An internal redirect** — an Nginx `internal;` location reached through
  `X-Accel-Redirect`, or `mod_xsendfile` on Apache — keeps per-request
  authorization in the application and hands the transfer to the web server.
  Django ships neither; both are edge configuration. This is usually the right
  answer for private content, and the `internal;` marker is load-bearing:
  without it the location is directly reachable and the authorization is
  decorative.
- **A signed URL** offloads the bytes entirely and can be cached at an edge,
  but it moves authorization to issue time. It cannot be withdrawn while it
  lives, and it leaks through logs, referrers, and forwarding.

Whichever is used, range and partial reads must go through the same
authorization as a full read.

### Private objects and CDN cache keys

A signed URL behind a CDN whose cache key drops the query string is an
authorization bypass, not a caching inefficiency: one user's authorized
response is stored under a key that another user's request also produces, and
the second reader is served bytes no check was run for (CWE-524, CWE-525).

In order of preference: do not cache private objects at all, and return
`Cache-Control: private, no-store` on proxied private responses; or use the
CDN's own signed-URL or signed-cookie mechanism so the edge validates before
serving; or, if origin signed URLs must pass through a CDN, include the
signing parameters in the cache key. `Vary` is not a substitute — cookie
values are high-cardinality and every layer has to honor it for the boundary
to hold. The general rule this is one case of, including the invalidation
requirement, is in `a01-broken-access-control.md`, "Caching and
authorization"; the edge and CDN configuration itself is in
`deployment-and-runtime.md`.

Stored files outlive the rows that reference them: deleting a model instance
does not delete its file, so erasure and retention have to remove the bytes
explicitly. One property of delegated delivery bounds what an erasure can
promise, and it belongs here rather than there: a signed URL that has already
been issued cannot be recalled, so the only controls over it are the expiry it
was given, rotation of the credential that signed it, and, on Azure alone,
revocation of the stored access policy or user-delegation key behind it on a
timeline Microsoft does not publish. That is the practical
argument for short expiries on private content — every minute of lifetime is a
minute an erasure cannot reach. A generated export archive is this same
delivery primitive wrapped around a subject's whole record, with its own
lifetime. Deletion completeness itself, including what an ordinary delete
leaves behind on a versioned bucket, is in `data-lifecycle-and-privacy.md`.

## Review checklist

### Stack-neutral

- [ ] Accepted formats are allowlisted and checked by extension, declared type,
      detected signature, and a complete format-aware parse.
- [ ] Client filenames never determine paths or storage keys; archive entries
      cannot escape a fresh extraction root.
- [ ] Untrusted content is quarantined, non-executable, and served from an
      isolated origin or as a download with fixed response headers.
- [ ] SVG and other active formats are rejected or purpose-built sanitized,
      reserialized, and origin-isolated.
- [ ] Request, file, decoded-content, archive, processing, concurrency, and
      per-principal quotas are enforced before expensive work.
- [ ] Private downloads repeat object-level authorization; identifiers or signed
      URLs do not replace that check.
- [ ] Delegated upload URLs bind the operation, the key, a maximum size, the
      content type, and the shortest workable expiry, and are signed by a
      credential that can write only the quarantine prefix.
- [ ] An object becomes reachable only after server-side verification, with
      size and type re-derived from the store rather than from the client or
      the callback that announced the upload.
- [ ] The upload state machine has a terminal rejected state and a sweeper for
      objects that were uploaded and never confirmed.
- [ ] On S3, a bucket taking multipart uploads carries an
      `AbortIncompleteMultipartUpload` lifecycle rule with a
      `DaysAfterInitiation` value — the parts of an abandoned upload bill as
      storage and appear in no object listing.
- [ ] On GCS, the same rule under Object Lifecycle Management: an
      `AbortIncompleteMultipartUpload` action keyed on `age`, for the same
      invisible-cost reason.
- [ ] On Azure there is nothing to configure, and that is the finding: blocks
      left by a `Put Block` that no `Put Block List` ever committed are
      collected on a fixed seven-day schedule no policy can shorten, so the
      cleanup is the application's and the storage-versus-listing gap is what
      there is to monitor.
- [ ] Storage keys are opaque and disclose no name, address, sequence, or
      original filename.
- [ ] Private objects have no permanent public URL, and any CDN in front of one
      either does not cache it or includes the signing parameters in the key.
- [ ] Findings that depend on platform state — public-access blocking, bucket
      policy, versioning, the signing principal's permissions, bucket CORS —
      are marked for out-of-band verification rather than asserted from code.

### Django & DRF

- [ ] `UploadedFile.name`, `content_type`, DRF parser metadata, and
      `FileExtensionValidator` are treated as untrusted signals, not proof.
- [ ] Large inputs use `chunks()`; any prefix read is rewound before parsing or
      storage; full parsers run with image/archive limits.
- [ ] The edge provides the hard body cap; Django's memory thresholds are not
      misrepresented as hard file-size controls; multipart count limits are set.
- [ ] `MEDIA_ROOT`/object storage cannot execute uploads, public content is
      origin-isolated, and private media is not directly browsable.
- [ ] File-processing workers are least-privileged and resource-bounded, and
      promotion from quarantine is explicit.
- [ ] A distinct `STORAGES` alias separates private user content from public
      assets, and each sensitive `FileField` names it.
- [ ] `AWS_DEFAULT_ACL`, `AWS_QUERYSTRING_AUTH`, `AWS_S3_CUSTOM_DOMAIN`, and
      `AWS_S3_FILE_OVERWRITE` are read together: a custom domain with no
      CloudFront signer serves private media unsigned whatever the rest say.
- [ ] Delegated uploads use a presigned POST with `content-length-range`
      wherever a size limit has to be enforced rather than expected.
- [ ] Django carries the CVE-2026-5766 fix (6.0.5 / 5.2.14 or later) and the
      request-body ceiling is set at the web server regardless.
