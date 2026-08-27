# File Upload Handling

This file covers untrusted file ingestion from request to storage to download.
It includes the architecture where the bytes never transit the application at
all. The topics in scope are spoofed types, unsafe names, active content, and
parser and decompression hazards. They also include quotas, object-store
configuration, delegated upload and download URLs, and authorization for
private files.

Maps primarily to CWE-434, CWE-22, CWE-79, CWE-400, CWE-409, CWE-284, and
CWE-770. Relevant OWASP categories include A01:2025, A02:2025, A05:2025,
A06:2025, A08:2025, and API4:2023.

This file owns **the file from the request to the reader**, and that includes
the architecture where the bytes never reach the application at all. It owns
what a delegated upload URL binds. It owns the quarantine prefix an object
waits in until the server has verified it against the store rather than against
the uploader's claims. It also owns the choice between a proxy for a private
download and a signed URL for it.

`a08-integrity-and-deserialization.md` owns the signature, timestamp, and
replay rules a storage callback has to satisfy. `a01-broken-access-control.md`
owns import-from-URL SSRF. It also owns the cache-mediated leak that a dropped
CDN signing parameter is one case of. It owns path traversal on a read whose
path the request named. This file therefore keeps the name an upload brings and
the key it lands under. `a05-injection.md` owns the sink a storage key or a
filename reaches. `data-lifecycle-and-privacy.md` owns whether the bytes are
gone. This file keeps only the fact that an already-issued signed URL is beyond
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

An uploaded file is attacker-controlled input in several forms at once. Those
forms are its bytes, filename, extension, declared media type, structure, size,
and eventual serving behavior. A check of only one signal cannot establish
safety. The security invariant is: **accept only formats the feature needs, and
establish the type from the content with a real parser. Generate the storage
identity on the server, keep untrusted bytes non-executable, and apply
authorization again when the file is retrieved.**

Design the full lifecycle, not just the upload endpoint:

- Allowlist the minimum formats needed. Compare extension, declared media type,
  detected signature, and parser result, and reject contradictions. Signatures
  identify a container. They do not show whether the entire document is
  well-formed or safe.
- Replace client filenames with server-generated opaque keys. You may retain a
  display name as metadata after you remove path and control characters. That
  name must never decide a filesystem or object-store path.
- Store new files in a quarantined, non-executable location. Scan, parse, or
  transform before promotion. Serve untrusted content from an isolated origin
  or as a download, not from the application's authenticated origin.
- Bound work before expensive parsing. Bound request bytes, bytes per file,
  number of files, decoded dimensions, archive entries, total expanded bytes,
  nesting, processing time, and per-principal storage or processing quota.
- Treat archives as collections of hostile paths and payloads. Every extracted
  entry must stay under a fresh destination, and links or special files must not
  escape it.
- Keep private-file identifiers unguessable, but never use unguessability as
  authorization. Resolve an allowed object for the current principal before you
  return bytes or a short-lived delegated download.

## Django & DRF implementation

`UploadedFile.name`, `UploadedFile.content_type`, and a DRF parser's media type
come from the request, and they are untrusted. Django's
`FileExtensionValidator` checks the filename extension only. It is a useful
allowlist signal, not content validation. DRF's `MultiPartParser` and
`FileUploadParser` use Django's upload handlers, but they do not make the
content safe. With `FileUploadParser`, both the URL filename and the
`Content-Disposition` filename remain attacker-controlled.

Process large uploads through `UploadedFile.chunks()` rather than an unbounded
`read()`. A bounded prefix may support signature detection, if you reset the
file position before later parsing or storage. Validate with multiple
independent signals and a maintained format-specific parser, then decode the
complete bounded file. A canonical re-encode is stronger than a magic-byte
match. Do not newly recommend `python-magic` or `filetype`, because their
release and maintenance signals do not pass the 9 Aug 2026 dependency gate.
Existing use must be re-vetted.

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

No single detector proves a file safe. Select a maintained parser for each
format the product actually accepts, and run it through the A03 package gate.
Otherwise remove that format from the allowlist.

**Write-time.** When you generate an upload field or handler, write three
things in the same edit as the field itself. Write the format allowlist, the
size cap, and the server-generated storage key. Each one is separately
load-bearing, and the one you defer is the one that ships.
`FileExtensionValidator` belongs in that first edit as the cheapest of the
signals, not as the whole gate, because it reads the name the client chose.
Never assemble the stored path from `upload.name`. Settle where the bytes will
be served from before the first file arrives, because a change afterwards means
a move of every object already stored.

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

If custom storage or archive extraction joins paths, resolve the final path and
verify that it remains below the intended root. Reject absolute paths,
drive-qualified paths, `..` traversal, NUL and control characters, alternate
path separators, links, devices, and other special entries. A sanitized display
name is still not a safe storage path.

A display name is also rendered text, and "control characters" does not reach
the characters that change how it reads. A bidirectional override (U+202E) and
the zero-width characters are formatting characters, so a control-character
filter keeps them. An override before the extension reverses the tail of the
name, and an executable presents to the reader as a document. Normalize the
display name to NFKC, then remove the bidirectional and zero-width formatting
characters. Keep the server's own extension separate from it, because that
extension follows the detected type rather than the name.

A key has to be **unguessable and inert**. `uuid4().hex` carries 122 bits of
randomness, a 128-bit value with six bits fixed for version and variant. That
settles the guessing question for any bucket that does not let the world list
its contents. The threat is a guess at one key, not an exhaustion of the space.

Unguessability still is not authorization, and it only decides how bad the
other failures are. A predictable key with an object readable without
credentials is a mass-exposure primitive, because an attacker can walk the
whole corpus. Either one alone is a far smaller finding.

Inert means that the key discloses nothing when somebody sees it. Keys travel
further than the objects they name, into access logs, referrer headers, support
tickets, and analytics. Treat the key itself as published text. Customer and
tenant names, email addresses, sequential identifiers, original filenames,
document titles, and dates in a key path all leak (CWE-201). A sequential
identifier discloses volume and invites enumeration. A retained filename such
as `redundancy-letter-2026.pdf` discloses the content of a file nobody was
authorized to read.

Add a tenant prefix on top of the random component, not instead of it. Its
value is that the platform can enforce it *below* the application. A storage
credential restricted to one prefix stops an application bug from a write or a
read across tenants. A check in view code cannot promise that. Keep the prefix
a surrogate identifier rather than a name.

Finally, a key is an identity, so two writes to the same key are one object.
Object stores overwrite by default rather than deduplicate. S3 replaces the
existing object on a PUT to an existing key, and `FileSystemStorage` is the
outlier that appends a suffix instead. Under a server-generated key that is
irrelevant. Under a user-influenced key it is silent data loss, and across a
tenant boundary it is an unauthorized write (CWE-639).

## Storage and serving

- Keep uploads out of application code, templates, and static roots. The web
  server and object store must never interpret them as scripts or configuration.
- Prefer a separate object store or a distinct registrable-domain origin for
  public user content. A sibling subdomain can still share some browser trust
  boundaries. Do not send application cookies to the upload origin.
- Return `X-Content-Type-Options: nosniff`, an allowlisted `Content-Type`, and
  usually `Content-Disposition: attachment`. Do not reflect the supplied media
  type into the response.
- Use a quarantine state until validation or scanning completes. Make state
  transitions explicit so an unapproved object cannot be fetched through a
  predictable media URL.
- Keep permissions non-executable and credentials least-privileged. The upload
  worker may write quarantine. The serving tier should not be able to modify
  application code.

- Use Django's Storage API with an official, maintained provider SDK, or a
  freshly vetted backend. Do not newly recommend `django-storages==1.14.6` for
  the Django 6 baseline. `1.14.6` was released in April 2025, and its own
  Django classifiers stop at 5.1. It therefore declares support for neither 5.2
  LTS nor 6.0. Existing deployments need a compatibility review and a
  credential and URL-signing review before a framework upgrade. "Object storage
  configuration" below holds the settings that decide whether that review
  passes.

See `deployment-and-runtime.md` for edge and serving configuration. An upload
served outside the web root is useful only if the separate serving path is also
configured to be inert.

### Metadata the store echoes back

An object store persists metadata the uploader influenced, and returns it on
retrieval. Stored metadata is therefore an input to the response rather than a
record about it. Custom metadata lives under `x-amz-meta-*` on S3,
`x-goog-meta-*` on GCS, and `x-ms-meta-*` on Azure. All three come back as
response headers on a read.

Those are the obvious half. The dangerous half is the content-type and
content-disposition pair, because that pair decides whether a browser renders
the bytes or saves them. Every provider offers a route by which something other
than your serving code chooses it:

- **S3** stores `Content-Type` at upload and returns it on a read. A signed
  request can override it for that request through the `response-content-type`
  and `response-content-disposition` query parameters. Those parameters take
  precedence over the stored value.
- **GCS** stores `Content-Type`, `Content-Disposition`, `Content-Encoding`,
  `Cache-Control`, and `Content-Language` as object metadata and serves them
  back as given.
- **Azure** stores the blob content-type and content-disposition system
  properties, and serves them as the corresponding response headers. A SAS that
  carries an `rsct` or `rscd` override wins for that request.

So whoever controlled the upload controls how the object is later interpreted.
A filename that reaches a disposition header unescaped controls the header
itself. `text/html` served from an origin that holds session cookies is stored
XSS (CWE-79), and an unsanitized filename in a disposition is header injection
(CWE-116). Neither needs a second bug, because trust in a stored value is the
whole of it.

The serving rules above are the answer, applied one layer earlier. The content
type and the disposition belong to the server's validated verdict at serve
time, not to anything the upload supplied. Set them explicitly on the response,
and let the stored copy be a record rather than an instruction. Where a display
name has to survive into a disposition, encode it as `filename*` rather than
interpolate it. Treat every `*-meta-*` value as untrusted text wherever the
code renders it.

Those rules assume a response of your own to set the headers on. Two paths in
this file have none. A delegated download URL sends the bytes from the store,
and the promotion copy writes the served object with no reader present. On both
of them the stored value is the value the reader receives, so the verdict
belongs in the object rather than in a response.

Set the content type, the disposition, and the cache directive on the promotion
copy. Take each one from the server's own record, and discard what the upload
stored. Where the provider offers the response-header overrides named above,
sign them into a delegated read. The verdict then reaches that reader too. An
uploader-set
`Cache-Control` is the quiet one of the three. A shared cache in front of a
private object stores it under that directive, and serves it to the next
reader.

**Write-time.** When you write the code that serves an upload back, pass the
content type from the server's own record. That record holds what the file was
found to be. Set the disposition explicitly, in the same edit as the read. The
default in every one of these APIs is to return what was stored, so the value
that nobody chose is the uploader's.

## Object storage configuration

Storage configuration decides whether any of the controls above are reachable.
An object that a reader can get without the application has no authorization on
it at all. Maps to CWE-284 (Improper Access Control), CWE-668 (Exposure of
Resource to Wrong Sphere), and CWE-732 (Incorrect Permission Assignment), under
A01:2025 and A02:2025.

### Principle layer

Two questions decide exposure, and a code review can only answer the first:

1. **Does the application hand out a URL that grants access by itself?** A URL
   built from a bucket or CDN hostname with no signature is a bearer
   capability. Whoever holds it reads the object, and logs, forwards, and
   indexes can all carry it. This is visible in the repository.
2. **Would the object be readable without that URL?** Public-access blocking,
   the bucket policy, and object ownership answer that, and none of them lives
   in the codebase.

Report the first, name the second as an open question, and do not collapse the
two. A signal of the first kind is Critical only when the second answer is bad.
Against a bucket that blocks public access, the same signal is a hardening
finding.

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

Name these items as items that need out-of-band verification, rather than
assert them from code. They are public-access blocking, the bucket policy, and
the object-ownership setting. They are also versioning and delete protection,
the permissions actually attached to the signing principal, bucket-level CORS,
and lifecycle rules. Infrastructure code in the same repository brings some of
them back into scope. Read it when it is there, and say which findings came
from it.

Two platform defaults are worth knowing, so that a review does not raise
something the platform already closed. On S3, public access has been blocked
and ACLs disabled on new buckets since April 2023. Server-side encryption with
S3-managed keys has applied to every new object since January 2023, and nobody
can turn it off. Encryption at rest is therefore not the finding. Which key
protects it, and who may use that key, still is.

**A bucket per tenant, or one bucket with a prefix per tenant.** Both are
defensible, and the choice is an architecture decision rather than a security
verdict. You make it once, and it is expensive to undo. Make it deliberately
rather than by default:

| Dimension | Bucket per tenant | Shared bucket, prefix per tenant |
| --- | --- | --- |
| Blast radius | A wrong policy exposes one tenant | A wrong policy exposes every tenant at once |
| Policy granularity | Public-access blocking, versioning, retention, and the encryption key are all set per tenant | Those are bucket-level, so every tenant gets one setting: the strictest tenant's cost or the weakest tenant's risk |
| Credential scoping | A credential cannot name a bucket it was not given; the boundary is structural | The boundary is a prefix condition in the policy, which holds only if it was written correctly and is absent silently |
| Operational cost | Provisioning, per-account bucket limits, and per-bucket configuration drift become the scaling constraint | One bucket to configure, monitor, and reason about |

The failure that decides most cases is the third row against the second. A
shared bucket is sound when the prefix condition on the upload and download
credentials is real and tested. It is a cross-tenant read the moment that
condition is merely intended. A per-tenant bucket makes that failure
structurally unavailable. That property makes it the stronger default for
high-sensitivity content. It is the wrong default at high tenant counts, where
the bucket limit and the configuration drift become the larger risk.

Either way, the tenant component of the key stays a surrogate identifier rather
than a name, for the reasons in "Filenames and storage keys" above. Either way,
the prefix or bucket restriction on the signing credential is the control that
a check in view code cannot promise.

### Django & DRF implementation layer

`STORAGES` is the configuration form, because Django 5.1 removed
`DEFAULT_FILE_STORAGE` and `STATICFILES_STORAGE`. A second named alias is the
built-in way to keep private user content off the backend that serves public
assets:

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

A second alias is a name, and a name isolates nothing on its own. Django
passes each alias's `OPTIONS` to its backend as keyword arguments, and that is
the only per-alias input the backend gets. A backend class that reads
module-level settings therefore resolves the same bucket, the same custom
domain, and the same signing policy under both aliases. Give the private alias
its own values, in `OPTIONS` or as attributes on its own class. Name the
bucket, the signing policy, and the custom domain among them. Otherwise the
split above is reviewable rather than real, and the permanent unsigned URL
arrives through the alias rather than through the settings file.

`FILE_UPLOAD_PERMISSIONS` (`0o644` since Django 3.0) and
`FILE_UPLOAD_DIRECTORY_PERMISSIONS` (`None`, which leaves it to the process
umask) govern `FileSystemStorage` only. An object store ignores both, so a
clean local-storage review says nothing about the bucket. Where a private alias
does use `FileSystemStorage`, `0o644` makes every stored file readable to every
account on the host. The umask alone decides the directory. Set
`file_permissions_mode` and `directory_permissions_mode` in that alias's
`OPTIONS`, because the per-alias value wins over the global setting.

Where `django-storages` is already installed, four of its S3 defaults decide
whether a private object is private. Read them off the backend's own source
rather than off documentation:

- `AWS_DEFAULT_ACL` defaults to `None`, which means the object inherits the
  bucket's permissions — not that it is explicitly private. On a bucket with
  public access blocked and ACLs disabled that is safe. On an older bucket it
  is not, and an install carried across the version where the default was
  `public-read` may still be setting it.
- `AWS_QUERYSTRING_AUTH` defaults to `True`, with `AWS_QUERYSTRING_EXPIRE` at
  3600 seconds. A value of `False` on private media publishes unsigned URLs
  that work only if the object is public. That value is therefore a strong
  indication that the bucket is public.
- `AWS_S3_CUSTOM_DOMAIN` silently overrides both of those. With a custom domain
  set, `url()` returns a signed URL only when a CloudFront signer is *also*
  configured. With no signer it returns the plain domain-and-key URL, and
  `AWS_QUERYSTRING_AUTH = True` has no effect on that path. A custom domain on
  private media without `AWS_CLOUDFRONT_KEY_ID` and `AWS_CLOUDFRONT_KEY` is a
  permanent, unsigned URL for every private object. Nothing in the settings
  file looks wrong.
- `AWS_S3_FILE_OVERWRITE` defaults to `True`, so `get_available_name()` returns
  the key unchanged and a second save replaces the first. That is the opposite
  of the behavior a `FileSystemStorage` habit expects.

That last pair is the reason to review the *combination* of settings rather
than each one. Grep for `AWS_S3_CUSTOM_DOMAIN`, `AWS_QUERYSTRING_AUTH`,
`AWS_DEFAULT_ACL`, and `MEDIA_URL` together, and read them against which
storage alias the sensitive `FileField`s actually use.

## Direct-to-storage uploads

When the client uploads straight to the object store, that path bypasses every
synchronous control above. The bytes never reach the application, so nothing
validates a type, counts a byte, or rejects an archive before the object
exists. The controls do not disappear. They move to either side of the
transfer, and an architecture that omits the second half never applies them at
all. Maps to CWE-770, CWE-434, CWE-639, CWE-345, and CWE-306, under A01:2025,
A08:2025, and API4:2023.

### Principle layer

A delegated upload URL is the issuer's authority in a link. Whatever the
signing principal may do, the holder of the link may do, within the signed
constraints and for as long as it lives. It is a bearer token that survives a
copy. The question is never whether the URL stays secret. The question is what
the URL permits.

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
- **A least-privileged signing principal.** The URL cannot be narrower than the
  credential behind it. A signer that can also read and list the bucket
  therefore makes every scoping decision above advisory (CWE-269, CWE-732).

Severity turns on combinations. An unbounded size on a private bucket is a cost
and availability finding. A predictable key with an unsigned public URL is a
mass-exposure primitive.

The size bound is where the three major stores diverge. What to look for
therefore depends on which one is behind the URL, rather than on one rule
generalized from S3:

- **S3** — a presigned PUT binds no size at all. The enforced form is a
  presigned POST whose policy carries a `content-length-range` condition.
- **GCS** — a V4 signed PUT *can* bind one, by signing an
  `x-goog-content-length-range` header of `MIN,MAX` bytes into the URL. Cloud
  Storage rejects a body outside that inclusive range with `400`, and the POST
  policy supports a `content-length-range` condition as well.
- **Azure** — a SAS binds no size in any form. Its whole signed field set is
  the permission, the resource, the window, an IP range, the protocol, a
  stored-policy identifier, and five response-header overrides. None of them is
  a length. The ceiling has to be applied after the object exists, which makes
  the verification step the only thing between a SAS and an unmetered write.

**No delegated URL can be recalled one at a time, and not within its lifetime.
What differs by provider is how much else you have to break to withdraw one
early.** On that point, the rule the rest of this section is written around
holds for S3 and GCS, and is too strong for Azure. On S3 and GCS the only lever
is the signing credential, so the URL dies when the credential dies.

A signature from a short-lived session credential rather than a long-lived key
is therefore the real control. On S3 an assumed-role session lasts one hour by
default, and an instance-profile credential roughly six, against the seven days
a long-lived key permits. The URL expires with the credential, even when the
caller requested a longer expiry. Rotation or deactivation of that credential
invalidates every URL it signed, which is blunt but works. And an object that
is still in quarantine grants a URL holder access to nothing that is served.

Azure's shared access signature comes in three forms, and which one was issued
decides how blunt the withdrawal is. A **user-delegation SAS** is signed with a
user-delegation key obtained through Entra credentials. The signing identity is
therefore a security principal, no account key is involved, and it is
Blob-only. A **service SAS** is signed with the storage account key and scoped
to one service. An **account SAS** is signed with the account key, and it spans
services and service-level operations. Only Azure offers a withdrawal that
leaves the signing credential in place:

| Form | Withdrawn before expiry by | Granularity, and on what timeline |
| --- | --- | --- |
| S3 presigned URL or POST policy | Rotating or deactivating the signing credential | Immediate, and takes every URL that credential signed with it |
| GCS V4 signed URL | Rotating the signing service account's key, or removing its IAM permission | Immediate, and takes every URL that key signed with it |
| Azure account SAS, or a service SAS with no stored policy | Regenerating the storage account key | Immediate, and takes every SAS in the account with it |
| Azure service SAS bound to a stored access policy | Deleting the policy, renaming it, or moving its expiry into the past | Per policy, so one grant goes without touching the account key; timeline not published |
| Azure user-delegation SAS | Revoking the user-delegation key, or removing the signing principal's role assignment | Per key or per principal, still not per URL; timeline not published, and both the key and the role assignments are cached |

Prefer those two on Azure for that reason, and note that the user-delegation
SAS also keeps the account key out of the process. Neither is a recall button.
The granularity is a policy or a key rather than a URL. Azure publishes no
number for how long a revocation takes to land, and states only that there may
be a delay. Treat any specific latency you are told as unverified.

So the lifetime cap remains the control that does not depend on anybody's
attention. Every provider has the same maximum of 604800 seconds, or seven
days. That maximum holds on a GCS V4 signature, an S3 SigV4 presigned URL, and
an Azure user-delegation key, whatever expiry the caller requested. An upload
URL has no business near that ceiling, and minutes is the right order of
magnitude.

Where the platform can cap it centrally instead of trust in the issuer, it
should. That control is provider-specific rather than the S3 one generalized.
An S3 bucket policy can refuse requests whose signature is older than a chosen
age. An Azure storage account can carry a SAS expiration policy. GCS has no
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

The quarantine prefix must not be readable outside the verification tier
either. The uploader knows that key, because the URL they were issued named it.
An anonymous read on the bucket, or a CDN origin that covers it, therefore
hands them a link to their own unscanned bytes on your domain. Unguessability
answers nothing here. Keep the quarantine prefix off every public origin, and
give the read to the verification tier alone.

That state machine needs a terminal `REJECTED` state, and a sweeper for objects
that are uploaded and never confirmed. Without one, abandoned quarantine
objects accumulate as unreviewed content and unbilled-for storage. Where a scan
is part of the verdict, it must be asynchronous and must fail closed.

The store bounds one object, and nothing in it bounds how many. Issuance is
therefore the only count ceiling on this path. Cap the outstanding `PENDING`
rows per principal and per tenant, and refuse a new URL at the cap. Give the
sweeper a lifetime longer than the slowest legitimate upload and confirmation.
A shorter one deletes objects that are still in flight.

Four failure modes let unscanned content reach a reader. The first is a scanner
timeout treated as clean. The second is a copy to the served prefix before the
verdict is recorded. The third is a scan against the type in the database
rather than the bytes in the store. The fourth is an object that somebody can
still overwrite between the scan and the serve.

The last one is why the served prefix is write-denied to the uploader, and why
object versioning is worth the cost. Copy the exact `versionId` or generation
that the scanner read, so that a write after the scan cannot reach the reader.
The choice of a scanning engine is a separate decision, and it belongs to the
dependency gate in `a03-software-supply-chain.md`.

A verdict is a fact about bytes, not about a row. Cache it under a hash of the
content rather than under the object key or the filename. Keyed that way,
identical content uploaded twice reuses the existing verdict. A rename cannot
launder a rejected object into a fresh scan, and two different objects can
never share one.

That last property belongs to the hash, and not every hash has it. Compute
SHA-256 over the stored bytes yourself. Never key the cache on the S3 ETag. The
ETag is an MD5 only for a single-part upload, MD5 is not collision-resistant,
and a multipart ETag is a different value entirely. A chosen-prefix collision
otherwise carries one file's clean verdict onto another, and that other file
never reaches the scanner.

A verdict is also only as good as the signatures that produced it. Record the
engine and the signature version beside it, and treat a version advance as an
invalidation. Otherwise content admitted before a signature existed stays
admitted, and that window is exactly the one a novel sample occupies. A lazy
re-scan on next access is enough only where every read passes the application.
It is not, where the reader holds a delegated URL or reaches a CDN, because the
next access never arrives. Move those objects back to the quarantine state on a
version advance instead. The requirement is that a stale "clean" cannot become
permanent.

Where a detection gap is not tolerable at all, content disarm and
reconstruction is the other shape of the control. CDR does not decide whether a
file is malicious. It decomposes the file and discards every component outside
an allowlist: macros, embedded scripts, other active content. It then rebuilds
a functionally equivalent file from what is left. It depends on no signature,
so novel or polymorphic content does not affect it. It rewrites the file, so it
can break what the file was for, and editability, embedded logic, and fidelity
all move. That trade is why it is a control to choose deliberately rather than
a default, and it sits beside a scan rather than replaces it.

Confirmations and event notifications are the weak point, because they are the
step that grants availability. An unauthenticated callback that moves a row
from `PENDING` to `AVAILABLE` lets an attacker approve their own object
(CWE-306). A callback that takes the object key from the request body, and does
not check it against the row, lets one user confirm another's upload. A
confirmation that believes a client-supplied size or content type has undone
the entire verification. Verify the message's authenticity, then re-derive
every fact from the store.

`a08-integrity-and-deserialization.md`, "Webhook and callback integrity" owns
the signature, timestamp, and replay rules for that.
`a01-broken-access-control.md`, "SSRF" owns the SSRF rules that an "import from
a URL" upload path must satisfy.

### Django & DRF implementation layer

On S3 the two delegated-upload forms are not interchangeable. A presigned
`put_object` URL binds only what was signed into it, and no signed element
exists for a maximum body size. A presigned PUT therefore cannot bound how much
is uploaded at all. A presigned POST carries a policy document that S3 itself
evaluates, and `content-length-range` is the only mechanism either form offers
to cap object size.

Re-checked against `boto3` 1.43.67 on 9 Aug 2026 and still true.
`generate_presigned_url` accepts an operation, its parameters, and an expiry,
and admits no condition of any kind. The POST policy carries
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
# boto3 adds the key condition itself, and a literal key makes it an exact
# match, which is what binds this URL to one object. content-length-range is
# what makes the size limit real rather than expected, and the trailing slash
# is what keeps the prefix off a sibling tenant.
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

Three mechanics of that call are easy to misread. A condition and its field are
separate arguments, and neither implies the other, so a `Content-Type`
condition with no matching `Fields` entry rejects every upload. S3 also
requires every form field the client sends to appear in the conditions. The
exceptions are the signature, the file, the policy itself, and any `x-ignore-`
prefixed field. A field the client can add freely is a field you did not
constrain.

The third is that `boto3` writes a key condition of its own, and the `Key`
argument decides which one. A literal key produces an exact `{"key": ...}`
condition, and that condition is what binds the URL to one object. A key that
ends in `${filename}` produces a `starts-with` on the part before it instead.
Checked against `boto3` 1.43.81 on 27 Aug 2026.

That difference is the whole object-count bound on this path, because a
presigned POST is replayable for its whole lifetime. An exact key sends every
replay to the same object. A `${filename}` key sends each one to a new object,
so a single short-lived URL becomes an unmetered write (CWE-770). Prefer the
literal key. The prefix in any `starts-with` condition must also end with the
delimiter. A condition on `quarantine/1` matches `quarantine/12/`, so that
trailing slash is the whole of the boundary.

After the upload, `head_object` returns the size and content type the store
recorded, and verification runs against those. Read them there, never from the
confirmation request. Then apply "Type and content validation" above to the
bytes themselves, because a store-reported content type is only what the
uploader declared at PUT time. S3 has been strongly read-after-write consistent
for writes, overwrites, and deletes since 2020. An immediate read back is
therefore correct, and the retry loops that older guidance recommends are
obsolete. Bucket-level configuration is still eventually consistent, and other
S3-compatible stores may not offer the same guarantee.

Model the states as a field with an explicit transition, not as a boolean. Keep
the promotion in one order: copy to the served prefix, then mark `AVAILABLE`. A
crash then leaves an object that is present but unreachable, rather than
reachable but unverified. `a10-exceptional-conditions.md` owns how to enforce
the transition itself against concurrent confirmations.

#### GCS: the signed PUT that does bound size

`google-cloud-storage` expresses the binding through the `headers` argument of
`generate_signed_url`. Anything you pass there joins the canonical headers that
the V4 string-to-sign covers, and the URL names it in `X-Goog-SignedHeaders`.
The client must therefore send each one, unaltered, or the signature fails.
That is what makes an `x-goog-content-length-range` header a constraint rather
than a suggestion:

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

Verified against `google-cloud-storage` 3.13.1 on 9 Aug 2026. A signature on
that call puts `x-goog-content-length-range` into `X-Goog-SignedHeaders`. The
library itself enforces the seven-day ceiling: an expiration over 604800
seconds raises `ValueError` rather than returns a URL. That check is specific
to V4. A `version="v2"` signature accepts a longer expiration without
complaint, which is one more reason to sign V4.

Two bucket-level settings sound as though they would interfere, and they do
not. Uniform bucket-level access disables object ACLs and leaves IAM as the
only grant. It is the posture to want, and it does not restrict signed URLs.
Public access prevention does not restrict them either. A signed URL derives
its authority from the signing service account's own IAM permissions, rather
than from any public grant. The corollary is the one that matters for review.
Under UBLA the signing service account's IAM role *is* the ceiling on every URL
it issues, so narrow that role.

#### Azure: a SAS binds less than you would expect

Two things about `generate_blob_sas` have to be read off the source, because
its own docstring is wrong about the first. `protocol` has no default. If you
pass nothing, the call emits no `spr` field at all, which leaves the SAS usable
over plain HTTP. The docstring states that the default is HTTPS. State the
protocol yourself.

The second is that a `policy_id` waives `permission` and `expiry`, which are
ordinarily required. The resulting token carries only `si`, `sr`, `sv`, and the
signature. It takes its permission and its expiry from a stored access policy
on the container that no amount of reading the codebase will show you. That is
one of the two forms the revocation table above prefers, so the trade is
explicit. The withdrawable SAS is also the one whose grant is invisible in
code, and a review of it means a read of the container's policy.

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

**Write-time.** When you generate a delegated upload URL, settle the provider
before the constraints, because the provider decides which of them can be
signed at all. On GCS, write the `x-goog-content-length-range` header into the
same call as the key and the expiry. On S3, use the presigned POST rather than
the PUT the moment a size matters. On Azure, write the verification step in the
same change as the SAS, because nothing in the token will bound the bytes.

State the protocol and the expiry explicitly on every provider, rather than
inherit a default. Sign with the narrowest credential the platform offers: a
session credential on S3, a scoped service account on GCS, and a
user-delegation key on Azure.

## SVG and other active content

SVG is XML-based active content, not a passive image. It can contain scripts,
event handlers, links, external resource loads, and `foreignObject` HTML.
Reject SVG by default for image uploads. If the product genuinely requires it,
use a dedicated, maintained allowlist sanitizer. Remove scripts, event
attributes, external references, unnecessary animation, and `foreignObject`.
Then reserialize it, and serve it from an isolated origin or as an attachment.

A CSP header is defense in depth, not a substitute for sanitization and origin
isolation. Apply the same scrutiny to HTML, XML, and office and document
containers that can carry active content.

## Images and archives

For images, open and decode under limits, and verify the reported format. Cap
width, height, total pixels, frames, and metadata, and re-encode to an approved
format. Keep Pillow's decompression-bomb protection enabled. Treat its warning
as a rejection for untrusted uploads, rather than disable `MAX_IMAGE_PIXELS`.

For ZIP, tar, and similar archives:

- inspect the central directory before extraction;
- cap entry count, per-entry size, total uncompressed size, compression ratio,
  nesting depth, and processing time;
- reject absolute/traversing names, duplicate/conflicting destinations,
  symlinks, devices, and special files;
- resolve every destination beneath a fresh extraction root;
- run every extracted entry through the format allowlist and the content
  validation above; and
- extract and process in a low-privilege, resource-constrained worker.

An archive is a second upload channel, and each entry is an upload. An
allowlist that admits `.zip` and rejects `.svg` still admits an `.svg` inside a
`.zip`, unless every entry passes the gate again. Reject the whole archive when
one entry fails.

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

The filter API is backported to Python 3.8.17, 3.9.17, 3.10.12, and 3.11.4.
Python 3.12 warns when the caller gives no filter. Python 3.14 makes `"data"`
the default.
Pass the filter explicitly, and do not depend on the version default. An older
micro version has no filter API, so test with `hasattr(tarfile, "data_filter")`
before you call it. For a user upload, reject a tar member that is a symlink or
a hardlink.

**Write-time.** When you generate tar extraction code, pass `filter="data"` in
the same call. When you generate ZIP extraction code, write the member checks
before the extraction call. The library enforces no policy of its own.

## Size, count, and quota limits

Put a hard request-body limit at the reverse proxy, CDN, or gateway, so that it
rejects oversized requests before the application reads or spools them. Add
endpoint-specific limits for each file, aggregate bytes and file count per
request, and rolling quotas per authenticated user, tenant, destination, and
time window. An expensive scan or conversion should run under worker CPU,
memory, wall-clock, and concurrency limits.

Django settings have narrower meanings than their names suggest:

- `DATA_UPLOAD_MAX_MEMORY_SIZE` limits request data Django reads into memory and
  excludes uploaded-file content; it is not a hard upload-size cap.
- `FILE_UPLOAD_MAX_MEMORY_SIZE` chooses when an upload moves from memory to a
  temporary file; it is a spooling threshold, not a rejection limit.
- `DATA_UPLOAD_MAX_NUMBER_FIELDS` and `DATA_UPLOAD_MAX_NUMBER_FILES` (the
  latter defaults to 100) constrain multipart complexity, and you should not
  raise them casually.
- From Django 6.1 `HttpRequest.multipart_parser_class` selects the parser that
  reads the request body. A replacement parser owns every bound above, because
  the parser reads the settings rather than something around it applying them.
  Review a custom value as request-handling code, not as configuration.
- Django 6.1 validates Base64 strictly where it decodes request and stored
  data. `django.http.multipartparser.MultiPartParser` raises
  `MultiPartParserError` on invalid Base64, where earlier versions could ignore
  it or produce an empty value. `django.db.models.BinaryField` raises
  `ValidationError`, and `django.core.cache.backends.db.DatabaseCache` raises
  on a corrupt entry rather than skipping it. Each is a fail-closed change:
  confirm the handler around these paths returns a 400 rather than a 500.
- A custom upload handler can stop a stream early, but an edge limit is still
  required. Under ASGI, the server may already have received or spooled request
  data before application-level code rejects it. CVE-2026-5766, fixed in Django
  6.0.5 and 5.2.14, was that failure exactly. An ASGI request with a missing or
  understated `Content-Length` bypassed `FILE_UPLOAD_MAX_MEMORY_SIZE`, and
  Django read it into memory. Two bodies record its severity and they disagree:
  low under Django's own security policy, medium in the GitHub Advisory
  Database. Put both in a report. Otherwise a scanner keyed to the second and a
  reviewer who quotes the first describe the same install in different words. A
  patch closes that instance, but the size ceiling belongs at the web server
  either way.

A direct-to-storage upload has no reverse proxy in its path, so none of the
above applies to it. The equivalent ceiling is a `content-length-range`
condition in the signed policy, and it is the only one there is.

Keep application checks even with an edge limit, because different endpoints
and principals need different policies. Use `upload.size` only as an early
signal. Enforce a counted byte limit during the stream when the storage or
transport does not guarantee it.

Size, count, and expansion ratio are this file's instances of a rule that runs
across every surface. Every caller-controlled value that multiplies work
carries a server-enforced ceiling. `a06-insecure-design.md`, "Algorithmic
resource exhaustion" holds the design rule and the table of surfaces.

## Private downloads

Resolve the file through a requester-scoped queryset before you open storage:

```python
from django.contrib.auth.decorators import login_required
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.cache import never_cache


@never_cache
@login_required
def download_document(request, public_id):
    document = get_object_or_404(
        Document.objects.visible_to(request.user),
        public_id=public_id,
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

The `content_type` argument there is not decoration. `FileResponse` sets the
header from the filename when the caller gives no type, so a stored display
name would choose the response's media type. The validated type is the one that
belongs in the header, and `as_attachment=True` supplies the `attachment`
disposition.

The route takes `public_id` rather than `pk` for the reason in the principle
above. The queryset is what authorizes, and a sequential primary key in the URL
does not weaken it. The identifier decides the size of the next authorization
bug: an enumerable one turns a single regression in `visible_to` into the whole
table.

### Proxy or signed URL

If Nginx, a CDN, or object storage sends the bytes, perform the same
authorization first. Then issue an internal redirect, or a short-lived,
single-purpose signed URL. Bind delegated URLs to the exact object and
disposition, use a short expiry, and prevent a shared cache of private
responses. Do not expose a permanent public media URL for a private object.

The two arrangements fail differently, so choose deliberately:

- **A proxy through the application** authorizes every request, logs every
  access, and revokes the moment the permission changes. It costs application
  bandwidth. Under WSGI it occupies a worker for the whole transfer, so a slow
  reader on a large file is an availability concern of its own.
- **An internal redirect** keeps per-request authorization in the application
  and hands the transfer to the web server. It is an Nginx `internal;` location
  reached through `X-Accel-Redirect`, or `mod_xsendfile` on Apache. Django
  ships neither, and both are edge configuration. This is usually the right
  answer for private content. The `internal;` marker is load-bearing: without
  it the location is directly reachable, and the authorization does nothing.
- **A signed URL** offloads the bytes entirely and can be cached at an edge,
  but it moves authorization to issue time. It cannot be withdrawn while it
  lives, and it leaks through logs, referrers, and forwarding.

Whichever you use, range and partial reads must go through the same
authorization as a full read.

### Private objects and CDN cache keys

A signed URL behind a CDN whose cache key drops the query string is an
authorization bypass, not a cache inefficiency. The CDN stores one user's
authorized response under a key that another user's request also produces. The
second reader then receives bytes that no check was run for (CWE-524, CWE-525).

Three options follow, in order of preference. Do not cache private objects at
all, and return `Cache-Control: private, no-store` on proxied private
responses. Or use the CDN's own signed-URL or signed-cookie mechanism, so the
edge validates before it serves. Or, if origin signed URLs must pass through a
CDN, include the signing parameters in the cache key.

`Vary` is not a substitute, because cookie values are high-cardinality and
every layer has to honor it for the boundary to hold.
`a01-broken-access-control.md`, "Caching and authorization" holds the general
rule this is one case of, and the invalidation requirement.
`deployment-and-runtime.md` holds the edge and CDN configuration itself.

Stored files outlive the rows that reference them. A delete of a model instance
does not delete its file, so erasure and retention have to remove the bytes
explicitly. One property of delegated delivery bounds what an erasure can
promise, and it belongs here rather than there. Nobody can recall a signed URL
that has already been issued. The only controls over it are the expiry it was
given, and rotation of the credential that signed it. On Azure alone,
revocation of the stored access policy or user-delegation key behind it is a
third, on a timeline Microsoft does not publish.

That is the practical argument for short expiries on private content, because
every minute of lifetime is a minute an erasure cannot reach. A generated
export archive is this same delivery primitive around a subject's whole record,
with its own lifetime. `data-lifecycle-and-privacy.md` owns deletion
completeness itself, including what an ordinary delete leaves behind on a
versioned bucket.

## Review checklist

### Stack-neutral

- [ ] Accepted formats are allowlisted and checked by extension, declared type,
      detected signature, and a complete format-aware parse. Every archive
      entry passes that same gate.
- [ ] Client filenames never determine paths or storage keys; archive entries
      cannot escape a fresh extraction root.
- [ ] Untrusted content is quarantined, non-executable, and served from an
      isolated origin or as a download with fixed response headers.
- [ ] The quarantine prefix is readable only by the verification tier. The
      promotion copy takes content type, disposition, and cache directive from
      the server's record, and a delegated read signs the same values where
      the provider offers the override.
- [ ] SVG and other active formats are rejected or purpose-built sanitized,
      reserialized, and origin-isolated.
- [ ] Request, file, decoded-content, archive, processing, concurrency, and
      per-principal quotas are enforced before expensive work.
- [ ] Private downloads repeat object-level authorization; identifiers or signed
      URLs do not replace that check.
- [ ] Delegated upload URLs bind the operation, the key, a maximum size, the
      content type, and the shortest workable expiry. A credential that can
      write only the quarantine prefix signs them.
- [ ] An object becomes reachable only after server-side verification. That
      verification re-derives size and type from the store, rather than from
      the client or the callback that announced the upload.
- [ ] A cached verdict is keyed on a SHA-256 of the stored bytes, never on the
      ETag. A signature-version advance reaches objects whose reads bypass the
      application.
- [ ] The upload state machine has a terminal rejected state and a sweeper for
      objects that were uploaded and never confirmed.
- [ ] On S3, a bucket that takes multipart uploads carries an
      `AbortIncompleteMultipartUpload` lifecycle rule with a
      `DaysAfterInitiation` value. The parts of an abandoned upload bill as
      storage, and appear in no object listing.
- [ ] On GCS, the same rule under Object Lifecycle Management: an
      `AbortIncompleteMultipartUpload` action keyed on `age`, for the same
      invisible-cost reason.
- [ ] On Azure there is nothing to configure, and that is the finding. A
      `Put Block` that no `Put Block List` ever committed leaves blocks behind.
      Azure collects them on a fixed seven-day schedule that no policy can
      shorten. The cleanup is therefore the application's, and the
      storage-versus-listing gap is what there is to monitor.
- [ ] Storage keys are opaque and disclose no name, address, sequence, or
      original filename.
- [ ] Private objects have no permanent public URL. Any CDN in front of one
      either does not cache it, or includes the signing parameters in the key.
- [ ] The review marks findings that depend on platform state for out-of-band
      verification, rather than asserts them from code. That state is
      public-access blocking, bucket policy, versioning, the signing
      principal's permissions, and bucket CORS.

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
      assets, and each sensitive `FileField` names it. That alias overrides
      bucket, signing, and custom domain in its own `OPTIONS` or class, because
      the alias name alone shares the module-level settings.
- [ ] `AWS_DEFAULT_ACL`, `AWS_QUERYSTRING_AUTH`, `AWS_S3_CUSTOM_DOMAIN`, and
      `AWS_S3_FILE_OVERWRITE` are read together: a custom domain with no
      CloudFront signer serves private media unsigned whatever the rest say.
- [ ] Delegated uploads use a presigned POST with `content-length-range`
      wherever a size limit has to be enforced rather than expected. The `Key`
      is a literal, because a `${filename}` key downgrades boto3's own key
      condition to a prefix match.
- [ ] Django carries the CVE-2026-5766 fix (6.0.5 / 5.2.14 or later) and the
      request-body ceiling is set at the web server regardless.
