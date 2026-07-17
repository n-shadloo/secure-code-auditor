# File Upload Handling

Untrusted file ingestion from request to storage to download. Covers spoofed
types, unsafe names, active content, parser and decompression hazards, quotas,
and authorization for private files. Maps primarily to CWE-434, CWE-22,
CWE-79, CWE-400, and CWE-409; relevant OWASP categories include A01:2025,
A05:2025, A06:2025, and API4:2023.

## Contents
- [Principle](#principle)
- [Django & DRF implementation](#django--drf-implementation)
- [Type and content validation](#type-and-content-validation)
- [Filenames and storage keys](#filenames-and-storage-keys)
- [Storage and serving](#storage-and-serving)
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
`read()`. A small prefix may be read for signature detection, provided the file
position is reset before later parsing or storage. For accepted document and
image types, use a maintained detector such as `python-magic` or `filetype`,
then open the complete file with the format's parser. Re-encoding an image or
document into a canonical form is stronger than merely accepting a magic-byte
match.

## Type and content validation

Use independent checks and fail closed. This example is an ingestion gate, not
a complete malware scanner:

```python
from pathlib import Path

import magic
from django.core.exceptions import ValidationError

MAX_FILE_BYTES = 10 * 1024 * 1024
ALLOWED_TYPES = {
    "application/pdf": {".pdf"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
}


def validate_upload(upload):
    if upload.size is None or upload.size > MAX_FILE_BYTES:
        raise ValidationError("File is too large.")

    suffix = Path(upload.name).suffix.lower()
    prefix = upload.read(8192)
    upload.seek(0)
    detected_type = magic.from_buffer(prefix, mime=True)

    allowed_suffixes = ALLOWED_TYPES.get(detected_type)
    if allowed_suffixes is None or suffix not in allowed_suffixes:
        raise ValidationError("File type is not allowed.")

    # The declared type is only a consistency signal; normalize documented
    # aliases before comparing in applications that need to accept them.
    if upload.content_type and upload.content_type != detected_type:
        raise ValidationError("File metadata does not match its content.")
```

After this gate, parse the complete PDF or image with a format-aware library,
enforce feature-specific rules, and reject malformed or trailing active content.
Do not claim that magic-byte detection proves a file harmless. Antivirus or
content-disarm scanning may be an additional control for the threat model, but
it does not replace allowlisting, parser limits, inert storage, or authorization.

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

See `deployment-and-runtime.md` for edge and serving configuration. Serving an
upload outside the web root is useful only if the separate serving path is also
configured to be inert.

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

For ZIP and similar archives:

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
- `DATA_UPLOAD_MAX_NUMBER_FIELDS` and `DATA_UPLOAD_MAX_NUMBER_FILES` constrain
  multipart complexity and should not be raised casually.
- A custom upload handler can stop a stream early, but an edge limit is still
  required. Under ASGI, request data may already have been received or spooled
  before application-level handling rejects it.

Keep application checks even with an edge limit because different endpoints and
principals need different policies. Use `upload.size` only as an early signal;
enforce a counted byte limit while streaming when the storage or transport does
not guarantee it.

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

If Nginx, a CDN, or object storage sends the bytes, perform the same
authorization first and issue an internal redirect or short-lived,
single-purpose signed URL. Bind delegated URLs to the exact object and
disposition, use a short expiry, and prevent shared caching of private
responses. Do not expose a permanent public media URL for a private object.

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
