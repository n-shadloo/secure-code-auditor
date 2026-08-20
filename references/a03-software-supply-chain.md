# A03:2025 — Software Supply Chain Failures

New/expanded category in 2025 (absorbs "Vulnerable and Outdated Components").
Covers dependencies, pinning and integrity, vulnerability scanning, EOL
frameworks, and the integrity of versioned schema/data migrations.

This file owns **the dependency as a decision** — the gate a third-party
package has to pass before it is added, pinning and hash integrity, advisory
scanning, the end-of-life framework, the SBOM, and the versioned migration as
a change to data nobody can simply re-run. The recorded output of that gate for
the current baseline is `security-hardening-libraries.md`, which holds the tier
and the minimum-safe floor for each named package and is dated rather than
permanent. `a08-integrity-and-deserialization.md` owns the integrity of what
the project itself produces and consumes, `a04-cryptographic-failures.md` owns
the signing primitive underneath both, and each topic file owns the control the
dependency was chosen to implement.

## Contents
- [Principle](#principle)
- [Run a supported Django](#run-a-supported-django)
- [Pin and verify](#pin-and-verify)
- [Scan continuously](#scan-continuously)
- [Trust and provenance](#trust-and-provenance)
- [SBOM, scan gate, and provenance](#sbom-scan-gate-and-provenance)
- [Third-party dependency vetting](#third-party-dependency-vetting)
- [A development dependency in the production requirements file](#a-development-dependency-in-the-production-requirements-file)
- [Migration and data-integrity safety](#migration-and-data-integrity-safety)
- [Review checklist](#review-checklist)

## Principle

Your security is bounded by your weakest dependency and by the integrity of how
that dependency reaches production. The principle is **know exactly what you
run, keep it patched, and make substitution hard**: pin versions, verify
integrity (hashes/lockfiles), scan for known vulnerabilities on every build, and
pull only from trusted sources. Transitive dependencies count — most of the tree
is code you never chose directly.

## Run a supported Django

As of 9 Aug 2026 the supported lines are **Django 6.1**, **6.0.8**, and
**5.2.17 LTS**. Django 6.1 was released on 5 Aug 2026, which moved 6.0 onto
security and data-loss fixes only through April 2027; 5.2 LTS runs to April
2028. The current patch level matters as much as the line: 6.0.8 and 5.2.17
were security releases on 4 Aug 2026 fixing four issues, the most serious being
CVE-2026-15307, a file-write and request-forgery flaw reachable through spatial
lookups. **Django 4.2 is end-of-life** (final release 4.2.30 on 7 Apr 2026);
5.1 is EOL too. Running an unsupported release means security fixes stop
reaching you —
flag unsupported lines and supported lines below the current security patch
(severity scales with exposure). The same applies to the language runtime and
to DRF/SimpleJWT/Channels/allauth versions; see the libraries file for current
pins.

## Pin and verify

- Pin exact versions (`==`) for applications; a lockfile (`pip-tools`,
  `uv`, Poetry, PDM) captures the full resolved tree.
- Use hash-checking so a swapped artifact fails the install:

```
pip install --require-hashes -r requirements.txt
```

- Keep dev/test tooling out of the production dependency set.

## Scan continuously

- `pip-audit` (PyPA) checks installed/declared packages against advisory
  databases. `pip-audit==2.10.1` passes the current package gate. Treat results
  as known-advisory input, not proof that a dependency is maintained or safe;
  do not add a second scanner without separately vetting its license, data flow,
  advisory source, maintenance, and operating model.
- Enable automated update PRs (Dependabot / Renovate) and treat security updates
  as expedited.
- An advisory recorded as accepted — `pip-audit --ignore-vuln ID` is the
  mechanism here — is an exception, and carries the same three fields as any
  other: owner, reason, and an expiry something executable enforces.
  `a02-security-misconfiguration.md`, "Configuration drift and the expiring
  exception" owns that discipline across all four kinds of suppression a
  Python project accumulates.
- Generate an SBOM (CycloneDX or SPDX) if you need to answer "are we affected?"
  quickly when a CVE drops. Which file it is generated from, in which format,
  and what it does not prove are in "SBOM, scan gate, and provenance" below.

```
pip-audit -r requirements.txt
```

## Trust and provenance

- Install from PyPI (or a controlled internal index), not arbitrary VCS URLs or
  copy-pasted wheels.
- Be wary of typosquats and newly published look-alike names; check the project
  is real and maintained before adding it.
- CI is a credential store, and usually the least-guarded one. Prefer
  short-lived OIDC federation from the CI provider to the cloud account over a
  long-lived deployment key held as a repository secret; see
  `service-identity-and-secrets.md`, "Choosing a machine-authentication
  mechanism".
- This applies to **Claude Skills too**: a skill can direct an agent to run code
  or move data. Only install skills from sources you trust, and read the bundled
  files.
- The same reasoning extends to components an agent discovers and loads at
  **runtime**, where the trust decision happens at call time and no build-time
  pinning, lockfile, or scanner reaches it. Pin the tools and servers a backend
  will connect to, require signed provenance or an allowlist entry before use,
  and treat a tool's own description as untrusted content rather than
  configuration. See `agent-and-llm-interfaces.md`, "Runtime-discovered tools
  and servers".

## SBOM, scan gate, and provenance

Maps to CWE-1395 (Dependency on Vulnerable Third-Party Component) where the
scan gate is absent or disabled, and CWE-494 (Download of Code Without
Integrity Check) where an artifact is consumed without verified provenance.
Severity: medium for an inventory or scan that gates nothing, high where the
missing check is the one standing between a substituted artifact and
production.

### Principle layer

A hashed lockfile is the strongest claim this file can make from the
repository alone. `--require-hashes` turns the install into a verification
step, so a substituted artifact fails instead of running. It stops at three
questions it was never able to answer: whether those pinned versions carry
known advisories *today*, what actually ended up inside the artifact that
shipped, and who built that artifact. An SBOM, a scan gate, and build
provenance answer those three in order. Each is worth exactly as much as the
enforcement attached to it, which is why the useful review question is never
"is there one" but "what happens when it says no".

**The SBOM is generated from the lock, not from the finished image alone.**
An SBOM produced by scanning a built image records what a scanner could
identify inside it; one produced from the lockfile records what the project
resolved and pinned. The two disagree exactly where it matters — a wheel
installed by a build step, a vendored dependency, anything the scanner's
Python detector did not recognize — and only the second is traceable to a
file a reviewer can open. Generate it in the same job that performs the
install, from the same file the install reads, so the two cannot drift apart
without someone editing both.

CycloneDX is the Python ecosystem's working default. Spec 1.7 was published
in October 2025, and `cyclonedx-py` 7.3.1 still emits 1.6 unless told
otherwise, so set `--spec-version` explicitly rather than letting a tool
upgrade silently change the format a consumer parses. SPDX is the
alternative — 3.0.1 on the 3.0 line from April 2024, with 2.2.1 the version
standardized as ISO/IEC 5962:2021 — but no maintained Python-native SPDX
generator of comparable standing exists, so SPDX output comes from a
general-purpose tool such as Syft rather than from anything pip-installable.
Pick on what the consumer requires and record which one you picked.

**An SBOM is not a hash-pinning control**, and the failure is quiet enough to
be worth stating on its own. `cyclonedx-py` 7.3.1 parses a `pip-compile
--generate-hashes` requirements file without complaint and emits components
carrying no `hashes` member at all — verified against 7.3.1 on 9 Aug 2026 in
both `requirements` and `environment` modes. The `--hash=` values survive
only inside the component's free-text description, where nothing can verify
against them. Integrity evidence is `--require-hashes` on the install step
and nothing else. An SBOM sitting beside an install that does not pass it is
an inventory, not a control, and reading it as one is how a project ends up
believing it verifies artifacts it never verified.

**A scan gate is configuration, so review it as configuration.** Read what
the workflow does with the result rather than whether the step is present.
`continue-on-error: true`, a trailing `|| true`, a severity threshold set
above the findings the project actually has, and a report uploaded to an
artifact nobody opens are all the same finding written four ways: the
scanner runs and gates nothing. The exit code is the control.

For Python dependencies the primary scanner stays `pip-audit` — maintained by
the PyPA, Apache-2.0, 2.10.1 as of 10 June 2026 — and its advisory sources
are the reason rather than an incidental detail. It draws on the PyPI
advisory service and OSV rather than on NVD's CPE matching, and that
distinction now carries weight it did not carry a year ago. On 15 April 2026
NIST moved the National Vulnerability Database to risk-based triage: it
enriches CVEs in CISA's Known Exploited Vulnerabilities catalog, CVEs in
software used by the federal government, and software critical under
Executive Order 14028, and marks everything else lowest priority and not
scheduled — including every backlogged CVE with an NVD publish date earlier
than 1 March 2026. NVD-derived CPE and CVSS data is systematically
incomplete from that date forward, so weight an ecosystem-native finding
above an NVD-derived one, and treat a quiet NVD-backed scanner as less
reassuring than it used to be.

The image scanners are worth naming for what they are not. Trivy (v0.73.0,
3 Aug 2026), Grype (v0.116.1, 28 July 2026), Syft (v1.50.0, 28 July 2026)
and cosign (v3.1.3, 6 Aug 2026) are all Apache-2.0, and Anchore's
stewardship of Grype and Syft carries no relicensing, no source-available
move, and no CLA-driven ownership change as of 9 Aug 2026. All four are
distributed as Go binaries, which puts them outside the maintained-package
gate entirely: they are CI patterns, they take no row in
`security-hardening-libraries.md`, and the gate applies here to the two
pip-installable tools, `pip-audit` and `cyclonedx-py`. What the image
scanner is pointed at is `deployment-and-runtime.md`, "Scanning the built
image"; this section owns the pipeline around it.

Pin every action to a commit SHA rather than a tag, and treat that as a
supply-chain control rather than as hygiene. On 19 March 2026 an attacker
holding compromised credentials published a malicious Trivy v0.69.4,
force-pushed 76 of 77 version tags in `aquasecurity/trivy-action` to an
infostealer that dumped the runner process's memory and swept the filesystem
for cloud credentials, and replaced all seven tags in
`aquasecurity/setup-trivy`; a second wave put malicious v0.69.5 and v0.69.6
images on Docker Hub on 22 March. Trivy's advisory GHSA-69fq-xp46-6x23,
carrying CVE-2026-33634, is precise about what survived: releases at v0.69.3
or earlier, images referenced by digest, builds from source, and action
references pinned to a safe commit. No `setup-trivy` tag was safe, because
every one of them was force-pushed — which is the reason to record the rule
as "pin the SHA" and never as "pin the last known-good tag". A tag is a name
the publisher can repoint, and so can anyone holding the publisher's
credentials.

**Provenance is produced inside the repository and verified outside it, and
only the second half is a control.** A GitHub artifact attestation binds a
subject — a named artifact and its digest — to a SLSA build-provenance
predicate in in-toto format, signed with a short-lived Sigstore certificate
minted from the workflow's OIDC identity. Public repositories use the
Sigstore public-good instance and the bundle is copied to a transparency log
that is publicly readable; private and internal repositories use GitHub's
own Sigstore instance, which has no transparency log. Either way the bundle
is uploaded to GitHub's attestations API rather than committed, so what a
repository review can actually read is the workflow that asked for it.

Verification without an identity constraint proves nothing. `gh attestation
verify` scoped only by `--repo` establishes that the artifact carries some
attestation from that repository; `--signer-workflow` is what pins which
workflow signed it, and `--deny-self-hosted-runners` is what refuses one
built where the platform's isolation properties do not apply. `cosign
verify` has the same shape: without `--certificate-identity` or
`--certificate-identity-regexp`, plus `--certificate-oidc-issuer`, it
confirms that a signature exists rather than who produced it. A verify step
missing those arguments is a decorative gate, and it is a finding at the
severity of whatever it was supposed to be gating.

**SLSA, at claim level.** SLSA v1.2 was approved in November 2025 and is the
current specification; its Build track runs L0 to L3 and defines no L4. L0
offers no guarantee. L1 is provenance that exists and identifies the output
package by cryptographic digest — it may be unsigned and is trivial to
forge, so it establishes a record rather than a guarantee. L2 adds a hosted
build platform that signs the provenance and a consumer who validates that
signature, and is aimed at tampering after the build. L3 adds a hardened
platform: builds isolated from one another, and signing material
unreachable from user-defined build steps, aimed at tampering during the
build. What a team on GitHub-hosted runners may honestly claim is fixed by
GitHub's own documentation, which states that artifact attestations by
themselves provide SLSA v1.0 Build Level 2, and that reaching Build Level 3
requires provenance generated by a reusable workflow isolated from the
calling workflow. So L2 is the default claim, L3 is a workflow structure a
reviewer has to actually see, and a report asserting L3 because attestations
exist is inflating the level rather than reporting it.

### The artifact boundary

This line is the section's spine. A review that tells its reader to "check"
something the repository cannot show them is worse than one that stays
silent, because it turns an open question into an apparent pass.

| Artifact | Where it lives | Review position |
|---|---|---|
| Hashed lockfile and the install step that reads it | Files in the repository | Read both. The finding is a lockfile beside an install that never passes `--require-hashes` |
| SBOM | A repository file only if committed; otherwise a build artifact of one CI run | Read the generating step. An uncommitted SBOM is a claim about a workflow, not a file you can audit |
| Scanner step and its gate | The workflow file | Read the failure behavior, not the step's presence |
| Attestation-generating step, its permissions, and the actions it pins | The workflow file | Read it. The attestation it produces is not in the repository |
| Verification step and its identity constraints | The deploy workflow, where it is in the repository at all | Read it where present; confirm with the operator where verification happens off-repository |
| Signature or attestation stored in the registry | The container registry, beside the image | Confirm with the platform |
| Deploy-time enforcement that can actually block a rollout | The cluster or deployment platform | Confirm with the platform |
| Runner isolation underpinning any Build L3 claim | The CI platform | Confirm with the platform |

Two platform facts belong in the same conversation, because both decide
whether the repository-side work produces anything at all: artifact
attestations are unavailable on GitHub Enterprise Server, and on Free, Pro,
and Team plans they cover public repositories only — a private repository
needs GitHub Enterprise Cloud. A workflow that requests an attestation on a
plan that cannot issue one is a build failure rather than a silent downgrade,
but it is worth confirming before recommending the step.

Where a row says confirm with the platform, the review output is a question
addressed to whoever operates it, written with the answer that would satisfy
it — not a finding, and not a checkbox left for the reader to interpret.
`a08-integrity-and-deserialization.md`, "Pipeline and artifact integrity",
owns the same boundary from the integrity side.

### Django & DRF implementation layer

A Django project's pipeline is reviewable in one file. The wrong version is
not a project with no controls; it is a project with all four controls and no
gate on any of them.

```yaml
# Wrong: every control is present and none of them can fail the build. The
# actions float on mutable tags, the install ignores the hashes already
# sitting in the lockfile, the audit's exit code is thrown away by `|| true`,
# and the SBOM is built by scanning the finished image -- so it records what
# a scanner could identify in it rather than what the project pinned.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: pip install -r requirements.txt
      - run: pip-audit -r requirements.txt || true
      - run: syft app:latest -o cyclonedx-json > sbom.json
        continue-on-error: true
```

```yaml
# Correct: each step either passes or fails the job. Actions are pinned to
# commit SHAs with the tag in a trailing comment, the install verifies the
# lockfile's hashes, the audit's exit code is the gate, the SBOM is built
# from the same file the install read, and provenance and SBOM attestations
# are requested separately because one step produces one predicate.
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
    steps:
      - uses: actions/checkout@<commit-sha>  # v7.0.1
      - uses: actions/setup-python@<commit-sha>  # v7.0.0
        with:
          python-version: "3.13"
      - run: pip install --require-hashes -r requirements.txt
      - run: pip-audit --strict -r requirements.txt
      - run: >-
          cyclonedx-py requirements requirements.txt
          --sv 1.6 --of JSON -o sbom.json
      - run: python -m build --wheel
      - uses: actions/attest@<commit-sha>  # v4.2.2
        with:
          subject-path: dist/*.whl
      - uses: actions/attest@<commit-sha>  # v4.2.2
        with:
          subject-path: dist/*.whl
          sbom-path: sbom.json
```

Three details in that file decide whether it is a control or a decoration.
`actions/attest` is the current action and `actions/attest-build-provenance`
is a wrapper over it as of v4, kept for existing workflows; new work should
name `actions/attest` directly. It selects its mode from its inputs, so a
step given `sbom-path` produces an SBOM attestation and *not* build
provenance — the two steps above are two attestations, and collapsing them
into one silently drops the provenance. And the permission block is three
entries rather than one: `id-token: write` to mint the OIDC token the
Sigstore certificate is issued against, `attestations: write` to persist the
attestation, and `artifact-metadata: write` to create the artifact storage
record. A workflow declaring only `id-token: write` fails at the attestation
step rather than producing an unsigned one, which is the right failure but an
easy one to misread as the action being broken.

`pip-audit` has one behavior worth knowing before writing the gate: passing
it a requirements file in which any package carries a `--hash` option implies
`--require-hashes`, so auditing the hashed lockfile enforces the hash
discipline in the audit step as well as in the install. `--strict` is
separate and does something the exit code alone does not — it fails the run
when a dependency cannot be resolved or audited, rather than passing quietly
over the package nobody could look up.

Verification belongs in whatever job consumes the artifact, and it is the
step most often missing entirely:

```bash
gh attestation verify ./dist/app-1.4.2-py3-none-any.whl \
  --repo my-org/my-service \
  --signer-workflow my-org/my-service/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

**Write-time.** When generating a build or release workflow, write the SHA
pin, the `--require-hashes` install, the scanner step with no
`continue-on-error` and no `|| true`, and the SBOM generated from the
lockfile in the first version of the file rather than as a later hardening
pass, because each of these is the kind of line that gets added once and
never revisited — and a scan step that was added with `|| true` to get a red
build green reads, a year later, exactly like a scan step that works. Put
the attestation's three permissions on the job rather than the workflow, so
the write scopes do not extend to jobs that have no reason to hold them, and
write the verification step in the same change as the attestation step,
complete with `--signer-workflow`, because an attestation that is generated
and never verified is a build artifact rather than a control.

### Pipeline review checklist

#### Stack-neutral

- [ ] The install step enforces the lockfile beside it — `--require-hashes` or
      the equivalent — and the SBOM is not read as evidence that it does.
- [ ] The scanner's result changes the outcome of the build: no
      `continue-on-error`, no `|| true`, no severity floor set above the
      project's actual findings, and no report written to an artifact that
      nothing reads.
- [ ] Every action and build image is pinned by commit SHA or digest rather
      than by a mutable tag, on the basis that a tag can be repointed by
      anyone holding the publisher's credentials.
- [ ] Provenance is verified somewhere by a step that pins the expected
      signer identity and issuer, rather than merely asserting that a
      signature or attestation exists.
- [ ] Any SLSA level claimed in a report is the level the platform's own
      documentation supports — Build L2 for attestations alone — with L3
      claimed only where the isolating reusable workflow is visible.
- [ ] Registry-side signatures, deploy-time admission enforcement, and runner
      isolation are recorded as questions for whoever operates them, with the
      answer that would satisfy each stated, rather than as repository
      findings.

#### Django & DRF

- [ ] The requirements file the production image installs is the file the
      SBOM and the audit step are both generated from, so the inventory,
      the advisory scan, and the install describe one dependency set.
- [ ] `pip-audit` runs against the hashed requirements file with `--strict`,
      so an unresolvable dependency fails the run instead of passing as
      unexamined.
- [ ] `cyclonedx-py` is invoked with an explicit `--spec-version`, so a tool
      upgrade cannot change the format a downstream consumer parses.
- [ ] The attestation job declares `id-token`, `attestations`, and
      `artifact-metadata` write scopes on the job rather than the workflow,
      and provenance and SBOM attestations are requested as separate steps.

## Third-party dependency vetting

### Principle layer

Every dependency adds code, maintainers, release infrastructure, transitive
dependencies, licenses, and defaults to the trust boundary. Do not choose a
security package from popularity, a stale tutorial, or a scanner suggestion
alone. First ask whether the framework, standard library, platform, or a small
reviewable local implementation already provides the control.

Before newly recommending or adding a package, record all of the following:

1. the exact security job it performs and why built-in facilities are
   insufficient;
2. maintenance health, including the latest release and recent project activity;
3. known advisories and the minimum safe version;
4. supported Python, framework, and runtime versions;
5. license and operational/transitive-dependency cost;
6. security-sensitive defaults that must be changed; and
7. the exit plan if the package becomes incompatible or abandoned.

A missing field is a finding, not permission to assume safety. Classify the
result as **recommend**, **conditional**, **existing-install audit only**, or
**reject for new use**. Pin a compatible version or bounded range, preserve hash
verification where the project uses it, and document why an exception is safe.
Advisory scanners find known records; they do not prove maintenance, correct
configuration, provenance, compatibility, or absence of design flaws.

### Django & DRF implementation layer

- Prefer current Django/DRF features before adding middleware or auth packages.
- Compare every candidate's declared Django/Python classifiers with the actual
  project baseline; do not infer Django 6 support from Django 5.2 support.
- Read release notes and security advisories across the installed version range,
  including transitive protocol libraries such as `oauthlib`.
- Verify secure defaults in code or official settings documentation. Pay special
  attention to automatic account linking, redirect matching, PKCE/nonce checks,
  token persistence, proxy-derived client IPs, and fail-open behavior.
- Use `python -m pip_audit` (currently vetted at `2.10.1`) as one CI/review input.
  Correlate results with reachability and vendor fixes; never silently ignore a
  vulnerability because a scanner lacks a fix.
- Keep `references/security-hardening-libraries.md` as the dated decision index.
  Re-vet a package when upgrading Django/Python, after a relevant advisory, or
  when its maintenance/compatibility signals change.

**Review evidence:** name the package and installed version, disposition, minimum
safe version, compatibility result, advisory result, defaults reviewed, and the
file/setting that proves the project's actual configuration.

## A development dependency in the production requirements file

A package tiered development-only is a finding when it appears in a production
requirements file, and it is two findings at once. It is unreviewed
supply-chain surface, because a dependency that was accepted on the basis of
"it only runs on a laptop" was never held to the gate above. And it is
exposure, because development tooling exists to make internals reachable, and
shipping it makes them reachable in production. Neither depends on the
package being vulnerable; the finding is that it is installed where nobody
decided it should be.

The disposition belongs in `security-hardening-libraries.md`, which is the
dated record of what each package was tiered as and why. Do not re-tier a
package here — read the tier there, then check the requirements file that
actually builds the production image against it.

`django-extensions` is the case that recurs. Its tier is development-only in
the index, for `show_urls` on an existing install, and the index also names
the reason it must not ship: it carries `runserver_plus`, and therefore the
Werkzeug interactive debugger, which is arbitrary code execution by design,
along with `shell_plus` and other commands whose whole purpose is direct
access to the model layer. Finding it under `install_requires` or in the
production layer of a requirements split is a finding at that severity, not a
tidiness note. The runtime side of the same exposure — what happens when such
a route or console is actually reachable — is in `deployment-and-runtime.md`,
"Operational and development endpoints".

Read the file the production image installs, not the one at the repository
root: a `requirements.txt` that ends with `-r requirements-dev.txt`, an
unsplit extras group installed with `pip install .[dev]`, and a Dockerfile
that copies every requirements file and installs all of them are the three
ways a development pin arrives in production without anyone adding it there.

**Write-time.** When adding a package whose purpose is development or
debugging, put it in the development requirements file or extras group in the
same edit that adds it, and confirm the production install path does not
include that file, because the default outcome of a single undifferentiated
requirements list is that every development convenience ships. Where the
package is only wanted on an existing install for one command, add nothing:
the equivalent recursion over `get_resolver().url_patterns` is a few lines
with no dependency, and from Django 6.2 the built-in `listurls` supersedes
both.

CWE-1104 (Use of Unmaintained Third Party Components) where the tier reflects
maintenance, and CWE-489 (Active Debug Code) where the shipped tooling exposes
a console or debugger. Severity: high where the package carries an interactive
debugger or shell, medium otherwise.

## Migration and data-integrity safety

Maps to the consequence created by a bad migration, commonly CWE-20 (Improper
Input Validation), CWE-284 (Improper Access Control), or CWE-798 (Use of
Hard-coded Credentials), with OWASP A01:2025, A02:2025, or A04:2025 applying as
appropriate.

### Principle layer

A migration is privileged, versioned deployment code. It can transform every
row, temporarily change the meaning of missing data, or preserve a secret in
history forever. The invariant is: **the old application, migration phase, and
new application must all preserve the intended access and data constraints, and
every transformed row must be accounted for before enforcement changes.**

- Use an expand/backfill/enforce/contract sequence for changes that span
  releases. During mixed-version deployment, both old and new code must interpret
  data safely; unknown, null, or unmapped security state must deny by default.
- Define preconditions, deterministic mappings, expected row counts, invalid-row
  handling, verification queries, rollback/forward-repair strategy, and backup
  or restore points before production execution.
- Make large backfills bounded, resumable, observable, and safe under retry.
  Avoid one unbounded transaction that locks a hot table or exhausts logs.
- Do not call external services or depend on mutable network state from an
  immutable migration. Persist local state and perform external coordination in
  a separately operated, idempotent job (idempotency design:
  `a10-exceptional-conditions.md`).
- Never commit credentials, private keys, production tokens, or real customer
  data in migration source, defaults, fixtures, examples, or reverse functions.
  Deleting a later line does not remove it from repository history.
- Treat rollback as a designed operation. When a change cannot be reversed
  without data loss, say so explicitly and prepare a tested forward repair
  rather than a misleading reverse step.

### Django & DRF implementation layer

Use historical models from the migration's `apps` registry. Importing the live
model can run today's code against yesterday's schema. Historical models do not
have custom model methods, overridden `save()`, or current managers unless they
were made available for migrations. Neither normal `save()` nor migration
updates automatically call `full_clean()`.

Use the database selected by the schema editor and validate source values
explicitly:

```python
from django.db import migrations
from django.db.models import Q

ROLE_MAP = {
    "owner": "admin",
    "writer": "editor",
    "reader": "viewer",
}


def forwards(apps, schema_editor):
    Membership = apps.get_model("accounts", "Membership")
    alias = schema_editor.connection.alias
    memberships = Membership.objects.using(alias).all()

    invalid = list(
        memberships.filter(
            Q(legacy_role__isnull=True)
            | ~Q(legacy_role__in=tuple(ROLE_MAP))
        )
        .values_list("pk", "legacy_role")[:20]
    )
    if invalid:
        raise RuntimeError(f"Unmapped legacy roles; sample: {invalid!r}")

    for old_role, new_role in ROLE_MAP.items():
        memberships.filter(legacy_role=old_role).update(role=new_role)

    remaining = memberships.filter(role__isnull=True).count()
    if remaining:
        raise RuntimeError(f"{remaining} memberships were not backfilled")


def backwards(apps, schema_editor):
    Membership = apps.get_model("accounts", "Membership")
    alias = schema_editor.connection.alias
    memberships = Membership.objects.using(alias).all()

    valid_roles = tuple(ROLE_MAP.values())
    invalid = list(
        memberships.filter(Q(role__isnull=True) | ~Q(role__in=valid_roles))
        .values_list("pk", "role")[:20]
    )
    if invalid:
        raise RuntimeError(f"Unmapped current roles; sample: {invalid!r}")

    for old_role, new_role in ROLE_MAP.items():
        memberships.filter(role=new_role).update(legacy_role=old_role)


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0041_membership_role"),
    ]
    operations = [
        migrations.RunPython(forwards, backwards),
    ]
```

This example intentionally does not depend on model methods or signals.
`QuerySet.update()` bypasses both, so the migration owns validation, audit
requirements, and verification. Adapt the fictional app, migration, and field
names to the real project; do not copy them literally into this skill repo as an
executable migration.

For a security-sensitive role or visibility change:

1. add the new nullable field or table without a permissive default;
2. deploy code that writes both representations and treats null/unknown as
   denied;
3. backfill deterministic mappings in bounded batches and verify counts;
4. add database constraints/non-null enforcement only after verification; and
5. deploy reads from the new representation, then remove the old one in a later
   release.

Never use a temporary "allow everyone", `is_public=True`, superuser role, or
wildcard tenant default to get through the transition. A migration that widens
access for one deployment window is still an access-control vulnerability.

Migration transaction behavior varies by database backend and by the
migration's `atomic` setting. Separate schema operations from `RunPython` data
work, especially on PostgreSQL, where mixing them can produce pending-trigger
errors. For a large backfill, consider an `atomic = False` migration or a
separate operated backfill with small explicit atomic batches, a stable ordering
key, progress metrics, and restart-safe predicates. Do not sacrifice the
invariant merely to make the operation resumable.

Use `schema_editor.connection.alias` with `.using(alias)` for every query so
database routers and multi-database deployments are respected. Omit
`reverse_code` when an operation is genuinely irreversible so Django refuses
reversal. Use `migrations.RunPython.noop` only when intentionally doing nothing
in one direction is safe and truthful; otherwise provide and test a real reverse
or a forward repair.

Test:

- migration from the last released schema with representative valid, invalid,
  null, duplicate, and cross-tenant rows;
- a fresh database applying the complete migration history;
- mixed old/new application behavior across each rollout phase;
- forward, retry/resume, and reverse or forward-repair behavior;
- row counts, constraints, indexes, permissions, and query plans; and
- backups and restore/rehearsal for destructive or high-volume changes.

**Write-time.** When generating a data migration, take the model from
`apps.get_model()` and route every query through `.using(alias)` with the
alias read from `schema_editor.connection`, because the imported model is
today's code running against yesterday's schema and the default alias ignores
the router a multi-database deployment relies on. Verify before transforming
and stop on an unmapped or null row rather than defaulting it, since a
migration is the one place where a permissive fallback silently becomes the
access decision for every row it touched. Write the reverse function in the
same change, or omit `reverse_code` so Django refuses the reversal, and keep
credentials and real customer data out of the file entirely — deleting the
line later does not remove it from the repository's history.

### Migration review checklist

#### Stack-neutral

- [ ] The rollout preserves deny-by-default access under old, mixed, and new
      application versions; no temporary permissive default exists.
- [ ] Every source value has a deterministic mapping or explicit failure path,
      and pre/post row counts plus invalid records are verified.
- [ ] Backfills are bounded, resumable, observable, retry-safe, and accompanied
      by a tested rollback, forward repair, and restore plan.
- [ ] Versioned migration code contains no secret, production token, private
      key, customer data, or mutable external-service dependency.

#### Django & DRF

- [ ] `RunPython` uses `apps.get_model()` and
      `schema_editor.connection.alias`; it does not import live models or assume
      model methods, signals, or `full_clean()` will run.
- [ ] Schema and data phases are separated appropriately for the database;
      transaction size, locks, routers, and multi-database behavior are tested.
- [ ] Security-sensitive null/unknown values fail closed, constraints are added
      only after verified backfill, and destructive cleanup is deferred to a
      later compatible release.
- [ ] Fresh-install, released-version upgrade, retry/resume, and reverse or
      forward-repair paths are covered by migration tests.

## Review checklist

- [ ] Django/DRF/runtime on supported, patched versions (no EOL 4.2/5.1, no
      unmaintained deps).
- [ ] Dependencies pinned; a lockfile exists; hashes verified on install.
- [ ] `pip-audit` runs in CI as an advisory input; automated update PRs enabled.
- [ ] Each pipeline control gates rather than merely runs — hashes enforced on
      install, the scanner's exit code failing the build, the SBOM generated
      from the lockfile, and provenance verified against a pinned signer
      identity; platform-side artifacts are recorded as operator questions.
- [ ] Dependencies come from trusted indexes; no stray VCS/wheel installs.
- [ ] Components discovered and loaded at runtime are pinned or provenance-
      checked at call time; tool descriptions are treated as untrusted input.
- [ ] every security dependency has a recorded need, maintenance/advisory check,
      minimum safe version, compatibility, license, secure-default review, and
      disposition; scanners are not treated as proof of safety;
- [ ] the requirements file the production image actually installs carries no
      package the library index tiers development-only — `django-extensions`
      in particular, which ships `runserver_plus` and `shell_plus`.
- [ ] Migrations use historical models, explicit validation and DB aliases,
      preserve fail-closed mixed-version access, and contain no secrets.
