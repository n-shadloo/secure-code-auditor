# A03:2025 — Software Supply Chain Failures

This is a new and expanded category in 2025, and it absorbs "Vulnerable and
Outdated Components". It covers dependencies, pinning and integrity,
vulnerability scanning, EOL frameworks, and the integrity of versioned schema
and data migrations.

This file owns **the dependency as a decision**. It owns the gate a
third-party package has to pass before you add it, pinning and hash integrity,
and advisory scanning. It also owns the end-of-life framework, the SBOM, and
the versioned migration as a change to data nobody can simply re-run.
`security-hardening-libraries.md` records the output of that gate for the
current baseline. That file holds the tier and the minimum-safe floor for each
named package, and it is dated rather than permanent.

`a08-integrity-and-deserialization.md` owns the integrity of what the project
itself produces and consumes. `a04-cryptographic-failures.md` owns the signing
primitive underneath both. Each topic file owns the control the dependency was
chosen to implement.

## Contents
- [Principle](#principle)
- [Run a supported Django](#run-a-supported-django)
- [Pin and verify](#pin-and-verify)
- [Index resolution and dependency confusion](#index-resolution-and-dependency-confusion)
- [Scan continuously](#scan-continuously)
- [Trust and provenance](#trust-and-provenance)
- [SBOM, scan gate, and provenance](#sbom-scan-gate-and-provenance)
- [Third-party dependency vetting](#third-party-dependency-vetting)
- [A development dependency in the production requirements file](#a-development-dependency-in-the-production-requirements-file)
- [Migration and data-integrity safety](#migration-and-data-integrity-safety)
- [Review checklist](#review-checklist)

## Principle

Your weakest dependency bounds your security. The integrity of the path that
dependency takes to production bounds it as well. The principle is **know
exactly what you run, keep it patched, and make substitution hard**. Pin the
versions. Verify the integrity with hashes and lockfiles. Scan for known
vulnerabilities on every build.

Install only from trusted sources. Transitive dependencies count, because most
of the tree is code you never chose directly.

## Run a supported Django

As of 9 Aug 2026 the supported lines are **Django 6.1**, **6.0.8**, and
**5.2.17 LTS**. Django released 6.1 on 5 Aug 2026, which moved 6.0 onto
security and data-loss fixes only, through April 2027. 5.2 LTS runs to April
2028. The current patch level matters as much as the line. 6.0.8 and 5.2.17
were security releases on 4 Aug 2026, and they fixed four issues. The most
serious is CVE-2026-15307, a file-write and request-forgery flaw reachable
through spatial lookups.

**Django 4.2 is end-of-life**, with the final release 4.2.30 on 7 Apr 2026.
5.1 is EOL too. An unsupported release means that security fixes stop reaching
you. Flag an unsupported line, and flag a supported line below the current
security patch, where the severity scales with the exposure. The same applies
to the language runtime, and to the DRF, SimpleJWT, Channels, and allauth
versions. See the libraries file for current pins.

## Pin and verify

- Pin exact versions (`==`) for applications. A lockfile from `pip-tools`,
  `uv`, Poetry, or PDM captures the full resolved tree.
- Use hash-checking, so that a swapped artifact fails the install:

```
pip install --require-hashes -r requirements.txt
```

- Keep the development and test tooling out of the production dependency set.

**The hash binds the artifact to the pin. Nothing binds the pin to a
decision.** The install proves that the bytes match the lockfile line, and
never that a person chose that line. So the trust decision happens when the pin
moves, and that moment carries the least review. An update bot regenerates the
hash from the artifact the index serves that day. A release from a compromised
maintainer account then passes the install, the audit, the SBOM, and the
attestation.

Auto-merge on a dependency pull request removes the only person on that path.
Refuse it. Require a person to read each lockfile diff. Treat a version bump as
a re-vet trigger. Treat a change of maintainer or owner as one too.

**`--require-hashes` bounds the requirements in the file it reads, and nothing
more.** Two other install inputs stay outside it. The first is `[build-system]
requires` in `pyproject.toml`. `pip` resolves those packages from the index
inside the build isolation environment, with no pin and no hash. The audit of
the requirements file never sees them, and an SBOM built from the lock omits
them. The second is `pip install .`, which resolves `[project] dependencies` at
image build time.

Pin and hash the build requirements in their own file. Pass
`--no-build-isolation` where the job already holds a vetted toolchain. Compile
`[project] dependencies` into the hashed lockfile the production image reads.

**A verified artifact still runs code at install time.** The hash proves the
bytes, and it proves nothing about what the bytes do. A source distribution
runs its own build backend during the install. A wheel can install a `.pth`
file, which Python then runs at the start of every later interpreter. That
includes the interpreter that runs the scanner.

Install from wheels with `--only-binary :all:`. Keep source distributions out
of the lockfile.

## Index resolution and dependency confusion

`pip` treats every configured index as one pool. With `--extra-index-url`, the
resolver may take the highest version from any index. An attacker who registers
your internal package name on PyPI with a higher version then supplies the
install. Apply these rules:

- Use one `--index-url` and no `--extra-index-url` in any project with private
  packages. Point it at a proxy index that hosts the internal packages and
  mirrors PyPI. Let the proxy decide precedence by name.
- Read the environment as part of the resolution. `pip` accepts
  `PIP_INDEX_URL` and `PIP_EXTRA_INDEX_URL` from the environment. It also reads
  `PIP_CONFIG_FILE`, and a `pip.conf` at the global, site, or user level. An
  extra index set that way survives an explicit `--index-url` on the command
  line, and `pip` searches both. Look for an `ENV` line in a Dockerfile, a job
  `env:` block, and a `pip.conf` in an image. Look also for a step that writes
  to `$GITHUB_ENV`.
- Set `PIP_EXTRA_INDEX_URL` to empty in the job that installs. A rule that only
  removes the flag leaves the environment in control.
- Reserve the exact internal package names on PyPI. A prefix is a convention
  and not a reservation, because anyone can register a name that carries it.
- Hash-pin the lockfile (`--require-hashes`). A squatted substitute fails the
  hash even when the resolution goes wrong.
- Alert where the resolution is observable. With one proxy index the client
  never contacts the public index, so the record lives at the proxy. Ask the
  proxy operator which upstream served each internal name.

## Scan continuously

- `pip-audit` (PyPA) checks installed and declared packages against advisory
  databases. `pip-audit==2.10.1` passes the current package gate. Treat the
  results as known-advisory input, not as proof that a dependency is
  maintained or safe. Do not add a second scanner before you separately vet
  its license, data flow, advisory source, maintenance, and operating model.
- Enable automated update PRs (Dependabot / Renovate) and treat security updates
  as expedited.
- An advisory recorded as accepted is an exception, and `pip-audit
  --ignore-vuln ID` is the mechanism here. It carries the same three fields as
  any other exception: an owner, a reason, and an expiry that executable code
  enforces. `a02-security-misconfiguration.md`, "Configuration drift and the
  expiring exception" owns that discipline across all four kinds of
  suppression a Python project accumulates.
- Generate an SBOM (CycloneDX or SPDX) if you need to answer "are we
  affected?" quickly when a new CVE is published. "SBOM, scan gate, and
  provenance" below gives the file to generate it from, the format, and what
  it does not prove.

```
pip-audit -r requirements.txt
```

## Trust and provenance

- Install from PyPI (or a controlled internal index), not arbitrary VCS URLs or
  copy-pasted wheels.
- Examine typosquats and newly published look-alike names carefully. Check
  that the project is real and maintained before you add it.
- CI is a credential store, and usually the least-guarded one. Prefer
  short-lived OIDC federation from the CI provider to the cloud account. Do
  not use a long-lived deployment key held as a repository secret. See
  `service-identity-and-secrets.md`, "Choosing a machine-authentication
  mechanism".
- This applies to **Claude Skills too**: a skill can direct an agent to run code
  or move data. Only install skills from sources you trust, and read the bundled
  files.
- The same reasoning extends to components an agent discovers and loads at
  **runtime**. The trust decision happens at call time, and no build-time
  pinning, lockfile, or scanner reaches it. Pin the tools and servers a
  backend will connect to. Require signed provenance or an allowlist entry
  before use. Treat a tool's own description as untrusted content rather than
  as configuration. See `agent-and-llm-interfaces.md`, "Runtime-discovered
  tools and servers".

## SBOM, scan gate, and provenance

Maps to CWE-1395 (Dependency on Vulnerable Third-Party Component) where the
scan gate is absent or disabled. Maps to CWE-494 (Download of Code Without
Integrity Check) where a project consumes an artifact without verified
provenance. Severity: medium for an inventory or scan that gates nothing.
Severity: high where the missing check is the only barrier between a
substituted artifact and production.

### Principle layer

A hashed lockfile is the strongest claim this file can make from the
repository alone. `--require-hashes` turns the install into a verification
step, so a substituted artifact fails instead of runs. It stops at three
questions it was never able to answer. Those questions are whether the pinned
versions carry known advisories *today*, what is inside the artifact that
shipped, and who built that artifact. An SBOM, a scan gate, and build
provenance answer those three in order. Each one is worth exactly as much as
the enforcement attached to it.

Therefore the useful review question is never "is there one". The useful
question is "what happens when it says no".

**The SBOM is generated from the lock, not from the finished image alone.** An
SBOM produced from a scan of a built image records what a scanner could
identify inside it. An SBOM produced from the lockfile records what the project
resolved and pinned. The two disagree exactly where it matters. That is a wheel
installed by a build step, a vendored dependency, or anything the scanner's
Python detector did not recognize. Only the second is traceable to a file a
reviewer can open. Generate it in the same job that performs the install, and
from the same file the install reads. The two then cannot diverge unless
somebody edits both.

CycloneDX is the Python ecosystem's working default. The 1.7 specification
appeared in October 2025, and `cyclonedx-py` 7.3.1 still emits 1.6 unless you
tell it otherwise. Set `--spec-version` explicitly, so that a tool upgrade
cannot silently change the format a consumer parses. SPDX is the alternative,
at 3.0.1 on the 3.0 line from April 2024, with 2.2.1 the version standardized
as ISO/IEC 5962:2021. No maintained Python-native SPDX generator of comparable
standing exists, so SPDX output comes from a general-purpose tool such as Syft
rather than from anything pip-installable. Pick on what the consumer requires,
and record which one you picked.

**An SBOM is not a hash-pinning control**, and the failure is quiet enough to
state on its own. `cyclonedx-py` 7.3.1 parses a `pip-compile
--generate-hashes` requirements file without complaint, and it emits
components that carry no `hashes` member at all. Verified against 7.3.1 on 9
Aug 2026, in both `requirements` and `environment` modes. The `--hash=` values
survive only inside the component's free-text description, where nothing can
verify against them. Integrity evidence is `--require-hashes` on the install
step, and nothing else.

An SBOM beside an install that does not pass `--require-hashes` is an
inventory, not a control. A reader who takes it for a control makes the
project believe it verifies artifacts it never verified.

**A scan gate is configuration, so review it as configuration.** Read what the
workflow does with the result, rather than whether the step is present. Four
conditions are the same finding written four ways. They are
`continue-on-error: true`, a trailing `|| true`, and a severity threshold set
above the findings the project actually has. The fourth is a report uploaded to
an artifact nobody opens. In each one the scanner runs and gates nothing. The
exit code is the control.

For Python dependencies the primary scanner stays `pip-audit`. The PyPA
maintains it under Apache-2.0, at 2.10.1 as of 10 June 2026. Its advisory
sources are the reason for that choice, rather than an incidental detail. It
draws on the PyPI advisory service and OSV rather than on NVD's CPE matching.
That distinction now carries weight it did not carry a year ago.

On 15 April 2026 NIST moved the National Vulnerability Database to risk-based
triage. NVD now enriches CVEs in CISA's Known Exploited Vulnerabilities
catalog, CVEs in software used by the federal government, and software
critical under Executive Order 14028. It marks everything else lowest priority
and not scheduled, including every backlogged CVE with an NVD publish date
earlier than 1 March 2026. NVD-derived CPE and CVSS data is systematically
incomplete from that date forward. Therefore weight an ecosystem-native
finding above an NVD-derived one. Treat a quiet NVD-backed scanner as less
reassuring than before.

Name the image scanners for what they are not. Trivy (v0.73.0, 3 Aug 2026),
Grype (v0.116.1, 28 July 2026), Syft (v1.50.0, 28 July 2026) and cosign
(v3.1.3, 6 Aug 2026) are all Apache-2.0. Anchore's stewardship of Grype and
Syft carries no relicensing, no source-available move, and no CLA-driven
ownership change as of 9 Aug 2026. All four are distributed as Go binaries,
which puts them outside the maintained-package gate entirely. They are CI
patterns, and they take no row in `security-hardening-libraries.md`. The gate
applies here to the two pip-installable tools, `pip-audit` and `cyclonedx-py`.

`deployment-and-runtime.md`, "Scanning the built image", owns what the image
scanner is pointed at. This section owns the pipeline around it.

Pin every action to a commit SHA rather than to a tag, and treat that as a
supply-chain control rather than as hygiene. On 19 March 2026 an attacker
holding compromised credentials published a malicious Trivy v0.69.4. The
attacker force-pushed 76 of 77 version tags in `aquasecurity/trivy-action` to
an infostealer. That infostealer dumped the runner process's memory and
searched the filesystem for cloud credentials. The attacker also replaced all
seven tags in `aquasecurity/setup-trivy`. A second wave put malicious v0.69.5
and v0.69.6 images on Docker Hub on 22 March.

Trivy's advisory GHSA-69fq-xp46-6x23, which carries CVE-2026-33634, is precise
about what survived. That is releases at v0.69.3 or earlier, images referenced
by digest, builds from source, and action references pinned to a safe commit.
No `setup-trivy` tag was safe, because the attacker force-pushed every one of
them. That is the reason to record the rule as "pin the SHA", and never as "pin
the last known-good tag". A tag is a name the publisher can repoint, and so can
anyone holding the publisher's credentials.

**Provenance is produced inside the repository and verified outside it, and
only the second half is a control.** A GitHub artifact attestation binds a
subject to a SLSA build-provenance predicate in in-toto format. The subject is
a named artifact and its digest. A short-lived Sigstore certificate, minted
from the workflow's OIDC identity, signs the attestation. Public repositories
use the Sigstore public-good instance, and the bundle is copied to a
transparency log that is publicly readable. Private and internal repositories
use GitHub's own Sigstore instance, which has no transparency log.

Either way the bundle is uploaded to GitHub's attestations API rather than
committed. Therefore a repository review can actually read only the workflow
that asked for it.

Verification without an identity constraint proves nothing. `gh attestation
verify` scoped only by `--repo` establishes that the artifact carries some
attestation from that repository. `--signer-workflow` pins which workflow
signed it. `--deny-self-hosted-runners` refuses one built where the platform's
isolation properties do not apply. `cosign verify` has the same shape: without
`--certificate-identity` or `--certificate-identity-regexp`, plus
`--certificate-oidc-issuer`, it confirms that a signature exists rather than
who produced it.

A verify step that omits those arguments is a decorative gate. It is a finding
at the severity of whatever it was supposed to be gating.

**SLSA, at claim level.** SLSA v1.2 was approved in November 2025, and it is
the current specification. Its Build track runs L0 to L3, and it defines no
L4. L0 offers no guarantee. L1 is provenance that exists and identifies the
output package by cryptographic digest. L1 may be unsigned and is trivial to
forge, so it establishes a record rather than a guarantee. L2 adds a hosted
build platform that signs the provenance, and a consumer who validates that
signature; it is aimed at tampering after the build.

L3 adds a hardened platform: builds isolated from one another, and signing
material unreachable from user-defined build steps. L3 is aimed at tampering
during the build. GitHub's own documentation fixes what a team on
GitHub-hosted runners may honestly claim. It states that artifact attestations
by themselves provide SLSA v1.0 Build Level 2. It also states that Build Level
3 requires provenance generated by a reusable workflow isolated from the
calling workflow. Thus L2 is the default claim, and L3 is a workflow structure
a reviewer has to actually see.

A report that asserts L3 because attestations exist inflates the level rather
than reports it.

### The artifact boundary

This line is central to the section. A review that tells its reader to "check"
something the repository cannot show them is worse than one that stays silent.
It turns an open question into an apparent pass.

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

Two platform facts belong in the same discussion, because both decide whether
the repository-side work produces anything at all. Artifact attestations are
unavailable on GitHub Enterprise Server. On the Free, Pro, and Team plans they
cover public repositories only, and a private repository needs GitHub
Enterprise Cloud. A workflow that requests an attestation on a plan that
cannot issue one is a build failure rather than a silent downgrade. Confirm
the plan before you recommend the step.

Where a row says confirm with the platform, the review output is a question
addressed to whoever operates it. That question states the answer that would
satisfy it. It is not a finding, and it is not a checkbox left for the reader
to interpret. `a08-integrity-and-deserialization.md`, "Pipeline and artifact
integrity", owns the same boundary from the integrity side.

### Django & DRF implementation layer

You can review a Django project's pipeline in one file. The wrong version is
not a project with no controls. It is a project with all four controls and no
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
# are requested separately because one step produces one predicate. The job
# that holds the signing permissions runs no third-party code.
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<commit-sha>  # v7.0.1
      - uses: actions/setup-python@<commit-sha>  # v7.0.0
        with:
          python-version: "3.13"
      - run: pip install --require-hashes -r requirements-ci.txt
      - run: pip install --require-hashes -r requirements.txt
      - run: pip-audit --strict -r requirements.txt
      - run: >-
          cyclonedx-py requirements requirements.txt
          --sv 1.6 --of JSON -o sbom.json
      - run: python -m build --wheel
      - uses: actions/upload-artifact@<commit-sha>  # v7.0.1
        with:
          name: release-files
          path: |
            dist/*.whl
            sbom.json

  attest:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
    steps:
      - uses: actions/download-artifact@<commit-sha>  # v8.0.1
        with:
          name: release-files
      - uses: actions/attest@<commit-sha>  # v4.2.2
        with:
          subject-path: dist/*.whl
      - uses: actions/attest@<commit-sha>  # v4.2.2
        with:
          subject-path: dist/*.whl
          sbom-path: sbom.json
```

Three details in that file decide whether it is a control or a decoration.
`actions/attest` is the current action, and `actions/attest-build-provenance`
is a wrapper over it as of v4, kept for existing workflows. New work should
name `actions/attest` directly. The action selects its mode from its inputs,
so a step given `sbom-path` produces an SBOM attestation and *not* build
provenance. The two steps above are two attestations, and one combined step
silently drops the provenance.

The permission block is three entries rather than one. `id-token: write` mints
the OIDC token the Sigstore certificate is issued against. `attestations:
write` persists the attestation. `artifact-metadata: write` creates the
artifact storage record. A workflow that declares only `id-token: write` fails
at the attestation step rather than produces an unsigned one. That is the
right failure, but a reader misreads it easily as a broken action.

`pip-audit` has one behavior to know before you write the gate. A requirements
file in which any package carries a `--hash` option implies
`--require-hashes`. Thus an audit of the hashed lockfile enforces the hash
discipline in the audit step as well as in the install. `--strict` is
separate, and it does something the exit code alone does not do. It fails the
run when a dependency cannot be resolved or audited, rather than passes
quietly over the package nobody could resolve.

**A job that can sign must not run third-party code.** `id-token: write` puts
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` into the
job environment, where every process in the job reads them. A build backend, a
`.pth` file from an installed package, or a substituted gate tool can therefore
mint the workflow's own OIDC token. The same code can rewrite `dist/` before
`actions/attest` reads it, and the action then signs the replaced artifact
correctly. SLSA Build L3 describes this boundary as signing material that
user-defined build steps cannot reach. The split above does not reach L3, and
it removes the reach that one job gave every dependency.

The gate tools install from their own hashed file, for the same reason.
Whoever controls the effective index controls the scanner's verdict.

Verification belongs in whatever job consumes the artifact, and it is the
step most often missing entirely:

```bash
gh attestation verify ./dist/app-1.4.2-py3-none-any.whl \
  --repo my-org/my-service \
  --signer-workflow my-org/my-service/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

**Write-time.** When you generate a build or release workflow, write four
things into the first version of the file. They are the SHA pin, the
`--require-hashes` install, and the scanner step with no `continue-on-error`
and no `|| true`. The fourth is the SBOM generated from the lockfile. Do not
leave them for a later hardening pass. Each of these is the kind of line a team
adds once and never examines again. A scan step that somebody added with
`|| true` to make a red build green reads, a year later, exactly like a scan
step that works.

Put the attestation's three permissions on the job rather than on the
workflow. The write scopes then do not extend to jobs that have no reason to
hold them. Write the verification step in the same change as the attestation
step, complete with `--signer-workflow`. An attestation that is generated and
never verified is a build artifact rather than a control.

### Pipeline review checklist

#### Stack-neutral

- [ ] The install step enforces the lockfile beside it, with
      `--require-hashes` or the equivalent. Nobody reads the SBOM as evidence
      that it does.
- [ ] The scanner's result changes the outcome of the build. There is no
      `continue-on-error`, no `|| true`, no severity floor set above the
      project's actual findings, and no report written to an artifact that
      nothing reads.
- [ ] Every action and build image is pinned by commit SHA or digest rather
      than by a mutable tag. The basis is that anyone holding the publisher's
      credentials can repoint a tag. A pinned action can still fetch its tool
      by a mutable version input, so pin that input as well.
- [ ] The job that holds `id-token: write` runs no third-party code. The build
      and the attestation are separate jobs, and the gate tools install from a
      hashed file.
- [ ] Provenance is verified somewhere by a step that pins the expected signer
      identity and issuer. That step does not merely assert that a signature
      or attestation exists.
- [ ] Any SLSA level claimed in a report is the level the platform's own
      documentation supports, which is Build L2 for attestations alone. L3 is
      claimed only where the isolating reusable workflow is visible.
- [ ] Registry-side signatures, deploy-time admission enforcement, and runner
      isolation are recorded as questions for whoever operates them. Each
      question states the answer that would satisfy it. They are not recorded
      as repository findings.

#### Django & DRF

- [ ] The SBOM and the audit step are both generated from the requirements
      file the production image installs. Thus the inventory, the advisory
      scan, and the install describe one dependency set.
- [ ] `pip-audit` runs against the hashed requirements file with `--strict`,
      so an unresolvable dependency fails the run instead of passes as
      unexamined.
- [ ] `cyclonedx-py` is invoked with an explicit `--spec-version`, so a tool
      upgrade cannot change the format a downstream consumer parses.
- [ ] The attestation job declares the `id-token`, `attestations`, and
      `artifact-metadata` write scopes on the job rather than on the workflow.
      Provenance and SBOM attestations are requested as separate steps.

## Third-party dependency vetting

### Principle layer

Every dependency adds code, maintainers, release infrastructure, transitive
dependencies, licenses, and defaults to the trust boundary. Do not choose a
security package from popularity, a stale tutorial, or a scanner suggestion
alone. First ask whether the framework, standard library, platform, or a small
reviewable local implementation already provides the control.

Before you newly recommend or add a package, record all of the following:

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
**reject for new use**. Pin a compatible version or a bounded range. Preserve
hash verification where the project uses it. Document why an exception is
safe. Advisory scanners find known records, and they do not prove maintenance,
correct configuration, provenance, compatibility, or the absence of design
flaws.

### Django & DRF implementation layer

- Prefer current Django and DRF features before you add a middleware or auth
  package.
- Compare every candidate's declared Django and Python classifiers with the
  actual project baseline. Do not infer Django 6 support from Django 5.2
  support.
- Read release notes and security advisories across the installed version range,
  including transitive protocol libraries such as `oauthlib`.
- Verify secure defaults in code or official settings documentation. Pay special
  attention to automatic account linking, redirect matching, PKCE/nonce checks,
  token persistence, proxy-derived client IPs, and fail-open behavior.
- Use `python -m pip_audit` (currently vetted at `2.10.1`) as one CI and
  review input. Correlate the results with reachability and vendor fixes.
  Never silently ignore a vulnerability because a scanner lacks a fix.
- Keep `references/security-hardening-libraries.md` as the dated decision
  index. Re-vet a package when you upgrade Django or Python, after a relevant
  advisory, or when its maintenance or compatibility signals change. Re-vet it
  on a version bump too, and on a change of maintainer or owner.

**Review evidence:** name the package and its installed version, the
disposition, the minimum safe version, the compatibility result, and the
advisory result. Also name the defaults you reviewed, and the file or setting
that proves the project's actual configuration.

## A development dependency in the production requirements file

A package tiered development-only is a finding when it appears in a production
requirements file, and it is two findings at once. It is unreviewed
supply-chain surface, because nobody held a dependency accepted on the basis
of "it only runs on a laptop" to the gate above. It is also exposure, because
development tooling exists to make internals reachable, and a shipped copy
makes them reachable in production. Neither finding depends on a vulnerability
in the package. The finding is that the package is installed where nobody
decided it should be.

The disposition belongs in `security-hardening-libraries.md`, which is the
dated record of what each package was tiered as, and why. Do not re-tier a
package here. Read the tier there. Then check the requirements file that
actually builds the production image against that tier.

`django-extensions` is the case that recurs. Its tier is development-only in
the index, for `show_urls` on an existing install. The index also names the
reason it must not ship. It carries `runserver_plus`, and therefore the
Werkzeug interactive debugger, which is arbitrary code execution by design. It
also carries `shell_plus` and other commands whose whole purpose is direct
access to the model layer. The package under `install_requires`, or in the
production layer of a requirements split, is a finding at that severity, not a
tidiness note.

`deployment-and-runtime.md`, "Operational and development endpoints", owns the
runtime side of the same exposure. That is what happens when such a route or
console is actually reachable.

Read the file the production image installs, not the one at the repository
root. Four ways bring a development pin into production without anyone adding
it there. The first is a `requirements.txt` that ends with `-r
requirements-dev.txt`. The second is an unsplit extras group installed with
`pip install .[dev]`. The third is a Dockerfile that copies every requirements
file and installs all of them. The fourth is a production dependency that
declares the package as its own requirement.

The fourth way defeats a check that reads declared lines. No line names the
package, so the tier check never runs against it. Check the tier of every
distribution in the resolved lockfile, and not only the ones a person wrote.

**Write-time.** When you add a package whose purpose is development or
debugging, put it in the development requirements file or extras group in the
same edit. Confirm that the production install path does not include that
file. The default outcome of a single undifferentiated requirements list is
that every development convenience ships. Where a project wants the package
only on an existing install, for one command, add nothing. The equivalent
recursion over `get_resolver().url_patterns` is a few lines with no
dependency, and from Django 6.2 the built-in `listurls` supersedes both.

CWE-1104 (Use of Unmaintained Third Party Components) where the tier reflects
maintenance. CWE-489 (Active Debug Code) where the shipped tooling exposes a
console or debugger. Severity: high where the package carries an interactive
debugger or shell. Severity: medium in every other case.

## Migration and data-integrity safety

Maps to the consequence created by a bad migration, commonly CWE-20 (Improper
Input Validation), CWE-284 (Improper Access Control), or CWE-798 (Use of
Hard-coded Credentials). OWASP A01:2025, A02:2025, or A04:2025 applies as
appropriate.

### Principle layer

A migration is privileged, versioned deployment code. It can transform every
row, temporarily change the meaning of missing data, or preserve a secret in
history forever. The invariant is: **the old application, migration phase, and
new application must all preserve the intended access and data constraints.
Every transformed row must be accounted for before enforcement changes.**

- Use an expand/backfill/enforce/contract sequence for changes that span
  releases. During a mixed-version deployment, both old and new code must
  interpret data safely. An unknown, null, or unmapped security state must
  deny by default.
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
  data in migration source, defaults, fixtures, examples, or reverse
  functions. A deletion of the line later does not remove it from repository
  history.
- Treat rollback as a designed operation. When a change cannot be reversed
  without data loss, say so explicitly and prepare a tested forward repair
  rather than a misleading reverse step.

### Django & DRF implementation layer

Use historical models from the migration's `apps` registry. An import of the
live model can run today's code against yesterday's schema. A historical model
has no custom model method, no overridden `save()`, and no current manager,
unless the project made them available for migrations. Neither a normal
`save()` nor a migration update calls `full_clean()` automatically.

**A manager that reaches a migration can hide the rows the migration must
transform.** `use_in_migrations = True` copies the manager into the historical
model, together with any filter in its `get_queryset()`. A soft-delete or
tenant-scoped manager then removes rows from the backfill, and from the count
that verifies the backfill. The migration reports success, and the hidden rows
keep their old security state. They return to view later, when somebody
restores the row or changes the tenant.

Read every migration queryset through the model's `_base_manager`. Confirm that
`Meta.base_manager_name` does not name the filtered manager.

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
    memberships = Membership._base_manager.using(alias).all()

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
    memberships = Membership._base_manager.using(alias).all()

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
names to the real project. Do not copy them literally into this skill repo as
an executable migration.

For a security-sensitive role or visibility change:

1. add the new nullable field or table without a permissive default;
2. deploy code that writes both representations and treats null/unknown as
   denied;
3. backfill deterministic mappings in bounded batches and verify counts;
4. add database constraints/non-null enforcement only after verification; and
5. deploy reads from the new representation, then remove the old one in a later
   release.

Never use a temporary "allow everyone", `is_public=True`, superuser role, or
wildcard tenant default to complete the transition. A migration that widens
access for one deployment window is still an access-control vulnerability.

A large backfill runs in batches. The batch boundary is where the invariant
breaks. Never sacrifice the invariant to make the operation resumable. A batch
that leaves rows at a permissive default widens access for that window. Batch
design, transaction behavior, and the `atomic` setting belong to migration
operations and lock behavior, which this file does not cover. This file owns
one thing only: the access rule holds at every batch boundary.

Use `schema_editor.connection.alias` with `.using(alias)` for every query. A
query that ignores the router writes to the wrong database, which defeats
tenant isolation. Omit `reverse_code` when an operation is genuinely
irreversible. A reversal that runs re-widens the access the forward migration
closed.

Test:

- migration from the last released schema with representative valid, invalid,
  null, duplicate, and cross-tenant rows;
- a fresh database applying the complete migration history;
- mixed old/new application behavior across each rollout phase;
- forward, retry/resume, and reverse or forward-repair behavior;
- row counts, constraints, indexes, permissions, and query plans; and
- backups and restore/rehearsal for destructive or high-volume changes.

**Write-time.** When you generate a data migration, take the model from
`apps.get_model()`, and route every query through `.using(alias)` with the
alias read from `schema_editor.connection`. The imported model is today's code
running against yesterday's schema, and the default alias ignores the router a
multi-database deployment relies on. Verify before you transform. Stop on an
unmapped or null row rather than default it. A migration is the one place
where a permissive fallback silently becomes the access decision for every row
it touched.

Write the reverse function in the same change, or omit `reverse_code` so that
Django refuses the reversal. Keep credentials and real customer data out of
the file entirely. A deletion of the line later does not remove it from the
repository's history.

### Migration review checklist

#### Stack-neutral

- [ ] The rollout preserves deny-by-default access under old, mixed, and new
      application versions. No temporary permissive default exists.
- [ ] Every source value has a deterministic mapping or explicit failure path,
      and pre/post row counts plus invalid records are verified.
- [ ] Backfills are bounded, resumable, observable, retry-safe, and accompanied
      by a tested rollback, forward repair, and restore plan.
- [ ] Versioned migration code contains no secret, production token, private
      key, customer data, or mutable external-service dependency.

#### Django & DRF

- [ ] `RunPython` uses `apps.get_model()` and
      `schema_editor.connection.alias`. It does not import a live model, and
      it does not assume that model methods, signals, or `full_clean()` will
      run. It reads rows through `_base_manager`, so a filtering manager
      cannot hide rows from the backfill or from its count check.
- [ ] Schema and data phases are separated appropriately for the database.
      Transaction size, locks, routers, and multi-database behavior are
      tested.
- [ ] Security-sensitive null/unknown values fail closed, constraints are added
      only after verified backfill, and destructive cleanup is deferred to a
      later compatible release.
- [ ] Fresh-install, released-version upgrade, retry/resume, and reverse or
      forward-repair paths are covered by migration tests.

## Review checklist

- [ ] Django/DRF/runtime on supported, patched versions (no EOL 4.2/5.1, no
      unmaintained deps).
- [ ] Dependencies are pinned, a lockfile exists, and hashes are verified on
      install. `[build-system] requires` and `[project] dependencies` are
      pinned and hashed as well.
- [ ] `pip-audit` runs in CI as an advisory input, and automated update PRs
      are enabled. No dependency pull request merges without a person who read
      the lockfile diff.
- [ ] Each pipeline control gates rather than merely runs. Hashes are enforced
      on install, and the scanner's exit code fails the build. The SBOM is
      generated from the lockfile, and provenance is verified against a pinned
      signer identity. Platform-side artifacts are recorded as operator
      questions.
- [ ] Dependencies come from trusted indexes, and there is no stray VCS or
      wheel install.
- [ ] One `--index-url` serves any project with private packages, and no
      `--extra-index-url` lets a public index win the version race. The
      environment and any `pip.conf` are read as part of that rule.
- [ ] Components discovered and loaded at runtime are pinned or
      provenance-checked at call time. Tool descriptions are treated as
      untrusted input.
- [ ] Every security dependency has a recorded need, a maintenance and advisory
      check, and a minimum safe version. It also has compatibility, a license,
      a secure-default review, and a disposition. Scanners are not treated as
      proof of safety.
- [ ] The requirements file the production image actually installs carries no
      package the library index tiers development-only. `django-extensions` is
      the case in particular, which ships `runserver_plus` and `shell_plus`.
      The check covers the resolved set, and not only the declared lines.
- [ ] Migrations use historical models, explicit validation and DB aliases,
      preserve fail-closed mixed-version access, and contain no secrets.
