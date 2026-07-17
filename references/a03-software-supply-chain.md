# A03:2025 — Software Supply Chain Failures

New/expanded category in 2025 (absorbs "Vulnerable and Outdated Components").
Covers dependencies, pinning and integrity, vulnerability scanning, EOL
frameworks, and the integrity of versioned schema/data migrations.

## Contents
- [Principle](#principle)
- [Run a supported Django](#run-a-supported-django)
- [Pin and verify](#pin-and-verify)
- [Scan continuously](#scan-continuously)
- [Trust and provenance](#trust-and-provenance)
- [Third-party dependency vetting](#third-party-dependency-vetting)
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

As of 17 Jul 2026 the supported lines are **Django 6.0.7** and **5.2.16 LTS**.
**Django 4.2 is end-of-life** (final release 4.2.30 on 7 Apr 2026); 5.1 is EOL
too. Running an unsupported release means security fixes stop reaching you —
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
- Generate an SBOM (CycloneDX or SPDX) for the deployed image if you need to
  answer "are we affected?" quickly when a CVE drops.

```
pip-audit -r requirements.txt
```

## Trust and provenance

- Install from PyPI (or a controlled internal index), not arbitrary VCS URLs or
  copy-pasted wheels.
- Be wary of typosquats and newly published look-alike names; check the project
  is real and maintained before adding it.
- This applies to **Claude Skills too**: a skill can direct an agent to run code
  or move data. Only install skills from sources you trust, and read the bundled
  files.

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

### Django and DRF implementation layer

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
  a separately operated, idempotent job.
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
- [ ] Dependencies come from trusted indexes; no stray VCS/wheel installs.
- [ ] every security dependency has a recorded need, maintenance/advisory check,
      minimum safe version, compatibility, license, secure-default review, and
      disposition; scanners are not treated as proof of safety;
- [ ] Migrations use historical models, explicit validation and DB aliases,
      preserve fail-closed mixed-version access, and contain no secrets.
