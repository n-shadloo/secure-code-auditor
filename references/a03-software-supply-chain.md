# A03:2025 — Software Supply Chain Failures

New/expanded category in 2025 (absorbs "Vulnerable and Outdated Components").
Covers dependencies, pinning and integrity, vulnerability scanning, and EOL
frameworks.

## Contents
- [Principle](#principle)
- [Run a supported Django](#run-a-supported-django)
- [Pin and verify](#pin-and-verify)
- [Scan continuously](#scan-continuously)
- [Trust and provenance](#trust-and-provenance)
- [Review checklist](#review-checklist)

## Principle

Your security is bounded by your weakest dependency and by the integrity of how
that dependency reaches production. The principle is **know exactly what you
run, keep it patched, and make substitution hard**: pin versions, verify
integrity (hashes/lockfiles), scan for known vulnerabilities on every build, and
pull only from trusted sources. Transitive dependencies count — most of the tree
is code you never chose directly.

## Run a supported Django

As of Jul 2026 the supported lines are **Django 6.0.x** and **5.2 LTS**.
**Django 4.2 is end-of-life** (final release 4.2.30 on 7 Apr 2026); 5.1 is EOL
too. Running an unsupported release means security fixes stop reaching you —
flag any project pinned below 5.2 as a finding (severity scales with exposure).
The same applies to the language runtime and to DRF/SimpleJWT/allauth versions;
see the libraries file for current pins.

## Pin and verify

- Pin exact versions (`==`) for applications; a lockfile (`pip-tools`,
  `uv`, Poetry, PDM) captures the full resolved tree.
- Use hash-checking so a swapped artifact fails the install:

```
pip install --require-hashes -r requirements.txt
```

- Keep dev/test tooling out of the production dependency set.

## Scan continuously

- `pip-audit` (PyPA) checks installed/declared packages against the advisory
  databases. `safety` is an alternative/second opinion.
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

## Review checklist

- [ ] Django/DRF/runtime on supported, patched versions (no EOL 4.2/5.1, no
      unmaintained deps).
- [ ] Dependencies pinned; a lockfile exists; hashes verified on install.
- [ ] `pip-audit`/`safety` run in CI; automated update PRs enabled.
- [ ] Dependencies come from trusted indexes; no stray VCS/wheel installs.
