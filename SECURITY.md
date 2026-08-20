# Security Policy

## In scope

- The three scanner scripts in `scripts/`.
- Skill content that can send a reader to an insecure implementation. A wrong
  code example, a control that fails open, and a minimum-safe version below the
  real fix are each in scope.

## Out of scope

- A vulnerability in your own project. This repository holds guidance and
  read-only scanners. Nothing here runs inside your application.
- A vulnerability in a third-party package that
  `references/security-hardening-libraries.md` names. Report that to the
  upstream project, because this repository does not ship the package. Open an
  issue here only when the index records the wrong verdict or the wrong
  minimum-safe version.

## How to report

Use GitHub private vulnerability reporting for an exploitable defect in a
scanner script. Open a normal issue for guidance that is only wrong or stale,
because that report is not sensitive and a public thread makes it easier to
correct.

## What the scanners do and do not do

The scanners hold four properties. A report that assumes otherwise is usually a
misunderstanding rather than a defect, so check these first.

- They are read-only. They write no file into the tree they read.
- They use the Python standard library only. They add no dependency.
- They make no network call.
- They never import or execute the audited project. All three parse with the
  `ast` module, so no line of the audited code runs.

The exit code is always 0, with one exception. `dangerous_patterns.py
--selftest` returns 1 when a check fails, because there the scanner itself is
what is under test. `scripts/README.md` carries the full contract. A scanner
that exits 0 on a tree with findings is therefore correct behavior and not a
bug.

## Handling

I handle each report myself, on a best-effort basis. I do not offer a service
level.
