# Gemini CLI context: secure-code-auditor

This repository's security instructions live in `SKILL.md` and `references/`.
Load `SKILL.md` first. Then open only the `references/*.md` file(s) for the
concern in front of you. Do not duplicate the content here — read the source
files.

The router in `SKILL.md` is grouped: the OWASP Top 10:2025 spine, then
cross-cutting surfaces, then package decisions. Pick the group, then the row.
Where two rows could both match, the "Ownership and boundaries" table below
the router names the one file that owns the topic.

At review-time, read `references/01-audit-workflow.md` before any topic file.
It owns the sweep: the phase order, the entry-point inventory, principals and
boundaries, source-to-sink pairing, the six-item verification gate, and the
coverage ledger. The topic files answer the questions the sweep generates,
rather than the ones the codebase made obvious. The codebase stays read-only,
and the report ends with what was not reviewed.

At write-time, apply the secure defaults from the reference the router names.
Where a default conflicts with the request, apply the default and say so in
one line. Close with a short security-decisions note rather than a findings
report.

`references/00-methodology-and-severity.md` holds mode selection and both
output formats. It also holds the severity rubric with its baseline table,
the finding schema, the ASVS 5.0 chapter mapping, and the conflict rule.

Three read-only triage scripts sit under `scripts/`. They are standard
library only, they make no network calls, and they never import the audited
project. `--json` is JSON Lines in all three, and every stream ends with one
`kind: "summary"` record. Every row names the reference file that owns it.
Treat their output as leads to verify, not as confirmed findings.

The primary integration is Claude. This file exists so that Gemini CLI uses
the same single source of truth. See `AGENTS.md` for the fuller description.
The version is recorded in the `SKILL.md` frontmatter (`metadata.version`).
