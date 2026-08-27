# AGENTS.md

This repository is a backend security skill. The canonical instructions live
in `SKILL.md`, which routes to the topic files under `references/`. An agent
that works in this repository loads `SKILL.md` first. Then it reads only the
`references/*.md` file(s) relevant to the task.

The primary integration is **Claude** (Anthropic Agent Skills). This file and
its siblings let other agents use the same content. They are pointers, not
copies. Where anything here disagrees with `SKILL.md`, `SKILL.md` wins. The
current version is recorded in the `SKILL.md` frontmatter
(`metadata.version`).

## What this skill does

It reviews backend code for security issues, and it applies secure defaults
while code is written. The corpus sits on the OWASP Top 10:2025 spine, with
the API Security Top 10:2023 and ASVS 5.0 beside it. Each reference carries a
stack-neutral principle layer and a deep Django and DRF layer. Every control
is stated in a review form and a write-time form together.

The coverage spans the whole backend. It runs from the audit workflow and the
entry-point inventory, through access control, authentication, injection,
integrity, cryptography, and configuration. It reaches the API surfaces that
are not DRF routes. It covers the database and data-lifecycle layers,
service identity, deployment, file uploads, and agent and MCP tool surfaces.
It also covers the auditing agent's own access. The `SKILL.md` router names
each file's exact surface, so do not duplicate that list here.

## Two modes

- **Review-time.** Audit existing code, and produce prioritized findings.
  Each finding carries a severity, a location, a CWE and OWASP mapping, the
  confirmed source-to-sink path with the protection that failed, and a fix.
  The codebase stays read-only. Load `references/01-audit-workflow.md` before
  any topic file. It owns the sweep, and the topic files answer the questions
  the sweep generates. The report ends with what was not reviewed.
- **Write-time.** Apply the standing secure-default contract while you
  generate code. Where a default conflicts with the request, apply the
  default and say so in one line. Close with a short security-decisions note
  rather than a findings report. The rule for each generation moment sits
  beside the control it completes, in the reference the router names.

`references/00-methodology-and-severity.md` defines mode selection, both
output formats, the severity rubric and its baseline table, the ASVS chapter
mapping, and the conflict rule.

## How to use the content

1. Read `SKILL.md` for the router, the ownership table, the mode logic, and
   the severity summary.
2. At review-time, read `references/01-audit-workflow.md` next and run its
   phases. The entry-point inventory decides which topic files are needed,
   and the coverage ledger records what each pass reached.
3. Open the `references/*.md` file(s) for the concern in front of you. The
   router is grouped: the OWASP spine, then cross-cutting surfaces, then
   package decisions. Pick the group, then the row.
4. Where two rows could both match, the "Ownership and boundaries" table in
   `SKILL.md` names the one file that owns the topic. Each reference also
   repeats its own half of that boundary in its opening paragraph.
5. Optional read-only triage (standard library only, no network):
   - `python scripts/entrypoint_inventory.py path/to/project --settings path/to/settings --json`
   - `python scripts/settings_scan.py path/to/settings/ --json`
   - `python scripts/dangerous_patterns.py path/to/project`
   - `python scripts/dangerous_patterns.py --selftest`

   `--json` is JSON Lines in all three, and every stream ends with one
   `kind: "summary"` record. All three parse with the `ast` module, so a hit
   is a structural match. Every row names the reference file that owns it,
   and a file that fails to parse is reported rather than skipped. Treat
   script output as leads to verify, not as confirmed findings.

## Tool-specific entry points

- Claude Code: `SKILL.md` (native Agent Skill).
- OpenAI Codex CLI: reads this `AGENTS.md`.
- Cursor: `.cursor/rules/secure-code-auditor.mdc`.
- Gemini CLI: `GEMINI.md`.

All of them defer to `SKILL.md` and `references/`.
