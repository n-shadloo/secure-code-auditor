# AGENTS.md

This repository is a backend security skill. Its canonical instructions live in
`SKILL.md`, which routes to the topic files under `references/`. Any agent
working in this repo should load `SKILL.md` first and then read only the
`references/*.md` file(s) relevant to the task.

Primary integration: **Claude** (Anthropic Agent Skills). The files below let
other agents use the same content; they are pointers, not copies. If anything
here disagrees with `SKILL.md`, `SKILL.md` wins. The current version is recorded
in `SKILL.md` frontmatter (`metadata.version`).

## What this skill does
Reviews backend code for security issues and applies secure defaults while
writing code. Organized on the OWASP Top 10:2025 spine, with a stack-agnostic
principle layer and a deep Django/DRF implementation layer per category.

## Two modes
- Review-time: audit existing code, produce prioritized findings (severity,
  location, CWE + OWASP mapping, concrete fix). Read-only by default.
- Write-time: apply secure defaults and flag risky patterns while generating code.
Mode selection and the findings format are defined in
`references/00-methodology-and-severity.md`.

## How to use the content
1. Read `SKILL.md` for the router, mode logic, and severity summary.
2. Open the `references/*.md` file(s) for the concern in front of you (the table
   in `SKILL.md` maps concern → file).
3. Optional read-only triage (standard library only, no network):
   - `python scripts/settings_scan.py path/to/settings.py`
   - `python scripts/dangerous_patterns.py path/to/project`
Treat script output as leads to verify, not confirmed findings.

## Tool-specific entry points
- Claude Code: `SKILL.md` (native Agent Skill).
- OpenAI Codex CLI: reads this `AGENTS.md`.
- Cursor: `.cursor/rules/secure-code-auditor.mdc`.
- Gemini CLI: `GEMINI.md`.
All of them defer to `SKILL.md` and `references/`.
