# Gemini CLI context: secure-code-auditor

This repo's security instructions live in `SKILL.md` and `references/`. Load
`SKILL.md` first, then the relevant `references/*.md` file. See `AGENTS.md` for
the full description. Do not duplicate the content here — read the source files.

Primary integration is Claude; this file exists so Gemini CLI uses the same
single source of truth. Modes (review-time / write-time), the severity rubric,
and the findings format are in `references/00-methodology-and-severity.md`. The
version is recorded in `SKILL.md` frontmatter (`metadata.version`).
