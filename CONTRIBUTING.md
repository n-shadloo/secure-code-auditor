# Contributing

This repository does not take a pull request. Pull request creation is
restricted to collaborators, so an external account cannot open one. Open an
issue instead. I read every issue and I implement the change myself.

## Why the policy is this way

One person maintains this repository. Three constraints do not appear in a
diff, and a patch that misses one costs more to review than to write again.

- The `description` field in `SKILL.md` has a hard budget of 1024 characters
  and measures 1013 today. A new trigger word therefore removes an existing
  one, and that trade needs the whole router in view.
- A cross-reference names an exact heading in another file. A renamed heading
  breaks the reference, and the document check in CI does not read prose.
- A research-and-verification pipeline stands behind each factual claim. Every
  version, setting name, RFC number, and CVE identifier is checked against a
  primary source before it lands, and the check date is recorded.

## What the skill covers

The skill covers the backend. That is server-side code, data handling,
configuration, and the deployment and runtime that the backend owns. It carries
Django and DRF depth on a stack-agnostic layer, so the general guidance suits
any backend language. It does not cover the browser or the frontend, except
where the server controls the output. That exception includes output encoding,
response headers, and cookies.

A report about client-side code is out of scope. So is a report about a
framework this skill does not name.

## How the repository is arranged

Point at the correct file, because the agent files are not where content
lives.

- `SKILL.md` is the canonical skill and the router. It decides which reference
  file answers a concern, and its ownership table decides which file owns a
  contested topic.
- `references/` holds the content. Each file owns its own topics.
- `scripts/` holds three read-only scanners and their reference.
- `AGENTS.md`, `GEMINI.md`, and `.cursor/rules/secure-code-auditor.mdc` are thin
  pointers rather than content copies. Report a content problem against
  `SKILL.md` or the reference file that owns it.

## What a good report contains

Name the file and the section in every report. Give the skill version from
`metadata.version` in `SKILL.md`. Name the agent that surfaced the item.

- **A bug.** Give the command you ran, the input, the output you got, and the
  output you expected. For a scanner, a small code sample that reproduces the
  behavior is the most useful thing you can attach.
- **Incorrect or stale guidance.** Quote the exact text. Name the primary
  source that disagrees, and give the version or the date that source carries.
  A claim is stale when the source moved, so the date matters as much as the
  text.
- **A coverage gap.** Describe the attack or the failure that the skill misses.
  Name the file that should own it under the ownership table in `SKILL.md`.
- **A new feature.** Describe the review question the skill cannot answer
  today. Give one code example that shows the question.

## What happens next

I triage the issue. I research the claim against a primary source, because a
correction here needs the same evidence as the original text. I implement the
change. The release note for the version that carries the change credits the
reporter.

## Conduct and security

Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before you post. Read
[SECURITY.md](SECURITY.md) before you report a vulnerability, because an
exploitable defect in a scanner goes through a different channel.
