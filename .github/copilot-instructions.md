# GitHub Copilot Instructions

These are the rules you must follow when working in this repository.

## Language and Communication

- Think and reason in English.
- Respond in Japanese for all user-facing chat output, including reviews, summaries, and progress updates.
- Write code, comments, and documentation in concise English.
- Do not change locale segments in reference URLs (for example `ja-jp`) unless explicitly requested.
- Greetings, thanks, and introductory remarks (such as "Understood," or "The following is the code") are strictly prohibited.
- Output the code with the minimum necessary logic.
- Avoid lengthy explanations; when explanation is unnecessary, output only the corrected code block.

---

## Change Strategy

- Keep diffs focused, minimal, and reviewable.
- Avoid broad style-only refactors unless explicitly requested.
- Prefer simple, readable implementations.
- Preserve existing conventions unless the user requests policy changes.
- Create a plan before breaking or impactful changes.
- Use Confirmation Criteria below to decide whether confirmation is required.
- Do not revert uncommitted changes or run destructive Git operations without permission.
- After edits, check and fix code style as needed.

### Execution Order

Follow this default sequence unless the user requests otherwise:

1. Gather context and scope the task.
2. Decide whether confirmation is required using Confirmation Criteria.
3. If confirmation is required, ask before editing.
4. Apply minimal, focused edits.
5. Validate results (tests, lint, or style checks as needed).
6. Report what changed and any remaining risks.

### Confirmation Criteria

Ask for confirmation before editing if any of the following apply:

- Adding or upgrading dependencies.
- Changing public API behavior (for example, function signatures, CLI arguments, or config keys with compatibility impact).
- Making breaking or impactful changes (for example, behavior changes that alter expected user workflows).

Proceed without extra confirmation for low-risk, behavior-preserving updates:

- Typo, grammar, and broken-link fixes.
- Lint/format-only adjustments.
- Refactors that preserve existing behavior.

## Priority Order

When instructions conflict, follow this order:

1. System/developer instructions.
2. This repository instruction file.
3. User request.
4. Existing codebase conventions.

---

## Tool Usage

- **Symbol-level operations** (find definition, rename, replace body):
  prefer workspace-native symbol-aware tools over broad manual rewrites.
- **Exploration and context gathering**: use VS Code workspace capabilities for file discovery,
  text search, and semantic lookup.
- **Terminal**: use when workspace-native tools are insufficient or command execution is required
  (for example, build/test/lint/format/script runs, line-numbered inspection, or Git operations
  without equivalent workspace actions).
- **Model/agent-specific names**: prefer capability-based wording; when explicit names are
  necessary, use VS Code-native names available in this environment.
- **File edits**: prefer targeted edits using VS Code editing capabilities, and avoid rewriting
  entire files unless necessary.
- **Destructive or irreversible actions** (delete files, force push, drop tables): always ask
  for user confirmation first.

## MCP Usage

- **Microsoft products** (Azure, .NET, Microsoft 365, etc.): use the Microsoft Learn MCP server
  (`microsoftdocs/mcp`) for the latest official documentation. Include the URL(s) consulted in responses.
- **Library and framework specifications**: use the Context7 MCP server (`io.github.upstash/context7`) to
  fetch the latest docs. Resolve the library ID first, then fetch docs.

---

## Security and Secrets

- Never commit real credentials, secrets, or machine-specific values in tracked files.
- For highly sensitive settings, use methods such as placeholders, environment variables, or generate them with scripts.
- Flag any existing secrets found in files and recommend remediation before proceeding.

---

## Commit Convention

Follow Conventional Commits:

```text
type(scope): subject
```

Common types:

- `feat`: new feature
- `fix`: bug fix
- `docs`: documentation only
- `style`: formatting, no logic change
- `refactor`: neither bug fix nor new feature
- `test`: adding or updating tests
- `chore`: maintenance tasks

Rules:

- Include a brief description in the subject line.
- Add a body for significant changes explaining rationale and verification steps.
- For breaking changes, include `BREAKING CHANGE:` in the body with impact and migration steps.

---

### Update Rule

- Keep this file minimal and always-on.
- Move details to split files unless they are required in most tasks.
- Promote a split rule into this file only if it is repeatedly needed.
