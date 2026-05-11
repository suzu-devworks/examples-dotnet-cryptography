---
name: readme-maintenance
description: 'Create or update top-level and project-level README.md files. Use when documenting a repository, refreshing setup steps, standardizing project README structure, or drafting concise English README content for .NET libraries, CLIs, and test projects.'
argument-hint: 'What README files should be created or updated?'
user-invocable: true
---

# README Maintenance

Create or update README.md files using concise English.

## Scope Definitions

- Top-level README.md:
  the README.md file located at the repository root.
- Project README.md:
  a README.md file located in the same directory as a *.csproj file.

## Mandatory Policy

- Before starting work, confirm the requested README.md updates and proceed only after user confirmation.
- When modifying any README.md covered by this skill, always consult this SKILL first.

### Changes Not Requiring User Confirmation

- Creating subsections within already defined sections is allowed.
- Running markdownlint and fixing all reported issues is allowed.

### Changes Requiring User Confirmation

- Any change not described in this SKILL requires explicit user confirmation before proceeding.
- Changing headings of defined sections, adding sections, or deleting sections
  requires explicit user confirmation before proceeding.
- Rewriting existing accurate content requires explicit user confirmation before proceeding.

## Split References

Read only the file you need for the current task:

- Top-level README tasks:
  [top-level rules](./references/top-level-readme-guidelines.md)
- Project README tasks:
  [project rules](./references/project-readme-guidelines.md)
- Completion validation:
  [README completion checklist](./references/CHECKLIST.md)

If a request touches both top-level and project README files, handle each scope independently
and follow the corresponding rule file for each scope.

## Shared Workflow

1. Identify all target README.md files.
2. Choose scope per file: top-level or project.
3. Read only the matching split rule file.
4. Add only missing or inconsistent parts without rewriting existing accurate content.
5. Run markdownlint for each changed README and fix all reported issues.

Recommended validation command:

```bash
npx -y markdownlint-cli <path-to-readme>
```

Examples:

```bash
npx -y markdownlint-cli README.md
npx -y markdownlint-cli src/Examples.Cryptography/README.md
```

If markdownlint is not available in the environment, report that clearly.
