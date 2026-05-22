---
name: readme-maintenance
description: 'Create or update repository root and project-level README.md files. Use when documenting repositories, refreshing setup steps, standardizing README structure, or drafting concise English README content across ecosystems.'
argument-hint: 'What README files should be created or updated?'
license: MIT
user-invocable: true
---

# README Maintenance

Create or update README.md files in concise English.

## Scope

- Repository root README.md: the README.md file at repository root.
- Project README.md: a README.md in a directory with a project manifest (for
  example, .csproj, package.json, pyproject.toml).
- Project detection notes: if multiple manifests exist in one directory, treat
  it as a solution/workspace candidate and ask which target to update. For
  nested manifests, use the closest manifest directory unless a broader scope is
  explicitly requested.
- Out of scope: non-README markdown files unless explicitly requested.

## Rule Routing

- Read policy first: [policy rules](./references/policy.md).
- For repository root README, use [repository root rules](./references/repository-root-readme-guidelines.md).
- For project README, use [project rules](./references/project-readme-guidelines.md)
  and matching language rules under `references/<language>/`.
- In this repository, project README rules are .NET:
  [dotnet project rules](./references/dotnet/dotnet-readme-guidelines.md).

## Quick Workflow

1. Identify target README files and classify each as repository root or project.
2. Route to the correct rules (policy, scope-specific, language-specific).
3. Review existing README content, or create from the matching template.
4. Confirm before changing badges, license wording, CI snippets, or sample
   commands/code when not explicitly requested.
5. Update missing or inconsistent content while preserving accurate sections.
6. For root README updates, preserve existing badges unless badge changes are
   explicitly requested.
7. Run markdownlint for each changed README and fix reported issues.
8. Use auto-fix only for formatting-safe issues; apply manual edits if wording
   or meaning might change.
9. For edge cases (submodules, generated folders, vendored content, secrets),
   avoid adding or rewriting related sections without explicit direction.
10. Run final checks in the matching scope guideline.

Recommended validation command:

```bash
npx -y markdownlint-cli <path-to-readme>
```

## References

- Policy rules: [policy rules](./references/policy.md)
- Repository root rules:
  [repository root rules](./references/repository-root-readme-guidelines.md)
- Project rules: [project rules](./references/project-readme-guidelines.md)
