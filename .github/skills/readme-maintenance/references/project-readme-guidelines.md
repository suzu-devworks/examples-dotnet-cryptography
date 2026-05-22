# Project README Rules

Use this file only when updating project-level `README.md` files. For language-specific rules,
read the matching reference under `references/<language>/` after this file.

## Common Project Workflow

1. Discover target project manifests, including nested projects.
2. For each target manifest, auto-detect `README.md` in the same folder.
3. If multiple candidate README files are detected and the target is not explicitly specified,
   ask the user which project README should be updated.
4. Classify each target by language first, then by project type.
5. Read the common rules in this file, then the matching language-specific rules.
6. Select the matching project template and replace placeholders with project-specific content.
7. Validate links, section order, and markdownlint output.

## Common Constraints

- Keep the section order defined by the language-specific reference.
- Do not add sections unless the language-specific reference allows them.
- Keep placeholders and headings aligned with the selected template.
- All links must be valid.
- markdownlint must pass with zero errors.
- Use concise English unless the language-specific reference says otherwise.

## Language References

- .NET: [dotnet project rules](./dotnet/dotnet-readme-guidelines.md)
