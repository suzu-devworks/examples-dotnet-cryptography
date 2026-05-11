# Project README Rules

Use this file only when updating project-level `README.md` files under `src/`.

## Templates

Select one template based on project type:

- Library: [project library template](../templates/project-readme-library-template.md)
- Executable: [project executable template](../templates/project-readme-executable-template.md)
- Test project: [project test template](../templates/project-readme-test-template.md)

## Scope

- Include all projects under `src/`.
- Include projects in nested subfolders under `src/`.
- Treat project targets as directories that contain a `.csproj` file.
- Add missing project README files when needed and report newly created files.

## Base Sections

1. Project name as the H1 heading
2. `## Table of Contents <!-- omit in toc -->`
3. Overview
4. References

## Conditional Sections

1. Usage: only when the project has an executable entry point
2. Features: library projects only, immediately after Overview
3. Test Target: test projects only
4. Test Index: test projects only, immediately after Test Target
5. Project-specific setup section: only when explicitly requested by the user,
   immediately before References

## Authoring Rules

- Place `## Table of Contents <!-- omit in toc -->` immediately before Overview.
- Keep template choice aligned with actual project type from project file and entry points.
- Do not add a `## Development` section.
- References should contain external docs, specs, and related repository docs.

### Table of Contents Format

Generate the Table of Contents to include all headings from H2 (##) onward, with the following rules:

- **Include**: All H2 and deeper headings in the document.
- **Exclude**: Any heading that contains the `<!-- omit in toc -->` comment.
- **Indentation**:
  - H2 headings: no indentation
  - H3 headings: 2-space indentation
  - H4 headings and deeper: continue nesting with 2-space indentation per level
- **Anchors**: Use markdown link anchors (e.g., `[Text](#anchor-id)`) with heading text
  lowercased and spaces replaced by hyphens.

Example TOC for mixed heading levels:

```markdown
- [Overview](#overview)
- [Features](#features)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [Advanced Options](#advanced-options)
    - [Option A](#option-a)
    - [Option B](#option-b)
- [References](#references)
```

### Library README

- Add `## Features` immediately after Overview.
- In `## Features`, list representative library capabilities in bullets.
- Target about 20 bullet items when information is available.

### Executable README

- Include simple and practical command examples in Usage.

### Test README

- Describe what the tests cover in Test Target.
- Add `## Test Index` immediately after `## Test Target`.
- Organize Test Index by functional categories with practical scope.
- Avoid categories that are too broad.
- Use links to folders, not links to individual files.

## Completion Checks

Use the shared checklist:
[README Completion Checklist](./CHECKLIST.md)
