# Top-Level README Rules

Use this file only when updating the repository root `README.md`.

## Section Structure

Use the structure from
[top-level template](../assets/top-level-readme-template.md).

Required sections, in order:

1. Repository name as the H1 heading
2. Badges
3. Repository description
4. Technology stack
5. Setup

## What to Write

- Keep required sections in the defined order.
- Add optional sections only after the required sections.
- In the repository description section, include:
  - A brief project explanation
  - A note that this may help engineers with similar problems
  - A disclaimer that content reflects personal views and may contain inaccuracies
- In the technology stack section, use the following format:
  - Language: [primary language]
  - Platform: [.NET versions for apps and libraries]
  - Frameworks: [key libraries and frameworks used]
  - Test runner: [test framework and platform]
  - Supporting tools: [relevant tools, libraries, and services]
- Keep setup steps runnable and minimal.
- Prefer baseline setup commands in this order when applicable:
  - `dotnet tool restore`
  - `dotnet restore`
  - `dotnet build`
  - `dotnet test`
- If setup prerequisites exist (for example asset generation scripts), place them before tests.

## Badge Rules

- Add a Framework badge using <https://img.shields.io/badge/dynamic/xml> and read
  `LatestFramework` from `src/Directory.Build.props`.
- If `src/Directory.Build.props` is missing, report that clearly.
- Add GitHub Actions status badges only when explicitly requested.
- If changing an existing badge, confirm with the user first.

Preferred framework badge pattern:

```markdown
![Dynamic XML Badge](https://img.shields.io/badge/dynamic/xml?url=<raw-url-to-Directory.Build.props>&query=%2F%2FLatestFramework&logo=dotnet&label=Framework)
```

## Completion Checks

Use the shared checklist:
[README Completion Checklist](./CHECKLIST.md)
