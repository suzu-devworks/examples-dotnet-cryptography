# .NET Project README Rules

Use this file when updating project-level `README.md` files for .NET projects.

## Templates

- **Library**: [dotnet library template](./templates/dotnet-readme-library-template.md)
- **Executable**: [dotnet executable template](./templates/dotnet-readme-executable-template.md)
- **Test Project**: [dotnet test template](./templates/dotnet-readme-test-template.md)

## Project Types

- **Library**: .NET SDK-style project with a library-oriented target, usually no `OutputType` or `OutputType` set to `Library`.
- **Executable**: .NET SDK-style project with `OutputType` set to `Exe` or `WinExe`.
- **Test Project**: .NET SDK-style project with `IsTestProject` set to `true`, or a project that
   references both a test framework package and `Microsoft.NET.Test.Sdk`.

Use `.csproj` and `global.json` as the sources of truth for .NET project and test detection.

## Required Sections (in order)

1. Project name (H1 heading)
2. Table of Contents with `<!-- omit in toc -->`
3. Overview
4. Technology Stack
5. Conditional sections based on project type:
   - **Library**: Features, immediately after Technology Stack
   - **Executable**: Usage, immediately after Technology Stack
   - **Test Project**: Test Target and Test Index, immediately after Technology Stack
6. Optional project-specific section, only when requested, immediately before References
7. References

## Section Guidelines

### Table of Contents

- Include all H2 headings onward.
- Exclude headings marked with `<!-- omit in toc -->`.
- Use lowercase, hyphenated anchors.

### Technology Stack

- Prefer .NET-specific values only.
- Include `Target Framework` for a single target or `Target Frameworks` when multi-targeting.
- Optionally include `Language` when it adds value.
- Do not include `SDK`.
- Do not add detailed version numbers by default.
- If an existing or user-added version entry is clearly necessary, preserve it during maintenance updates.
- Useful items include target framework information, test framework, and key NuGet packages.
- Format each item as `- name: value`.

### Features

- Describe representative capabilities for the library.
- Keep the list concise and concrete.

### Usage

- Show practical `dotnet` commands.
- Include `dotnet run`, `dotnet test`, or `dotnet publish` only when relevant.

### Test Target and Test Index

- Explain the test scope in Test Target.
- Organize Test Index by functional categories.
- Link to folders, not individual files.

### References

- Include official .NET docs, NuGet package pages, and related repository docs.
- Links to Japanese documentation sites are allowed.

## Workflow

1. Discover project files by searching for `.csproj` files.
2. For each target `.csproj`, auto-detect `README.md` in the same folder.
3. If multiple candidate README files are detected and the target is not explicitly specified,
   ask which project README should be updated.
4. Ignore build output folders such as `bin` and `obj`.
5. Determine the project type from `.csproj` and `global.json` values:
   `OutputType`, `IsTestProject`, `TargetFramework` or `TargetFrameworks`, and test package references.
6. Select the matching .NET template and fill it with .NET-specific values.
7. If `TargetFrameworks` is present, enumerate all targets in README.
8. Build the Table of Contents from the resulting headings.
9. Validate the file with markdownlint.

## Constraints

- Do not add `## Development`.
- Keep headings from the selected template unless the structure must change.
- Keep the `AS_NEEDED` placeholder pattern for optional items.
- Use concise English.
- Japanese links in references are allowed.
- All links must be valid.
- markdownlint must pass with zero errors.

## Final Checks

- [ ] Uses concise English.
- [ ] Required sections exist in the correct order.
- [ ] Includes `## Table of Contents` with `<!-- omit in toc -->` before Overview.
- [ ] Does not include `## Development`.
- [ ] Technology Stack uses `name: value` entries.
- [ ] Technology Stack may include `Language` when it adds value.
- [ ] Technology Stack does not include `SDK`.
- [ ] Detailed version numbers are not added by default; necessary existing version entries are preserved.
- [ ] Usage appears only when it adds value.
- [ ] Library projects place `## Features` immediately after Technology Stack.
- [ ] Test projects include `## Test Target` and `## Test Index` in that order.
- [ ] `TargetFrameworks` values are enumerated when multi-targeting.
- [ ] Test Index links point to folders, not individual files.
- [ ] Links point to valid resources.
- [ ] markdownlint passes with zero errors.
