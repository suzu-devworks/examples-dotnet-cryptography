# Repository Root README Guidelines

Use this file only when creating or updating the repository root `README.md`.

## Required Sections (in order)

1. Repository name (H1 heading)
2. Badges
3. Repository description
4. Technology Stack
5. Setup

Additional rules for required sections:

- Badges are listed directly under the repository name without a `## Badges` heading.
- The Repository description heading must be `## What is the purpose of this repository?`.

Optional sections may be added only after Setup when needed.
Badge entries are optional.

## Section Guidelines

### Repository Description

Include:

- Brief project explanation
- Note that this may help engineers with similar problems
- Disclaimer that content reflects personal views and may be inaccurate
- Fixed disclaimer that no responsibility is accepted for any issues caused by using this repository content

### Technology Stack

- List only repository-wide or shared technologies
- Remove technologies that are not common across the repository
- Use list format with `name: value`
- Do not add detailed version numbers by default
- If an existing or user-added version entry is clearly necessary, preserve it during maintenance updates

### Setup

Structure only when needed:

- DevContainer
- Build-Pre Environment Setup
- Test Environment Setup
- Build and Test

Standard command order: install/restore → build/compile → test.
Include prerequisites (e.g., asset generation scripts) before tests.
When needed, include concrete command examples or relevant configuration file entries.

### Badges

- Badges are manually managed.
- Preserve existing badges; do not modify or remove them unless explicitly requested by the user.
- Technology badges: only from repository metadata or build configuration files.
- GitHub Actions badges: only when explicitly requested.
- New badge additions require explicit user confirmation.
- Future direction: automated badge insertion may be introduced later, but current workflow remains manual.
- Link maintenance: fixing badge URLs to restore functionality is allowed as maintenance and does not require explicit confirmation.
- Template markers: templates may include `BADGES:START`/`BADGES:END` markers for future automation;
  agents should ignore these markers for now.

## Workflow

1. Use [repository root template](../templates/repository-root-readme-template.md)
2. Apply required section structure in order
3. Replace `{{PLACEHOLDER}}` text; remove placeholder-only lines
4. If additional content is needed, add optional sections after Setup
5. Keep badges manual and preserve existing entries unless explicit badge changes are requested.
6. Ensure section content matches guidelines above

## Constraints

- Use concise English
- Follow required section order
- Keep fixed template headings unless structural change is needed
- Use `AS_NEEDED` placeholder for optional second items
- Required headings must exist in correct order
- All links must point to valid resources
- markdownlint must pass with zero errors

## Final Checks

- [ ] Uses concise English.
- [ ] Required sections exist in the correct order.
- [ ] Optional sections, when present, are placed after Setup.
- [ ] Badges remain manually managed and existing entries are preserved unless explicitly requested.
- [ ] Technology Stack uses list format with `name: value`.
- [ ] Technology Stack includes only repository-wide shared technologies.
- [ ] Detailed version numbers are not added by default; necessary existing version entries are preserved.
- [ ] Links point to valid resources.
- [ ] markdownlint passes with zero errors.
