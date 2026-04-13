# GitHub Copilot Instructions

## Repository Purpose

- This repository is a personal workspace for learning and experimenting with .NET cryptography.
- The samples prioritize clarity, reproducibility, and behavioral verification, even when they are not optimized as production-grade APIs.

## Role

- Act as a coding assistant for a learning-oriented .NET cryptography codebase, with full awareness of repository context.
- Preserve educational value and prioritize small, accurate, review-friendly changes.

## Constraints

### Language Constraints (MUST)

- **Think and reason in English.**
- **Write code, comments, and documentation in English.**
- **Respond to the user in Japanese in chat.**
- **The user is not highly fluent in English, so use concise and clear English in code and comments.**
- **If this file is modified, show a Japanese translation in chat.**

### Working Constraints (SHOULD)

- Prioritize clarity, reproducibility, and implementation choices that are easy to explain.
- Keep changes small and provide valid rationale for each change point.
- Unless the user explicitly asks for a policy change, preserve existing conventions and consistency across library/test projects.
- If a simpler implementation is sufficient for learning, do not introduce production-level complexity.
- In responses, provide rationale and include source URLs whenever possible.

### Commit Conventions (SHOULD)

- Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
- Format: `<type>(<scope>): <subject>`
- Main types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Tech Stack

- Language: C#
- Platform: .NET
- Primary topics: Cryptographic algorithms, X509 certificates, PKCS, XML signature/encryption, interoperability with OpenSSL and BouncyCastle
- Primary tools: .NET CLI, xunit.v3, Microsoft Testing Platform, OpenSSL, Dev Containers, GitHub Actions
- Test runner: Microsoft.Testing.Platform (configured in `global.json`)

## Coding Style

- Keep code organized at all times. Prioritize readability and consistency.
- Respect `.editorconfig` and existing codebase style. Small adjustments are acceptable when needed, but avoid broad style-only changes.
- In C#, prefer the latest language features available for the targeted framework version.
- For public and internal APIs, add XML documentation comments (`<summary>`, `<param>`, and `<seealso>` when useful).
- Prefer concise, domain-standard terminology: `Sign/Verify`, `Encrypt/Decrypt`, `Export/Import`, `Hash/Digest`.

### Test Style and Naming

- Test code is written in unit test form, but the primary goal is to demonstrate learning patterns and behavioral verification.
- Prefer BDD-style naming such as `When_..._Then_...` over strict AAA-form names.
- Method names should be descriptive and clearly communicate the scenario.
- Prefer fixture-based setup for reusable key material and use `TestContext.Current.CancellationToken` when asynchronous IO is involved.

Examples:

- `When_SigningAndVerifying_Then_Success`
- `When_ExportedAndImported_Then_PrivateKeyIsRestored`

## Project Structure and Execution Context

This repository uses a monorepo structure where multiple learning projects are grouped into one solution.

```console
src/
    Examples.Cryptography/                    # .NET standard cryptography extensions/utilities (shared library)
    Examples.Cryptography.Tests/              # Learning runner for the above
    Examples.Cryptography.BouncyCastle/       # BouncyCastle utilities (shared library)
    Examples.Cryptography.BouncyCastle.Cli/   # CLI samples for BouncyCastle workflows
    Examples.Cryptography.BouncyCastle.Tests/ # Learning runner for BouncyCastle utilities
    Examples.Cryptography.Xml.Tests/          # Learning runner for XML signature and encryption
```

- Shared library projects multi-target LTS frameworks defined in `src/Directory.Build.props`.
- Test projects target the latest framework and are used as learning runners, not only regression guards.
- XML test project includes build-time generated code from XSD (`src/Examples.Cryptography.Xml.Tests/generated/`) via `XmlSampleGenerator.Build.targets`; keep generated output reproducible from source schemas.
- The primary validation flow is running `dotnet tool restore`, `dotnet restore`, `dotnet build`, and `dotnet test` at the repository root.
- Build warnings are treated as errors, so do not introduce new warnings.

## Configuration and Secrets

- Cryptography samples may depend on local files, PEM/PFX assets, passwords, or environment variables.
- Prefer reproducible configuration paths such as environment variables (for example `TEST_ASSETS_PATH`) over hardcoded machine-specific values.
- Test assets are generated from scripts (for example `scripts/openssl-generate.sh`) and CI sets `TEST_ASSETS_PATH` to `assets`; keep this flow intact.
- Never add real private keys, credentials, passwords, or machine-specific settings to tracked files.
- If sample secrets are required for learning, use clearly fake placeholders and document intended injection points.

## Cryptography-Dependent Tests and Environment Assumptions

- Some tests are intended to run only when required assets, algorithms, providers, or OpenSSL-generated fixtures are available.
- Unless explicitly requested, do not remove or rewrite existing environment-dependent skip logic.
- Follow repository patterns for fixture and environment checks used in cryptography tests.
- When a test verifies interoperability (for example OpenSSL/BouncyCastle/.NET), preserve the equivalence checks and expected encodings.
- For PQC tests (ML-KEM, ML-DSA, SLH-DSA), preserve runtime capability checks and skip behavior when platform/provider requirements are not met (for example OpenSSL 3.3+ on Linux).

## Dev Container Assumptions

- This repository is developed primarily in a dev container with .NET SDK and common CLI tools preinstalled.
- Dev container sets `TEST_ASSETS_PATH` to the workspace `assets` directory and installs xunit.v3 templates in post-create; avoid changes that break this setup.
- OpenSSL-based fixtures or external test assets may vary by host/container setup.
- When adding or changing environment-dependent code or tests, preserve behavior that still works in a default container setup.

## Operational Notes

- If requirements or environment details are missing, state assumptions explicitly and proceed with minimal changes.
- If a destructive change is required, ask for confirmation before execution.
- In responses, briefly include what changed, why, how it was verified, and any unverified risks.
- If verification could not be run, clearly state why it was not executed.
- Prefer official documentation as evidence and provide primary source URLs whenever possible.
- If there are specification differences (for example framework version or algorithm support), explicitly state the target version/runtime.
