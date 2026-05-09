# C# Coding Standards

All formatting and style rules are governed by `.editorconfig` and the repository's build-time enforcement.
`EnforceCodeStyleInBuild` is enabled in shared props so violations can fail the build.

## General

- Write code, comments, and documentation in concise English.
- Use XML documentation comments (`<summary>`, `<param>`, `<returns>`) on reusable public or internal APIs.

## Naming and Style

- Follow standard .NET naming conventions.
- Prefer predefined C# type keywords (for example, `string`) over BCL aliases.
- Avoid `this.` qualifier unless necessary for clarity.

## Method Design

- Introduce a parameter class when a method has many parameters.
- Suffix async methods returning `Task`/`ValueTask` with `Async`.
- Add `CancellationToken cancellationToken = default` as the last parameter of public async methods returning `Task` or `ValueTask` where appropriate.

## Cryptography-specific Guidelines

- Keep cryptographic primitives isolated and small.
- Avoid rolling your own crypto; prefer primitives from the framework or vetted libraries (BouncyCastle, OpenSSL interoperability).
- Clearly document threat model and intended use for samples that demonstrate algorithms.

## Test Naming

- Prefer descriptive test names in the form `When_Condition_Then_ExpectedResult`.

## Test Style and Naming

Test guidance (naming, asset handling, and environment assumptions) has been moved to
[`.github/copilot/tests-and-assets.md`](.github/copilot/tests-and-assets.md).
