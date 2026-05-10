# Repository Context

## Purpose

This repository is a personal learning and experimentation workspace for .NET cryptography.
It covers cryptographic algorithms, X.509 and PKCS formats, XML signature/encryption,
interoperability with OpenSSL and BouncyCastle, and practical examples for key management and testing.

## Tech Stack

- Language: C#
- Platform: .NET (multi-targets defined in `src/Directory.Build.props`)
- Primary topics: Cryptographic algorithms, X509 certificates, PKCS, XML signatures,
  interoperability with OpenSSL and BouncyCastle
- Test runner: Microsoft.Testing.Platform with xUnit v3
- Supporting tools: OpenSSL, BouncyCastle, Dev Containers, GitHub Actions

## Key Configuration

- `src/Directory.Build.props` enables TreatWarningsAsErrors and shared build props.
- `global.json` configures the .NET SDK and test runner where applicable.
- `nuget.config` defines package sources.
- `.editorconfig` defines formatting and naming rules; CI enforces style.
- Test assets (certificates, keys, fixtures) should be produced by scripts in the `scripts/` directory and
  not committed to source control. Tests and samples must read those files from the path provided by the
  `TEST_ASSETS_PATH` environment variable.

## Project Conventions

- Keep cryptographic code small, auditable, and well-documented.
- Place projects under `src/` with clear naming: shared libraries, test runners, and CLI samples.
- Place design documents, explanations, and other supporting materials under `docs/` in an appropriate subfolder.
- Preserve interoperability tests that compare outputs with OpenSSL or BouncyCastle.
- Environment-dependent tests should use runtime checks and skip when prerequisites are missing.

## Commands

Run from repository root:

```bash
dotnet tool restore
dotnet restore
dotnet build
dotnet test
```

Clean generated outputs:

```bash
dotnet msbuild -t:RemoveDirectories
```

## Default branch

Default branch: `main`
