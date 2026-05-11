# examples-dotnet-cryptography

![Dynamic XML Badge](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsuzu-devworks%2Fexamples-dotnet-cryptography%2Frefs%2Fheads%2Fmain%2Fsrc%2FDirectory.Build.props&query=%2F%2FLatestFramework&logo=dotnet&label=Framework&color=%23512bd4)
[![build](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml)
[![CodeQL](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql)

## What is the purpose of this repository?

This repository is the author's personal playground for learning cryptography programming
with .NET.

It might be useful for developers who have the same problem.

However, please note that the code discussed here is based on my personal opinion and may
contain many inaccuracies.

## Technology Stack

- Language: C#
- Platform: .NET 10.0 for apps; shared libraries target net8.0 and net10.0
- Frameworks: BouncyCastle (cryptography), System.Security.Cryptography (built-in)
- Test runner: Microsoft.Testing.Platform with xUnit v3
- Supporting tools: OpenSSL, Dev Containers, GitHub Actions

## Setup

### Prerequisites

- .NET SDK (see `src/Directory.Build.props` for `LatestFramework` and `LTSFrameworks`)
- OpenSSL installed on `PATH` for local test asset generation and interoperability checks

### Dev Container (optional)

If you use the repository Dev Container, upgrade OpenSSL before generating assets or
running tests to use the latest PQC features:

```shell
# Upgrade OpenSSL in the dev container (may require rebuild or sudo)
./scripts/openssl-3.3-upgrade.sh
```

### Prepare test assets (optional)

If you want to regenerate test assets locally:

```shell
export TEST_ASSETS_PATH="$(pwd)/assets"
./scripts/openssl-generate.sh "$TEST_ASSETS_PATH"
```

### Build and test

Run from the repository root:

```shell
dotnet tool restore
dotnet restore
dotnet build
dotnet test
```

## Generate test assets with OpenSSL

Use this section when you need full details for generating and inspecting local test assets.

Note: To try the latest Post-Quantum Cryptography (PQC) features, use OpenSSL 3.3 or newer.

### Requirements

- OpenSSL must be installed and available on `PATH` for local generation and inspection
- Run the generator script from the repository root (or pass an explicit target directory)

### Generated assets

- Root CA and intermediate CA certificates
- RSA, ECDSA, and Ed25519 keys and certificates
- PKCS#7, PKCS#8, and PKCS#12 sample files
- `.password` used for encrypted PKCS files

> [!CAUTION]
> The `assets/` directory contains generated development artifacts, including private
> keys, certificates, and `.password` files.
> It is gitignored and must not be tracked or committed to the repository.

Inspect generated files with OpenSSL:

```shell
./scripts/openssl-show.sh all ./assets
```

The OpenSSL configuration used by the generator is defined in `scripts/openssl-test.cnf`.
