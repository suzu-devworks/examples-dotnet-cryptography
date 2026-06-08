# examples-dotnet-cryptography

![Dynamic XML Badge](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsuzu-devworks%2Fexamples-dotnet-cryptography%2Frefs%2Fheads%2Fmain%2Fsrc%2FDirectory.Build.props&query=%2F%2FLatestFramework&logo=dotnet&label=Framework&color=%23512bd4)
[![build](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml)
[![CodeQL](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql)

## What is this repository?

This repository contains samples and experiments on cryptographic programming using .NET.
Most of the content focuses on the Generic Host and the infrastructure commonly used in .NET applications,
such as dependency injection, configuration, logging, application lifetime management, and command-line argument handling.

The repository primarily serves as a personal knowledge base and a place to explore ideas through small, focused examples.

The examples reflect my current understanding of each topic and may evolve over time.

## What topics are covered?

- **Symmetric Cryptography**: [AES](docs/algorithms/symmetric/aes.md)
- **Asymmetric Cryptography**: [Post-Quantum Cryptography (PQC)](docs/algorithms/asymmetric/pqc.md)
- **PKCS**: [PKCS standards and usage](docs/pkcs/README.md)
- **XML Security**: [Signed XML](docs/xml/signed-xml.md), [XAdES](docs/xml/xades.md)

## Why use Dev Containers?

I recommend using Dev Containers when working with this repository.

The development container provides the tools and dependencies needed to build and run the
examples, making it easy to get started without modifying your local environment.

For container details, see [`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json).

After the container is created, run
[`.devcontainer/postCreateCommand.sh`](.devcontainer/postCreateCommand.sh)
and follow the instructions shown in the terminal.

To use the latest Post-Quantum Cryptography (PQC) features, upgrade OpenSSL inside
the container after creation:

```shell
./scripts/openssl-3.3-upgrade.sh
```

## How are test assets generated?

Test assets (CA certificates, keys, PKCS files) are generated locally using OpenSSL
and the scripts in `scripts/`. To regenerate:

```shell
export TEST_ASSETS_PATH="$(pwd)/assets"
./scripts/openssl-generate.sh "$TEST_ASSETS_PATH"
```

> [!CAUTION]
> The `assets/` directory contains generated development artifacts, including private
> keys, certificates, and `.password` files.
> It is gitignored and must not be tracked or committed to the repository.
