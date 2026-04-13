# examples-dotnet-cryptography

![Dynamic XML Badge](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsuzu-devworks%2Fexamples-dotnet-cryptography%2Frefs%2Fheads%2Fmain%2Fsrc%2FDirectory.Build.props&query=%2F%2FLatestFramework&logo=dotnet&label=Framework&color=%23512bd4)
[![build](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml)
[![CodeQL](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql)

## What is the purpose of this repository?

This repository is the author's personal playground for learning cryptography programming with .NET.

It might be useful for developers who have the same problem.

However, please note that the code discussed here is based on my personal opinion and may contain many inaccuracies.

## Generate test assets with OpenSSL

This repository includes OpenSSL scripts for generating test certificates, keys, and container files under the `assets` directory.

Requirements:

- OpenSSL must be installed and available on `PATH`
- Run the script from the repository root

Generate or refresh the test assets:

```shell
./scripts/openssl-generate.sh ./assets
```

The script generates development-only assets such as the following:

- Root CA and intermediate CA certificates
- RSA, ECDSA, and Ed25519 keys and certificates
- PKCS#7, PKCS#8, and PKCS#12 sample files
- `.password` used for encrypted PKCS files

> [!CAUTION]
> The `assets/` directory contains generated development artifacts, including private keys, certificates, and `.password` files.
> It is gitignored and must not be tracked or committed to the repository.

Inspect generated files with OpenSSL:

```shell
./scripts/openssl-show.sh all ./assets
```

The OpenSSL configuration used by the generator is defined in `scripts/openssl-test.cnf`.
