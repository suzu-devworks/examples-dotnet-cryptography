# examples-dotnet-cryptography

![Dynamic XML Badge](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsuzu-devworks%2Fexamples-dotnet-cryptography%2Frefs%2Fheads%2Fmain%2Fsrc%2FDirectory.Build.props&query=%2F%2FLatestFramework&logo=dotnet&label=Framework&color=%23512bd4)
[![build](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/dotnet-build.yml)
[![CodeQL](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/suzu-devworks/examples-dotnet-cryptography/actions/workflows/github-code-scanning/codeql)

## What is the purpose of this repository?

This repository is the author's personal playground for learning cryptography programming with .NET.

It might be useful for developers who have the same problem.

However, please note that the code discussed here is based on my personal opinion and may contain many inaccuracies.

## Current learning topics

- Classical cryptography with .NET `System.Security.Cryptography`
- Post-quantum cryptography (PQC)
  - ML-KEM key encapsulation (shared secret establishment for encryption)
  - ML-DSA and SLH-DSA digital signatures
- XML digital signatures and XAdES (XML Advanced Electronic Signatures)
  - XAdES-BES, XAdES-T, XAdES-C, XAdES-X, XAdES-X-L, XAdES-A levels
  - Schema-based approach using ETSI TS 101 903 XSD schemas with `dotnet-xscgen`
