# Examples.Cryptography.BC.Tests

## Table of Contents <!-- omit in toc -->

- [Examples.Cryptography.BC.Tests](#examplescryptographybctests)
  - [BouncyCastle.Cryptography](#bouncycastlecryptography)
    - [Algorithms](#algorithms)
    - [PKCS](#pkcs)
    - [X.509](#x509)
  - [Development](#development)
    - [How the project was initialized](#how-the-project-was-initialized)

## BouncyCastle.Cryptography

- [Bouncy Castle C# API! ...](https://www.bouncycastle.org/csharp/index.html)

### Algorithms

- [Symmetry](./Cryptography.BouncyCastle.Tests/Algorithms/Symmetry/)
  - AES(Advanced Encryption Standard)
- [Asymmetry](./Cryptography.BouncyCastle.Tests/Algorithms/Asymmetry/)
  <!-- spell-checker: disable-next-line -->
  - RSA(Rivest-Shamir-Adleman cryptosystem)
  - DSA(Digital Signature Algorithm)
  - ECDSA(Elliptic Curve Digital Signature Algorithm)
  - EdDSA(Edwards-curve Digital Signature Algorithm)
- [Hashing](./Cryptography.BouncyCastle.Tests/Algorithms/Hashing/)
  - SHA-2(Secure Hash Algorithm 2)
  - SHA-3(Secure Hash Algorithm 3)

### PKCS

- [PKCS](./Cryptography.BouncyCastle.Tests/PKCS/)
  - PKCS #8 Private-Key Information Syntax Standard
  - PKCS #10 Certification Request Standard
  - PKCS #12 Personal Information Exchange Syntax Standard

### X.509

- [X.509](./Cryptography.BouncyCastle.Tests/X509/)
  - X.509 Certificate ([RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280))
  - CRL(Certificate Revocation List: [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280))
  - OCSP(Online Certificate Status Protocol: [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960))
  - TSP(Time-Stamp Protocol : [RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161))

## Development

### How the project was initialized

This project was initialized with the following command:

```shell
## Solution
dotnet new sln -o .

## Examples.Cryptography
dotnet new classlib -o src/Examples.Cryptography
dotnet sln add src/Examples.Cryptography/
cd src/Examples.Cryptography
cd ../../

## Examples.Cryptography.BC.Tests
dotnet new xunit -o src/Examples.Cryptography.BC.Tests
dotnet sln add src/Examples.Cryptography.BC.Tests/
cd src/Examples.Cryptography.BC.Tests
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package coverlet.collector
dotnet add package Moq
dotnet add package ChainingAssertion.Core.Xunit
dotnet add package Microsoft.Extensions.Http
dotnet add package BouncyCastle.Cryptography
dotnet add reference ../../src/Examples.Cryptography/
cd ../../

# Update outdated package
dotnet list package --outdated
```
