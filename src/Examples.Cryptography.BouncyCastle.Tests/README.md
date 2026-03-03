# Examples.Cryptography.BouncyCastle.Tests

## Table of Contents <!-- omit in toc -->

- [Org.BouncyCastle](#orgbouncycastle)
  - [Algorithms](#algorithms)
- [Development](#development)
  - [How the project was initialized](#how-the-project-was-initialized)

## Org.BouncyCastle

- [Bouncy Castle for C# .NET ...](https://www.bouncycastle.org/documentation/documentation-c/)

### Algorithms

- [Asymmetry](./Cryptography.BouncyCastle.Tests/Algorithms/Asymmetric/)
  <!-- spell-checker: disable-next-line -->
  - RSA(Rivest-Shamir-Adleman cryptosystem)
  - DSA(Digital Signature Algorithm)
  - ECDSA(Elliptic Curve Digital Signature Algorithm)
  - EdDSA(Edwards-curve Digital Signature Algorithm)
- [Symmetry](./Cryptography.BouncyCastle.Tests/Algorithms/Symmetric/)
  - AES(Advanced Encryption Standard)
- [Hashing](./Cryptography.BouncyCastle.Tests/Algorithms/Hashing/)
  - SHA-2(Secure Hash Algorithm 2)
  - SHA-3(Secure Hash Algorithm 3)

## Development

### How the project was initialized

This project was initialized with the following command:

```shell
## Solution
dotnet new sln -o .

## Examples.Cryptography.BouncyCastle.Tests
dotnet new xunit3 -o src/Examples.Cryptography.BouncyCastle.Tests
dotnet sln add src/Examples.Cryptography.BouncyCastle.Tests/
cd src/Examples.Cryptography.BouncyCastle.Tests
dotnet add package xunit.v3.mtp-v2
dotnet add package Microsoft.Testing.Extensions.CodeCoverage
dotnet add package BouncyCastle.Cryptography

dotnet add reference ../Examples.Cryptography/
cd ../../

# Update outdated package
dotnet list package --outdated
```
