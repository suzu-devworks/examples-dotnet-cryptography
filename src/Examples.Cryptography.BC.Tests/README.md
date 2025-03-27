# Examples.Cryptography.BC.Tests

## Table of Contents <!-- omit in toc -->

- [Examples.Cryptography.BC.Tests](#examplescryptographybctests)
  - [BouncyCastle.Cryptography](#bouncycastlecryptography)
    - [Algorithms](#algorithms)
    - [PKCS](#pkcs)
    - [X509](#x509)
  - [Development](#development)
    - [How the project was initialized](#how-the-project-was-initialized)

## BouncyCastle.Cryptography

- [Bouncy Castle C# API! ...](https://www.bouncycastle.org/csharp/index.html)

### Algorithms

- [Symmetry](./Cryptography.BouncyCastle.Tests/Algorithms/Symmetry/)
- [Asymmetry](./Cryptography.BouncyCastle.Tests/Algorithms/Asymmetry/)
- [Hashing](./Cryptography.BouncyCastle.Tests/Algorithms/Hashing/)

### PKCS

- [PKCS](./Cryptography.BouncyCastle.Tests/PKCS/)

### PKIX

- [PKIX](./Cryptography.BouncyCastle.Tests/PKIX/)

### X509

- [X509](./Cryptography.BouncyCastle.Tests/X509/)

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
