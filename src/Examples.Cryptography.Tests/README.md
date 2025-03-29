# Examples.Cryptography.Tests

## Table of Contents <!-- omit in toc -->

- [Examples.Cryptography.Tests](#examplescryptographytests)
  - [System.Security.Cryptography](#systemsecuritycryptography)
    - [Algorithms](#algorithms)
    - [PKCS](#pkcs)
    - [X.509](#x509)
    - [XML](#xml)
  - [Development](#development)
    - [How the project was initialized](#how-the-project-was-initialized)

## System.Security.Cryptography

- [System.Security.Cryptography Namespace ...](https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography)

### Algorithms

- [Symmetry](./Cryptography.Tests/Algorithms/Symmetry/)
  - AES(Advanced Encryption Standard)
- [Asymmetry](./Cryptography.Tests/Algorithms/Asymmetry/)
  <!-- spell-checker: disable-next-line -->
  - RSA(Rivest-Shamir-Adleman cryptosystem)
  - ECDSA(Elliptic Curve Digital Signature Algorithm)
- [Hashing](./Cryptography.Tests/Algorithms/Hashing/)
  - SHA-2(Secure Hash Algorithm 2)

### PKCS

- [PKCS](./Cryptography.Tests/PKCS/)
  - PKCS #8 Private-Key Information Syntax Standard
  - PKCS #10 Certification Request Standard
  - PKCS #12 Personal Information Exchange Syntax Standard

### X.509

- [X.509](./Cryptography.Tests/X509/)
  - X.509 Certificate
  - X.509 Store

### XML

- [XML](./Cryptography.Tests/Xml/XmlSignures/)
  - XML signature
  - [XAdES](./Cryptography.Tests/Xml/XAdES/README.md)

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

## Examples.Cryptography.Tests
dotnet new xunit -o src/Examples.Cryptography.Tests
dotnet sln add src/Examples.Cryptography.Tests/
cd src/Examples.Cryptography.Tests
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package coverlet.collector
dotnet add package Moq
dotnet add package ChainingAssertion.Core.Xunit
dotnet add package System.Security.Cryptography.Xml 
dotnet add reference ../../src/Examples.Cryptography/
cd ../../

# Update outdated package
dotnet list package --outdated

# Tools config
dotnet new tool-manifest
dotnet tool install dotnet-xscgen

dotnet tool restore
```
