# Examples.Cryptography.Tests

## Table of Contents <!-- omit in toc -->

- [Examples.Cryptography.Tests](#examplescryptographytests)
  - [System.Security.Cryptography](#systemsecuritycryptography)
    - [Algorithms](#algorithms)
    - [PKCS](#pkcs)
    - [X509](#x509)
    - [XML](#xml)
  - [Development](#development)
    - [How the project was initialized](#how-the-project-was-initialized)

## System.Security.Cryptography

- [System.Security.Cryptography Namespace ...](https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography)

### Algorithms

- [Symmetry](./Cryptography.Tests/Algorithms/Symmetry/)
- [Asymmetry](./Cryptography.Tests/Algorithms/Asymmetry/)
- [Hashing](./Cryptography.Tests/Algorithms/Hashing/)

### PKCS

- [PKCS](./Cryptography.Tests/PKCS/)

### X509

- [X509](./Cryptography.Tests/X509/)

### XML

- [XML](./Cryptography.Tests/Xml/)
- [XAdES](./Cryptography.Tests/Xml/XAdES/)

The package provides Xml wrapper classes related to SignedXml, but does not provide classes related to XAdES.
However, having wrapper classes would make implementation easier.

I downloaded the XAdES schema file from the link below and ran `dotnet-xscgen` to create the classes.

- <https://uri.etsi.org/01903/v1.4.1/>

[XmlSampleGenerator.Build.targets](./XmlSampleGenerator.Build.targets) for information on how to generate it.

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
