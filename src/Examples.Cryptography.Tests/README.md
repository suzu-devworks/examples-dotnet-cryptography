# Examples.Cryptography.Tests

## Table of Contents <!-- omit in toc -->

- [System.Security.Cryptography](#systemsecuritycryptography)
  - [Algorithms](#algorithms)
  - [PKCS](#pkcs)
  - [X.509](#x509)
- [Development](#development)
  - [How the project was initialized](#how-the-project-was-initialized)

## System.Security.Cryptography

- [System.Security.Cryptography Namespace ...](https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography)

### Algorithms

- [Asymmetry](./Cryptography.Tests/Algorithms/Asymmetric/)
  <!-- spell-checker: disable-next-line -->
  - RSA(Rivest-Shamir-Adleman cryptosystem)
  - ECDSA(Elliptic Curve Digital Signature Algorithm)
- [Symmetry](./Cryptography.Tests/Algorithms/Symmetric/)
  - AES(Advanced Encryption Standard)
- [Hashing](./Cryptography.Tests/Algorithms/Hashing/)
  - SHA-2(Secure Hash Algorithm 2)

### PKCS

- [PKCS #7](./Cryptography.Tests/Pkcs/Pkcs7/)
  - PKCS #7 CertificateSet - Cryptographic Message Syntax Standard
- [PKCS #8](./Cryptography.Tests/Pkcs/Pkcs8/)
  - PKCS #8 Private-Key Information Syntax Standard
- [PKCS #10](./Cryptography.Tests/Pkcs/Pkcs10/)
  - PKCS #10 Certification Request Standard
- [PKCS #12](./Cryptography.Tests/Pkcs/Pkcs12/)
  - PKCS #12 Personal Information Exchange Syntax Standard

### X.509

- [X.509](./Cryptography.Tests/X509/)

## Development

### How the project was initialized

This project was initialized with the following command:

```shell
## Solution
dotnet new sln -o .

## Examples.Cryptography.Tests
dotnet new xunit3 -o src/Examples.Cryptography.Tests
dotnet sln add src/Examples.Cryptography.Tests/
cd src/Examples.Cryptography.Tests
dotnet add package xunit.v3.mtp-v2
dotnet add package Microsoft.Testing.Extensions.CodeCoverage
dotnet add package System.Security.Cryptography.Pkcs

dotnet add reference ../Examples.Cryptography/
cd ../../

# Update outdated package
dotnet list package --outdated
```
