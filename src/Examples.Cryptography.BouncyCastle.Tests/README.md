# Examples.Cryptography.BouncyCastle.Tests

## Overview and Purpose

This project contains tests and executable examples for cryptographic features based on
Org.BouncyCastle.

## Test Target

- [Bouncy Castle for C# .NET ...](https://www.bouncycastle.org/documentation/documentation-c/)

## Test Index

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

### PKCS

- [PKCS #8](./Cryptography.BouncyCastle.Tests/Pkcs/Pkcs8/)
  - PKCS #8 Private-Key Information Syntax Standard
- [PKCS #10](./Cryptography.BouncyCastle.Tests/Pkcs/Pkcs10/)
  - PKCS #10 Certification Request Standard
- [PKCS #12](./Cryptography.BouncyCastle.Tests/Pkcs/Pkcs12/)
  - PKCS #12 Personal Information Exchange Syntax Standard

### X.509

- [X.509](./Cryptography.BouncyCastle.Tests/X509/)
- [X509 Revocations](./Cryptography.BouncyCastle.Tests/X509/Revocations/)
- [TimeStamp](./Cryptography.BouncyCastle.Tests/X509/TimeStamp/)

## References

- [xUnit.net](https://xunit.net/)
- [BouncyCastle.Cryptography NuGet](https://www.nuget.org/packages/BouncyCastle.Cryptography)
