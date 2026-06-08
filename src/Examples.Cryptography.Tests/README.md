# Examples.Cryptography.Tests

## Overview and Purpose

This project contains tests and executable examples around
`System.Security.Cryptography` APIs.

## Test Target

- [System.Security.Cryptography namespace](https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography)

## Test Index

### Algorithms

- [Asymmetry](./Cryptography.Tests/Algorithms/Asymmetric/)
  <!-- spell-checker: disable-next-line -->
  - RSA(Rivest-Shamir-Adleman cryptosystem)
  - ECDSA(Elliptic Curve Digital Signature Algorithm)
- [Symmetry](./Cryptography.Tests/Algorithms/Symmetric/)
  - AES(Advanced Encryption Standard)
- [Hashing](./Cryptography.Tests/Algorithms/Hashing/)
  - SHA-2(Secure Hash Algorithm 2)

### PQC

> PQC (Post-Quantum Cryptography)

- [PQC](./Cryptography.Tests/Pqc/)
  - ML-KEM (Module Lattice Key Encapsulation Mechanism)
    - Quantum-resistant key encapsulation for establishing a shared secret used in encryption.
  - ML-DSA (Module Lattice Digital Signature Algorithm)
    - Quantum-resistant digital signatures.
  - SLH-DSA (Stateless Hash-based Digital Signature Algorithm)
    - Quantum-resistant hash-based digital signatures.

### PKCS

> PKCS (Public-Key Cryptography Standards)

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

## References

- [xUnit.net](https://xunit.net/)
