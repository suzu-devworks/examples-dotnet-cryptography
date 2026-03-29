# Post-Quantum Cryptography (PQC)

## Overview

Post-Quantum Cryptography (PQC) is a family of cryptographic algorithms designed to remain secure even if large-scale quantum computers become practical.

Classical public-key algorithms such as RSA, ECDH, and ECDSA are expected to be breakable by Shor's algorithm on a sufficiently powerful quantum computer. PQC provides drop-in successors for key exchange and digital signatures.

## Why PQC is Needed

- Protect future data confidentiality from "harvest now, decrypt later" attacks.
- Prepare long-lived systems (PKI, firmware signing, archives) for quantum-era security.
- Reduce migration risk by introducing quantum-resistant algorithms before large quantum computers arrive.

## Main Roles in This Repository

- ML-KEM (FIPS 203)
  - Purpose: Key establishment (KEM).
  - Typical use: Establish a shared secret, then use symmetric encryption (for example AES-GCM) for bulk data.
  - Replacement target: ECDH key agreement and RSA key transport.
- ML-DSA (FIPS 204)
  - Purpose: Digital signatures.
  - Typical use: Document signing, API/auth token signing, code signing, certificate-related signatures.
  - Replacement target: ECDSA and RSA signatures.
- SLH-DSA (FIPS 205)
  - Purpose: Digital signatures with hash-based security assumptions.
  - Typical use: High-assurance signing scenarios where conservative assumptions are preferred.
  - Trade-off: Very small keys but larger signatures.

## Practical Adoption Pattern

1. Start with key establishment migration: classical key exchange -> ML-KEM.
2. Migrate signature workflows: ECDSA/RSA -> ML-DSA or SLH-DSA.
3. Use hybrid designs during transition where interoperability is required.

## Notes

- PQC is not a replacement for symmetric cryptography. It mainly replaces public-key primitives.
- Symmetric algorithms (AES, SHA-2/3, HMAC) remain core building blocks and are still required.
- Platform support may depend on runtime and native crypto provider versions.

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [Microsoft Learn: Cryptography model](https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
