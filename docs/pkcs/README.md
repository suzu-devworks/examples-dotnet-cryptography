# PKCS (Public-Key Cryptography Standards)

## Table of Contents <!-- omit in toc -->

- [Overview](#overview)
- [PKCS Standards Summary](#pkcs-standards-summary)
- [PKCS Covered in This Repository](#pkcs-covered-in-this-repository)
- [.NET API Mapping (Quick Reference)](#net-api-mapping-quick-reference)
- [Common Encodings and Containers](#common-encodings-and-containers)
- [References](#references)

## Overview

PKCS (Public-Key Cryptography Standards) is a family of specifications originally defined by RSA Laboratories.
Although many items have since moved to IETF RFCs or other standards bodies, the PKCS naming remains the de-facto vocabulary in engineering practice.

In practical .NET development, PKCS usually appears in the following areas:

- key and key-package formats (PKCS #8, #12)
- certificate request formats (PKCS #10)
- signed/enveloped message syntax (PKCS #7 / CMS)
- password-based key derivation and encryption schemes (PKCS #5)

## PKCS Standards Summary

|          | Name                                            | Comments                                                                |
| -------- | ----------------------------------------------- | ----------------------------------------------------------------------- |
| PKCS #1  | RSA Cryptography Standard                       | [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)               |
| PKCS #2  | (Withdrawn)                                     |                                                                         |
| PKCS #3  | Diffie–Hellman Key Agreement Standard           |                                                                         |
| PKCS #4  | (Withdrawn)                                     |                                                                         |
| PKCS #5  | Password-based Encryption Standard              | [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018), PBKDF2       |
| PKCS #6  | Extended-Certificate Syntax Standard            | Obsoleted by X.509 v3                                                   |
| PKCS #7  | Cryptographic Message Syntax Standard           | [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652)               |
| PKCS #8  | Private-Key Information Syntax Standard         | [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958)               |
| PKCS #9  | Selected Attribute Types                        | [RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985)               |
| PKCS #10 | Certification Request Standard                  | [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986)               |
| PKCS #11 | Cryptographic Token Interface                   | Turned over to the OASIS PKCS 11 Technical Committee.                   |
| PKCS #12 | Personal Information Exchange Syntax Standard   | [RFC 7292](https://datatracker.ietf.org/doc/html/rfc7292)               |
| PKCS #13 | Elliptic-curve cryptography Standard            | Apparently abandoned.                                                   |
| PKCS #14 | Pseudo-random Number Generation                 | Apparently abandoned.                                                   |
| PKCS #15 | Cryptographic Token Information Format Standard | Relinquished IC-card-related parts of this standard to ISO/IEC 7816-15. |

## PKCS Covered in This Repository

This repository currently focuses mainly on the following PKCS specifications:

- PKCS #7 (CMS): certificate collections and signed-data-related handling
- PKCS #8: private key package import/export and encrypted private key handling
- PKCS #10: certificate signing request (CSR) creation and parsing
- PKCS #12 (PFX/P12): personal information exchange container handling

Related learning runners and implementations are placed under these folders:

- `src/Examples.Cryptography.Tests/Cryptography.Tests/Pkcs/`
- `src/Examples.Cryptography.BouncyCastle.Tests/Cryptography.BouncyCastle.Tests/Pkcs/`
- `src/Examples.Cryptography.BouncyCastle/Cryptography.BouncyCastle/Pkcs/`

## .NET API Mapping (Quick Reference)

| PKCS | Typical .NET APIs | Notes |
| --- | --- | --- |
| #5 | `Rfc2898DeriveBytes` | PBKDF2 key derivation |
| #7 (CMS) | `System.Security.Cryptography.Pkcs` namespace | Signed/enveloped message processing |
| #8 | `ImportPkcs8PrivateKey`, `ImportEncryptedPkcs8PrivateKey`, `ExportPkcs8PrivateKey` | Key algorithm types (RSA/ECDsa/etc.) expose import/export helpers |
| #10 | `CertificateRequest` + custom encoding/decoding helpers | CSR generation and signing flows |
| #12 | `X509Certificate2`, `X509CertificateLoader` | PFX/P12 import/export and key binding |

## Common Encodings and Containers

PKCS content is often represented in either DER (binary) or PEM (Base64 with header/footer) form.

- DER examples: `.p8`, `.p10`, `.p12`, `.p7b`
- PEM examples: `-----BEGIN PRIVATE KEY-----`, `-----BEGIN CERTIFICATE REQUEST-----`, `-----BEGIN PKCS7-----`

When validating interoperability with OpenSSL, the same semantic object can be converted between DER and PEM without changing cryptographic meaning.

## References

- [RFC 5652: Cryptographic Message Syntax (CMS, related to PKCS #7)](https://datatracker.ietf.org/doc/html/rfc5652)
- [RFC 5958: Asymmetric Key Packages (related to PKCS #8)](https://datatracker.ietf.org/doc/html/rfc5958)
- [RFC 2986: Certification Request Syntax Specification (PKCS #10)](https://datatracker.ietf.org/doc/html/rfc2986)
- [RFC 7292: PKCS #12](https://datatracker.ietf.org/doc/html/rfc7292)
- [Microsoft Learn: System.Security.Cryptography.Pkcs namespace](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs)
