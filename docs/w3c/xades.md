# XAdES (XML Advanced Electronic Signatures)

## Table of Contents <!-- omit in toc -->

- [Overview](#overview)
- [XAdES Signature Levels](#xades-signature-levels)
  - [Basic Levels](#basic-levels)
  - [Extended Levels (Long-term validation)](#extended-levels-long-term-validation)
- [Key Features](#key-features)
- [XAdES vs XML-DSig](#xades-vs-xml-dsig)
- [Implementation in .NET](#implementation-in-net)
  - [Standard .NET Libraries](#standard-net-libraries)
  - [Basic Approach](#basic-approach)
- [References](#references)

## Overview

**XAdES** (XML Advanced Electronic Signatures) is an extension specification for XML signatures standardized by ETSI (European Telecommunications Standards Institute). Based on W3C XML Signature (XML-DSig), it defines additional elements to achieve legally valid electronic signatures and long-term verifiability.

XAdES is widely adopted as an electronic signature format that complies with the European Union's eIDAS regulation (electronic IDentification, Authentication and trust Services).

## XAdES Signature Levels

XAdES defines multiple signature levels to enhance signature verifiability and legal validity.

### Basic Levels

| Level | Full Name | Description |
| --- | --- | --- |
| **XAdES-BES** | Basic Electronic Signature | The most basic XAdES signature. Includes signer's certificate information, signing time, signature policy, etc. |
| **XAdES-EPES** | Explicit Policy-based Electronic Signature | In addition to XAdES-BES, includes an explicit signature policy identifier |

### Extended Levels (Long-term validation)

| Level | Full Name | Description |
| --- | --- | --- |
| **XAdES-T** | Electronic Signature with Time | Adds a trusted timestamp to XAdES-BES or EPES. Enables proof of signing time |
| **XAdES-C** | Electronic Signature with Complete validation data | Includes references to certificates and revocation information required for signature verification |
| **XAdES-X** | eXtended Electronic Signature | Adds additional timestamps to XAdES-C for long-term preservation |
| **XAdES-X-L** | eXtended Long-term Electronic Signature | Embeds actual certificate and revocation data into XAdES-X |
| **XAdES-A** | Archival Electronic Signature | Adds archive timestamps to guarantee the longest-term verifiability |

```console
XAdES-BES ──→ XAdES-T ──→ XAdES-C ──→ XAdES-X ──→ XAdES-X-L ──→ XAdES-A
    ↓
XAdES-EPES ──→ (same progression as above)
```

## Key Features

1. **Explicit Signature Attributes**
   - Signing time (SigningTime)
   - Signer's certificate (SigningCertificate)
   - Signature policy (SignaturePolicy)
   - Signer role (SignerRole)
   - Signature production place (SignatureProductionPlace)

2. **Long-term Verifiability**
   - Proof of signing time via timestamps (XAdES-T and above)
   - Preservation of certificate chain information (XAdES-C and above)
   - Incorporation of revocation information (CRL/OCSP) (XAdES-X-L and above)
   - Long-term preservation via archive timestamps (XAdES-A)

3. **Legal Validity**
   - Qualified electronic signature format compliant with eIDAS regulation
   - Explicit legal requirements through signature policy
   - Provision of audit trails

## XAdES vs XML-DSig

| Feature | XML-DSig (W3C) | XAdES (ETSI) |
| --- | --- | --- |
| **Purpose** | Electronic signatures for XML documents | Advanced electronic signatures with legal validity |
| **Standardization** | W3C Recommendation | ETSI Standard (TS 101 903) |
| **Long-term validation** | Not supported | Timestamps, certificate and revocation information preservation |
| **Signature policy** | Not supported | Supports explicit policy identifiers |
| **Legal compliance** | General signature verification | eIDAS, eSignature compliant |
| **Complexity** | Simple | Feature-rich but complex |

XAdES is an extension of XML-DSig, and all XAdES signatures are also valid XML-DSig signatures.

## Implementation in .NET

### Standard .NET Libraries

The `System.Security.Cryptography.Xml` namespace in .NET supports W3C XML-DSig, but **does not natively support XAdES**.

To implement XAdES, one of the following approaches is required:

1. **Manual implementation**: Extend the `SignedXml` class and manually add XAdES-specific elements
2. **Third-party libraries**:
   - [FirmaXadesNet](https://github.com/ctt-gob-es/FirmaXadesNet) - XAdES signature library
   - [DSS (Digital Signature Service)](https://github.com/esig/dss) - Java implementation but can be used as reference
   - BouncyCastle - Can be used as cryptographic foundation

### Basic Approach

```csharp
// Create XML-DSig based signature
var signedXml = new SignedXml(xmlDocument);

// Manually add XAdES-specific elements
var qualifyingProperties = CreateQualifyingProperties();
var xadesObject = new DataObject();
xadesObject.Data = qualifyingProperties.SelectNodes(".");
xadesObject.Id = "XadesObjectId";

signedXml.AddObject(xadesObject);

// Compute and add signature
signedXml.ComputeSignature();
```

**Note**: A complete XAdES implementation requires many additional implementations, such as signature policy, integration with timestamp services, and certificate validation logic.

## References

- [ETSI TS 101 903 - XAdES Specification](https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/)
- [W3C XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core/)
- [W3C Canonical XML](https://www.w3.org/TR/xml-c14n)
- [eIDAS Regulation (EU)](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation)
- [Microsoft: SignedXml Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml)
- [Related: Signed XML](./signed-xml.md)
