# Signed Xml

## Table of Contents <!-- omit in toc -->

- [Overview](#overview)
- [Core XML-DSig Elements](#core-xml-dsig-elements)
- [SignedXml class](#signedxml-class)
  - [Signature Type](#signature-type)
  - [Digest and Signature Algorithms](#digest-and-signature-algorithms)
  - [Reference and Transform](#reference-and-transform)
  - [CanonicalizationMethod](#canonicalizationmethod)
- [Implementation in .NET](#implementation-in-net)
  - [Create an Enveloped Signature](#create-an-enveloped-signature)
  - [Verify Signature](#verify-signature)
- [Practical Notes](#practical-notes)
- [References](#references)

## Overview

XML digital signatures (XML-DSig) are a W3C standard for signing XML documents.

Main goals:

- **Integrity**: Detect whether signed XML content was modified.
- **Authenticity**: Prove which key generated the signature.
- **Non-repudiation**: In PKI-based scenarios, provide evidence of signer intent.

In .NET, XML-DSig is implemented through the `System.Security.Cryptography.Xml` namespace, mainly via the `SignedXml` class.

## Core XML-DSig Elements

| Element | Role |
| --- | --- |
| `SignedInfo` | Defines what is signed and with which algorithms (canonicalization, signature method, references). |
| `Reference` | Points to target data and specifies transforms + digest method/value. |
| `SignatureValue` | Result of signing canonicalized `SignedInfo` with the signer's private key. |
| `KeyInfo` | Optional metadata for key discovery (certificate, key value, issuer/serial, etc.). |
| `Object` | Optional container for application-specific or signature-related data. |

## SignedXml class

### Signature Type

The SignedXml class allows you to create the following three kinds of XML digital signatures:

| Signature Type              | Description                                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Enveloped signature         | The signature is contained within the XML element being signed.                                                   |
| Enveloping signature        | The signed XML is contained within the \<Signature\> element.                                                     |
| Internal detached signature | The signature and signed XML are in the same document, but neither element contains the other.                    |
| External detached signature | **Not supported by the SignedXml class.** [see KB article 3148821. ...](https://support.microsoft.com/kb/3148821) |

### Digest and Signature Algorithms

Use modern algorithms unless compatibility requirements force otherwise.

| Purpose | Typical URI / Value in .NET | Notes |
| --- | --- | --- |
| Digest | `SignedXml.XmlDsigSHA256Url` | Prefer SHA-256 or stronger. |
| Signature (RSA) | `SignedXml.XmlDsigRSASHA256Url` | Recommended for RSA keys. |
| Signature (ECDSA) | `SignedXml.XmlDsigECDSAUrl` + SHA-256 digest | Framework and interoperability support should be verified. |

Avoid SHA-1 based options (`rsa-sha1`, `sha1`) for new implementations.

### Reference and Transform

For an **enveloped signature**, the `Signature` node is inserted into the same XML element being signed.
In that case, add `XmlDsigEnvelopedSignatureTransform`; otherwise, signature verification may fail because the digest input unexpectedly includes the signature itself.

Typical transform sequence for signed XML content:

1. `XmlDsigEnvelopedSignatureTransform`
2. Canonicalization transform (often exclusive canonicalization for interop scenarios)

### CanonicalizationMethod

Use the CanonicalizationMethod property to specify the canonicalization algorithm applied to the XML output of the SignedInfo class before performing signature calculations.

| Canonicalization Method               | Value                                                                | defined                                            |
| ------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------- |
| Canonical XML                         | <https://www.w3.org/TR/2001/REC-xml-c14n-20010315>                   | `SignedXml.XmlDsigCanonicalizationUrl`             |
| Canonical XML with comments           | <https://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments>      | `SignedXml.XmlDsigCanonicalizationWithCommentsUrl` |
| Exclusive Canonical XML               | <https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/>              | `SignedXml.XmlDsigExcC14NTransformUrl`             |
| Exclusive Canonical XML with comments | <https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/#WithComments> | `SignedXml.XmlDsigExcC14NWithCommentsTransformUrl` |

## Implementation in .NET

### Create an Enveloped Signature

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

var document = new XmlDocument { PreserveWhitespace = true };
document.LoadXml("""
<Invoice Id="invoice-001">
  <Amount Currency="JPY">1200</Amount>
</Invoice>
""");

using var rsa = RSA.Create(2048);

var signedXml = new SignedXml(document)
{
  SigningKey = rsa,
};

signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

var reference = new Reference("#invoice-001")
{
  DigestMethod = SignedXml.XmlDsigSHA256Url,
};

reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
reference.AddTransform(new XmlDsigExcC14NTransform());

signedXml.AddReference(reference);
signedXml.KeyInfo = new KeyInfo();
signedXml.KeyInfo.AddClause(new RSAKeyValue(rsa));

signedXml.ComputeSignature();

var xmlSignature = signedXml.GetXml();
document.DocumentElement!.AppendChild(document.ImportNode(xmlSignature, true));
```

### Verify Signature

```csharp
using System.Security.Cryptography.Xml;
using System.Xml;

var signatureNodes = document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
if (signatureNodes.Count == 0)
{
  throw new InvalidOperationException("Signature element was not found.");
}

var verifier = new SignedXml(document);
verifier.LoadXml((XmlElement)signatureNodes[0]!);

// For strict trust validation in production, verify certificate chain separately.
var isValid = verifier.CheckSignature();
```

## Practical Notes

- Set `PreserveWhitespace = true` consistently for signing and verification to avoid unintended canonicalization mismatches.
- Treat `CheckSignature()` as cryptographic validation only; perform trust validation (certificate chain, revocation, policy) separately.
- Be explicit about ID attributes (`Id`) and reference URIs (`#...`) to avoid ambiguity and wrapping-related risks.
- Prefer RSA/ECDSA with SHA-256+; keep algorithm choices aligned with your interoperability target.
- Use detached signatures when payload and signature transport are separated, but remember that external detached signatures are not directly supported by `SignedXml`.

## References

- Start here (.NET)
  - [Microsoft Learn: SignedXml class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml)
  - [Microsoft Learn: How to sign XML documents with digital signatures](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-sign-xml-documents-with-digital-signatures)
  - [Microsoft Learn: How to verify the digital signatures of XML documents](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-verify-the-digital-signatures-of-xml-documents)

- Specifications
  - [W3C XML Signature Syntax and Processing 1.1](https://www.w3.org/TR/xmldsig-core1/)
  - [W3C Exclusive XML Canonicalization](https://www.w3.org/TR/xml-exc-c14n/)

- Related
  - [ETSI XAdES baseline profile (EN 319 132)](https://www.etsi.org/standards#page=1&search=319%20132)
  - [Related: XAdES](./xades.md)
