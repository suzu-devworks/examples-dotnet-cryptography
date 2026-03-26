# Signed Xml

## Table of Contents <!-- omit in toc -->

- [Signed Xml](#signed-xml)
  - [SignedXml class](#signedxml-class)
    - [Signature Type](#signature-type)
    - [CanonicalizationMethod](#canonicalizationmethod)

## SignedXml class

### Signature Type

The SignedXml class allows you to create the following three kinds of XML digital signatures:

| Signature Type              | Description                                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Enveloped signature         | The signature is contained within the XML element being signed.                                                   |
| Enveloping signature        | The signed XML is contained within the \<Signature\> element.                                                     |
| Internal detached signature | The signature and signed XML are in the same document, but neither element contains the other.                    |
| External detached signature | **Not supported by the SignedXml class.** [see KB article 3148821. ...](https://support.microsoft.com/kb/3148821) |

### CanonicalizationMethod

Use the CanonicalizationMethod property to specify the canonicalization algorithm applied to the XML output of the SignedInfo class before performing signature calculations.

| Canonicalization Method               | Value                                                                | defined                                            |
| ------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------- |
| Canonical XML                         | <https://www.w3.org/TR/2001/REC-xml-c14n-20010315>                   | `SignedXml.XmlDsigCanonicalizationUrl`             |
| Canonical XML with comments           | <https://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments>      | `SignedXml.XmlDsigCanonicalizationWithCommentsUrl` |
| Exclusive Canonical XML               | <https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/#WithComments> | `SignedXml.XmlDsigExcC14NTransformUrl`             |
| Exclusive Canonical XML with comments | <https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/#WithComments> | `SignedXml.XmlDsigExcC14NWithCommentsTransformUrl` |

<!-- spell-checker:words Dsig -->
