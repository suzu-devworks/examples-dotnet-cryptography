using Examples.Cryptography.Extensions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Asn1;

/// <summary>
/// Extension methods for ASN1 parsing for <see cref="TimeStampToken"/>.
/// </summary>
public static class TimeStampTokenExtensions
{
    public static string ToStructureString(this TimeStampToken timeStampToken)
    {
        using var writer = new StringWriter();
        WriteStructure(writer, timeStampToken);
        return writer.ToString();
    }

    /// <summary>
    /// Writes the structure of the <see cref="TimeStampToken"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="writer">The text writer to write the structure to.</param>
    /// <param name="timeStampToken">The timestamp token to write the structure for.</param>
    public static void WriteStructure(TextWriter writer, TimeStampToken timeStampToken)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

        // ```asn.1
        // TimeStampToken ::= ContentInfo
        //      -- contentType is id - signedData([CMS])
        //      -- content is SignedData([CMS])
        // ```

        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-3

        // ```asn.1
        // ContentInfo ::= SEQUENCE {
        //     contentType ContentType,
        //     content [0] EXPLICIT ANY DEFINED BY contentType }
        //
        // ContentType ::= OBJECT IDENTIFIER
        // ```
        var contentInfo = ContentInfo.GetInstance(timeStampToken.GetEncoded());

        writer.WriteLine("TimeStampToken ::= {");
        writer.WriteLine($"             contentType: id-signedData({contentInfo.ContentType})");
        writer.WriteLine($"             content [0]: ...");

        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-5.1

        // ```asn.1
        // SignedData ::= SEQUENCE {
        //      version             CMSVersion,
        //      digestAlgorithms    DigestAlgorithmIdentifiers,
        //      encapContentInfo    EncapsulatedContentInfo,
        //      certificates    [0] IMPLICIT CertificateSet OPTIONAL,
        //      crls            [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        //      signerInfos         SignerInfos }
        //
        // DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
        //
        // SignerInfos ::= SET OF SignerInfo
        // ```
        /* spell-checker: words crls encap */
        var signedData = timeStampToken.ToCmsSignedData().SignedData;

        writer.WriteLine($"                 version: {signedData.Version}");
        writer.WriteLine($"        digestAlgorithms: ... ");
        foreach (var (digestAlgorithm, index) in signedData.DigestAlgorithms.Select((a, index) => (a, index)))
        {
            writer.WriteLine($"                        : --- digestAlgorithms[{index}] --- ");
            WriteDigestAlgorithmIdentifierStructure(writer, AlgorithmIdentifier.GetInstance(digestAlgorithm));
            writer.WriteLine($"                        : --- digestAlgorithms[{index}] end --- ");
        }

        writer.WriteLine($"        encapContentInfo: ... ");
        WriteEncapsulatedContentInfoStructure(writer, signedData.EncapContentInfo);

        if (signedData.Certificates is not null)
        {
            // OPTIONAL
            writer.WriteLine($"        certificates [0]: ... ");
            foreach (var (certificate, index) in signedData.Certificates.Select((c, index) => (c, index)))
            {
                writer.WriteLine($"                        : --- certificates[{index}] --- ");
                WriteX509CertificateStructure(writer, X509CertificateStructure.GetInstance(certificate));
                writer.WriteLine($"                        : --- certificates[{index}] end --- ");
            }
        }

        if (signedData.CRLs is not null)
        {
            // OPTIONAL
            writer.WriteLine($"                crls [1]: ... ");
            foreach (var (crl, index) in signedData.CRLs.Select((c, index) => (c, index)))
            {
                writer.WriteLine($"                        : --- crls[{index}] --- ");
                WriteCertificateListStructure(writer, CertificateList.GetInstance(crl));
                writer.WriteLine($"                        : --- crls[{index}] end --- ");
            }
        }

        writer.WriteLine($"             signerInfos: ... ");
        foreach (var (signerInfo, index) in signedData.SignerInfos.Select((s, index) => (s, index)))
        {
            writer.WriteLine($"                        : --- signerInfos[{index}] --- ");
            WriteSignerInfoStructure(writer, SignerInfo.GetInstance(signerInfo));
            writer.WriteLine($"                        : --- signerInfos[{index}] end --- ");
        }

        writer.WriteLine("}");
    }

    private static void WriteAlgorithmIdentifierStructure(TextWriter writer, AlgorithmIdentifier algorithmId)
    {
        // RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2

        // ```asn.1
        // AlgorithmIdentifier  ::=  SEQUENCE  {
        //      algorithm               OBJECT IDENTIFIER,
        //      parameters              ANY DEFINED BY algorithm OPTIONAL  }
        // ```
        writer.WriteLine($"               algorithm: {algorithmId.Algorithm}");

        if (algorithmId.Parameters is not null)
        {
            writer.WriteLine($"              parameters: {algorithmId.Parameters}");
        }
    }

    private static void WriteDigestAlgorithmIdentifierStructure(TextWriter writer, AlgorithmIdentifier digestAlgorithmId)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-10.1.1

        // ```asn.1
        // DigestAlgorithmIdentifier ::= AlgorithmIdentifier
        // ```
        WriteAlgorithmIdentifierStructure(writer, digestAlgorithmId);
    }

    private static void WriteSignatureAlgorithmIdentifier(TextWriter writer, AlgorithmIdentifier signatureAlgorithmId)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-10.1.2

        // ```asn.1
        // SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
        // ```
        WriteAlgorithmIdentifierStructure(writer, signatureAlgorithmId);
    }

    private static void WriteEncapsulatedContentInfoStructure(TextWriter writer, ContentInfo encapContentInfo)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-5.2

        // ```asn.1
        // EncapsulatedContentInfo ::= SEQUENCE {
        //      eContentType ContentType,
        //      eContent [0] EXPLICIT OCTET STRING OPTIONAL }

        // ContentType ::= OBJECT IDENTIFIER
        // ```
        writer.WriteLine($"            eContentType: id-ct-TSTInfo({encapContentInfo.ContentType})");
        writer.WriteLine($"            eContent [0]: ...");

        Asn1OctetString content = (Asn1OctetString)encapContentInfo.Content;
        WriteTstInfoStructure(writer, TstInfo.GetInstance(content.GetOctets()));
    }

    private static void WriteTstInfoStructure(TextWriter writer, TstInfo tstInfo)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

        // ```asn.1
        // TSTInfo ::= SEQUENCE  {
        //      version             INTEGER  { v1(1) },
        //      policy              TSAPolicyId,
        //      messageImprint      MessageImprint,
        //      serialNumber        INTEGER,
        //      genTime             GeneralizedTime,
        //      accuracy            Accuracy OPTIONAL,
        //      ordering            BOOLEAN DEFAULT FALSE,
        //      nonce               INTEGER OPTIONAL,
        //      tsa             [0] GeneralName OPTIONAL,
        //      extensions      [1] IMPLICIT Extensions  OPTIONAL   }
        //
        // TSAPolicyId ::= OBJECT IDENTIFIER
        // ```
        writer.WriteLine($"                 version: {tstInfo.Version}");
        writer.WriteLine($"                  policy: {tstInfo.Policy}");
        writer.WriteLine($"          messageImprint: ... ");
        WriteMessageImprintStructure(writer, tstInfo.MessageImprint);

        writer.WriteLine($"            serialNumber: {tstInfo.SerialNumber.LongValueExact:x}");
        writer.WriteLine($"                 genTime: {tstInfo.GenTime.ToDateTime():o}");

        if (tstInfo.Accuracy is not null)
        {
            // OPTIONAL
            writer.WriteLine($"                accuracy: ... ");
            WriteAccuracyStructure(writer, tstInfo.Accuracy);
        }

        writer.WriteLine($"                ordering: {tstInfo.Ordering}");

        if (tstInfo.Nonce is not null)
        {
            // OPTIONAL
            writer.WriteLine($"                   nonce: {tstInfo.Nonce.LongValueExact:x}");
        }

        if (tstInfo.Tsa is not null)
        {
            // OPTIONAL
            writer.WriteLine($"                    tsa: {tstInfo.Tsa}");
        }

        if (tstInfo.Extensions is not null)
        {
            // OPTIONAL
            writer.WriteLine($"             extensions: {tstInfo.Extensions}");
        }
    }

    private static void WriteMessageImprintStructure(TextWriter writer, MessageImprint messageImprint)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1

        // ```asn.1
        // MessageImprint ::= SEQUENCE  {
        //      hashAlgorithm       AlgorithmIdentifier,
        //      hashedMessage       OCTET STRING  }
        // ```
        writer.WriteLine($"           hashAlgorithm: ... ");
        WriteAlgorithmIdentifierStructure(writer, messageImprint.HashAlgorithm);

        writer.WriteLine($"           hashedMessage: {messageImprint.GetHashedMessage().ToBase64String()}");
    }

    private static void WriteAccuracyStructure(TextWriter writer, Accuracy accuracy)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1

        // ```asn.1
        // Accuracy ::= SEQUENCE {
        //      seconds        INTEGER              OPTIONAL,
        //      millis     [0] INTEGER  (1..999)    OPTIONAL,
        //      micros     [1] INTEGER  (1..999)    OPTIONAL  }
        // ```
        // spell-checker: words millis
        if (accuracy.Seconds is not null)
        {
            writer.WriteLine($"                seconds: {accuracy.Seconds}");
        }

        if (accuracy.Millis is not null)
        {
            writer.WriteLine($"                millis: {accuracy.Millis}");
        }

        if (accuracy.Micros is not null)
        {
            writer.WriteLine($"                micros: {accuracy.Micros}");
        }
    }

    private static void WriteX509CertificateStructure(TextWriter writer, X509CertificateStructure certificate)
    {
        writer.WriteLine($"                  issuer: {certificate.Issuer}");
        writer.WriteLine($"            serialNumber: {certificate.SerialNumber.LongValueExact:x}");
        writer.WriteLine($"                 subject: {certificate.Subject}");
    }

    private static void WriteCertificateListStructure(TextWriter writer, CertificateList crl)
    {
        writer.WriteLine($"                  issuer: {crl.Issuer}");
        writer.WriteLine($"              thisUpdate: {crl.ThisUpdate.ToDateTime():o}");
        foreach (var (entry, index) in crl.GetRevokedCertificates().Select((e, i) => (e, i)))
        {
            var reasonCode = entry.Extensions.GetExtensionValue(X509Extensions.ReasonCode);
            var reason = new CrlReason(DerEnumerated.GetInstance(X509ExtensionUtilities.FromExtensionValue(reasonCode)));

            writer.Write($"                        : [{index}]");
            writer.Write($" {entry.RevocationDate.ToDateTime():o}");
            writer.Write($", {entry.UserCertificate.LongValueExact:x}");
            writer.Write($", {reason}");
            writer.WriteLine();
        }
    }

    private static void WriteSignerInfoStructure(TextWriter writer, SignerInfo signerInfo)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3

        // ```asn.1
        // SignerInfo   ::= SEQUENCE {
        //      version             CMSVersion,
        //      sid                 SignerIdentifier,
        //      digestAlgorithm     DigestAlgorithmIdentifier,
        //      signedAttrs     [0] IMPLICIT SignedAttributes OPTIONAL,
        //      signatureAlgorithm  SignatureAlgorithmIdentifier,
        //      signature           SignatureValue,
        //      unsignedAttrs   [1] IMPLICIT UnsignedAttributes OPTIONAL }
        //
        // SignerIdentifier ::= CHOICE {
        //      issuerAndSerialNumber IssuerAndSerialNumber,
        //      subjectKeyIdentifier [0] SubjectKeyIdentifier }
        //
        // SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
        //
        // UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
        //
        // Attribute ::= SEQUENCE {
        //      attrType OBJECT IDENTIFIER,
        //      attrValues SET OF AttributeValue }
        //
        // AttributeValue ::= ANY
        //
        // SignatureValue ::= OCTET STRING
        // ```
        writer.WriteLine($"                 version: {signerInfo.Version}");
        writer.WriteLine($"                     sid: ... ");
        WriteSignerIDStructure(writer, signerInfo.SignerID);

        writer.WriteLine($"         digestAlgorithm: ... ");
        WriteDigestAlgorithmIdentifierStructure(writer, signerInfo.DigestAlgorithm);

        if (signerInfo.SignedAttrs is not null)
        {
            // OPTIONAL
            writer.WriteLine($"             signedAttrs: ... ");
            foreach (var (attr, index) in signerInfo.SignedAttrs.Select((a, i) => (a, i)))
            {
                writer.WriteLine($"                        : --- signedAttrs[{index}] --- ");
                WriteAttributeStructure(writer, Org.BouncyCastle.Asn1.Cms.Attribute.GetInstance(attr));
                writer.WriteLine($"                        : --- signedAttrs[{index}] end --- ");
            }
        }

        writer.WriteLine($"      signatureAlgorithm: {signerInfo.SignatureAlgorithm}");
        WriteSignatureAlgorithmIdentifier(writer, signerInfo.SignatureAlgorithm);

        writer.WriteLine($"               signature: {signerInfo.Signature.GetOctets().ToBase64String()}");

        if (signerInfo.UnsignedAttrs is not null)
        {
            // OPTIONAL
            writer.WriteLine($"           unsignedAttrs: ... ");
            foreach (var (attr, index) in signerInfo.UnsignedAttrs.Select((a, i) => (a, i)))
            {
                writer.WriteLine($"                        : --- unsignedAttrs[{index}] --- ");
                WriteAttributeStructure(writer, Org.BouncyCastle.Asn1.Cms.Attribute.GetInstance(attr));
                writer.WriteLine($"                        : --- unsignedAttrs[{index}] end --- ");
            }
        }
    }

    private static void WriteSignerIDStructure(TextWriter writer, SignerIdentifier signerID)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // ```asn.1
        // SignerIdentifier ::= CHOICE {
        //      issuerAndSerialNumber       IssuerAndSerialNumber,
        //      subjectKeyIdentifier    [0] SubjectKeyIdentifier }
        // ```

        if (!signerID.IsTagged)
        {
            // ```asn.1
            // IssuerAndSerialNumber ::= SEQUENCE {
            //      issuer              Name,
            //      serialNumber        CertificateSerialNumber }
            // ```

            var issuerAndSerialNumber = IssuerAndSerialNumber.GetInstance(signerID.ID);

            writer.WriteLine($"   issuerAndSerialNumber: ... ");
            writer.WriteLine($"                  issuer: {issuerAndSerialNumber.Issuer} ");
            writer.WriteLine($"            serialNumber: {issuerAndSerialNumber.SerialNumber.LongValueExact:x} ");
        }
        else
        {
            // ```asn.1
            // SubjectKeyIdentifier ::= OCTET STRING
            // ```

            var subjectKeyIdentifier = SubjectKeyIdentifier.GetInstance(signerID.ID);
            writer.WriteLine($"    subjectKeyIdentifier: {subjectKeyIdentifier.GetKeyIdentifier().ToBase64String()}");
        }
    }

    private static void WriteAttributeStructure(TextWriter writer, Org.BouncyCastle.Asn1.Cms.Attribute attribute)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3

        // ```asn.1
        // Attribute ::= SEQUENCE {
        //      attrType OBJECT IDENTIFIER,
        //      attrValues SET OF AttributeValue }
        //
        // AttributeValue ::= ANY
        // ```
        writer.WriteLine($"                attrType: {attribute.AttrType}");
        writer.WriteLine($"              attrValues: ... ");
        foreach (var (attrValue, valueIndex) in attribute.AttrValues.Select((v, i) => (v, i)))
        {
            writer.WriteLine($"                        : [{valueIndex}] {attrValue}");
        }
    }
}
