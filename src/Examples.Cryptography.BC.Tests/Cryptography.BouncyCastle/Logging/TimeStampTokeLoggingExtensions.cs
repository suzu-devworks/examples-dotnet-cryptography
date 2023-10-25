using System.Text;
using Examples.Fluency;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.Logging;

/// <summary>
/// Extension methods for <see cref="TimeStampToken" /> logging.
/// </summary>
public static class TimeStampTokeLoggingExtensions
{
    /// <summary>
    /// Converts the contents of <see cref="TimeStampToken" /> to a <c>string</c> for log output.
    /// </summary>
    /// <param name="tat">The <see cref="TimeStampToken" /> instance.</param>
    /// <param name="indent">A indent indent.</param>
    /// <returns>A <c>string</c> for log output.</returns>
    public static string DumpAsString(this TimeStampToken tat, int indent = 0)
    {
        var builder = new StringBuilder();

        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

        // TimeStampToken ::= ContentInfo
        //      -- contentType is id - signedData([CMS])
        //      -- content is SignedData([CMS])
        //

        builder.AppendLebelLine(indent, "TimeStampToken");
        builder.AppendLebelLine(indent + 1, "contentType", "id-signedData(1.2.840.113549.1.7.2)");
        builder.AppendLebelLine(indent + 1, "content");

        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // SignedData ::= SEQUENCE {
        //      version             CMSVersion,
        //      digestAlgorithms    DigestAlgorithmIdentifiers,
        //      encapContentInfo    EncapsulatedContentInfo,
        //      certificates    [0] IMPLICIT CertificateSet OPTIONAL,
        //      crls[1]             IMPLICIT RevocationInfoChoices OPTIONAL,
        //      signerInfos         SignerInfos }

        var cms = tat.ToCmsSignedData();
        var signeddata = SignedData.GetInstance(cms.ContentInfo.Content);

        builder.AppendLebelLine(indent + 2, "version", $"{cms.Version}");

        // DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
        // DigestAlgorithmIdentifier ::= AlgorithmIdentifier

        builder.AppendLebelLine(indent + 2, "digestAlgorithms");
        foreach (var (algolysm, index) in signeddata.DigestAlgorithms.AsEnumerable<Asn1Encodable>()
            .Select(x => AlgorithmIdentifier.GetInstance(x))
            .Select((x, i) => (x, i)))
        {
            builder.AppendLebelLine(indent + 3, $"[{index}]");
            builder.Append(algolysm.DumpAsString(indent + 4));
        }

        // EncapsulatedContentInfo ::= SEQUENCE {
        //      eContentType        ContentType,
        //      eContent        [0] EXPLICIT OCTET STRING OPTIONAL }

        builder.AppendLebelLine(indent + 2, "encapContentInfo");
        builder.AppendLebelLine(indent + 3, "eContentType", $"id-ct-TSTInfo({cms?.SignedContentType})");

        builder.AppendLebelLine(indent + 3, "eContent is TSTInfo ");
        builder.Append(tat.TimeStampInfo.TstInfo.DumpAsString(indent: indent + 4));

        // CertificateSet ::= SET OF CertificateChoices

        var certs = tat.GetCertificates().EnumerateMatches(null);
        if (certs.Any())
        {
            builder.AppendLebelLine(indent + 2, "certificates");
            foreach (var (cert, index) in certs
                .Select((x, i) => (x, i)))
            {
                builder.AppendLebelLine(indent + 3, $"[{index}]");
                builder.Append(cert.DumpAsString(indent + 4));
            }
        }

        // RevocationInfoChoices ::= SET OF RevocationInfoChoice
        var crls = tat.GetCrls().EnumerateMatches(null);
        if (crls.Any())
        {
            builder.AppendLebelLine(indent + 2, "crls");
            foreach (var (crl, index) in crls
                .Select((x, i) => (x, i)))
            {
                builder.AppendLebelLine(indent + 3, $"[{index}]");
                builder.Append(crl.DumpAsString(indent + 4, showEntries: true));
            }
        }

        // SignerInfos ::= SET OF SignerInfo

        builder.AppendLebelLine(indent + 2, "signerInfos");
        foreach (var (signerInfo, index) in cms!.GetSignerInfos().GetSigners()
            .Select((x, i) => (x, i)))
        {
            builder.AppendLebelLine(indent + 3, $"[{index}]");
            builder.Append(signerInfo.DumpAsString(indent + 4));
        }

        return builder.ToString();
    }

    private static string DumpAsString(this TstInfo tstInfo, int indent = 0)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

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

        // TSAPolicyId ::= OBJECT IDENTIFIER

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "version", $"{tstInfo.Version}");
        builder.AppendLebelLine(indent, "policy", $"{tstInfo.Policy}");

        builder.AppendLebelLine(indent, "messageImprint");
        builder.Append(tstInfo.MessageImprint?.DumpAsString(indent + 1));

        builder.AppendLebelLine(indent, "serialNumber", $"{tstInfo.SerialNumber}");
        builder.AppendLebelLine(indent, "genTime", $"{tstInfo.GenTime.ToDateTime()}");

        if (tstInfo.Accuracy is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "accuracy");
            builder.Append(tstInfo.Accuracy!.DumpAsString(indent + 1));
        }

        builder.AppendLebelLine(indent, "ordering", $"{tstInfo.Ordering}");

        if (tstInfo.Nonce is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "nonce", $"{tstInfo.Nonce}");
        }

        if (tstInfo.Tsa is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "tsa", $"{tstInfo.Tsa}");
        }

        if (tstInfo.Extensions is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "extensions", $"{tstInfo.Extensions}");
        }

        return builder.ToString();
    }

    private static string? DumpAsString(this MessageImprint message, int indent = 0)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1

        // MessageImprint ::= SEQUENCE  {
        //      hashAlgorithm       AlgorithmIdentifier,
        //      hashedMessage       OCTET STRING  }

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "hashAlgorithm");
        builder.Append(message.HashAlgorithm.DumpAsString(indent + 1));

        builder.AppendLebelLine(indent, "hashedMessage", $"{message.GetHashedMessage().ToBase64String()}");

        return builder.ToString();
    }

    private static string? DumpAsString(this Accuracy acc, int indent = 0)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

        // Accuracy ::= SEQUENCE {
        //      seconds         INTEGER         OPTIONAL,
        //      millis      [0] INTEGER(1..999) OPTIONAL,
        //      micros      [1] INTEGER(1..999) OPTIONAL  }

        var builder = new StringBuilder();

        if (acc.Seconds is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "seconds", $"{acc.Seconds}s");
        }

        if (acc.Millis is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "millis", $"{acc.Millis}ms");
        }

        if (acc.Micros is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "micros", $"{acc.Micros}us");
        }

        return builder.ToString();
    }

    private static string? DumpAsString(this AlgorithmIdentifier algolysm, int indent = 0)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

        // AlgorithmIdentifier ::= SEQUENCE  {
        //      algorithm           OBJECT IDENTIFIER,
        //      parameters          ANY DEFINED BY algorithm OPTIONAL  }

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "algorithm", $"{algolysm.Algorithm.Id}");

        if ((algolysm.Parameters is not null) && (algolysm.Parameters != DerNull.Instance))
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "parameters", $"{algolysm.Parameters}");
        }

        return builder.ToString();
    }

    private static string DumpAsString(this SignerInformation signerInfo, int indent = 0)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // SignerInfo   ::= SEQUENCE {
        //      version             CMSVersion,
        //      sid                 SignerIdentifier,
        //      digestAlgorithm     DigestAlgorithmIdentifier,
        //      signedAttrs     [0] IMPLICIT SignedAttributes OPTIONAL,
        //      signatureAlgorithm  SignatureAlgorithmIdentifier,
        //      signature           SignatureValue,
        //      unsignedAttrs   [1] IMPLICIT UnsignedAttributes OPTIONAL }

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "version", $"{signerInfo.Version}");

        builder.AppendLebelLine(indent, "sid");
        builder.Append(signerInfo.SignerID.DumpAsString(indent + 1));

        // DigestAlgorithmIdentifier ::= AlgorithmIdentifier

        builder.AppendLebelLine(indent, "digestAlgorithm");
        builder.Append(signerInfo.DigestAlgorithmID.DumpAsString(indent + 1));

        // SignedAttributes ::= SET SIZE(1..MAX) OF Attribute

        if (signerInfo.SignedAttributes is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "signedAttrs");
            foreach (var (attr, index) in signerInfo.SignedAttributes.ToAttributes().GetAttributes()
                .Select((x, i) => (x, i)))
            {
                builder.AppendLebelLine(indent + 1, $"[{index}]");
                builder.Append(attr.DumpAsString(indent + 2));
            }
        }

        // SignatureAlgorithmIdentifier ::= AlgorithmIdentifier

        builder.AppendLebelLine(indent, "signatureAlgorithm");
        builder.Append(signerInfo.EncryptionAlgorithmID.DumpAsString(indent + 1));

        builder.AppendLebelLine(indent, "signature", $"{signerInfo.GetSignature().ToBase64String()}");

        // UnsignedAttributes ::= SET SIZE(1..MAX) OF Attribute

        if (signerInfo.UnsignedAttributes is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "unsignedAttrs");
            foreach (var (attr, index) in signerInfo.UnsignedAttributes!.ToAttributes().GetAttributes()
                .Select((x, i) => (x, i)))
            {
                builder.AppendLebelLine(indent + 1, $"[{index}]");
                builder.Append(attr.DumpAsString(indent + 2));
            }
        }

        return builder.ToString();
    }

    private static string DumpAsString(this SignerID signerId, int indent = 0)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // SignerIdentifier ::= CHOICE {
        //      issuerAndSerialNumber       IssuerAndSerialNumber,
        //      subjectKeyIdentifier    [0] SubjectKeyIdentifier }

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "issuerAndSerialNumber");

        // IssuerAndSerialNumber ::= SEQUENCE {
        //      issuer              Name,
        //      serialNumber        CertificateSerialNumber }

        builder.AppendLebelLine(indent + 1, "issuer", $"{signerId.Issuer}");
        builder.AppendLebelLine(indent + 1, "serialNumber", $"{signerId.SerialNumber}");

        // SubjectKeyIdentifier ::= OCTET STRING
        builder.AppendLebelLine(indent + 1, "subjectKeyIdentifier",
            $"{signerId.SubjectKeyIdentifier?.ToBase64String()}");

        return builder.ToString();
    }

    private static string DumpAsString(this Org.BouncyCastle.Asn1.Cms.Attribute attr, int indent = 0)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // Attribute ::= SEQUENCE {
        //      attrType            OBJECT IDENTIFIER,
        //      attrValues          SET OF AttributeValue }

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "attrType", $"{attr.AttrType}");
        builder.AppendLebelLine(indent, "attrValues", $"{attr.AttrValues}");

        return builder.ToString();
    }

}
