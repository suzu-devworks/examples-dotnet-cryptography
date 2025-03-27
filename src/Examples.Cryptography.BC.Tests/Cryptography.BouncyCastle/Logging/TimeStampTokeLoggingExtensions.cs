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

        // ```asn.1
        // TimeStampToken ::= ContentInfo
        //      -- contentType is id - signedData([CMS])
        //      -- content is SignedData([CMS])
        // ```

        builder.AppendLevelLine(indent, "TimeStampToken");
        builder.AppendLevelLine(indent + 1, "contentType", "id-signedData(1.2.840.113549.1.7.2)");
        builder.AppendLevelLine(indent + 1, "content");

        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // ```asn.1
        // SignedData ::= SEQUENCE {
        //      version             CMSVersion,
        //      digestAlgorithms    DigestAlgorithmIdentifiers,
        //      encapContentInfo    EncapsulatedContentInfo,
        //      certificates    [0] IMPLICIT CertificateSet OPTIONAL,
        //      crls[1]             IMPLICIT RevocationInfoChoices OPTIONAL,
        //      signerInfos         SignerInfos }
        // ```
        /* spell-checker: words crls encap */

        var cms = tat.ToCmsSignedData();
        var signedData = SignedData.GetInstance(cms.ContentInfo.Content);

        builder.AppendLevelLine(indent + 2, "version", $"{cms.Version}");

        // ```asn.1
        // DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
        // DigestAlgorithmIdentifier ::= AlgorithmIdentifier
        // ```

        builder.AppendLevelLine(indent + 2, "digestAlgorithms");
        foreach (var (algorism, index) in signedData.DigestAlgorithms.AsEnumerable<Asn1Encodable>()
            .Select(x => AlgorithmIdentifier.GetInstance(x))
            .Select((x, i) => (x, i)))
        {
            builder.AppendLevelLine(indent + 3, $"[{index}]");
            builder.Append(algorism.DumpAsString(indent + 4));
        }

        // ```asn.1
        // EncapsulatedContentInfo ::= SEQUENCE {
        //      eContentType        ContentType,
        //      eContent        [0] EXPLICIT OCTET STRING OPTIONAL }
        // ```

        builder.AppendLevelLine(indent + 2, "encapContentInfo");
        builder.AppendLevelLine(indent + 3, "eContentType", $"id-ct-TSTInfo({cms?.SignedContentType})");

        builder.AppendLevelLine(indent + 3, "eContent is TSTInfo ");
        builder.Append(tat.TimeStampInfo.TstInfo.DumpAsString(indent: indent + 4));

        // ```asn.1
        // CertificateSet ::= SET OF CertificateChoices
        // ```

        var certs = tat.GetCertificates().EnumerateMatches(null);
        if (certs.Any())
        {
            builder.AppendLevelLine(indent + 2, "certificates");
            foreach (var (cert, index) in certs
                .Select((x, i) => (x, i)))
            {
                builder.AppendLevelLine(indent + 3, $"[{index}]");
                builder.Append(cert.DumpAsString(indent + 4));
            }
        }

        // ```asn.1
        // RevocationInfoChoices ::= SET OF RevocationInfoChoice
        // ```

        var crls = tat.GetCrls().EnumerateMatches(null);
        if (crls.Any())
        {
            builder.AppendLevelLine(indent + 2, "crls");
            foreach (var (crl, index) in crls
                .Select((x, i) => (x, i)))
            {
                builder.AppendLevelLine(indent + 3, $"[{index}]");
                builder.Append(crl.DumpAsString(indent + 4, showEntries: true));
            }
        }

        // ```asn.1
        // SignerInfos ::= SET OF SignerInfo
        // ```

        builder.AppendLevelLine(indent + 2, "signerInfos");
        foreach (var (signerInfo, index) in cms!.GetSignerInfos().GetSigners()
            .Select((x, i) => (x, i)))
        {
            builder.AppendLevelLine(indent + 3, $"[{index}]");
            builder.Append(signerInfo.DumpAsString(indent + 4));
        }

        return builder.ToString();
    }

    private static string DumpAsString(this TstInfo tstInfo, int indent = 0)
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

        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "version", $"{tstInfo.Version}");
        builder.AppendLevelLine(indent, "policy", $"{tstInfo.Policy}");

        builder.AppendLevelLine(indent, "messageImprint");
        builder.Append(tstInfo.MessageImprint?.DumpAsString(indent + 1));

        builder.AppendLevelLine(indent, "serialNumber", $"{tstInfo.SerialNumber}");
        builder.AppendLevelLine(indent, "genTime", $"{tstInfo.GenTime.ToDateTime()}");

        if (tstInfo.Accuracy is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "accuracy");
            builder.Append(tstInfo.Accuracy!.DumpAsString(indent + 1));
        }

        builder.AppendLevelLine(indent, "ordering", $"{tstInfo.Ordering}");

        if (tstInfo.Nonce is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "nonce", $"{tstInfo.Nonce}");
        }

        if (tstInfo.Tsa is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "tsa", $"{tstInfo.Tsa}");
        }

        if (tstInfo.Extensions is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "extensions", $"{tstInfo.Extensions}");
        }

        return builder.ToString();
    }

    private static string? DumpAsString(this MessageImprint message, int indent = 0)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1

        // ```asn.1
        // MessageImprint ::= SEQUENCE  {
        //      hashAlgorithm       AlgorithmIdentifier,
        //      hashedMessage       OCTET STRING  }
        // ```

        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "hashAlgorithm");
        builder.Append(message.HashAlgorithm.DumpAsString(indent + 1));

        builder.AppendLevelLine(indent, "hashedMessage", $"{message.GetHashedMessage().ToBase64String()}");

        return builder.ToString();
    }

    private static string? DumpAsString(this Accuracy acc, int indent = 0)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

        // ```asn.1
        // Accuracy ::= SEQUENCE {
        //      seconds         INTEGER         OPTIONAL,
        //      millis      [0] INTEGER(1..999) OPTIONAL,
        //      micros      [1] INTEGER(1..999) OPTIONAL  }
        // ```
        /* spell-checker: words millis */

        var builder = new StringBuilder();

        if (acc.Seconds is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "seconds", $"{acc.Seconds}s");
        }

        if (acc.Millis is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "millis", $"{acc.Millis}ms");
        }

        if (acc.Micros is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "micros", $"{acc.Micros}us");
        }

        return builder.ToString();
    }

    private static string? DumpAsString(this AlgorithmIdentifier algorism, int indent = 0)
    {
        // RFC 3161 Internet X.509 Public Key Infrastructure Time - Stamp Protocol(TSP)
        // https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2

        // ```asn.1
        // AlgorithmIdentifier ::= SEQUENCE  {
        //      algorithm           OBJECT IDENTIFIER,
        //      parameters          ANY DEFINED BY algorithm OPTIONAL  }
        // ```

        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "algorithm", $"{algorism.Algorithm.Id}");

        if ((algorism.Parameters is not null) && (algorism.Parameters != DerNull.Instance))
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "parameters", $"{algorism.Parameters}");
        }

        return builder.ToString();
    }

    private static string DumpAsString(this SignerInformation signerInfo, int indent = 0)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // ```asn.1
        // SignerInfo   ::= SEQUENCE {
        //      version             CMSVersion,
        //      sid                 SignerIdentifier,
        //      digestAlgorithm     DigestAlgorithmIdentifier,
        //      signedAttrs     [0] IMPLICIT SignedAttributes OPTIONAL,
        //      signatureAlgorithm  SignatureAlgorithmIdentifier,
        //      signature           SignatureValue,
        //      unsignedAttrs   [1] IMPLICIT UnsignedAttributes OPTIONAL }
        // ```

        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "version", $"{signerInfo.Version}");

        builder.AppendLevelLine(indent, "sid");
        builder.Append(signerInfo.SignerID.DumpAsString(indent + 1));

        // ```asn.1
        // DigestAlgorithmIdentifier ::= AlgorithmIdentifier
        // ```

        builder.AppendLevelLine(indent, "digestAlgorithm");
        builder.Append(signerInfo.DigestAlgorithmID.DumpAsString(indent + 1));

        // ```asn.1
        // SignedAttributes ::= SET SIZE(1..MAX) OF Attribute
        // ```

        if (signerInfo.SignedAttributes is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "signedAttrs");
            foreach (var (attr, index) in signerInfo.SignedAttributes.ToAttributes().GetAttributes()
                .Select((x, i) => (x, i)))
            {
                builder.AppendLevelLine(indent + 1, $"[{index}]");
                builder.Append(attr.DumpAsString(indent + 2));
            }
        }

        // ```asn.1
        // SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
        // ```

        builder.AppendLevelLine(indent, "signatureAlgorithm");
        builder.Append(signerInfo.EncryptionAlgorithmID.DumpAsString(indent + 1));

        builder.AppendLevelLine(indent, "signature", $"{signerInfo.GetSignature().ToBase64String()}");

        // ```asn.1
        // UnsignedAttributes ::= SET SIZE(1..MAX) OF Attribute
        // ```

        if (signerInfo.UnsignedAttributes is not null)
        {
            // OPTIONAL
            builder.AppendLevelLine(indent, "unsignedAttrs");
            foreach (var (attr, index) in signerInfo.UnsignedAttributes!.ToAttributes().GetAttributes()
                .Select((x, i) => (x, i)))
            {
                builder.AppendLevelLine(indent + 1, $"[{index}]");
                builder.Append(attr.DumpAsString(indent + 2));
            }
        }

        return builder.ToString();
    }

    private static string DumpAsString(this SignerID signerId, int indent = 0)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // ```asn.1
        // SignerIdentifier ::= CHOICE {
        //      issuerAndSerialNumber       IssuerAndSerialNumber,
        //      subjectKeyIdentifier    [0] SubjectKeyIdentifier }
        // ```

        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "issuerAndSerialNumber");

        // ```asn.1
        // IssuerAndSerialNumber ::= SEQUENCE {
        //      issuer              Name,
        //      serialNumber        CertificateSerialNumber }
        // ```

        builder.AppendLevelLine(indent + 1, "issuer", $"{signerId.Issuer}");
        builder.AppendLevelLine(indent + 1, "serialNumber", $"{signerId.SerialNumber}");

        // ```asn.1
        // SubjectKeyIdentifier ::= OCTET STRING
        // ```

        builder.AppendLevelLine(indent + 1, "subjectKeyIdentifier",
            $"{signerId.SubjectKeyIdentifier?.ToBase64String()}");

        return builder.ToString();
    }

    private static string DumpAsString(this Org.BouncyCastle.Asn1.Cms.Attribute attr, int indent = 0)
    {
        // RFC 5652 Cryptographic Message Syntax (CMS)
        // https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

        // ```asn.1
        // Attribute ::= SEQUENCE {
        //      attrType            OBJECT IDENTIFIER,
        //      attrValues          SET OF AttributeValue }
        // ```

        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "attrType", $"{attr.AttrType}");
        builder.AppendLevelLine(indent, "attrValues", $"{attr.AttrValues}");

        return builder.ToString();
    }

}
