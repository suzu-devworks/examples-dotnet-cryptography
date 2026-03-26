using Examples.Cryptography.Extensions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;

namespace Examples.Cryptography.BouncyCastle.Asn1;

/// <summary>
/// Extension methods for ASN1 parsing for <see cref="OcspResp"/>.
/// </summary>
public static class OcspRespExtensions
{
    /// <summary>
    /// Returns a string representation of the structure of the <see cref="OcspResp"/> instance.
    /// </summary>
    /// <param name="response">The <see cref="OcspResp"/> instance.</param>
    /// <returns>A string representation of the structure.</returns>
    public static string ToStructureString(this OcspResp response)
    {
        using var writer = new StringWriter();
        WriteStructure(writer, response);
        return writer.ToString();
    }

    /// <summary>
    /// Writes the structure of the <see cref="OcspResp"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="writer">The <see cref="TextWriter"/> to write the structure to.</param>
    /// <param name="response">The <see cref="OcspResp"/> instance.</param>
    public static void WriteStructure(TextWriter writer, OcspResp response)
    {
        // RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP
        // https://datatracker.ietf.org/doc/html/rfc6960#section-4.2

        // ```asn.1
        // OCSPResponse::= SEQUENCE {
        //      responseStatus      OCSPResponseStatus,
        //      responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL }
        //
        // OCSPResponseStatus ::= ENUMERATED {
        //      successful          (0),    -- Response has valid confirmations
        //      malformedRequest    (1),    -- Illegal confirmation request
        //      internalError       (2),    -- Internal error in issuer
        //      tryLater            (3),    -- Try again later
        //                                  -- (4) is not used
        //      sigRequired         (5),    -- Must sign the request
        //      unauthorized        (6)     -- Request unauthorized
        //  }
        // ```
        var ocspResponse = OcspResponse.GetInstance(response.GetEncoded());
        writer.WriteLine($"OCSPResponse ::= {{ ");
        writer.WriteLine($"          responseStatus: {ocspResponse.ResponseStatus.Value}");
        writer.WriteLine($"       responseBytes [0]: ... ");

        // ```asn.1
        // ResponseBytes ::=        SEQUENCE {
        //     responseType    OBJECT IDENTIFIER,
        //     response        OCTET STRING }
        // ```
        var responseBytes = ocspResponse.ResponseBytes;
        writer.WriteLine($"            responseType: id-pkix-ocsp-basic ({responseBytes.ResponseType})");
        writer.WriteLine($"                response: ... ");

        // ```asn.1
        // BasicOCSPResponse       ::= SEQUENCE {
        //     tbsResponseData      ResponseData,
        //     signatureAlgorithm   AlgorithmIdentifier,
        //     signature            BIT STRING,
        //     certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
        // ```
        var basicOcspResponse = BasicOcspResponse.GetInstance(ocspResponse.ResponseBytes.Response.GetOctets());
        writer.WriteLine($"         tbsResponseData: ... ");
        WriteTbsResponseDataStructure(writer, basicOcspResponse.TbsResponseData);

        writer.WriteLine($"      signatureAlgorithm: ... ");
        WriteAlgorithmIdentifierStructure(writer, basicOcspResponse.SignatureAlgorithm);

        writer.WriteLine($"               signature: {basicOcspResponse.Signature}");

        if (basicOcspResponse.Certs is not null)
        {
            // OPTIONAL
            writer.WriteLine($"               certs [0]: ... ");
            foreach (var (cert, index) in basicOcspResponse.Certs.Select((c, i) => (c, i)))
            {
                writer.WriteLine($"                        : --- certs[{index}] --- ");
                WriteX509CertificateStructure(writer, X509CertificateStructure.GetInstance(cert));
                writer.WriteLine($"                        : --- certs[{index}] end --- ");

            }
        }

        writer.WriteLine($"}} ");
    }

    private static void WriteTbsResponseDataStructure(TextWriter writer, ResponseData tbsResponseData)
    {
        // ```asn.1
        // ResponseData ::= SEQUENCE {
        //       version              [0] EXPLICIT Version DEFAULT v1,
        //       responderID              ResponderID,
        //       producedAt               GeneralizedTime,
        //       responses                SEQUENCE OF SingleResponse,
        //       responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
        // ```
        writer.WriteLine($"             version [0]: {tbsResponseData.Version}");
        writer.WriteLine($"             responderID: ... ");
        WriteResponderIDStructure(writer, tbsResponseData.ResponderID);

        writer.WriteLine($"              producedAt: {tbsResponseData.ProducedAt.ToDateTime():o}");

        writer.WriteLine($"               responses: ... ");
        WriteSingleResponsesStructure(writer, tbsResponseData.Responses);

        if (tbsResponseData.ResponseExtensions is not null)
        {
            // OPTIONAL
            writer.WriteLine($"  responseExtensions [1]: ... ");
            foreach (var (oid, index) in tbsResponseData.ResponseExtensions.GetExtensionOids().Select((o, i) => (o, i)))
            {
                var extension = tbsResponseData.ResponseExtensions.GetExtension(oid);
                writer.WriteLine($"                        : --- responseExtensions[{index}] --- ");
                WriteX509ExtensionStructure(writer, oid, extension);
                writer.WriteLine($"                        : --- responseExtensions[{index}] end --- ");
            }
        }
    }

    private static void WriteResponderIDStructure(TextWriter writer, ResponderID responderID)
    {
        // ```asn.1
        // ResponderID ::= CHOICE {
        //       byName               [1] Name,
        //       byKey                [2] KeyHash }
        //
        // KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
        // (excluding the tag and length fields)

        if (responderID.Name is not null)
        {
            writer.WriteLine($"                  byName: {responderID.Name}");
        }
        else
        {
            writer.WriteLine($"                   byKey: {responderID.GetKeyHash()?.ToBase64String()}");
        }
    }

    private static void WriteSingleResponsesStructure(TextWriter writer, Asn1Sequence responses)
    {
        // ```asn.1
        // SingleResponse ::= SEQUENCE {
        //       certID                      CertID,
        //       certStatus                  CertStatus,
        //       thisUpdate                  GeneralizedTime,
        //       nextUpdate          [0]     EXPLICIT GeneralizedTime OPTIONAL,
        //       singleExtensions    [1]     EXPLICIT Extensions OPTIONAL }
        //
        // CertStatus ::= CHOICE {
        //       good                [0]     IMPLICIT NULL,
        //       revoked             [1]     IMPLICIT RevokedInfo,
        //       unknown             [2]     IMPLICIT UnknownInfo }
        //
        // RevokedInfo ::= SEQUENCE {
        //       revocationTime              GeneralizedTime,
        //       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
        //
        // UnknownInfo ::= NULL
        //
        // Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
        // ```
        if (responses.Count == 0)
        {
            writer.WriteLine($"                        : ... No responses ...");
            return;
        }

        var singleResponses = SingleResponse.GetInstance(responses[0]);
        writer.WriteLine($"                  certID: ... ");
        WriteCertIdStructure(writer, singleResponses.CertId);

        writer.WriteLine($"              certStatus: {GetCertStatusText(singleResponses.CertStatus)}");
        if (singleResponses.CertStatus.Status is RevokedInfo revoked)
        {
            writer.WriteLine($"          revocationTime: {revoked.RevocationTime.ToDateTime():o}");
            if (revoked.RevocationReason is not null)
            {
                // OPTIONAL
                writer.WriteLine($"    revocationReason [0]: {revoked.RevocationReason}");
            }
        }

        writer.WriteLine($"              thisUpdate: {singleResponses.ThisUpdate.ToDateTime():o}");

        if (singleResponses.NextUpdate is not null)
        {
            // OPTIONAL
            writer.WriteLine($"              nextUpdate: {singleResponses.NextUpdate.ToDateTime():o}");
        }

        if (singleResponses.SingleExtensions is not null)
        {
            // OPTIONAL
            writer.WriteLine($"    singleExtensions [1]: ... ");
            foreach (var (oid, index) in singleResponses.SingleExtensions.GetExtensionOids().Select((o, i) => (o, i)))
            {
                writer.WriteLine($"                        : --- singleExtensions[{index}] --- ");
                WriteX509ExtensionStructure(writer, oid, singleResponses.SingleExtensions.GetExtension(oid));
                writer.WriteLine($"                        : --- singleExtensions[{index}] end --- ");
            }
        }

        static string? GetCertStatusText(CertStatus certStatus)
        {
            return certStatus.TagNo switch
            {
                0 => "[0] good",
                1 => "[1] revoked",
                2 => "[2] unknown",
                _ => $"unknown({certStatus.TagNo})"
            };
        }
    }

    private static void WriteCertIdStructure(TextWriter writer, CertID certId)
    {
        // ```asn.1
        // CertID ::= SEQUENCE {
        //
        //      hashAlgorithm           AlgorithmIdentifier
        //                                   { DIGEST - ALGORITHM, { ...} },
        //       issuerNameHash          OCTET STRING, -- Hash of issuer's DN
        //       issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
        //       serialNumber            CertificateSerialNumber }
        // ```
        writer.WriteLine($"           hashAlgorithm: ... ");
        WriteAlgorithmIdentifierStructure(writer, certId.HashAlgorithm);

        writer.WriteLine($"          issuerNameHash: {certId.IssuerNameHash}");
        writer.WriteLine($"           issuerKeyHash: {certId.IssuerKeyHash}");
        writer.WriteLine($"            serialNumber: {certId.SerialNumber}");
    }

    private static void WriteAlgorithmIdentifierStructure(TextWriter writer, AlgorithmIdentifier hashAlgorithm)
    {
        // RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2

        // ```asn.1
        // AlgorithmIdentifier  ::=  SEQUENCE  {
        //      algorithm               OBJECT IDENTIFIER,
        //      parameters              ANY DEFINED BY algorithm OPTIONAL  }
        // ```
        writer.WriteLine($"               algorithm: {hashAlgorithm.Algorithm}");
        if (hashAlgorithm.Parameters is not null)
        {
            // OPTIONAL
            writer.WriteLine($"              parameters: {hashAlgorithm.Parameters}");
        }
    }

    private static void WriteX509CertificateStructure(TextWriter writer, X509CertificateStructure certificate)
    {
        writer.WriteLine($"                  issuer: {certificate.Issuer}");
        writer.WriteLine($"            serialNumber: {certificate.SerialNumber.LongValueExact:x}");
        writer.WriteLine($"                 subject: {certificate.Subject}");
    }

    private static void WriteX509ExtensionStructure(TextWriter writer, DerObjectIdentifier oid, X509Extension extension)
    {
        // RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1

        // ```asn.1
        // Extension  ::=  SEQUENCE  {
        //      extnID      OBJECT IDENTIFIER,
        //      critical    BOOLEAN DEFAULT FALSE,
        //      extnValue   OCTET STRING
        //                  -- contains the DER encoding of an ASN.1 value
        //                  -- corresponding to the extension type identified
        //                  -- by extnID
        // }
        // ```
        // spell-checker: words extn

        writer.WriteLine($"                  extnID: {oid.Id}");
        writer.WriteLine($"                critical: {extension.IsCritical}");
        writer.WriteLine($"               extnValue: {extension.Value}");
    }
}
