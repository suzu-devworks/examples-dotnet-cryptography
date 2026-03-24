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
        response.WriteStructure(writer);
        return writer.ToString();
    }

    /// <summary>
    /// Writes the structure of the <see cref="OcspResp"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="response">The <see cref="OcspResp"/> instance.</param>
    /// <param name="output">The <see cref="TextWriter"/> to write the structure to.</param>
    public static void WriteStructure(this OcspResp response, TextWriter output)
    {
        // RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP
        // 4.2 Response Syntax
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
        output.WriteLine($"OCSPResponse ::= {{ ");
        output.WriteLine($"      responseStatus : {ocspResponse.ResponseStatus.Value}");
        output.WriteLine($"   responseBytes [0] : ... ");

        // ```asn.1
        // ResponseBytes ::=        SEQUENCE {
        //     responseType    OBJECT IDENTIFIER,
        //     response        OCTET STRING }
        // ```
        var responseBytes = ocspResponse.ResponseBytes;
        output.WriteLine($"        responseType : id-pkix-ocsp-basic ({responseBytes.ResponseType})");
        output.WriteLine($"            response : ... ");

        // ```asn.1
        // BasicOCSPResponse       ::= SEQUENCE {
        //     tbsResponseData      ResponseData,
        //     signatureAlgorithm   AlgorithmIdentifier,
        //     signature            BIT STRING,
        //     certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
        // ```
        var basicOcspResponse = BasicOcspResponse.GetInstance(ocspResponse.ResponseBytes.Response.GetOctets());
        output.WriteLine($"     tbsResponseData : ... ");
        WriteTbsResponseDataStructure(basicOcspResponse.TbsResponseData, output);

        output.WriteLine($"  signatureAlgorithm : ... ");
        WriteAlgorithmIdentifierStructure(basicOcspResponse.SignatureAlgorithm, output);

        output.WriteLine($"           signature : {basicOcspResponse.Signature}");
        output.WriteLine($"               certs : ... ");
        WriteCertsStructure(basicOcspResponse.Certs, output);

        output.WriteLine($"}} ");
    }


    private static void WriteTbsResponseDataStructure(ResponseData tbsResponseData, TextWriter output)
    {
        // ```asn.1
        // ResponseData ::= SEQUENCE {
        //       version              [0] EXPLICIT Version DEFAULT v1,
        //       responderID              ResponderID,
        //       producedAt               GeneralizedTime,
        //       responses                SEQUENCE OF SingleResponse,
        //       responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
        // ```
        output.WriteLine($"         version [0] : {tbsResponseData.Version}");
        output.WriteLine($"         responderID : ... ");
        WriteResponderIDStructure(tbsResponseData.ResponderID, output);

        output.WriteLine($"          producedAt : {tbsResponseData.ProducedAt.ToDateTime():o}");

        output.WriteLine($"           responses : ... ");
        WriteSingleResponsesStructure(tbsResponseData.Responses, output);

        output.WriteLine($"  responseExtensions : ... ");
        WriteExtensionsStructure(tbsResponseData.ResponseExtensions, output);
    }

    private static void WriteResponderIDStructure(ResponderID responderID, TextWriter output)
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
            output.WriteLine($"              byName : {responderID.Name}");
        }
        else
        {
            output.WriteLine($"              byKey : {responderID.GetKeyHash()?.ToBase64String()}");
        }
    }

    private static void WriteSingleResponsesStructure(Asn1Sequence responses, TextWriter output)
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
        // ```
        if (responses.Count == 0)
        {
            output.WriteLine($"                     : ... No responses ...");
            return;
        }

        var singleResponses = SingleResponse.GetInstance(responses[0]);
        output.WriteLine($"              certID : ... ");
        WriteCertIdStructure(singleResponses.CertId, output);

        output.WriteLine($"          certStatus : {GetCertStatusText(singleResponses.CertStatus)}");
        if (singleResponses.CertStatus.Status is RevokedInfo revoked)
        {
            output.WriteLine($"      revocationTime : {revoked.RevocationTime.ToDateTime():o}");
            output.WriteLine($"revocationReason [0] : {revoked.RevocationReason}");
        }
        output.WriteLine($"          thisUpdate : {singleResponses.ThisUpdate.ToDateTime():o}");
        output.WriteLine($"      nextUpdate [0] : {singleResponses.NextUpdate?.ToDateTime():o}");
        output.WriteLine($"singleExtensions [1] : ... ");
        WriteExtensionsStructure(singleResponses.SingleExtensions, output);

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

    private static void WriteCertIdStructure(CertID certId, TextWriter output)
    {
        // ```asn.1
        // CertID ::= SEQUENCE {
        //       hashAlgorithm           AlgorithmIdentifier
        //                                   { DIGEST - ALGORITHM, { ...} },
        //       issuerNameHash          OCTET STRING, -- Hash of issuer's DN
        //       issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
        //       serialNumber            CertificateSerialNumber }
        // ```
        output.WriteLine($"       hashAlgorithm : ... ");
        WriteAlgorithmIdentifierStructure(certId.HashAlgorithm, output);

        output.WriteLine($"      issuerNameHash : {certId.IssuerNameHash}");
        output.WriteLine($"       issuerKeyHash : {certId.IssuerKeyHash}");
        output.WriteLine($"        serialNumber : {certId.SerialNumber}");
    }

    private static void WriteAlgorithmIdentifierStructure(AlgorithmIdentifier hashAlgorithm, TextWriter output)
    {
        // RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
        // 4.1.1.2.  signatureAlgorithm
        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2

        // ```asn.1
        //    AlgorithmIdentifier  ::=  SEQUENCE  {
        //         algorithm               OBJECT IDENTIFIER,
        //         parameters              ANY DEFINED BY algorithm OPTIONAL  }
        // ```
        output.WriteLine($"           algorithm : {hashAlgorithm.Algorithm}");
        output.WriteLine($"          parameters : {hashAlgorithm.Parameters}");
    }

    private static void WriteCertsStructure(Asn1Sequence certs, TextWriter output)
    {
        for (int i = 0; i < certs.Count; i++)
        {
            var cert = X509CertificateStructure.GetInstance(certs[i]);
            output.WriteLine($"                 [{i}] : issuer : {cert.Issuer}");
            output.WriteLine($"                     : serialNumber : {cert.SerialNumber}");
            output.WriteLine($"                     : subject : {cert.Subject}");
        }
    }

    private static void WriteExtensionsStructure(X509Extensions responseExtensions, TextWriter output)
    {
        // RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
        // 4.1.  Basic Certificate Fields
        // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1

        // ```asn.1
        // Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
        //
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
        var index = 0;
        foreach (var oid in responseExtensions?.GetExtensionOids() ?? [])
        {
            var extension = responseExtensions!.GetExtension(oid);
            output.WriteLine($"                 [{index}] : extnID : {oid.Id}");
            output.WriteLine($"                     : critical : {extension.IsCritical}");
            output.WriteLine($"                     : extnValue : {extension.Value}");
            ++index;
        }
    }
}
