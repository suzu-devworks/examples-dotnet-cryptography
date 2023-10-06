using System.Text;
using Examples.Cryptography.BouncyCastle.Utilities;
using Examples.Fluency;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.PKIX;

/// <summary>
/// Extension methods for <see cref="OcspResp" />.
/// </summary>
public static class OcspRespExtensions
{
    /// <summary>
    /// Validates response against to see if it a well formed response for the passed in request.
    /// </summary>
    /// <param name="response">The OCSP response instance.</param>
    /// <param name="request">The OCSP request instance.</param>
    /// <exception cref="OcspException">If validation fails.</exception>
    public static void Validate(this OcspResp response,
        OcspReq request
        )
    {
        if (response.Status != OcspRespStatus.Successful)
        {
            throw new OcspException($"Bad status: {response.Status}");
        }

        var basic = (BasicOcspResp)response.GetResponseObject();

        var responeNonce = basic.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        var requestNonce = request.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        if (!responeNonce.Equals(requestNonce))
        {
            throw new OcspException("Bad nonce value.");
        }

        return;
    }

    /// <summary>
    /// Validates according to RFC 6960 '3.2 Signed Response Acceptance Requirements'
    /// </summary>
    /// <param name="response">The OCSP response instance.</param>
    /// <param name="issuer">The OCSP issuer X.509 certificate instance.</param>
    /// <param name="time">Date and time to validate(default now.</param>
    /// <exception cref="OcspException">If validation fails.</exception>
    public static void Validate(this OcspResp response,
        X509Certificate issuer,
        DateTime? time = null
        )
    {
        var validatingAt = time?.ToUniversalTime()
            ?? DateTime.UtcNow;

        var basic = (BasicOcspResp)response.GetResponseObject();

        // https://datatracker.ietf.org/doc/html/rfc6960#section-3.2

        var single = basic.Responses.First();
        var signer = basic.GetCertificates().EnumerateMatches(null).First();

        // 1.The certificate identified in a received response corresponds to
        //  the certificate that was identified in the corresponding request;
        if (!single.GetCertID().MatchesIssuer(issuer))
        {
            throw new OcspException("Certificate identified does not match.");
        }

        // 2.The signature on the response is valid;
        if (!basic.Verify(signer.GetPublicKey()))
        {
            throw new OcspException("Signature is invalid.");
        }

        // 3.The identity of the signer matches the intended recipient of the
        //  request;
        if (!basic.ResponderId.Equals(new RespID(signer.SubjectDN)))
        {
            throw new OcspException("Signer does not match.");
        }

        // 4.The signer is currently authorized to provide a response for the
        //  certificate in question;
        var extendKeyUsages = signer.GetExtendedKeyUsage();
        if (!extendKeyUsages.Any(x => x.Equals(KeyPurposeID.id_kp_OCSPSigning)))
        {
            throw new OcspException("Unauthorized signer.");
        }

        // 5.The time at which the status being indicated is known to be
        //  correct(thisUpdate) is sufficiently recent;
        var daysAllowed = -1;
        if (single.ThisUpdate < validatingAt.AddDays(daysAllowed))
        {
            throw new OcspException("Update time is too old.");
        }

        // 6.When available, the time at or before which newer information will
        //  be available about the status of the certificate(nextUpdate) is
        //  greater than the current time.
        if ((single.NextUpdate is not null)
             && (single.NextUpdate <= validatingAt))
        {
            throw new OcspException("Not the latest status.");
        }

        return;
    }

    /// <summary>
    /// Converts the contents of <see cref="OcspResp" /> to a <c>string</c> for log output.
    /// </summary>
    /// <param name="response">The <see cref="OcspResp" /> instance.</param>
    /// <param name="indent">A indent indent.</param>
    /// <returns>A <c>string</c> for log output.</returns>
    public static string? DumpAsString(this OcspResp response, int indent = 0)
    {
        // RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol -OCSP
        // https://datatracker.ietf.org/doc/html/rfc6960#appendix-B.2

        // OCSPResponse::= SEQUENCE {
        //      responseStatus      OCSPResponseStatus,
        //      responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }

        // OCSPResponseStatus ::= ENUMERATED {
        //      successful          (0),    -- Response has valid confirmations
        //      malformedRequest    (1),    -- Illegal confirmation request
        //      internalError       (2),    -- Internal error in issuer
        //      tryLater            (3),    -- Try again later
        //                                  -- (4) is not used
        //      sigRequired         (5),    -- Must sign the request
        //      unauthorized        (6)     -- Request unauthorized
        //  }

        // RESPONSE ::= TYPE-IDENTIFIER

        // ResponseSet RESPONSE ::= {basicResponse, ...}

        // ResponseBytes ::= SEQUENCE {
        //     responseType        RESPONSE.
        //                             &id ({ResponseSet}),
        //     response            OCTET STRING (CONTAINING RESPONSE.
        //                             &Type({ResponseSet}{@responseType}))}

        // basicResponse RESPONSE ::=
        //     { BasicOCSPResponse IDENTIFIED BY id-pkix-ocsp-basic }

        var basic = (BasicOcspResp)response.GetResponseObject();

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "OcspResp");
        builder.AppendLebelLine(indent + 1, "responseStatus", $"{response.Status}");
        builder.AppendLebelLine(indent + 1, "responseBytes");
        builder.AppendLebelLine(indent + 2, "responseType", "id-pkix-ocsp-basic(1.3.6.1.5.5.7.48.1.1)");
        builder.AppendLebelLine(indent + 2, "response (BasicOCSPResponse)");
        builder.Append(basic.DumpAsString(indent + 3));

        return builder.ToString();
    }

    private static string? DumpAsString(this BasicOcspResp basic, int indent = 0)
    {
        // RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol -OCSP
        // https://datatracker.ietf.org/doc/html/rfc6960#appendix-B.2

        // BasicOCSPResponse ::= SEQUENCE {
        //      tbsResponseData         ResponseData,
        //      signatureAlgorithm      AlgorithmIdentifier{
        //                                  SIGNATURE - ALGORITHM,
        //                                  {sa-dsaWithSHA1 | sa-rsaWithSHA1 |
        //                                      sa-rsaWithMD5 | sa-rsaWithMD2, ...}
        //                                  },
        //      signature               BIT STRING,
        //      certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

        // ResponseData ::= SEQUENCE {
        //      version             [0] EXPLICIT Version DEFAULT v1,
        //      responderID             ResponderID,
        //      producedAt              GeneralizedTime,
        //      responses               SEQUENCE OF SingleResponse,
        //      responseExtensions  [1] EXPLICIT Extensions
        //                              {{re-ocsp-nonce, ...,
        //                                  re-ocsp-extended-revoke}} OPTIONAL }

        var tbs = ResponseData.GetInstance(Asn1Sequence.GetInstance(basic.GetTbsResponseData()));

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "tbsResponseData");
        builder.AppendLebelLine(indent + 1, "version", $"{basic.Version}");
        builder.AppendLebelLine(indent + 1, "responderID");
        builder.Append(basic.ResponderId.DumpAsString(indent + 2));

        builder.AppendLebelLine(indent + 1, "producedAt", $"{basic.ProducedAt}");
        builder.AppendLebelLine(indent + 1, "responses");

        foreach (var (single, index) in basic.Responses
            .Select((x, i) => (x, i)))
        {
            builder.AppendLebelLine(indent + 2, $"[{index}]");
            builder.Append(single.DumpAsString(indent + 3));
        }

        if (basic.ResponseExtensions?.GetExtensionOids().Any() ?? false)
        {
            // OPTIONS
            builder.AppendLebelLine(indent + 1, "responseExtensions");
            builder.Append(basic.ResponseExtensions.DumpAsString(indent + 1));
        }

        builder.AppendLebelLine(indent, "signatureAlgorithm");
        builder.AppendLebelLine(indent + 1, "algorithm", basic.SignatureAlgOid);
        builder.AppendLebelLine(indent, "signature", basic.GetSignature().ToBase64String());

        if (basic.GetCerts().Any())
        {
            // OPTIONS
            builder.AppendLebelLine(indent, "certs");

            foreach (var (cert, index) in basic.GetCerts()
                .Select((x, i) => (x, i)))
            {
                builder.AppendLebelLine(indent + 2, $"[{index}]");
                builder.Append(cert.DumpAsString(indent + 3));
            }
        }

        return builder.ToString();
    }

    private static string? DumpAsString(this RespID responder, int indent = 0)
    {
        // RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol -OCSP
        // https://datatracker.ietf.org/doc/html/rfc6960#appendix-B.2

        // ResponderID ::= CHOICE {
        //    byName   [1] Name,
        //    byKey    [2] KeyHash }

        var asn1 = responder.ToAsn1Object();

        var builder = new StringBuilder();

        if (asn1.Name is not null)
        {
            builder.AppendLebelLine(indent, "byName", $"{asn1.Name}");
        }
        else
        {
            builder.AppendLebelLine(indent, "byKey (SHA-1)", $"{asn1.GetKeyHash().ToBase64String()}");
        }

        return builder.ToString();
    }

    private static string? DumpAsString(this SingleResp single, int indent = 0)
    {
        // RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol -OCSP
        // https://datatracker.ietf.org/doc/html/rfc6960#appendix-B.2

        // SingleResponse ::= SEQUENCE {
        //      certID                      CertID,
        //      certStatus                  CertStatus,
        //      thisUpdate                  GeneralizedTime,
        //      nextUpdate          [0]     EXPLICIT GeneralizedTime OPTIONAL,
        //      singleExtensions    [1]     EXPLICIT Extensions{{re-ocsp-crl |
        //                                              re-ocsp-archive-cutoff |
        //                                              CrlEntryExtensions, ...}
        //                                              } OPTIONAL }

        // CertStatus ::= CHOICE {
        //      good                [0]     IMPLICIT NULL,
        //      revoked             [1]     IMPLICIT RevokedInfo,
        //      unknown             [2]     IMPLICIT UnknownInfo }

        // RevokedInfo ::= SEQUENCE {
        //      revocationTime              GeneralizedTime,
        //      revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }

        var status = single.GetCertStatus() switch
        {
            RevokedStatus _ => "revoked",
            UnknownStatus _ => "unknown",
            _ => "good"
        };

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "certID");
        builder.Append(single.GetCertID().DumpAsString(indent + 1));

        builder.AppendLebelLine(indent, "certStatus", $"{status}");
        if (single.GetCertStatus() is RevokedStatus revoke)
        {
            builder.AppendLebelLine(indent + 1, "revocationTime", $"{revoke.RevocationTime}");
            builder.AppendLebelLine(indent + 1, "revocationReason", $"{revoke.RevocationReason}");
        }

        builder.AppendLebelLine(indent, "thisUpdate", $"{single.ThisUpdate}");

        if (single.NextUpdate is not null)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "nextUpdate", $"{single.NextUpdate}");
        }

        if (single.SingleExtensions?.GetExtensionOids().Any() ?? false)
        {
            // OPTIONAL
            builder.AppendLebelLine(indent, "singleExtensions");
            builder.Append(single.SingleExtensions.DumpAsString(indent));
        }

        return builder.ToString();
    }

    private static string? DumpAsString(this CertificateID certId, int indent = 0)
    {
        // RFC 6960 X.509 Internet Public Key Infrastructure Online Certificate Status Protocol -OCSP
        // https://datatracker.ietf.org/doc/html/rfc6960#appendix-B.2

        // CertID ::= SEQUENCE {
        //    hashAlgorithm           AlgorithmIdentifier,
        //    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
        //    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
        //    serialNumber            CertificateSerialNumber }

        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "hashAlgorithm");
        builder.AppendLebelLine(indent + 1, "algorithm", certId.HashAlgOid);
        builder.AppendLebelLine(indent, "issuerNameHash", $"{certId.GetIssuerNameHash().ToBase64String()}");
        builder.AppendLebelLine(indent, "issuerKeyHash", $"{certId.GetIssuerKeyHash().ToBase64String()}");
        builder.AppendLebelLine(indent, "serialNumber", $"{certId.SerialNumber}");

        return builder.ToString();
    }

    private static string DumpAsString(this X509Certificate cert, int indent = 0)
    {
        var builder = new StringBuilder();

        builder.AppendLebelLine(indent, "subject", $"{cert.SubjectDN}");
        builder.AppendLebelLine(indent, "issuer", $"{cert.IssuerDN}");
        builder.AppendLebelLine(indent, "serialNumber", $"{cert.SerialNumber}");
        builder.AppendLebelLine(indent, "notAfter", $"{cert.NotAfter}");

        return builder.ToString();
    }

    private static string? DumpAsString(this X509Extensions extensions, int indent = 0)
    {
        var builder = new StringBuilder();

        foreach (var (oid, index) in extensions.GetExtensionOids()
            .Select((x, i) => (x, i)))
        {
            var ext = extensions.GetExtension(oid);
            builder.AppendLebelLine(indent + 1, $"[{index}]", $"critical({ext.IsCritical}) {oid} value = {ext.Value}");
        }

        return builder.ToString();
    }

}
