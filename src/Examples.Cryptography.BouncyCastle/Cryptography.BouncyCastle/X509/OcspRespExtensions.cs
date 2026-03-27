using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="OcspResp" />.
/// </summary>
public static class OcspRespExtensions
{
    /// <summary>
    /// Validates the OCSP response against the original request and issuer certificate.
    /// </summary>
    /// <remarks>
    /// This method performs the following checks based on <a href="https://datatracker.ietf.org/doc/html/rfc6960">RFC 6960</a>.
    /// </remarks>
    /// <param name="response">The OCSP response to validate.</param>
    /// <param name="request">The original OCSP request.</param>
    /// <param name="issuerCert">The issuer certificate of the certificate being checked.</param>
    /// <param name="strict">
    /// Enables additional RFC-oriented checks that may reduce interoperability with public OCSP responders.
    /// Nonce validation still runs whenever the request includes a nonce.
    /// </param>
    /// <param name="validatingTime">(Optional) The time at which to validate the OCSP response. Defaults to the current UTC time.</param>
    /// <exception cref="OcspException"></exception>
    public static void Validate(this OcspResp response,
        OcspReq request,
        X509Certificate issuerCert,
        bool strict = false,
        DateTime? validatingTime = null)
    {
        _ = request ?? throw new ArgumentNullException(nameof(request));

        // Response Status Check (RFC 6960 2.1)
        if (response.Status != OcspRespStatus.Successful)
        {
            throw new OcspException($"Bad status: {response.Status}");
        }

        var basicResp = (BasicOcspResp)response.GetResponseObject();
        var single = basicResp.Responses.FirstOrDefault()
            ?? throw new OcspException("No response in OCSP response.");

        // 1. The certificate identified in a received response corresponds to
        //    the certificate that was identified in the corresponding request; (RFC 6960 3.2.1)
        if (!single.GetCertID().MatchesIssuer(issuerCert))
        {
            throw new OcspException("Certificate identified does not match.");
        }

        var responderCert = FindAndVerifySigner(basicResp, issuerCert, strict);

        // 2. The signature on the response is valid; (RFC 6960 3.2.2)
        if (!basicResp.Verify(responderCert.GetPublicKey()))
        {
            throw new OcspException("Signature is invalid.");
        }

        // 3. The identity of the signer matches the intended recipient of the
        //    request; (RFC 6960 3.2.3)
        if (!basicResp.ResponderId.Equals(new RespID(responderCert.SubjectDN)) &&
            !basicResp.ResponderId.Equals(new RespID(responderCert.GetPublicKey())))
        {
            throw new OcspException("Signer does not match.");
        }

        // 4. The signer is currently authorized to provide a response for the
        //    certificate in question; (RFC 6960 3.2.4)
        if (strict && !HasOcspSigningExtendedKeyUsage(responderCert))
        {
            throw new OcspException("Responder certificate lacks id-kp-OCSPSigning extension.");
        }

        var validatingAt = validatingTime?.ToUniversalTime() ?? DateTime.UtcNow;
        TimeSpan skew = TimeSpan.FromMinutes(5);

        // 5. The time at which the status being indicated is known to be
        //    correct (thisUpdate) is sufficiently recent; (RFC 6960 3.2.5)
        if (single.ThisUpdate > validatingAt.Add(skew))
        {
            throw new OcspException("Response 'thisUpdate' is in the future.");
        }

        // 6. When available, the time at or before which newer information will
        //    be available about the status of the certificate (nextUpdate) is
        //    greater than the current time. (RFC 6960 3.2.5)
        if (single.NextUpdate != null && validatingAt > single.NextUpdate.Value.Add(skew))
        {
            throw new OcspException("Response 'nextUpdate' has passed. Information is stale.");
        }

        if (strict || HasNonce(basicResp))
        {
            basicResp.ValidateNonce(request);
        }
    }

    private static X509Certificate FindAndVerifySigner(BasicOcspResp basicResp, X509Certificate issuerCert, bool strict)
    {
        // A. CA direct signature pattern (issuerCert == responder)

        RespID caRespIdByName = new RespID(issuerCert.SubjectDN);
        RespID caRespIdByPubKey = new RespID(issuerCert.GetPublicKey());

        if (basicResp.ResponderId.Equals(caRespIdByName) || basicResp.ResponderId.Equals(caRespIdByPubKey))
        {
            return issuerCert;
        }

        // B. Authorized Responder Pattern (RFC 6960 4.2.2.2)

        X509Certificate[] certs = basicResp.GetCerts();
        X509Certificate? responderCert = certs.FirstOrDefault(c =>
            new RespID(c.SubjectDN).Equals(basicResp.ResponderId) ||
            new RespID(c.GetPublicKey()).Equals(basicResp.ResponderId)
        );

        if (responderCert is null)
        {
            throw new OcspException("Responder certificate not found in response.");
        }

        // - sign the OCSP responses itself, or
        responderCert.Verify(issuerCert.GetPublicKey());

        // - explicitly designate this authority to another entity
        if (strict && !HasOcspSigningExtendedKeyUsage(responderCert))
        {
            throw new OcspException("Responder certificate lacks id-kp-OCSPSigning extension.");
        }

        return responderCert;
    }

    private static bool HasOcspSigningExtendedKeyUsage(X509Certificate certificate)
    {
        var eku = certificate.GetExtendedKeyUsage();
        return eku is not null && eku.Contains(KeyPurposeID.id_kp_OCSPSigning);
    }

    private static bool HasNonce(BasicOcspResp response)
        => response.GetExtension(OcspObjectIdentifiers.PkixOcspNonce) is not null;

    private static void ValidateNonce(this BasicOcspResp resp, OcspReq req)
    {
        // Check Nonce (RFC 6960 4.4.1)

        var reqNonce = req.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
        var respNonce = resp.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);

        if (reqNonce is not null)
        {
            if (respNonce is null || !reqNonce.Equals(respNonce))
                throw new OcspException("Nonce mismatch. Potential replay attack detected.");
        }
    }

    /// <summary>
    /// Convenience method to extract the certificate status from an OCSP response.
    /// </summary>
    /// <param name="response">The OCSP response whose certificate status should be verified.</param>
    /// <returns>True if the certificate status in the response is <see cref="CertificateStatus.Good"/>, otherwise false.</returns>
    /// <exception cref="OcspException"></exception>
    public static bool VerifyStatus(this OcspResp response)
    {
        var basicResp = (BasicOcspResp)response.GetResponseObject();
        var single = basicResp.Responses.FirstOrDefault()
            ?? throw new OcspException("No response in OCSP response.");
        var status = single.GetCertStatus();
        return status == CertificateStatus.Good;
    }

}
