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

        var respondNonce = basic.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        var requestNonce = request.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        if (!respondNonce.Equals(requestNonce))
        {
            throw new OcspException("Bad nonce value.");
        }


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


    }

}
