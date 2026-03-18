using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.X509.Revocations;

/// <summary>
/// Tests for creating OCSP responses using BouncyCastle's BasicOcspRespGenerator and OCSPRespGenerator.
/// </summary>
/// <param name="fixture"></param>
public class OcspRespTests(OcspFixture fixture) : IClassFixture<OcspFixture>
{
    private static OcspResp CreateOcspResponse(
        OcspReq request,
        X509Certificate issuerCert,
        AsymmetricKeyParameter responderKey,
        X509Certificate responderCert,
        CertificateStatus? revocationStatus = null)
    {
        // 1. Initialize the generator (specify the responder's public key or name)
        BasicOcspRespGenerator gen = new(new RespID(responderCert.SubjectDN));

        // 2. Add the status of each certificate included in the request.
        Req[] requests = request.GetRequestList();
        foreach (Req req in requests)
        {
            CertificateID certId = req.GetCertID();

            // Check if the request is addressed to this CA
            if (!certId.MatchesIssuer(issuerCert))
            {
                gen.AddResponse(certId, new UnknownStatus());
                continue;
            }

            // Ideally, the expiration date should be checked by referring to a database or similar system.
            CertificateStatus status = revocationStatus ?? CertificateStatus.Good;

            gen.AddResponse(
                    certId,
                    status,
                    thisUpdate: DateTime.UtcNow,
                    nextUpdate: DateTime.UtcNow.AddDays(1),
                    singleExtensions: null
                    );
        }

        // 3. If the request has a Nonce, include it in the response as well (important!).
        X509Extension nonceExtension = request.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
        if (nonceExtension is not null)
        {
            gen.SetResponseExtensions(
                new X509Extensions(new Dictionary<DerObjectIdentifier, X509Extension> {
                        { OcspObjectIdentifiers.PkixOcspNonce, nonceExtension }
                })
            );
        }

        // 4. Generate the response (sign it with the responder's private key)
        BasicOcspResp basicResponse = gen.Generate(
            responderKey.GetSignatureAlgorithmName(),
            responderKey,
            chain: [responderCert],
            thisUpdate: DateTime.UtcNow
        );

        var generator = new OCSPRespGenerator();
        var response = generator.Generate(OCSPRespGenerator.Successful, basicResponse);

        return response;
    }

    [Fact]
    public void When_CreatingOcspResponse_WithGoodStatus_Then_CertificateIsValid()
    {
        byte[] requestBytes = fixture.CreateOcspRequest();
        var issuerCert = fixture.IssuerCert;
        var responderCert = fixture.SignerCert;
        var responderKeyPair = fixture.SignerKeyPair;

        var request = new OcspReq(requestBytes);

        var response = CreateOcspResponse(request, issuerCert, responderKeyPair.Private, responderCert);

        Assert.NotNull(response);
        response.Validate(request, issuerCert);

        Assert.Equal(OCSPRespGenerator.Successful, response.Status);

        var basicResponse = Assert.IsType<BasicOcspResp>(response.GetResponseObject());
        Assert.NotNull(basicResponse);
        Assert.NotEmpty(basicResponse.Responses);
        Assert.Equal(CertificateStatus.Good, basicResponse.Responses[0].GetCertStatus());

        Assert.True(response.VerifyStatus());
    }

    [Fact]
    public void When_CreatingOcspResponse_WithRevokedStatus_Then_CertificateIsRevoked()
    {
        byte[] requestBytes = fixture.CreateOcspRequest();
        var issuerCert = fixture.IssuerCert;
        var responderCert = fixture.SignerCert;
        var responderKeyPair = fixture.SignerKeyPair;

        var request = new OcspReq(requestBytes);

        var response = CreateOcspResponse(request, issuerCert, responderKeyPair.Private, responderCert,
             new RevokedStatus(DateTime.UtcNow, ReasonFlags.KeyCompromise));

        Assert.NotNull(response);
        response.Validate(request, issuerCert);

        Assert.Equal(OCSPRespGenerator.Successful, response.Status);

        var basicResponse = Assert.IsType<BasicOcspResp>(response.GetResponseObject());
        Assert.NotNull(basicResponse);
        Assert.NotEmpty(basicResponse.Responses);
        var revoked = Assert.IsType<RevokedStatus>(basicResponse.Responses[0].GetCertStatus());
        Assert.Equal(ReasonFlags.KeyCompromise, revoked.RevocationReason);

        Assert.False(response.VerifyStatus());
    }
}
