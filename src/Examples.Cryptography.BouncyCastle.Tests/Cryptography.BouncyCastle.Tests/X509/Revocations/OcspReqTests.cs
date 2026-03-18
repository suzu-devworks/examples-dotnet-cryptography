using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.X509.Revocations;

/// <summary>
/// Tests for creating OCSP requests using BouncyCastle's OcspReqGenerator.
/// </summary>
/// <param name="fixture"></param>
public class OcspReqTests(OcspFixture fixture) : IClassFixture<OcspFixture>
{
    private static OcspReq CreateUnsignedOcspRequest(X509Certificate issuerCert, X509Certificate targetCert)
    {
        // Unsigned Request:
        // This is the most common. To protect privacy and reduce server load, the sender's identity is not revealed.
        // In this case, SetRequestorName is not used.

        // 1. Create a CertificateID (SHA-1 is still the standard for compatibility reasons,
        // but consider using SHA-256 if supported by the server)
        CertificateID id = new(
            CertificateID.DigestSha1,
            issuerCert, // Used to obtain a hash of the issuer's name and public key
            targetCert.SerialNumber // Used to obtain a serial number that identifies the subject
        );

        // 2. Initialize the generator and add the request
        OcspReqGenerator gen = new OcspReqGenerator();
        gen.AddRequest(id);

        // 3. Add a nonce (random value) (Recommended: Replay attack prevention)
        // If the server supports nonce, the same value will be included in the response.
        byte[] nonce = new byte[16];
        new Random().NextBytes(nonce);
        gen.AddNonce(nonce);

        return gen.Generate();
    }

    private static OcspReq CreateSignedOcspRequest(
        X509Certificate issuerCert,
        X509Certificate targetCert,
        AsymmetricKeyParameter signerPrivateKey,
        X509Certificate signerCert,
        X509Certificate[]? signerChain = null)
    {
        // Signed Request:
        // Used when only authenticated users are allowed to make OCSP queries for a particular service.
        // In this case, SetRequestorName is set to clarify "who signed it",
        // and signing is performed with gen.Generate(sigName, key, chain).

        CertificateID id = new(CertificateID.DigestSha1, issuerCert, targetCert.SerialNumber);

        OcspReqGenerator gen = new OcspReqGenerator();
        gen.AddRequest(id);

        gen.SetRequestorName(new GeneralName(signerCert.SubjectDN));

        // Include the signer certificate in the chain
        // It is customary not to include the root certificate (Root CA).
        // Place the signer at the beginning and arrange them in chain order
        X509Certificate[] certChain = [signerCert, .. signerChain ?? []];
        string signatureAlgorithm = signerPrivateKey.GetSignatureAlgorithmName();

        return gen.Generate(signatureAlgorithm, signerPrivateKey, certChain);
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_CreatingBasicOcspRequest_Then_ContainsNonce()
    {
        var issuerCert = fixture.IssuerCert;
        var targetCert = fixture.TargetCert;

        var ocspReq = CreateUnsignedOcspRequest(issuerCert, targetCert);
        Output?.WriteLine($"OCSP Request:\n{ocspReq}");

        // this OCSP request is not signed.
        bool isSigned = ocspReq.IsSigned;
        Assert.False(isSigned, "OCSP request is signed.");

        // Check that the request does not contain any certificates (since it's unsigned)
        X509Certificate[] certs = ocspReq.GetCerts();
        Assert.Null(certs);

        // Check that the request contains the expected certificate ID
        Req[] requests = ocspReq.GetRequestList();
        Assert.Single(requests);
        Assert.Equal(targetCert.SerialNumber, requests[0].GetCertID().SerialNumber);

        // Check that the request contains the expected nonce
        var extension = ocspReq.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
        Assert.NotNull(extension);
        var nonceValue = extension.Value.GetOctets();
        Assert.Equal(16, nonceValue.Length);
    }

    [Fact]
    public void When_CreatingSignedOcspRequest_Then_ContainsValidSignature()
    {
        var issuerCert = fixture.IssuerCert;
        var targetCert = fixture.TargetCert;

        var signerCert = fixture.SignerCert;
        var signerPrivateKey = fixture.SignerKeyPair.Private;

        var ocspReq = CreateSignedOcspRequest(issuerCert, targetCert, signerPrivateKey, signerCert);
        Output?.WriteLine($"OCSP Request:\n{ocspReq}");

        // this OCSP request is signed.
        bool isSigned = ocspReq.IsSigned;
        Assert.True(isSigned, "OCSP request is not signed.");

        // Check that the request contains the expected signer certificate
        X509Certificate[] certs = ocspReq.GetCerts();
        Assert.Single(certs);
        Assert.Equal(signerCert, certs[0]);

        // Check that the request contains the expected certificate ID
        Req[] requests = ocspReq.GetRequestList();
        Assert.Single(requests);
        Assert.Equal(targetCert.SerialNumber, requests[0].GetCertID().SerialNumber);

        // Check that the request does not contain a nonce (since it's signed)
        var extension = ocspReq.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
        Assert.Null(extension);

        // Verify the signature of the OCSP request
        bool isValid = ocspReq.Verify(fixture.SignerCert.GetPublicKey());
        Assert.True(isValid, "OCSP request signature is invalid.");
    }
}
