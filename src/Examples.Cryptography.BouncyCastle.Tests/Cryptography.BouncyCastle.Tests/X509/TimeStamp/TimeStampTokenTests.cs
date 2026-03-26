using System.Text;
using Examples.Cryptography.BouncyCastle.Asn1;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.X509.TimeStamp;

/// <summary>
/// Tests for TimeStampToken generation and validation using BouncyCastle.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc3161"/>
public class TimeStampTokenTests(
    TimeStampAuthorityFixture fixture
    ) : IClassFixture<TimeStampAuthorityFixture>
{

    private static void AssertContent(TimeStampToken timeStampToken)
    {
        // SignerIdentifier
        var sid = timeStampToken.SignerID;
        Assert.Equal("C=JP,CN=Test CA root for TSA", sid.Issuer.ToString());
        Assert.NotEqual(BigInteger.Zero, sid.SerialNumber);
        Assert.Null(sid.SubjectKeyIdentifier);

        var certs = timeStampToken.GetCertificates().EnumerateMatches(null);
        var crls = timeStampToken.GetCrls().EnumerateMatches(null);
        var sAttrs = timeStampToken.SignedAttributes;
        var uAttrs = timeStampToken.UnsignedAttributes;

        // ContentInfo
        var content = timeStampToken.ToCmsSignedData().ContentInfo;
        Assert.Equal("1.2.840.113549.1.7.2", content.ContentType.Id); // id-signedData

        // SignedData
        var cms = timeStampToken.ToCmsSignedData();
        Assert.Equal(3, cms.Version);
        Assert.Equal("2.16.840.1.101.3.4.2.3", cms.GetDigestAlgorithms().Single().Algorithm.Id); // id-sha512
        Assert.Equal("1.2.840.113549.1.9.16.1.4", cms.SignedContentType.Id); // id-ct-TSTInfo
        Assert.Equal(certs, cms.GetCertificates().EnumerateMatches(null));
        Assert.Equal(crls, cms.GetCrls().EnumerateMatches(null));

        // SignerInfo
        var signer = timeStampToken.ToCmsSignedData().GetSignerInfos().Single();
        Assert.Equal(1, signer.Version);
        Assert.Equal(sid, signer.SignerID);
        Assert.Equal("2.16.840.1.101.3.4.2.3", signer.DigestAlgorithmID.Algorithm.Id); // id-sha512
        Assert.Equal(sAttrs, signer.SignedAttributes);
        Assert.Equal("1.2.840.10045.4.3.4", signer.SignatureAlgorithm.Algorithm.Id); // ecdsa-with-SHA512
        Assert.Equal(uAttrs, signer.UnsignedAttributes);

        // TSTInfo
        var tst = timeStampToken.TimeStampInfo;
        Assert.Equal("0.1.2.3.4.5", tst.Policy);
        Assert.Equal("2.16.840.1.101.3.4.2.3", tst.MessageImprintAlgOid); // id-sha512
        Assert.Equal(BigInteger.One, tst.SerialNumber);
        Assert.False(tst.IsOrdered);
        Assert.Equal(BigInteger.Zero, tst.Nonce);
        Assert.Null(tst.Tsa);

        var tstTime = timeStampToken.TimeStampInfo.GenTime;
        Assert.True(DateTime.UtcNow.AddSeconds(-10) < tstTime);
        Assert.True(tstTime < DateTime.UtcNow.AddSeconds(10));
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_CreatingNewTST_WithCheckItsContents()
    {
        var data = Encoding.UTF8.GetBytes("TEST MESSAGE PHRASE");

        // Prepare your MessageImprint
        var algorithm = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
        var digest = DigestUtilities.CalculateDigest(algorithm.Algorithm, data);
        var message = new MessageImprint(algorithm, digest);

        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(certReq: true);

        var request = requestGenerator.Generate(
                    digestAlgorithmOid: message.HashAlgorithm.Algorithm.Id,
                    digest: message.GetHashedMessage(),
                    nonce: BigInteger.Zero);
        var requestBytes = request.GetEncoded(); // Encode the request to bytes for sending to the TSA.

        // client --- send --->  TSA server.

        var responseBytes = DoTSAServer(requestBytes);

        // client <-- recv --- TSA server.

        var response = new TimeStampResponse(responseBytes);

        Output?.WriteLine($"TimeStampResponse:\n{response.TimeStampToken.ToStructureString()}");

        // Validate the response against the original request.
        response.Validate(request);

        // If you check with the TSA certificate, it will be successful.
        response.TimeStampToken.Validate(fixture.TsaCertificate);

        // Assert:

        Assert.Equal((int)PkiStatus.Granted, response.Status);
        AssertContent(response.TimeStampToken);

        byte[] DoTSAServer(byte[] requestBytes)
        {
            AsymmetricCipherKeyPair tsaKeyPair = fixture.TsaPrivateKey;
            X509Certificate tsaCert = fixture.TsaCertificate;
            X509Certificate tsaSignerCert = fixture.TsaSignerCertificate;
            X509Crl? tsaSignerCrl = fixture.TsaSignerCrl;

            var request = new TimeStampRequest(requestBytes);

            var generator = new TimeStampTokenGenerator(
                key: tsaKeyPair.Private,
                cert: tsaCert,
                digestOID: NistObjectIdentifiers.IdSha512.Id,
                tsaPolicyOID: "0.1.2.3.4.5")
                .Configure(gen =>
                {
                    // Optionally, you can set additional certificates and CRLs if needed.
                    // This is useful if the TSA certificate is not directly trusted and you want to include the chain.
                    gen.SetCertificates(CollectionUtilities.CreateStore<X509Certificate>(new[] { tsaCert, tsaSignerCert }));

                    // If you have CRLs to include, you can set them as well.
                    gen.SetCrls(CollectionUtilities.CreateStore<X509Crl>(new[] { tsaSignerCrl! }));
                });

            var responseGenerator = new TimeStampResponseGenerator(generator, TspAlgorithms.Allowed);

            var now = DateTimeOffset.UtcNow; // TimeStamp
            var response = responseGenerator.Generate(request, BigInteger.One, now.UtcDateTime);

            return response.GetEncoded();
        }
    }

}
