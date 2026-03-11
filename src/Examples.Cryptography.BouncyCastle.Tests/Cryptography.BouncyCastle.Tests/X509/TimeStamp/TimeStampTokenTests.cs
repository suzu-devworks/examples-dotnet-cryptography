using System.Text;
using Examples.Cryptography.BouncyCastle.X509;
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

        Output?.WriteLine($"TimeStampResponse:\n{response.TimeStampToken}");

        // If you check with the TSA certificate, it will be successful.
        response.TimeStampToken.Validate(fixture.TsaCertificate);

        // Assert:

        // TODO
        var tstTime = response.TimeStampToken.TimeStampInfo.GenTime;
        Assert.NotEqual(DateTime.MinValue, tstTime);
        Assert.NotEqual(DateTime.MaxValue, tstTime);

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
