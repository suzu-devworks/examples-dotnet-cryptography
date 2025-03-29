using System.Text;
using Examples.Cryptography.BouncyCastle.Logging;
using Examples.Cryptography.BouncyCastle.X509;
using Examples.Cryptography.Generics;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.X509;

public class TimeStampTokenTests : IClassFixture<TimeStampDataFixture>
{
    private readonly TimeStampDataFixture _fixture;
    private readonly ITestOutputHelper _output;

    public TimeStampTokenTests(TimeStampDataFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;

        // ```shell
        // dotnet test --logger "console;verbosity=detailed"
        // ```
        _output = output;
    }

    [Fact]
    public void WhenCreatingNewTST_WithCheckItsContents()
    {
        // https://datatracker.ietf.org/doc/html/rfc3161

        // ### Arrange. ###
        var now = DateTimeOffset.Now;

        // Prepare your TSA certificate
        var (_, caCert) = _fixture.CaSet;
        var (tsaKeyPair, tsaCert) = _fixture.TsaSet;
        var caCrl = _fixture.CaCrl;

        // Prepare your MessageImprint
        var data = Encoding.UTF8.GetBytes("TEST MESSAGE PHRASE");
        var algorithm = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
        var digest = DigestUtilities.CalculateDigest(algorithm.Algorithm, data);
        var message = new MessageImprint(algorithm, digest);

        // ### Act. ###
        var token = new TimeStampTokenGenerator(
                key: tsaKeyPair.Private,
                cert: tsaCert,
                digestOID: NistObjectIdentifiers.IdSha512.Id,
                tsaPolicyOID: "1.2.3.4.5")
            .Configure(gen =>
            {
                var store1 = CollectionUtilities.CreateStore<X509Certificate>(new[] { tsaCert, caCert });
                gen.SetCertificates(store1);

                var store2 = CollectionUtilities.CreateStore<X509Crl>(new[] { caCrl! });
                gen.SetCrls(store2);
            })
            .Generate(
                message,
                nonce: BigInteger.Zero,
                serialNumber: BigInteger.One,
                genTime: now.UtcDateTime
            );

        // ### Assert. ###
        // If you check with the TSA certificate, it will be successful.
        token.Validate(tsaCert);

        _output.WriteLine($"# TimeStampToken:");
        //_output.WriteLine(Asn1Dump.DumpAsString(Asn1Sequence.GetInstance(token.GetEncoded())));
        _output.WriteLine(token.DumpAsString());

    }

}
