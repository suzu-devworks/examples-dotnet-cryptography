using System.Text;
using Examples.Cryptography.BouncyCastle.Pkcs;
using Examples.Cryptography.Tests.BouncyCastle.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.Tests.BouncyCastle.Pkcs;

public class TimeStampTokenTests
{
    private readonly ITestOutputHelper _output;

    public TimeStampTokenTests(ITestOutputHelper output)
    {
        /// ```
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        InitializeCerts(DateTimeOffset.Now);
    }

    // https://datatracker.ietf.org/doc/html/rfc3161

    private (AsymmetricCipherKeyPair, X509Certificate, X509Crl?) _ca;
    private (AsymmetricCipherKeyPair, X509Certificate, X509Crl?) _tsa;

    [Fact]
    public void WhenCreatingNewTST_WithCheckItsContents()
    {
        // ### Arrange. ###
        var now = DateTimeOffset.Now;

        // Prepare your TSA certificate
        var (_, caCert, caCrl) = _ca;
        var (tsaKeyPair, tsaCert, _) = _tsa;

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
                tsaPolicyOID: TsaPolicyPUF5YearsExpiration.Id)
            .Configure(gen =>
            {
                var store1 = CollectionUtilities.CreateStore(new[] { tsaCert, caCert });
                gen.SetCertificates(store1);

                var store2 = CollectionUtilities.CreateStore(new[] { caCrl });
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

        return;
    }


    private static readonly DerObjectIdentifier TsaPolicyPUF5YearsExpiration
        = new("0.2.440.200185.1.1.1.1");

    private void InitializeCerts(DateTimeOffset now)
    {
        var notBefore = now.AddSeconds(-50);

        var rootKeyPair = X509CertificateTestDataGenerator.GenerateKeyPair("Ed25519");
        var rootCert = X509CertificateTestDataGenerator.GenerateRootCACertificate(
                   rootKeyPair,
                   new X509Name("C=JP,CN=Test CA root for TSA"),
                   notBefore);
        var rootCrl = X509CertificateTestDataGenerator.GenerateCRL(
                    rootKeyPair,
                    rootCert,
                    crlNumber: BigInteger.One,
                    notBefore,
                    configureAction: gen =>
                    {
                        gen.AddCrlEntry(BigInteger.One, notBefore.UtcDateTime, CrlReason.KeyCompromise);
                        gen.AddCrlEntry(BigInteger.Two, notBefore.UtcDateTime, CrlReason.PrivilegeWithdrawn);
                    });
        _ca = (rootKeyPair, rootCert, rootCrl);

        var tsaKeyPair = X509CertificateTestDataGenerator.GenerateKeyPair("ECDSA");
        var tsaCert = X509CertificateTestDataGenerator.GenerateCertificate(
            tsaKeyPair,
            new X509Name("C=JP,CN=Test TSA"),
            rootKeyPair,
            rootCert,
            BigInteger.One,
            notBefore,
            configure: gen =>
            {
                gen.AddExtension(X509Extensions.KeyUsage, critical: true,
                    new KeyUsage(KeyUsage.DigitalSignature));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, critical: true,
                    new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
            }
        );
        _tsa = (tsaKeyPair, tsaCert, null);

    }

}
