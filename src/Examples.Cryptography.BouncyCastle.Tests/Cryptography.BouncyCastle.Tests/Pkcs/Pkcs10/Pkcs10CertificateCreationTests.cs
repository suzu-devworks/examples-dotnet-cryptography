using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Tests.Pkcs.Pkcs10;

public class Pkcs10CertificateCreationTests(
    Pkcs10CertificateCreationTests.Fixture fixture
    ) : IClassFixture<Pkcs10CertificateCreationTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public Fixture()
        {
            KeyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
                .ConfigureECParameter(CustomNamedCurves.GetByName("P-256"))
                .GenerateKeyPair();

            Request = new(
                signatureAlgorithm: X9ObjectIdentifiers.ECDsaWithSha512.Id,

                new X509Name("CN=bc.pkcs10.example.com"),
                publicKey: KeyPair.Public,
                attributes: null,
                signingKey: KeyPair.Private
            );
        }

        public async ValueTask InitializeAsync()
        {
            await CaCerts.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await CaCerts.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public AsymmetricCipherKeyPair KeyPair { get; }
        public Pkcs10CertificationRequest Request { get; }

        public CaCertificatesOpenSslFixture CaCerts { get; } = new(includePrivateKeys: true);
        public X509Certificate SignerCert => CaCerts.IntermediateCaCertificate;
        public AsymmetricCipherKeyPair SignerKeyPair => CaCerts.IntermediateCaPrivateKey!;
    }

    [Fact]
    public void When_SignedBySelfSignedCert_Then_SelfSignedCertificateIsReturned()
    {
        Pkcs10CertificationRequest request = fixture.Request;
        AsymmetricCipherKeyPair keyPair = fixture.KeyPair;

        var now = DateTimeOffset.UtcNow;

        var subject = request.GetCertificationRequestInfo().Subject;
        var cert = new X509V3CertificateGenerator()
            .Configure(g =>
            {
                g.SetIssuerDN(subject);
                g.SetSerialNumber(BigInteger.One);
                g.SetSubjectDN(subject);
                g.SetPublicKey(request.GetPublicKey());
            })
            .WithValidityPeriod(now, days: 1)
            .Generate(new Asn1SignatureFactory("SHA256WithECDSA", keyPair.Private));

        // Assert:

        // The certificate is created.
        Assert.NotNull(cert);

        // When receive your certificate, please verify that it is yours.
        cert.Verify(keyPair.Public);
    }

    [Fact]
    public void When_SignedWithSignerCert_Then_CertificateIsReturned()
    {
        Pkcs10CertificationRequest request = fixture.Request;

        X509Certificate signerCert = fixture.SignerCert;
        AsymmetricCipherKeyPair keyPair = fixture.SignerKeyPair;

        var now = DateTimeOffset.UtcNow;
        var serial = new BigInteger(256, new SecureRandom());

        var cert = new X509V3CertificateGenerator()
            .Configure(g =>
            {
                g.SetIssuerDN(signerCert.SubjectDN);
                g.SetSerialNumber(serial);
                g.SetSubjectDN(request.GetCertificationRequestInfo().Subject);
                g.SetPublicKey(request.GetPublicKey());

                g.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                    critical: false,
                    X509ExtensionUtilities.CreateAuthorityKeyIdentifier(signerCert));
                g.AddExtension(X509Extensions.SubjectKeyIdentifier,
                    critical: false,
                    X509ExtensionUtilities.CreateSubjectKeyIdentifier(request.GetPublicKey()));
                g.AddExtension(X509Extensions.BasicConstraints,
                    critical: true,
                    new BasicConstraints(cA: false));
                g.AddExtension(X509Extensions.KeyUsage,
                    critical: true,
                    new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
            })
            .WithValidityPeriod(now, days: 1)
            .Generate(new Asn1SignatureFactory("SHA256WithECDSA", keyPair.Private));

        // Assert:

        // The certificate is created.
        Assert.NotNull(cert);

        // When receive your certificate, please verify that it is yours.
        cert.Verify(signerCert.GetPublicKey());
    }
}

