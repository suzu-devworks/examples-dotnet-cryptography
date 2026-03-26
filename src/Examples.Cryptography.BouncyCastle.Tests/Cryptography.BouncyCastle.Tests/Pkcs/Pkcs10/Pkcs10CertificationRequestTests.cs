using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Pkcs;
using Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Pkcs.Pkcs10;

public class Pkcs10CertificationRequestTests(
    Pkcs10CertificationRequestTests.Fixture fixture
    ) : IClassFixture<Pkcs10CertificationRequestTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await Pkcs10.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await Pkcs10.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public AsymmetricCipherKeyPair KeyPair => _keyPair.Value;
        private readonly Lazy<AsymmetricCipherKeyPair> _keyPair = new(() =>
        {
            var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
                .ConfigureECParameter(CustomNamedCurves.GetByName("P-256"))
                .GenerateKeyPair();

            return keyPair;
        });

        public Pkcs10OpenSslFixture Pkcs10 { get; } = new();
        public string EcdsaCertRequestPem => Pkcs10.EcdsaCertRequestPem;
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public async Task When_ExportedToPemAndImported_Then_IsRestored()
    {
        var keyPair = fixture.KeyPair;

        Pkcs10CertificationRequest request = new(
            signatureAlgorithm: X9ObjectIdentifiers.ECDsaWithSha512.Id,
            new X509Name("CN=bc.pkcs10.example.com"),
            publicKey: keyPair.Public,
            attributes: null,
            signingKey: keyPair.Private
        );

        var pem = request.ExportCertificateRequestPem();
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync("bc-pkcs10.example.csr", pem,
            TestContext.Current.CancellationToken);

        var imported = Pkcs10CertificationRequestLoader.LoadFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", pem);
        Assert.EndsWith("-----END CERTIFICATE REQUEST-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        Assert.True(imported.Verify());
        Assert.True(imported.Verify(keyPair.Public));
    }

    [Fact]
    public void When_OpenSSLPemLoaded_Then_ExtensionsIsLoaded()
    {
        var pem = fixture.EcdsaCertRequestPem;

        var imported = Pkcs10CertificationRequestLoader.LoadFromPem(pem);

        // Assert:

        Assert.NotNull(imported);

        var csrInfo = imported.GetCertificationRequestInfo();
        Assert.Multiple(
            () => Assert.Equal(DerInteger.Zero, csrInfo.Version),
            () => Assert.Equal("C=JP,CN=*.ecdsa.example.com", csrInfo.Subject.ToString()),
            () => Assert.Equal(X9ObjectIdentifiers.IdECPublicKey, csrInfo.SubjectPublicKeyInfo.Algorithm.Algorithm),
            () => Assert.Equal(X9ObjectIdentifiers.Prime256v1, csrInfo.SubjectPublicKeyInfo.Algorithm.Parameters),
            () => Assert.NotNull(csrInfo.SubjectPublicKeyInfo.PublicKey),
            () => Assert.NotEmpty(csrInfo.Attributes)
        );

        var extensions = imported.GetRequestedExtensions();
        Assert.Collection(extensions.ExtensionOids,
            (oid) =>
            {
                Assert.Equal(X509Extensions.BasicConstraints, oid);

                var extension = extensions.GetExtension(oid);
                Assert.False(extension.IsCritical);

                var basic = BasicConstraints.GetInstance(extension);
                Assert.False(basic.IsCA());
                Assert.Null(basic.PathLenConstraint);
            },
            (oid) =>
            {
                Assert.Equal(X509Extensions.KeyUsage, oid);

                var extension = extensions.GetExtension(oid);
                Assert.False(extension.IsCritical);

                var keyUsage = KeyUsage.GetInstance(extension);
                Assert.Equal(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment, keyUsage.IntValue);
            },
            (oid) =>
            {
                Assert.Equal(X509Extensions.ExtendedKeyUsage, oid);

                var extension = extensions.GetExtension(oid);
                Assert.False(extension.IsCritical);

                var extendedKeyUsage = ExtendedKeyUsage.GetInstance(extension);
                var usage = Assert.Single(extendedKeyUsage.GetAllUsages());
                Assert.Equal(KeyPurposeID.id_kp_serverAuth, usage);
            },
            (oid) =>
            {
                Assert.Equal(X509Extensions.SubjectAlternativeName, oid);

                var extension = extensions.GetExtension(oid);
                Assert.False(extension.IsCritical);

                var san = GeneralNames.GetInstance(Asn1Object.FromByteArray(extension.Value.GetOctets()));
                Assert.Collection(san.GetNames(),
                    (x) =>
                    {
                        Assert.Equal(GeneralName.DnsName, x.TagNo);
                        Assert.Equal("localhost", ((DerStringBase)x.Name).GetString());
                    },
                    (x) =>
                    {
                        Assert.Equal(GeneralName.IPAddress, x.TagNo);
                        var ipBytes = ((DerOctetString)x.Name).GetOctets();
                        Assert.Equal(new byte[] { 127, 0, 0, 1 }, ipBytes);
                    });
            });
    }
}
