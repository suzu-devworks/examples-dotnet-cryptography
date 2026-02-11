using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Helpers;
using Examples.Cryptography.Tests.X509.Helper;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509CrlTests(
    X509CrlTests.Fixture fixture)
    : IClassFixture<X509CrlTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public ValueTask InitializeAsync()
        {
            X500DistinguishedName rootCaDname = new("C=JP, O=examples, CN=Issuer CA");
            X500DistinguishedName targetDname = new("CN=*.examples.jp");

            var certificates = new TestCertificateChainBuilder(rootCaDname)
                .AddEndEntity(targetDname, req => req
                    .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
                )
                .Build(DateTimeOffset.UtcNow, days: 1);

            IssuerCertificate = certificates.First(x => x.SubjectName.Name == rootCaDname.Name);
            Certificate = certificates.First(x => x.SubjectName.Name == targetDname.Name);
            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            Certificate.Dispose();
            IssuerCertificate.Dispose();
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }

        public X509Certificate2 IssuerCertificate { get; private set; } = default!;
        public X509Certificate2 Certificate { get; private set; } = default!;
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public async Task When_CreateCRLWithBuilder_Then_ReturnsDERBinaryArray()
    {
        var issuerCert = fixture.IssuerCertificate;
        var certificate = fixture.Certificate;
        var updateInterval = TimeSpan.FromDays(1);

        var builder = new CertificateRevocationListBuilder();

        builder.AddEntry(
            certificate,
            DateTimeOffset.Parse("2012-02-29"),
            X509RevocationReason.KeyCompromise);

        builder.AddEntry(
            new CertificateSerialNumber().ToBytes(),
            DateTimeOffset.Parse("2016-02-29"),
            X509RevocationReason.WeakAlgorithmOrKey);

        byte[] bytes = builder.Build(issuerCert,
            BigInteger.One,
            DateTimeOffset.UtcNow + updateInterval,
            HashAlgorithmName.SHA256);

        await FileOutput.WriteFileAsync(@"test.crl", bytes, TestContext.Current.CancellationToken);

        var x509crl = new X509Crl(bytes);
        Output?.WriteLine($"CrlData Dump: {x509crl.Dump()}");

        // Assert:

        Assert.NotEmpty(bytes);

        Assert.Equal(SignatureAlgorithms.Sha256ECDSA.Value, x509crl.SignatureAlgorithm?.Algorithm.Value);
        Assert.Equal("C=JP, O=examples, CN=Issuer CA", x509crl.TbsCertList.Issuer.Name);
        Assert.Equal(2, x509crl.TbsCertList.RevokedCertificates.Count);

    }
}
