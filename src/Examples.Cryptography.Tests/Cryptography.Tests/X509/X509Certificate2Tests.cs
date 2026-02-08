using System.Security.Cryptography.X509Certificates;
using System.Text;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.X509;

public class X509Certificate2Tests(
    X509Certificate2Tests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<X509Certificate2Tests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await Ecdsa.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await Ecdsa.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public EcdsaCertificateOpenSslFixture Ecdsa { get; } = new();
        public string CertificatePem => Ecdsa.CertificatePem;

        public X509Certificate2 Certificate { get; } = CreateCertificate();

        private static X509Certificate2 CreateCertificate()
        {
            var notBefore = DateTime.UtcNow.AddSeconds(-50);
            return TestCertificateFactory.CreateSelfSigned(new("CN=*.examples.jp"), notBefore);
        }
    }

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public void When_CertificateIsVerified_Then_SucceedsWithIssuerCertificate()
    {
        var target = fixture.Certificate;
        var issuer = fixture.Certificate;   // self signed.

        var verified = target.VerifiesSignature(issuer);

        Assert.True(verified);
    }

    [Fact]
    public void When_ExportedAndLoaded_Then_PrivateKeyIsNotRestored()
    {
        var original = fixture.Certificate;

        var exported = original.Export(X509ContentType.Cert);

        using var loaded = X509CertificateLoader.LoadCertificate(exported);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, loaded);

        // The contents should be the same.
        Assert.Equal(original, loaded);
        Assert.Equal(original.Thumbprint, loaded.Thumbprint);

        // Originally, I had a private key, but it was lost when I exported it.
        Assert.True(original.HasPrivateKey);
        Assert.False(loaded.HasPrivateKey);
    }

    [Fact]
    public async Task When_ExportedToPemAndLoaded_Then_PrivateKeyIsNotRestored()
    {
        var original = fixture.Certificate;

        var pem = original.ExportCertificatePem();
        output.WriteLine($"\n{pem}");
        await FileOutput.WriteFileAsync("localhost.crt", pem, TestContext.Current.CancellationToken);

        using var loaded = X509CertificateLoader.LoadCertificate(Encoding.UTF8.GetBytes(pem));

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
        Assert.EndsWith("-----END CERTIFICATE-----", pem);

        // They are different instances.
        Assert.NotSame(original, loaded);

        // The contents should be the same.
        Assert.Equal(original, loaded);
        Assert.Equal(original.Thumbprint, loaded.Thumbprint);
    }

    [Fact]
    public void When_OpenSSLIsImported_Then_CertificateIsRestored()
    {
        var pem = fixture.CertificatePem;

        using var loaded = X509CertificateLoader.LoadCertificate(Encoding.UTF8.GetBytes(pem));

        // Assert:

        Assert.NotNull(loaded);

        // The contents should be the same.
        Assert.Equal("CN=Example Intermediate CA, O=examples, C=JP", loaded.IssuerName.Name);
        Assert.Equal("CN=*.ecdsa.example.com, C=JP", loaded.SubjectName.Name);

        // Certificate can not hold private keys
        Assert.False(loaded.HasPrivateKey);
    }
}
