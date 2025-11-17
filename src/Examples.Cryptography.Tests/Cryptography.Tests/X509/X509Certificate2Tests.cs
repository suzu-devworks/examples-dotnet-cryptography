using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509Certificate2Tests(
    X509Certificate2Tests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<X509Certificate2Tests.Fixture>
{
    public class Fixture : IDisposable
    {
        public void Dispose()
        {
            Certificate.Dispose();
            GC.SuppressFinalize(this);
        }

        public X509Certificate2 Certificate { get; } = CreateCollection();

        private static X509Certificate2 CreateCollection()
        {
            var notBefore = DateTime.UtcNow.AddSeconds(-50);
            return Helper.TestCertificateFactory.CreateSelfSignedEntity(new("CN=*.examples.jp"), notBefore);
        }
    }

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
        var loadedKey = loaded.GetRSAPrivateKey();

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
    public void When_ExportedToPemAndLoaded_Then_PrivateKeyIsNotRestored()
    {
        var original = fixture.Certificate;

        var pem = original.ExportCertificatePem();
        //File.WriteAllText("localhost.crt", pem);

        using var loaded = X509Certificate2.CreateFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
        Assert.EndsWith("-----END CERTIFICATE-----", pem);

        // They are different instances.
        Assert.NotSame(original, loaded);

        // The contents should be the same.
        Assert.Equal(original, loaded);
        Assert.Equal(original.Thumbprint, loaded.Thumbprint);

        output.WriteLine($"\n{pem}");
    }

    [Fact]
    public void When_OpenSSLIsImported_Then_CertificateIsRestored()
    {
        using var loaded = Helper.TestCertificateFactory.GetStatic();

        // Assert:

        Assert.NotNull(loaded);

        // The contents should be the same.
        Assert.Equal("CN=x509.examples", loaded.IssuerName.Name);
        Assert.Equal("CN=x509.examples", loaded.SubjectName.Name);
        Assert.Equal("4BC148AE3B09146CEA2F58BC1A1AC901AA5C5BC5", loaded.SerialNumber);
        Assert.Equal("CEB765689BE077B587666897ADBB4E92A88FA0AE", loaded.Thumbprint);

        // Certificate can not hold private keys
        Assert.False(loaded.HasPrivateKey);
    }

}
