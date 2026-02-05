using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

/// <summary>
/// Tests for exporting and importing PKCS#7 certificate collections.
/// </summary>
/// <param name="fixture"></param>
public partial class PKCS7Certificate2CollectionExportableTests(
    PKCS7Certificate2CollectionExportableTests.Fixture fixture
    ) : IClassFixture<PKCS7Certificate2CollectionExportableTests.Fixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_ExportedAndImported_Then_CertificatesAreRestored()
    {
        var root = fixture.RootCaCertificate;
        var intermediate = fixture.IntermediateCaCertificate;
        var leaf = fixture.EndEntityCertificate;

        var original = new X509Certificate2Collection
        {
            leaf,
            intermediate,
            root
        };

        var exported = original.Export(X509ContentType.Pkcs7);

        var signedCms = new SignedCms();
        signedCms.Decode(exported ?? []);
        var imported = signedCms.Certificates;

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.Equal(original, imported);
    }

    [Fact]
    public void When_ExportedToPemAndImported_Then_CertificatesAreRestored()
    {
        var root = fixture.RootCaCertificate;
        var intermediate = fixture.IntermediateCaCertificate;
        var leaf = fixture.EndEntityCertificate;

        var original = new X509Certificate2Collection
        {
            leaf,
            intermediate,
            root
        };

        var pem = original.ExportPkcs7Pem();
        Output?.WriteLine($"{pem}");

        var missImporting = new X509Certificate2Collection();
        missImporting.ImportFromPem(pem.AsSpan());

        var fields = PemEncoding.Find(pem);
        var bytes = pem[fields.Base64Data].ToBase64Bytes();

        var signedCms = new SignedCms();
        signedCms.Decode(bytes);
        var imported = signedCms.Certificates;

        // Assert:

        Assert.Multiple(
            () => Assert.StartsWith("-----BEGIN PKCS7-----", pem),
            () => Assert.EndsWith("-----END PKCS7-----", pem)
        );

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.Equal(original, imported);
    }

    [Fact]
    public void When_OpenSSLPemIsImported_Then_ReturnsMultipleCertificates()
    {
        var pem = fixture.Pem;

        var pkcs7 = new X509Certificate2Collection();
        pkcs7.ImportFromPem(pem.AsSpan());

        Assert.NotEmpty(pkcs7);
        Assert.Equal(3, pkcs7.Count);
        Assert.Contains(pkcs7, c => c.Subject.Contains("CN=*.ecdsa.example.com, C=JP"));
        Assert.Contains(pkcs7, c => c.Subject.Contains("CN=Example Intermediate CA, O=examples, C=JP"));
        Assert.Contains(pkcs7, c => c.Subject.Contains("CN=Example Root CA, O=examples, C=JP"));
    }
}
