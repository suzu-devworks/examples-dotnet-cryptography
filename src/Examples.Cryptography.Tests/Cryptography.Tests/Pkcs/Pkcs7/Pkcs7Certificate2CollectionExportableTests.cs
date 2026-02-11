using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Fixtures.OpenSsl;

namespace Examples.Cryptography.Tests.Pkcs.Pkcs7;

/// <summary>
/// Tests for exporting and importing PKCS#7 certificate collections.
/// </summary>
/// <param name="fixture"></param>
public class Pkcs7Certificate2CollectionExportableTests(
    Pkcs7Certificate2CollectionExportableTests.Fixtures fixture
    ) : IClassFixture<Pkcs7Certificate2CollectionExportableTests.Fixtures>
{
    public class Fixtures : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await Certificates.InitializeAsync();
            await Pkcs7.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await Certificates.DisposeAsync();
            await Pkcs7.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public RsaCertificateChainOpenSslFixture Certificates { get; } = new();
        public Pkcs7OpenSslFixture Pkcs7 { get; } = new();

        public X509Certificate2 RootCaCertificate => Certificates.RootCaCertificate;
        public X509Certificate2 IntermediateCaCertificate => Certificates.IntermediateCaCertificate;
        public X509Certificate2 EndEntityCertificate => Certificates.EndEntityCertificate;
        public string ContainerPem => Pkcs7.ContainerPem;
        public string CertificateCollectionPem => Pkcs7.CertificateCollectionPem;
    }

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

        /* With OpenSSL use the following command:
        ```shell
        openssl crl2pkcs7 -nocrl \
            -certfile localhost.crt \
            -certfile ca.crt \
            -certfile ca-root.crt \
            -out ecdsa-certificates.p7b -outform DER
        ```
        */
        var exported = original.Export(X509ContentType.Pkcs7);

        var signedCms = new SignedCms();
        signedCms.Decode(exported ?? []);
        var imported = signedCms.Certificates;

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The same set of certificates
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

        /* With OpenSSL use the following command:
        ```shell
        openssl crl2pkcs7 -nocrl \
            -certfile localhost.crt \
            -certfile ca.crt \
            -certfile ca-root.crt \
            -out ecdsa-certificates.p7b -outform PEM
        ```
        */
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

        // The same set of certificates
        Assert.Equal(original, imported);
    }

    [Fact]
    public void When_OpenSSLPemIsImported_WithPkcs7Container_Then_ReturnsEmpty()
    {
        var pem = fixture.ContainerPem;

        var pkcs7 = new X509Certificate2Collection();
        pkcs7.ImportFromPem(pem.AsSpan());

        Assert.Empty(pkcs7);
    }

    [Fact]
    public void When_OpenSSLPemIsImported_WithPrintCertsFromPkcs7_Then_ReturnsMultipleCertificates()
    {
        var pem = fixture.CertificateCollectionPem;

        var pkcs7 = new X509Certificate2Collection();
        pkcs7.ImportFromPem(pem.AsSpan());

        Assert.NotEmpty(pkcs7);
        Assert.Equal(3, pkcs7.Count);
        Assert.Contains(pkcs7, c => c.Subject.Contains("CN=*.ecdsa.example.com, C=JP"));
        Assert.Contains(pkcs7, c => c.Subject.Contains("CN=Example Intermediate CA, O=examples, C=JP"));
        Assert.Contains(pkcs7, c => c.Subject.Contains("CN=Example Root CA, O=examples, C=JP"));
    }

}
