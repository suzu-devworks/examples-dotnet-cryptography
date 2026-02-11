using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.Pkcs.Pkcs10;

/// <summary>
/// PKCS #10: Certification Request Syntax Specification Version 1.7.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc2986"/>
public class Pkcs10CertificateRequestTests(
    Pkcs10CertificateRequestTests.Fixture fixture)
    : IClassFixture<Pkcs10CertificateRequestTests.Fixture>
{
    // private static readonly Oid IdEcPublicKey = new("1.2.840.10045.2.1");

    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await Pkcs10.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            KeyPair.Dispose();
            await Pkcs10.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public Pkcs10OpenSslFixture Pkcs10 { get; } = new();
        public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public string EcdsaCertRequestPem => Pkcs10.EcdsaCertRequestPem;
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    private void AssertSame(CertificateRequest original, CertificateRequest imported)
    {
        // 1. It's not overriding, so it's not working as expected.
        Assert.NotEqual(original, imported);

        // 2. The subject name must be the same.
        Assert.Multiple(
            () => Assert.Equal(original.SubjectName.Name, imported.SubjectName.Name),
            () => Assert.Equal(original.SubjectName.RawData, imported.SubjectName.RawData)
        );

        // 3. Public Key must be the same.
        Assert.Equal(
            original.PublicKey.EncodedKeyValue.RawData,
            imported.PublicKey.EncodedKeyValue.RawData);
    }

    [Fact]
    public void When_CreateNewCertificateRequest_Then_ReturnsAsConfigured()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.example.com")
            .Build();

        var req = new CertificateRequest(
             subject,
             privateKey,
             HashAlgorithmName.SHA256)
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity())
            .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
            .AddSubjectAlternativeName(san =>
            {
                san.AddDnsName("localhost");
                san.AddIpAddress(System.Net.IPAddress.Parse("127.0.0.1"));
            });

        // Assert:

        Assert.NotNull(req);
        Assert.Multiple(
            () => Assert.Equal("CN=pkcs10.example.com", req.SubjectName.Name),
            () => Assert.Null(req.SubjectName.Oid!.Value),
            () => Assert.NotEmpty(req.SubjectName.RawData)
        );
        Assert.Equal(HashAlgorithmName.SHA256, req.HashAlgorithm);
        Assert.Collection(req.CertificateExtensions,
            (x) =>
            {
                var basic = Assert.IsType<X509BasicConstraintsExtension>(x);
                Assert.False(basic.CertificateAuthority);
                Assert.False(basic.HasPathLengthConstraint);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                var keyUsage = Assert.IsType<X509KeyUsageExtension>(x);
                Assert.Equal(X509KeyUsageFlags.DigitalSignature, keyUsage.KeyUsages);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                var san = Assert.IsType<X509SubjectAlternativeNameExtension>(x, exactMatch: true);
                Assert.Equal(["localhost"], san.EnumerateDnsNames());
                Assert.Equal(["127.0.0.1"], san.EnumerateIPAddresses().Select(x => x.ToString()));
            });
    }

    [Fact]
    public void When_CreatedAndLoaded_Then_CertificateRequestIsRestored()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.example.com")
            .Build();

        /* With OpenSSL use the following command:
        ```shell
        openssl req -new -subj "/CN=pkcs10.example.com" \
            -key private.key \
            -sha256 -reqexts v3_req \
            -out pkcs10.example.csr.der -outform DER
        ```
        */
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256);
        byte[] exported = original.CreateSigningRequest();

        var imported = CertificateRequest.LoadSigningRequest(
                exported,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The content is the same
        AssertSame(original, imported);
    }


    [Fact]
    public async Task When_CreatedPemAndLoaded_Then_CertificateRequestIsRestored()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.example.com")
            .Build();

        /* With OpenSSL use the following command:
        ```shell
        openssl req -new -subj "/CN=pkcs10.example.com" \
            -key private.key \
            -sha256 -reqexts v3_req \
            -out pkcs10.example.csr.pem -outform PEM
        ```
        */
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256);
        string pem = original.CreateSigningRequestPem();
        Output?.WriteLine($"\n{pem}");
        await FileOutput.WriteFileAsync("pkcs10.example.csr", pem, TestContext.Current.CancellationToken);

        var imported = CertificateRequest.LoadSigningRequestPem(
                pem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The content is the same
        AssertSame(original, imported);
    }

    [Fact]
    public void When_RecreatingFromLoadedSigningRequest_Then_ThrowsInvalidOperation()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.example.com")
            .Build();
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256);

        string pem = original.CreateSigningRequestPem();

        _ = original.CreateSigningRequestPem(); // Non Error

        var imported = CertificateRequest.LoadSigningRequestPem(
                pem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Re-export is not allowed.
        var exception = Assert.Throws<InvalidOperationException>(() => imported.CreateSigningRequestPem());

        Assert.Equal("This method cannot be used since no signing key was provided via a constructor, "
            + "use an overload accepting an X509SignatureGenerator instead.",
            exception.Message);
    }

    [Fact]
    public void When_CreatedToAndLoaded_WithDefaultLoadOptions_Then_ExtensionsAreNotLoaded()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.example.com")
            .Build();
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256)
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity())
            .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
            .AddSubjectAlternativeName(san =>
            {
                san.AddDnsName("localhost");
                san.AddIpAddress(System.Net.IPAddress.Parse("127.0.0.1"));
            });

        byte[] exported = original.CreateSigningRequest();

        var imported = CertificateRequest.LoadSigningRequest(
                exported,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Assert:

        // For security reasons, extensions are not normally loaded.
        Assert.Empty(imported.CertificateExtensions);
    }

    [Fact]
    public void When_CreatedToAndLoaded_WithUnsafeLoadOptions_Then_ExtensionsAreLoaded()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.example.com")
            .Build();
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256)
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity())
            .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
            .AddSubjectAlternativeName(san =>
            {
                san.AddDnsName("localhost");
                san.AddIpAddress(System.Net.IPAddress.Parse("127.0.0.1"));
            });

        byte[] exported = original.CreateSigningRequest();

        var imported = CertificateRequest.LoadSigningRequest(
                exported,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // extensions are loaded.
        Assert.Equal(3, imported.CertificateExtensions.Count);
    }

    [Fact]
    public void When_OpenSSLPemLoaded_Then_ExtensionsIsLoaded()
    {
        var pem = fixture.EcdsaCertRequestPem;

        var imported = CertificateRequest.LoadSigningRequestPem(
                pem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        // Assert:

        Assert.NotNull(imported);
        Assert.Multiple(
            () => Assert.Equal("CN=*.ecdsa.example.com, C=JP", imported.SubjectName.Name),
            () => Assert.Null(imported.SubjectName.Oid!.Value),
            () => Assert.NotEmpty(imported.SubjectName.RawData)
        );
        Assert.Equal(HashAlgorithmName.SHA256, imported.HashAlgorithm);

        // Unsafe options load extensions.
        Assert.Collection(imported.CertificateExtensions,
           (x) =>
           {
               var basic = Assert.IsType<X509BasicConstraintsExtension>(x);
               Assert.False(basic.CertificateAuthority);
               Assert.False(basic.HasPathLengthConstraint);
           },
           (x) =>
           {
               Assert.False(x.Critical);
               var keyUsage = Assert.IsType<X509KeyUsageExtension>(x);
               Assert.Equal(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                keyUsage.KeyUsages);
           },
           (x) =>
           {
               Assert.False(x.Critical);
               var enhancedKeyUsages = Assert.IsType<X509EnhancedKeyUsageExtension>(x);
               var oid = Assert.Single(enhancedKeyUsages.EnhancedKeyUsages.Cast<Oid>());
               Assert.Equal("1.3.6.1.5.5.7.3.1", oid.Value);
           },
           (x) =>
           {
               Assert.False(x.Critical);
               var san = Assert.IsType<X509SubjectAlternativeNameExtension>(x, exactMatch: true);
               Assert.Equal(["localhost"], san.EnumerateDnsNames());
               Assert.Equal(["127.0.0.1"], san.EnumerateIPAddresses().Select(x => x.ToString()));
           });
    }
}
