using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

/// <summary>
/// PKCS #10: Certification Request Syntax Specification Version 1.7.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc2986"/>
public partial class PKCS10CertificateRequestTests(
    PKCS10CertificateRequestTests.Fixture fixture)
    : IClassFixture<PKCS10CertificateRequestTests.Fixture>
{
    // private static readonly Oid IdEcPublicKey = new("1.2.840.10045.2.1");

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_CreateNewCertificateRequest_Then_ReturnsAsConfigured()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.examples.com")
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
            () => Assert.Equal("CN=pkcs10.examples.com", req.SubjectName.Name),
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
            .WithCommonName("pkcs10.examples.com")
            .Build();
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256);

        byte[] exported = original.CreateSigningRequest();

        var imported = CertificateRequest.LoadSigningRequest(
                exported,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Different because of missing private key

        // The content must be the same.
        Assert.Multiple(
            () => Assert.Equal(original.SubjectName.Name, imported.SubjectName.Name),
            () => Assert.Equal(original.SubjectName.RawData, imported.SubjectName.RawData)
        );

        // Public Key must be the same.
        Assert.Equal(
            original.PublicKey.EncodedKeyValue.RawData,
            imported.PublicKey.EncodedKeyValue.RawData);
    }

    [Fact]
    public void When_CreatedToPemAndLoaded_Then_CertificateRequestIsRestored()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.examples.com")
            .Build();
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256);

        var pem = original.CreateSigningRequestPem();
        Output?.WriteLine($"\n{pem}");
        //File.WriteAllText("server-ec.csr", pem);

        var imported = CertificateRequest.LoadSigningRequestPem(
                pem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", pem);
        Assert.EndsWith("-----END CERTIFICATE REQUEST-----", pem);

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Different because of missing private key

        // The content must be the same.
        Assert.Multiple(
            () => Assert.Equal(original.SubjectName.Name, imported.SubjectName.Name),
            () => Assert.Equal(original.SubjectName.RawData, imported.SubjectName.RawData)
        );

        // Public Key must be the same.
        Assert.Equal(
            original.PublicKey.EncodedKeyValue.RawData,
            imported.PublicKey.EncodedKeyValue.RawData);
    }

    [Fact]
    public void When_LoadedSigningRequestIsRecreated_Then_ThrowsInvalidOperation()
    {
        ECDsa privateKey = fixture.KeyPair;

        var subject = new X500DistinguishedNameBuilder()
            .WithCommonName("pkcs10.examples.com")
            .Build();
        var original = new CertificateRequest(subject, privateKey, HashAlgorithmName.SHA256);

        var pem = original.CreateSigningRequestPem();

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
    public void When_OpenSSLPemLoaded_WithDefaultOptions_Then_ExtensionsIsNotLoaded()
    {
        var pem = fixture.Pem;

        var imported = CertificateRequest.LoadSigningRequestPem(
                pem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Assert:

        Assert.NotNull(imported);
        Assert.Multiple(
            () => Assert.Equal("CN=*.ecdsa.example.com, C=JP", imported.SubjectName.Name),
            () => Assert.Null(imported.SubjectName.Oid!.Value),
            () => Assert.NotEmpty(imported.SubjectName.RawData)
        );
        Assert.Equal(HashAlgorithmName.SHA256, imported.HashAlgorithm);

        // Default options do not load extensions.
        Assert.Empty(imported.OtherRequestAttributes);
    }

    [Fact]
    public void When_OpenSSLPemLoaded_WithUnsafeOptions_Then_ExtensionsIsLoaded()
    {
        var pem = fixture.Pem;

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
