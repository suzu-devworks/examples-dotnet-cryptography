using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

/// <summary>
/// PKCS #10: Certification Request Syntax Specification Version 1.7.
/// </summary>
/// <param name="fixture"></param>
/// <param name="output"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc2986"/>
public class PKCS10CertificateRequestTests(
    PKCS10CertificateRequestTests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<PKCS10CertificateRequestTests.Fixture>
{
    private readonly Oid _id_ecPublicKey = new("1.2.840.10045.2.1");

    public class Fixture : IDisposable
    {
        public Fixture()
        {
            KeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Request = CreateCertificateRequest();
        }

        public void Dispose()
        {
            KeyPair.Dispose();
            GC.SuppressFinalize(this);
        }

        public ECDsa KeyPair { get; }
        public CertificateRequest Request { get; }

        private CertificateRequest CreateCertificateRequest()
        {
            // With OpenSSL use the following command:
            //
            // ```shell
            /* openssl req -new \
                -key private.key \
                -sha256 -subj "/CN=pkcs.examples" \
                -reqexts v3_req \
                -out localhost.csr
            // ``` */

            var subject = new X500DistinguishedNameBuilder()
                .WithCommonName("pkcs.examples")
                .Build();

            return new CertificateRequest(
                 subject,
                 KeyPair,
                 HashAlgorithmName.SHA256)
                .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity())
                .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
                .AddSubjectAlternativeName(san =>
                {
                    san.AddDnsName("localhost");
                    san.AddIpAddress(System.Net.IPAddress.Parse("127.0.0.1"));
                });
        }

    }

    private void AssertCertificateRequest(CertificateRequest original, CertificateRequest imported)
    {
        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported);   // Maybe calling object.Equals()

        // The content must be the same.
        Assert.Multiple(
            () => Assert.Equal(original.SubjectName.Name, imported.SubjectName.Name),
            () => Assert.Null(imported.SubjectName.Oid!.Value),
            () => Assert.Equal(original.SubjectName.RawData, imported.SubjectName.RawData)
        );
        Assert.Empty(imported.OtherRequestAttributes);
        Assert.Multiple(
            () => Assert.NotNull(imported.PublicKey),
            () => Assert.Equal(_id_ecPublicKey.Value, imported.PublicKey.Oid.Value),
            () => Assert.Null(imported.PublicKey.EncodedKeyValue.Oid), // null ?
            () => Assert.Equal(original.PublicKey.EncodedKeyValue.RawData,
                    imported.PublicKey.EncodedKeyValue.RawData),
            () => Assert.Null(imported.PublicKey.EncodedParameters.Oid), // null ?
            () => Assert.Equal(original.PublicKey.EncodedParameters.RawData,
                    imported.PublicKey.EncodedParameters.RawData)
        );
        Assert.Equal(HashAlgorithmName.SHA256, imported.HashAlgorithm);
    }

    [Fact]
    public void When_CreatedAndLoaded_Then_SigningRequestIsRestored()
    {
        CertificateRequest original = fixture.Request;

        byte[] exported = original.CreateSigningRequest();

        var imported = CertificateRequest.LoadSigningRequest(
                exported,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        // Assert:

        AssertCertificateRequest(original, imported);
        Assert.Equal(3, imported.CertificateExtensions.Count);
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
                Assert.Equal(X509KeyUsageFlags.DigitalSignature, keyUsage.KeyUsages);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                var san = Assert.IsType<X509SubjectAlternativeNameExtension>(x);
                Assert.Equal(["localhost"], san.EnumerateDnsNames());
                Assert.Equal(["127.0.0.1"], san.EnumerateIPAddresses().Select(x => x.ToString()));
            }
        );
    }

    [Fact]
    public void When_CreatedToPemAndLoaded_Then_SigningRequestIsRestored()
    {
        CertificateRequest original = fixture.Request;

        var pem = original.CreateSigningRequestPem();
        output.WriteLine($"\n{pem}");
        //File.WriteAllText("server-ec.csr", pem);

        var imported = CertificateRequest.LoadSigningRequestPem(
                pem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", pem);
        Assert.EndsWith("-----END CERTIFICATE REQUEST-----", pem);

        AssertCertificateRequest(original, imported);
        Assert.Empty(imported.CertificateExtensions);
    }

    [Fact]
    public void When_LoadedSigningRequestIsRecreated_Then_ThrowsInvalidOperation()
    {
        CertificateRequest original = fixture.Request;

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
    public void When_OpenSSLPemIsImported_Then_PrivateKeyIsRestored()
    {
        // spell-checker: disable
        const string FROM_OPENSSL_PEM = """
            -----BEGIN CERTIFICATE REQUEST-----
            MIH9MIGjAgEAMBgxFjAUBgNVBAMMDXBrY3MuZXhhbXBsZXMwWTATBgcqhkjOPQIB
            BggqhkjOPQMBBwNCAAR+I5DM/a8LoxolXbSRBJBcc+KqUKj76lPUSyV0ig3iTuDp
            lWra84HO4xiJWFEEzC6m6k+IxK1dJDM82zJb60bioCkwJwYJKoZIhvcNAQkOMRow
            GDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAKBggqhkjOPQQDAgNJADBGAiEAtxPN
            fRLA5k+Qudzr0XBt/lsVIqsTMDsELIPQvZ9y38cCIQCZi2CcJLXCK+YTcOAWmdYj
            THDV3QyM1ne3jlitrEYsbQ==
            -----END CERTIFICATE REQUEST-----
            """;
        // spell-checker: enable

        var imported = CertificateRequest.LoadSigningRequestPem(
                FROM_OPENSSL_PEM,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        // Assert:

        // The content must be the same.
        Assert.Multiple(
            () => Assert.Equal("CN=pkcs.examples", imported.SubjectName.Name),
            () => Assert.Null(imported.SubjectName.Oid!.Value),
            () => Assert.NotEmpty(imported.SubjectName.RawData)
        );
        Assert.Equal(2, imported.CertificateExtensions.Count);
        Assert.Collection(imported.CertificateExtensions,
            (x) =>
            {
                Assert.False(x.Critical);
                var basic = Assert.IsType<X509BasicConstraintsExtension>(x);
                Assert.False(basic.CertificateAuthority);
                Assert.False(basic.HasPathLengthConstraint);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                var keyUsage = Assert.IsType<X509KeyUsageExtension>(x);
                Assert.Equal(X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.NonRepudiation |
                    X509KeyUsageFlags.KeyEncipherment,
                    keyUsage.KeyUsages);
            }
        );
        Assert.Empty(imported.OtherRequestAttributes);
        Assert.Multiple(
            () => Assert.NotNull(imported.PublicKey),
            () => Assert.Equal(_id_ecPublicKey.Value, imported.PublicKey.Oid.Value),
            () => Assert.Null(imported.PublicKey.EncodedKeyValue.Oid), // null ?
            () => Assert.NotEmpty(imported.PublicKey.EncodedKeyValue.RawData),
            () => Assert.Null(imported.PublicKey.EncodedParameters.Oid), // null ?
            () => Assert.NotEmpty(imported.PublicKey.EncodedParameters.RawData)
        );
        Assert.Equal(HashAlgorithmName.SHA256, imported.HashAlgorithm);
    }

}
