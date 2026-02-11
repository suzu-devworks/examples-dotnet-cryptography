using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.Pkcs.Pkcs10;
/// <summary>
/// PKCS #10: Certification Request Syntax Specification Version 1.7.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc2986"/>
public class Pkcs10CertificateCreationTests(
    Pkcs10CertificateCreationTests.Fixture fixture)
    : IClassFixture<Pkcs10CertificateCreationTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public Fixture()
        {
            KeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var subject = new X500DistinguishedNameBuilder()
                .WithCommonName("pkcs10.examples.com")
                .Build();

            Request = new CertificateRequest(
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

        public async ValueTask InitializeAsync()
        {
            await CaCerts.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            KeyPair.Dispose();
            await CaCerts.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public CaCertificatesOpenSslFixture CaCerts { get; } = new(includePrivateKeys: true);
        public ECDsa KeyPair { get; }
        public CertificateRequest Request { get; }
        public X509Certificate2 SignerCert => CaCerts.IntermediateCaCertificate;
    }

    private static void AssertContent(CertificateRequest request, X509Certificate2 cert, X509Certificate2 signer)
    {
        Assert.Equal(3, cert.Version);
        Assert.Equal("sha256ECDSA", cert.SignatureAlgorithm.FriendlyName);
        Assert.Equal(request.SubjectName.Name, cert.SubjectName.Name);
        Assert.Equal(signer.SubjectName.Name, cert.IssuerName.Name); // self signed.
        Assert.NotEmpty(cert.SerialNumber);
        Assert.NotEmpty(cert.Thumbprint);
        Assert.False(cert.Archived);

    }

    [Fact]
    public void When_SignedBySelfSignedCert_Then_SelfSignedCertificateIsReturned()
    {
        CertificateRequest request = fixture.Request;

        var notBefore = DateTimeOffset.UtcNow.AddSeconds(-50);
        var notAfter = notBefore.AddDays(1);

        /* With OpenSSL use the following command:
        ```shell
        openssl req -x509 -subj "/CN=pkcs10.examples" \
            -key private.key \
            -sha256 -days 365 -extensions v3_ca \
            -out localhost.crt
        ```
        */
        using var cert = request.CreateSelfSigned(notBefore, notAfter);

        // Assert:

        // Is self signed.
        Assert.False(cert.Verify());

        // This is a self-signed certificate, so we validate the signature against itself.
        cert.ValidateSignature(cert);

        // The content as expected.
        AssertContent(request, cert, cert);

        // Extensions as expected.
        Assert.Equal(3, cert.Extensions.Count);
        Assert.Collection(cert.Extensions,
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

        // It has the private key.
        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void When_SignedWithSignerCert_Then_CertificateIsReturned()
    {
        CertificateRequest request = fixture.Request;
        X509Certificate2 signerCert = fixture.SignerCert;

        var san = request.CertificateExtensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .FirstOrDefault();

        /* With OpenSSL use the following command:
        ```shell
        openssl x509 -req -in pkcs10.example.csr \
            -CA ca.crt -CAkey ca.key -CAcreateserial \
             -sha256 -days 365 \
             -extfile /etc/ssl/openssl.cnf -extensions v3_cert \
             -out localhost.crt
        ```
        */
        var notBefore = DateTimeOffset.UtcNow.AddSeconds(-50);
        var notAfter = notBefore.AddDays(1);
        var serial = new CertificateSerialNumber();

        // Reproduce `CertificateRequestLoadOptions.Default`.
        request.CertificateExtensions.Clear();

        request
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity())
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension(signerCert)
            .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
            .AddExtendedKeyUsageExtension(critical: false,
                usage =>
                {
                    usage.Add(X509ExtendedKeyUsages.IdKpServerAuth);
                    usage.Add(X509ExtendedKeyUsages.IdKpClientAuth);
                    usage.Add(X509ExtendedKeyUsages.IdKpCodeSigning);
                    usage.Add(X509ExtendedKeyUsages.IdKpEmailProtection);
                });

        if (san is not null)
        {
            request.CertificateExtensions.Add(san);
        }

        using var cert = request.Create(signerCert, notBefore, notAfter, serial.ToBytes());

        // Assert:

        // Is self signed.
        Assert.False(cert.Verify());

        // This is a self-signed certificate, so we validate the signature against itself.
        cert.ValidateSignature(signerCert);

        // The content as expected.
        AssertContent(request, cert, signerCert);

        // Extensions as expected.
        Assert.Equal(6, cert.Extensions.Count);
        Assert.Collection(cert.Extensions,
            (x) =>
            {
                var basic = Assert.IsType<X509BasicConstraintsExtension>(x);
                Assert.False(basic.CertificateAuthority);
                Assert.False(basic.HasPathLengthConstraint);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                Assert.IsType<X509SubjectKeyIdentifierExtension>(x);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                Assert.IsType<X509AuthorityKeyIdentifierExtension>(x);
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
                var eKeyUsage = Assert.IsType<X509EnhancedKeyUsageExtension>(x);
                Assert.Equal(4, eKeyUsage.EnhancedKeyUsages.Count);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                var san = Assert.IsType<X509SubjectAlternativeNameExtension>(x);
                Assert.Equal(["localhost"], san.EnumerateDnsNames());
                Assert.Equal(["127.0.0.1"], san.EnumerateIPAddresses().Select(x => x.ToString()));
            }
        );

        // It does not have the private key.
        Assert.False(cert.HasPrivateKey);
    }

}
