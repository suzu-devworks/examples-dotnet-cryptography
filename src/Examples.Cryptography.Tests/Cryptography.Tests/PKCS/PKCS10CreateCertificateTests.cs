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
public class CreateCertificateTests(
    CreateCertificateTests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<CreateCertificateTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            KeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Request = CreateCertificateRequest();
            SignerCert = CreateSigner();
        }

        public void Dispose()
        {
            SignerCert.Dispose();
            KeyPair.Dispose();
            GC.SuppressFinalize(this);
        }

        public ECDsa KeyPair { get; }
        public CertificateRequest Request { get; }
        public X509Certificate2 SignerCert { get; }

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

        private static X509Certificate2 CreateSigner()
        {
            using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var notBefore = DateTimeOffset.Now.AddSeconds(-50);
            var notAfter = notBefore.AddDays(1);

            var subject = new X500DistinguishedName("C=JP, O=examples, CN=PKCS #10 Signer");
            var cert = new CertificateRequest(
                subject,
                keyPair,
                HashAlgorithmName.SHA256)
                .AddSubjectKeyIdentifierExtension()
                .AddAuthorityKeyIdentifierExtension()
                .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority())
                .CreateSelfSigned(notBefore, notAfter);

            // include private key
            return cert;
        }
    }

    [Fact]
    public void When_SignedWithSelfSignedCert_Then_SelfSignedCertificateIsReturned()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        /* openssl req -x509 \
            -key private.key \
            -sha256 -subj "/CN=pkcs.examples" \
            -days 365 \
            -extensions v3_ca \
            -out localhost.crt
        // ``` */

        CertificateRequest request = fixture.Request;

        var notBefore = DateTimeOffset.UtcNow.AddSeconds(-50);
        var notAfter = notBefore.AddDays(1);
        using var cert = request.CreateSelfSigned(notBefore, notAfter);

        // Assert:

        // Is self signed.
        Assert.False(cert.Verify());

        // This is a self-signed certificate, so we validate the signature against itself.
        cert.ValidateSignature(cert);

        // The content as expected.
        Assert.Equal(3, cert.Version);
        Assert.Equal("sha256ECDSA", cert.SignatureAlgorithm.FriendlyName);
        Assert.Equal(request.SubjectName.Name, cert.SubjectName.Name);
        Assert.Equal(request.SubjectName.Name, cert.IssuerName.Name); // self signed.
        Assert.Equal(request.SubjectName.Name, cert.SubjectName.Name);
        Assert.NotEmpty(cert.SerialNumber);
        Assert.NotEmpty(cert.Thumbprint);
        Assert.False(cert.Archived);

        Assert.True(cert.HasPrivateKey);

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
    }

    [Fact]
    public void When_SignedWithSignerCert_Then_CertificateIsReturned()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        /* openssl x509 -req -in localhost.csr \
            -CAkey ca.key -CA ca.crt -CAcreateserial \
            -sha256 -days 365 \
            -extfile /etc/ssl/openssl.cnf -extensions v3_req \
            -out localhost.crt
        // ``` */

        CertificateRequest request = fixture.Request;

        var requestPem = request.CreateSigningRequestPem();
        output.WriteLine($"request:\n{requestPem}");

        var responsePem = DoIssuerProcessing(requestPem);
        output.WriteLine($"response:\n{responsePem}");

        using var cert = X509Certificate2.CreateFromPem(responsePem);

        // Assert:

        X509Certificate2 signerCert = fixture.SignerCert;

        // The signer is not Trusted.
        Assert.False(cert.Verify());

        // It can be verified with the signing certificate.
        cert.ValidateSignature(signerCert);

        // The content as expected.
        Assert.Equal(3, cert.Version);
        Assert.Equal("sha256ECDSA", cert.SignatureAlgorithm.FriendlyName);
        Assert.Equal(request.SubjectName.Name, cert.SubjectName.Name);
        Assert.Equal(signerCert.SubjectName.Name, cert.IssuerName.Name);
        Assert.Equal(request.SubjectName.Name, cert.SubjectName.Name);
        Assert.NotEmpty(cert.SerialNumber);
        Assert.NotEmpty(cert.Thumbprint);
        Assert.False(cert.Archived);

        Assert.False(cert.HasPrivateKey);

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
                var keyUsage = Assert.IsType<X509KeyUsageExtension>(x);
                Assert.Equal(X509KeyUsageFlags.DigitalSignature, keyUsage.KeyUsages);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                var san = Assert.IsType<X509SubjectAlternativeNameExtension>(x);
                Assert.Equal(["localhost"], san.EnumerateDnsNames());
                Assert.Equal(["127.0.0.1"], san.EnumerateIPAddresses().Select(x => x.ToString()));
            },
            (x) =>
            {
                Assert.False(x.Critical);
                Assert.IsType<X509AuthorityKeyIdentifierExtension>(x);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                Assert.IsType<X509SubjectKeyIdentifierExtension>(x);
            },
            (x) =>
            {
                Assert.False(x.Critical);
                var eKeyUsage = Assert.IsType<X509EnhancedKeyUsageExtension>(x);
                Assert.Equal(4, eKeyUsage.EnhancedKeyUsages.Count);
            }
        );

        string DoIssuerProcessing(string pem)
        {
            X509Certificate2 signerCert = fixture.SignerCert;

            var request = CertificateRequest.LoadSigningRequestPem(pem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

            var serial = new CertificateSerialNumber(new Random()).ToBytes();
            var notBefore = DateTimeOffset.UtcNow.AddSeconds(-50);
            var notAfter = notBefore.AddDays(1);

            using var cert = request
                .AddAuthorityKeyIdentifierExtension(signerCert)
                .AddSubjectKeyIdentifierExtension()
                .AddExtendedKeyUsageExtension(critical: false,
                    usage =>
                    {
                        usage.Add(X509ExtendedKeyUsages.IdKpServerAuth);
                        usage.Add(X509ExtendedKeyUsages.IdKpClientAuth);
                        usage.Add(X509ExtendedKeyUsages.IdKpCodeSigning);
                        usage.Add(X509ExtendedKeyUsages.IdKpEmailProtection);
                    })
                .Create(signerCert, notBefore, notAfter, serial);

            // It can be verified with the signing certificate.
            cert.ValidateSignature(signerCert);

            return cert.ExportCertificatePem();
        }
    }

}
