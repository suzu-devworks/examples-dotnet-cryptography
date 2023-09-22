using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509Certificates;

public class X509Certificate2Tests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly X509Certificate2 _certificate;

    public X509Certificate2Tests(ITestOutputHelper output)
    {
        _output = output;

        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddSeconds(-50);
        var notAfter = now.AddDays(365);

        using var keyPair = RSA.Create(4096);
        var subject = new X500DistinguishedName("C=JP,O=suzu-devworks,CN=localhost");
        var cert = new CertificateRequest(
             subject,
             keyPair,
             HashAlgorithmName.SHA256,
             RSASignaturePadding.Pkcs1)
             .CreateSelfSigned(notBefore, notAfter);

        _certificate = cert;
    }

    public void Dispose()
    {
        ((IDisposable)_certificate)?.Dispose();
        GC.SuppressFinalize(this);
    }


    [Fact]
    public void WhenExportAndImport()
    {
        // Arrange.

        // Act.
        var exported = _certificate.Export(X509ContentType.Cert);

        using var loaded = new X509Certificate2(exported);
        var logdedKey = loaded.GetRSAPrivateKey();

        // Assert.
        loaded.Is(_certificate);
        loaded.HasPrivateKey.IsFalse();
        _certificate.HasPrivateKey.IsTrue();
        logdedKey.IsNull();

        return;
    }


    [Fact]
    public void WhenExportCertificatePem()
    {
        // Arrange.

        // Act.
        var pem = _certificate.ExportCertificatePem();

        //File.WriteAllText("localhost.crt", pem);
        _output.WriteLine($"\n{pem}");

        using var loaded = X509Certificate2.CreateFromPem(pem);
        var logdedKey = loaded.GetRSAPrivateKey();

        // Assert.
        loaded.Is(_certificate);
        loaded.HasPrivateKey.IsFalse();
        _certificate.HasPrivateKey.IsTrue();
        logdedKey.IsNull();

        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE-----")
                    && x.EndsWith("-----END CERTIFICATE-----"));

        return;
    }

    /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/core/additional-tools/self-signed-certificates-guide#with-openssl" />
    [Fact]
    public void WhenGenerateTheSameSelfSignedCertificateAsMsDocs()
    {

        /* ```sh
        PARENT="contoso.com"
        openssl req \
        -x509 \
        -newkey rsa:4096 \
        -sha256 \
        -days 365 \
        -nodes \
        -keyout $PARENT.key \
        -out $PARENT.crt \
        -subj "/CN=${PARENT}" \
        -extensions v3_ca \
        -extensions v3_req \
        -config <( \
        echo '[req]'; \
        echo 'default_bits= 4096'; \
        echo 'distinguished_name=req'; \
        echo 'x509_extension = v3_ca'; \
        echo 'req_extensions = v3_req'; \
        echo '[v3_req]'; \
        echo 'basicConstraints = CA:FALSE'; \
        echo 'keyUsage = nonRepudiation, digitalSignature, keyEncipherment'; \
        echo 'subjectAltName = @alt_names'; \
        echo '[ alt_names ]'; \
        echo "DNS.1 = www.${PARENT}"; \
        echo "DNS.2 = ${PARENT}"; \
        echo '[ v3_ca ]'; \
        echo 'subjectKeyIdentifier=hash'; \
        echo 'authorityKeyIdentifier=keyid:always,issuer'; \
        echo 'basicConstraints = critical, CA:TRUE, pathlen:0'; \
        echo 'keyUsage = critical, cRLSign, keyCertSign'; \
        echo 'extendedKeyUsage = serverAuth, clientAuth')
        ```*/

        var parent = "contoso.com";
        using var rsa = RSA.Create(4096);

        var subject = new X500DistinguishedName($"CN={parent}");
        using var cert = new CertificateRequest(
                subject,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1)
            // basicConstraints = CA:FALSE
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity())
            // keyUsage = nonRepudiation, digitalSignature, keyEncipherment
            .AddKeyUsageExtension(critical: false,
                X509KeyUsageFlags.NonRepudiation |
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyEncipherment)
            // subjectAltName = @alt_names
            // [ alt_names ]';
            // DNS.1 = www.${PARENT}"
            // DNS.2 = ${PARENT}
            .AddSubjectAlternativeName(san =>
            {
                san.AddDnsName($"www.{parent}");
                san.AddDnsName($"{parent}");
            })
            .CreateSelfSigned(
                notBefore: DateTimeOffset.Now,
                notAfter: DateTimeOffset.Now.AddDays(365));

        var pem = cert.ExportCertificatePem();

        //File.WriteAllText($"{parent}.crt", pem);
        _output.WriteLine($"\n{pem}");

        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE-----")
                    && x.EndsWith("-----END CERTIFICATE-----"));

        return;
    }

}
