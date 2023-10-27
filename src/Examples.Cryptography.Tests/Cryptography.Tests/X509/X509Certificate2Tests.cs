using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509Certificate2Tests : IClassFixture<X509DataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly X509DataFixture _fixture;

    public X509Certificate2Tests(X509DataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        _fixture = fixture;
    }


    [Fact]
    public void WhenImportingFromExport_ReturnsToBeforeExport()
    {
        // Arrange.
        var cert = _fixture.RootCACert;

        // Act.
        var exported = cert.Export(X509ContentType.Cert);

        using var loaded = new X509Certificate2(exported);
        var loadedKey = loaded.GetRSAPrivateKey();

        // Assert.
        loaded.Is(cert);
        loaded.HasPrivateKey.IsFalse();
        cert.HasPrivateKey.IsTrue();

        loadedKey.IsNull();

        return;
    }


    [Fact]
    public void WhenImportingFromExportCertificatePem_ReturnsToBeforeExport()
    {
        // Arrange.
        var cert = _fixture.RootCACert;

        // Act.
        var pem = cert.ExportCertificatePem();

        //File.WriteAllText("localhost.crt", pem);
        _output.WriteLine($"\n{pem}");

        using var loaded = X509Certificate2.CreateFromPem(pem);
        var loadedKey = loaded.GetRSAPrivateKey();

        // Assert.
        loaded.Is(cert);
        loaded.HasPrivateKey.IsFalse();
        cert.HasPrivateKey.IsTrue();

        loadedKey.IsNull();

        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE-----")
                    && x.EndsWith("-----END CERTIFICATE-----"));

        return;
    }


    [Fact]
    public void WhenGenerateTheSelfSignedCertificate_WithMsDocs_WorkAsExpected()
    {
        /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/core/additional-tools/self-signed-certificates-guide#with-openssl" />

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
        using var rsa = RSA.Create(2048 /* 4096 */);

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
