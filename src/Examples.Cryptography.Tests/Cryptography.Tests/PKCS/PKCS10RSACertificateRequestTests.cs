using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;
using Examples.Fluency;

namespace Examples.Cryptography.Tests.PKCS;

public class PKCS10RSACertificateRequestTests : IClassFixture<PKCSDataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly PKCSDataFixture _fixture;

    public PKCS10RSACertificateRequestTests(PKCSDataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        _fixture = fixture;
    }


    [Fact]
    public void WhenLoadingFromCreateSigningRequest_ReturnsToBeforeRequest()
    {
        /* ```sh
        $ openssl req -new  \
            -newkey rsa:4096 -keyout private.key -nodes \
            -sha256 -subj "/C=JP/O=suzu-devworks/CN=localhost" \
            -out request-der.csr -outform der
        ``` */

        // Arrange.
        var rsa = _fixture.RSAKeyProvider;

        // Act.
        var subject = new X500DistinguishedName("C=JP,O=suzu-devworks,CN=localhost");
        var req = new CertificateRequest(
             subject,
             rsa,
             HashAlgorithmName.SHA256,
             RSASignaturePadding.Pkcs1);

        var requested = req.CreateSigningRequest();

        var loaded = CertificateRequest.LoadSigningRequest(requested,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.Default,
            RSASignaturePadding.Pkcs1);

        // Assert.
        loaded.SubjectName.RawData.Is(req.SubjectName.RawData);
        loaded.PublicKey.Oid.Value.Is(req.PublicKey.Oid.Value);
        loaded.PublicKey.EncodedKeyValue.RawData.Is(req.PublicKey.EncodedKeyValue.RawData);
        loaded.PublicKey.EncodedParameters.RawData.Is(req.PublicKey.EncodedParameters.RawData);
        loaded.HashAlgorithm.Name.Is(req.HashAlgorithm.Name);

        return;
    }


    [Fact]
    public void WhenLoadingFromCreateSigningRequestPem_ReturnsToBeforeRequest()
    {
        /* ```sh
        $ openssl req -new  \
            -newkey rsa:4096 -keyout private.key -nodes \
            -sha256 -subj "/C=JP/O=suzu-devworks/CN=localhost" \
            -out request.csr
        ``` */

        // Arrange.
        var rsa = _fixture.RSAKeyProvider;

        // Act.
        var subject = new X500DistinguishedNameBuilder()
            .Configure(builder =>
            {
                builder.AddCountryOrRegion("JP");
                builder.AddOrganizationName("suzu-devworks");
                builder.AddCommonName("localhost");
            })
            .Build();

        var req = new CertificateRequest(
             subject,
             rsa,
             HashAlgorithmName.SHA256,
             RSASignaturePadding.Pkcs1);

        var pem = req.CreateSigningRequestPem();

        //File.WriteAllText("server.csr", pem);
        _output.WriteLine($"\n{pem}");

        var loaded = CertificateRequest.LoadSigningRequestPem(pem,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.Default,
            RSASignaturePadding.Pkcs1);

        // Assert.
        loaded.SubjectName.RawData.Is(req.SubjectName.RawData);
        loaded.PublicKey.Oid.Value.Is(req.PublicKey.Oid.Value);
        loaded.PublicKey.EncodedKeyValue.RawData.Is(req.PublicKey.EncodedKeyValue.RawData);
        loaded.PublicKey.EncodedParameters.RawData.Is(req.PublicKey.EncodedParameters.RawData);
        loaded.HashAlgorithm.Name.Is(req.HashAlgorithm.Name);

        // Assert.
        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE REQUEST-----")
                    && x.EndsWith("-----END CERTIFICATE REQUEST-----"));

        return;
    }


    [Fact]
    public void WhenCallingCreateSelfSigned_WorkAsExpected()
    {
        /* ```sh
        $ openssl req -new -x509 \
            -newkey rsa:4096 -keyout private.key -nodes \
             -sha256 -subj "/C=JP/O=suzu-devworks/CN=localhost" \
            -days 365 \
            -out server.crt
        ``` */

        // Arrange.
        var rsa = _fixture.RSAKeyProvider;

        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddSeconds(-50);
        var notAfter = now.AddSeconds(60);

        // Act.
        var subject = new X500DistinguishedName("C=JP,O=suzu-devworks,CN=localhost");
        var req = new CertificateRequest(
             subject,
             rsa,
             HashAlgorithmName.SHA256,
             RSASignaturePadding.Pkcs1);

        // X509Extensions is empty.

        using var cert = req.CreateSelfSigned(notBefore, notAfter);

        var pem = cert.ExportCertificatePem();

        //File.WriteAllText("server.crt", pem);
        _output.WriteLine($"\n{pem}");

        // Assert.
        cert.Version.Is(3);
        cert.IssuerName.RawData.Is(subject.RawData);
        cert.SubjectName.RawData.Is(subject.RawData);
        cert.NotBefore.Is(notBefore.Truncate(TimeSpan.TicksPerSecond).LocalDateTime);
        cert.NotAfter.Is(notAfter.Truncate(TimeSpan.TicksPerSecond).LocalDateTime);
        cert.SignatureAlgorithm.FriendlyName.Is("sha256RSA");

        cert.VerifySignature(cert);

        // Assert.
        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE-----")
                    && x.EndsWith("-----END CERTIFICATE-----"));

        return;
    }

}
