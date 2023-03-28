using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates.Pkcs10;

public class ECDSACertificateRequestTests
{
    private readonly ITestOutputHelper _output;

    public ECDSACertificateRequestTests(ITestOutputHelper output)
    {
        _output = output;
    }


    [Fact]
    public void WhenCreateSigningRequestPem()
    {
        /* ```sh
        $ openssl ecparam -genkey -name secp384r1 -noout -out ecdsa-private.key
        $ openssl req -new \
            -key ecdsa-private.key \
            -sha256 -subj "/C=JP/O=suzu-devworks/CN=localhost" \
            -out server-ec.csr
        ``` */

        // Arrange.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

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
             ecdsa,
             HashAlgorithmName.SHA256);

        var pem = req.CreateSigningRequestPem();
        //File.WriteAllText("server-ec.csr", pem);
        _output.WriteLine($"\n{pem}");

        var loaded = CertificateRequest.LoadSigningRequestPem(pem,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.Default);

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
    public void WhenCreateSelfSigned()
    {
        /* ```sh
        $ openssl ecparam -genkey -name secp384r1 -noout -out ecdsa-private.key
        $ openssl req -new -x509 \
            -key ecdsa-private.key \
            -sha256 -subj "/C=JP/O=suzu-devworks/CN=localhost" \
            -days 365 \
            -out server-ec.crt
        ``` */

        // Arrange.
        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddSeconds(-50);
        var notAfter = now.AddDays(365);

        using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        // Act.
        var subject = new X500DistinguishedName("C=JP,O=suzu-devworks,CN=localhost");

        var req = new CertificateRequest(
             subject,
             keyPair,
             HashAlgorithmName.SHA256);

        // X509Extensions is empty.

        var cert = req.CreateSelfSigned(notBefore, notAfter);
        //_output.WriteLine($"\n{cert}");

        var pem = cert.ExportCertificatePem();
        //File.WriteAllText("server-ec.crt", pem);
        _output.WriteLine($"\n{pem}");

        // Assert.
        cert.Version.Is(3);
        cert.IssuerName.RawData.Is(subject.RawData);
        cert.SubjectName.RawData.Is(subject.RawData);
        cert.NotBefore.Is(notBefore.Truncate(TimeSpan.TicksPerSecond).LocalDateTime);
        cert.NotAfter.Is(notAfter.Truncate(TimeSpan.TicksPerSecond).LocalDateTime);
        cert.SignatureAlgorithm.FriendlyName.Is("sha256ECDSA");

        cert.VerifySignature(cert);

        // Assert.
        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE-----")
                    && x.EndsWith("-----END CERTIFICATE-----"));

        return;
    }


    [Fact]
    public void WhenCreate()
    {
        /* ```sh
         $ cat > test.conf << EOF
[ req ]
distinguished_name = req
req_extensions = v3_req
x509_extensions = v3_ca
[ v3_req ]
basicConstraints        = CA:FALSE
keyUsage                = digitalSignature
extendedKeyUsage        = serverAuth, clientAuth, codeSigning, emailProtection
subjectAltName          = @alt_names
[ alt_names ]
DNS.1 = www.localserver.jp
DNS.2 = localserver.jp
[ v3_ca ]
basicConstraints        = critical, CA:true
subjectKeyIdentifier    = hash
keyUsage                = critical, keyCertSign, cRLSign
EOF

        $ openssl ecparam -genkey -name secp384r1 -noout -out ecdsa-ca.key
        $ openssl req -new -x509 \
            -config test.conf \
            -key ecdsa-ca.key \
            -sha256 -subj "/C=JP/O=suzu-devworks CA/CN=Test CA" \
            -days 365 \
            -out ecdsa-ca.crt

        $ openssl ecparam -genkey -name prime256v1 -noout -out ecdsa-private.key
        $ openssl req -new \
            -config test.conf \
            -key ecdsa-private.key \
            -sha256 -subj "/C=JP/O=suzu-devworks/CN=localhost" \
            -out ecdsa-localhost.csr

        $ openssl x509 -req -in ecdsa-localhost.csr \
            -extfile test.conf -extensions v3_req \
            -CAkey ecdsa-ca.key -CA ecdsa-ca.crt -CAcreateserial \
            -sha256 -days 365 \
            -out ecdsa-localhost.crt
        ``` */

        // Arrange --- Requester side.
        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddSeconds(-50);
        var notAfter = now.AddDays(365);

        using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        var subject = new X500DistinguishedName("C=JP,O=suzu-devworks,CN=localhost");
        var requested = new CertificateRequest(
                subject,
                keyPair,
                HashAlgorithmName.SHA256)
            //TODO I think it should be set on request.
            .AddSubjectAlternativeName(san =>
                {
                    san.AddDnsName($"www.local-server.jp");
                    san.AddDnsName($"localserver.jp");
                })
            .CreateSigningRequestPem();
        //File.WriteAllText("ecdsa-localhost.csr", requested);
        _output.WriteLine($"\n{requested}");

        // Act --- CA side.
        using var caKeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var issuer = new X500DistinguishedName("C=JP,O=suzu-devworks CA,CN=Test CA");
        var caCert = new CertificateRequest(
                issuer,
                caKeyPair,
                HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority())
            .CreateSelfSigned(notBefore, notAfter);
        //_output.WriteLine($"\n{caCert}");

        var loaded = CertificateRequest.LoadSigningRequestPem(requested,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        var serial = new Random().CreateSerialNumber();
        var cert = loaded
            .AddAuthorityKeyIdentifierExtension(caCert)
            .AddSubjectKeyIdentifierExtension()
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity())
            .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
            .AddExtendedKeyUsageExtension(critical: false,
                usage =>
                {
                    usage.Add(X509ExtendedKeyUsages.IdKpServerAuth);
                    usage.Add(X509ExtendedKeyUsages.IdKpClientAuth);
                    usage.Add(X509ExtendedKeyUsages.IdKpCodeSigning);
                    usage.Add(X509ExtendedKeyUsages.IdKpEmailProtection);
                })
            .Create(caCert, notBefore, notAfter, serial);
        //_output.WriteLine($"\n{cert}");

        var pem = cert.ExportCertificatePem();
        File.WriteAllText("ecdsa-localhost.crt", pem);
        _output.WriteLine($"\n{pem}");

        // Assert.
        cert.Version.Is(3);
        cert.IssuerName.RawData.Is(issuer.RawData);
        cert.SubjectName.RawData.Is(subject.RawData);
        cert.NotBefore.Is(notBefore.Truncate(TimeSpan.TicksPerSecond).LocalDateTime);
        cert.NotAfter.Is(notAfter.Truncate(TimeSpan.TicksPerSecond).LocalDateTime);
        cert.SignatureAlgorithm.FriendlyName.Is("sha256ECDSA");

        cert.VerifySignature(caCert);

        // Assert.
        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE-----")
                    && x.EndsWith("-----END CERTIFICATE-----"));

        return;
    }
}
