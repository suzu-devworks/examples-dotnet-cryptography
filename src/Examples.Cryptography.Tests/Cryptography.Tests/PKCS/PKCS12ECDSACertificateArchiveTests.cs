using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

public class PKCS12ECDSACertificateArchiveTests : IClassFixture<PKCSDataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly PKCSDataFixture _fixture;

    public PKCS12ECDSACertificateArchiveTests(PKCSDataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        _fixture = fixture;
    }


    [Fact]
    public void WhenExportAndLoad()
    {
        /* ```sh
        $ openssl ecparam -genkey -name prime256v1 -noout -out ecdsa-private.key
        $ openssl req -new -x509 \
            -key ecdsa-private.key \
            -sha256 -subj "/C=JP/O=suzu-devworks/CN=localhost" \
            -days 365 \
            -out ecdsa-localhost.crt
        $ openssl pkcs12 -export \
            -inkey ecdsa-private.key -in ecdsa-localhost.crt \
            -out ecdsa-localhost.pfx
        ``` */

        // Arrange.
        var ecdsa = _fixture.ECKeyProvider;

        var password = "BadP@ssw0rd";
        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddSeconds(-50);
        var notAfter = now.AddDays(365);

        var subject = new X500DistinguishedName("C=JP,O=suzu-devworks,CN=localhost");
        var req = new CertificateRequest(
             subject,
             ecdsa,
             HashAlgorithmName.SHA256);
        var cert = req.CreateSelfSigned(notBefore, notAfter);

        _output.WriteLine($"¥n{cert}");

        // Act.
        // TODO Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
        var exported = cert.Export(X509ContentType.Pkcs12, password);
        //File.WriteAllBytes("ecdsa-localhost.pfx", exported);

        var loaded = new X509Certificate2(exported, password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        var logdedEcdsa = loaded.GetECDsaPrivateKey();
        var logdedRsa = loaded.GetRSAPrivateKey(); ;

        // Assert.
        loaded.Is(cert);
        loaded.HasPrivateKey.IsTrue();

        loaded.ValidateSignature(cert);

        logdedEcdsa.IsNotNull();
        logdedEcdsa!.KeySize.Is(ecdsa.KeySize);
        logdedEcdsa.SignatureAlgorithm.Is(ecdsa.SignatureAlgorithm);
        logdedEcdsa.ExportECPrivateKey().Is(ecdsa.ExportECPrivateKey());

        logdedRsa.IsNull();

        return;
    }

}
