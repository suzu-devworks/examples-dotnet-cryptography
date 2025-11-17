using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

/// <summary>
/// PKCS #12: Personal Information Exchange Syntax v1.1.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc7292" />
public class PKCS12PersonalInformationExchangeTests(
    PKCS12PersonalInformationExchangeTests.Fixture fixture)
    : IClassFixture<PKCS12PersonalInformationExchangeTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public void Dispose()
        {
            Certificate.Dispose();
            GC.SuppressFinalize(this);
        }

        public X509Certificate2 Certificate { get; } = CreateCertificate();

        private static X509Certificate2 CreateCertificate()
        {
            using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var notBefore = DateTimeOffset.Now.AddSeconds(-50);
            var notAfter = notBefore.AddDays(1);

            var subject = new X500DistinguishedName("C=JP, O=examples, CN=PKCS #12 Test");
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
    public void When_ExportedAndImported_Then_CertificateIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        /* openssl pkcs12 -export \
                -inkey private.key -in localhost.crt \
                -out localhost.pfx
           openssl pkcs12 -in localhost.pfx \
                -nocerts -nodes \
                -out localhost.out.key
           openssl pkcs12 -in localhost.pfx \
                -clcerts -nokeys \
                -out localhost.out.crt
        // ``` */

        var original = fixture.Certificate;

        var password = "BadP@ssw0rd";
        // spell-checker: disable-next-line
        // TODO Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
        var exported = original.Export(X509ContentType.Pkcs12, password);
        // File.WriteAllBytes("localhost.pfx", exported);

        var imported = X509CertificateLoader.LoadPkcs12(
                exported,
                password,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The contents should be the same.
        Assert.Equal(original, imported);
        Assert.Equal(original.Thumbprint, imported.Thumbprint);

        // Public keys match
        Assert.Equal(original.GetPublicKey(), imported.GetPublicKey());

        // PKCS #12 can hold private keys
        Assert.True(imported.HasPrivateKey);

        var originalPrivateKey = original.GetECDsaPrivateKey();
        var importedPrivateKey = imported.GetECDsaPrivateKey();

        // They are different instances.
        Assert.NotSame(originalPrivateKey, importedPrivateKey);
        Assert.NotEqual(originalPrivateKey, importedPrivateKey);   // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(originalPrivateKey!.ExportECPrivateKey(), importedPrivateKey!.ExportECPrivateKey());
    }

    [Fact]
    public void When_OpenSSLIsImported_Then_CertificateIsRestored()
    {
        // spell-checker: disable
        const string FROM_OPENSSL_BASE64 = """
            MIIEHAIBAzCCA9IGCSqGSIb3DQEHAaCCA8MEggO/MIIDuzCCAnIGCSqGSIb3DQEHB
            qCCAmMwggJfAgEAMIICWAYJKoZIhvcNAQcBMFcGCSqGSIb3DQEFDTBKMCkGCSqGSI
            b3DQEFDDAcBAijc/RpvtbBeAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASo
            EEHEmt2isXd8yfilAUm813ZaAggHwDERuckdl1oXk/tSohwHKmJRwV1o/OF5Uxu8x
            RQCoKRY8ye3kt4AyXH58MGVCJqDWB9Gw8Op179I6D9VCEe3HGqWBgpWybz1VXSW/0
            4T9iIRzJ2NvauLXsiqG7ylGZnG5w+WdXJ0irik+LKTN2ospvvx89n6+9fmNVmk0cY
            uJUsYmKXAfAFAuTS+6TnYZv0Bb+WV887GKYA2fqfjruUHhRh8tYoQv94zjDSqEi1S
            oaWSMZsSde6vXyhQRYL+GCEWn938dJBS7GKT87BT1EiDVC5sQuitMEQtvdkA3IWC6
            13xRNzNk3iQiFK6CgjBbAIFinFkziZT3hOE5b2ev6ZvkjYllVPxAlEqEU0zBiLfmO
            2HHq1X69X4OCi01vbKIwC9KOSCm3VzY2tU/4FwAoopT4/6fYLDaXhtCm+SHMdq/DT
            j34e7CrOEiYg13DCy7uCp00aO+/8lg1fVRBzBk3py+6Zr2kwxgTEKWw7zxaQFpIjy
            lk6/LkJD3kUmHHL65ef67qB4yn9FQ7pUlL5uNO7pJFifE5qk+m03Beoqk2XHJ+XFW
            W7xFKZsOUwVQyQ5K6t5hiU/ao0gc3hoqpvPEScKV9zVB39758y620u6f9DVq2a0Vb
            WKb3bvg/dG+e5N981KkFnzjsc+JmKED4USOAYA+ITCCAUEGCSqGSIb3DQEHAaCCAT
            IEggEuMIIBKjCCASYGCyqGSIb3DQEMCgECoIHvMIHsMFcGCSqGSIb3DQEFDTBKMCk
            GCSqGSIb3DQEFDDAcBAhEfRL6tfQnvQICCAAwDAYIKoZIhvcNAgkFADAdBglghkgB
            ZQMEASoEEFyjtkKo6t6WPiZLUXNjCycEgZBO3DrNfPAYCUKYjW8LQvSUkNRYYvFnM
            ZdPB75HThVOAbbvQUqPJWuWH7nkBYlmEqccv//Ypr+IufkHluV0j4YRGw/Jn2pS4h
            uImZb9D4SCGwZ1//RoSPhob7DVaDc3vGaKVnKtU6rnb8qDUnNkCjwX5c32GIPZYWt
            fBlm13j5m3KOGmoR2jHmfjNjNJ9+OpCsxJTAjBgkqhkiG9w0BCRUxFgQU9HWqGGBn
            HvNWdellDW7zktB+kFYwQTAxMA0GCWCGSAFlAwQCAQUABCCi6JDSKbtop8RyE4y2b
            6qY1SDxtfsYu79iFdcZw5pw2AQIsClBDoiobtQCAggA
            """;
        // spell-checker: enable

        var password = "BadP@ssw0rd";
        var imported = X509CertificateLoader.LoadPkcs12(
                Convert.FromBase64String(FROM_OPENSSL_BASE64),
                password,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);

        // Assert:

        Assert.NotNull(imported);

        // The contents should be the same.
        Assert.Equal("CN=pkcs.examples", imported.IssuerName.Name);
        Assert.Equal("CN=pkcs.examples", imported.SubjectName.Name);
        Assert.Equal("27D90D2A09497781727D17E210FBB9DA098EC6FE", imported.SerialNumber);
        Assert.Equal("F475AA1860671EF35675E9650D6EF392D07E9056", imported.Thumbprint);

        // PKCS #12 can hold private keys
        Assert.Equal("F475AA1860671EF35675E9650D6EF392D07E9056", imported.Thumbprint);
        Assert.True(imported.HasPrivateKey);

        var importedPrivateKey = imported.GetECDsaPrivateKey();
        Assert.NotNull(importedPrivateKey);

        // I think the private key would look like this.
        // spell-checker: disable
        const string EXPECTED_OPENSSL_PRIVATEKEY_PEM = """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIGlu2Wb2FNDi2E8AooK+hHfs81LrTSxGQD+jkC3vv9SZoAoGCCqGSM49
            AwEHoUQDQgAEfiOQzP2vC6MaJV20kQSQXHPiqlCo++pT1EsldIoN4k7g6ZVq2vOB
            zuMYiVhRBMwupupPiMStXSQzPNsyW+tG4g==
            -----END EC PRIVATE KEY-----
            """;
        // spell-checker: enable
        Assert.Equal(EXPECTED_OPENSSL_PRIVATEKEY_PEM, importedPrivateKey.ExportECPrivateKeyPem());
    }

}
