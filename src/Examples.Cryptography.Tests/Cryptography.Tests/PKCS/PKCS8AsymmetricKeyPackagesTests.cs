using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.PKCS;

/// <summary>
/// Asymmetric Key Packages.
/// </summary>
/// <param name="fixture"></param>
/// <param name="output"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc5958"/>
public class PKCS8AsymmetricKeyPackagesTests(
    PKCS8AsymmetricKeyPackagesTests.Fixture fixture,
    ITestOutputHelper output
    ) : IClassFixture<PKCS8AsymmetricKeyPackagesTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public void Dispose()
        {
            KeyPair?.Dispose();
            GC.SuppressFinalize(this);
        }

        public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    [Fact]
    public void When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl ecparam -genkey -name prime256v1 -noout -out private.key
        // openssl pkcs8 -in private.key -topk8 -nocrypt -out private.key.p8
        // openssl ec -in private.key.p8 -out private.out.key
        // ```

        ECDsa original = fixture.KeyPair;

        var pem = original.ExportPkcs8PrivateKeyPem();
        output.WriteLine($"{pem}");
        //File.WriteAllText(@"private.p8", pem);

        using var imported = ECDsa.Create();
        imported.ImportFromPem(pem.AsSpan());

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported);   // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(original.ExportECPrivateKey(), imported.ExportECPrivateKey());

        // Exporting again gives the same result.
        Assert.Equal(pem, imported.ExportPkcs8PrivateKeyPem());
    }

    [Fact]
    public void When_OpenSSLPemIsImported_Then_PrivateKeyIsRestored()
    {
        // spell-checker: disable
        const string FROM_OPENSSL_PEM = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgi0bmBUxlks85rdRs
            qKdIXp7qXzpFdAI9NnhjwZ1bkCqhRANCAASNNkr4plMj9WlMKMEkMYwA5zYiUbmC
            Cu/MDfx+b2QRSlj9UpwJdinjsJZwISHOckEtZYmvA9Y9OvnRrOL//HXN
            -----END PRIVATE KEY-----
            """;
        // spell-checker: enable

        using var imported = ECDsa.Create();
        imported.ImportFromPem(FROM_OPENSSL_PEM.AsSpan());

        // Assert:

        // I think the private key would look like this.
        // spell-checker: disable
        const string EXPECTED_OPENSSL_PRIVATEKEY_PEM = """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIItG5gVMZZLPOa3UbKinSF6e6l86RXQCPTZ4Y8GdW5AqoAoGCCqGSM49
            AwEHoUQDQgAEjTZK+KZTI/VpTCjBJDGMAOc2IlG5ggrvzA38fm9kEUpY/VKcCXYp
            47CWcCEhznJBLWWJrwPWPTr50azi//x1zQ==
            -----END EC PRIVATE KEY-----
            """;
        // spell-checker: enable
        Assert.Equal(EXPECTED_OPENSSL_PRIVATEKEY_PEM, imported.ExportECPrivateKeyPem());

        // Exporting again gives the same result.
        Assert.Equal(FROM_OPENSSL_PEM, imported.ExportPkcs8PrivateKeyPem());
    }

    [Fact]
    public void When_ExportedToEncryptedPemAndImported_Then_PrivateKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl ecparam -genkey -name prime256v1 -noout -out private.key
        // openssl pkcs8 -in private.key -topk8 -out private.key.p8e
        // openssl ec -in private.key.p8e -out private.out.key
        // ```

        ECDsa original = fixture.KeyPair;
        var password = "BadP@ssw0rd".ToCharArray();

        // he password-based encryption (PBE) parameters.
        var parameters = new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: RandomNumberGenerator.GetInt32(1, 100_000));

        var pem = original.ExportEncryptedPkcs8PrivateKeyPem(password, parameters);
        output.WriteLine($"{pem}");
        //File.WriteAllText(@"private.p8e", pem);

        using var imported = ECDsa.Create();
        imported.ImportFromEncryptedPem(pem, password);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END ENCRYPTED PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported);   // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(original.ExportECPrivateKey(), imported.ExportECPrivateKey());

        // Exporting again gives the same result.
        // TODO ???
        // imported.ExportEncryptedPkcs8PrivateKeyPem(password, parameters).Is(pem);
    }

    [Fact]
    public void When_OpenSSLEncryptedPemIsImported_Then_PrivateKeyIsRestored()
    {
        // spell-checker: disable
        const string FROM_OPENSSL_PEM = """
            -----BEGIN ENCRYPTED PRIVATE KEY-----
            MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAixLsmkuqdphQICCAAw
            DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEFIDHgYTV5PvrNt89y488HMEgZCT
            sM1O7a1gl0BFGnY/u76arBWHkKy2entuKjyr06l/vJwT4M0PDZWmbDGWyGGV86hT
            jiMYGQCTLjQL3s9g91vbn2y0Vph9LqhobVb3vdBpCM8cA4v64z/QgPQHzlrjq875
            9RueaKctOAonpzAzKiMp5CT9Dyi4VJbcMIa2HOJ2bXMdoO6aYvfU4Hadh8+gzq0=
            -----END ENCRYPTED PRIVATE KEY-----
            """;
        // spell-checker: enable
        var password = "BadP@ssw0rd".ToCharArray();

        using var imported = ECDsa.Create();
        imported.ImportFromEncryptedPem(FROM_OPENSSL_PEM.AsSpan(), password);

        // Assert:

        // Exporting again gives the same result.
        // TODO ???
        // imported.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters).Is(FROM_OPENSSL_PEM);
    }

}
