using System.Security.Cryptography;

namespace Examples.Cryptography.AsymmetricKey.Rsa;

public class RSAPkcs8PackageTests
{
    private readonly ITestOutputHelper _output;

    public RSAPkcs8PackageTests(ITestOutputHelper output)
    {
        _output = output;
    }

    // PKCS #8 = RFC 5958 Asymmetric Key Packages

    [Fact]
    public void WhenExportAndImportPkcs8PrivateKeyPem()
    {
        //```sh
        // $ openssl genrsa -out private.key 4096
        // $ openssl pkcs8 -topk8 -nocrypt -in private.key -out private.pk8
        //```

        // Arrange.
        var keySize = 4096;

        // Act.
        using var provider = RSA.Create(keySize);
        var pem = provider.ExportPkcs8PrivateKeyPem();

        //File.WriteAllText(@"private.pk8", pem);
        _output.WriteLine($"\n{pem}");

        using var otherProvider = RSA.Create();
        otherProvider.ImportFromPem(pem);
        var other = otherProvider.ExportPkcs8PrivateKeyPem();

        // Assert.
        other.Is(pem);
        pem.Is(x => x.StartsWith("-----BEGIN PRIVATE KEY-----")
                    && x.EndsWith("-----END PRIVATE KEY-----"));

        return;
    }


    [Fact]
    public void WhenExportAndImportEncryptedPkcs8PrivateKeyPem()
    {
        //```sh
        // $ openssl genrsa -out private.key 4096
        // $ openssl pkcs8 -topk8 -in private.key -out private.pk8e
        //```

        // Arrange.
        var keySize = 4096;
        var password = "BadP@ssw0rd".ToCharArray();
        // he password-based encryption (PBE) parameters.
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            RandomNumberGenerator.GetInt32(1, 100_000));

        // Act.
        using var provider = RSA.Create(keySize);
        var pem = provider.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);

        //File.WriteAllText(@"private.pk8e", pem);
        _output.WriteLine($"\n{pem}");

        using var otherProvider = RSA.Create();
        otherProvider.ImportFromEncryptedPem(pem, password);
        var other = otherProvider.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);

        // Assert.
        other.IsNot(pem);
        pem.Is(x => x.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                    && x.EndsWith("-----END ENCRYPTED PRIVATE KEY-----"));

        return;
    }

}
