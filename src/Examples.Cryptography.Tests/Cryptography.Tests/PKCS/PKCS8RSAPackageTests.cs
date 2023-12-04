using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.PKCS;

public class PKCS8RSAPackageTests : IClassFixture<PKCSDataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly PKCSDataFixture _fixture;

    public PKCS8RSAPackageTests(PKCSDataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        _fixture = fixture;
    }

    // PKCS #8 = RFC 5958 Asymmetric Key Packages

    [Fact]
    public void WhenImportingFromExportPkcs8PrivateKeyPem_ReturnsToBeforeExport()
    {
        //```sh
        // $ openssl genrsa -out private.key 2048
        // $ openssl pkcs8 -topk8 -nocrypt -in private.key -out private.pk8
        //```

        // Arrange.
        var provider = _fixture.RSAKeyProvider;

        // Act.
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
    public void WhenImportingFromExportEncryptedPkcs8PrivateKeyPem_ReturnsToBeforeExport()
    {
        //```sh
        // $ openssl genrsa -out private.key 2048
        // $ openssl pkcs8 -topk8 -in private.key -out private.pk8e
        //```

        // Arrange.
        var provider = _fixture.RSAKeyProvider;
        var password = "BadP@ssw0rd".ToCharArray();

        // Act.
        // he password-based encryption (PBE) parameters.
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            RandomNumberGenerator.GetInt32(1, 100_000));
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
