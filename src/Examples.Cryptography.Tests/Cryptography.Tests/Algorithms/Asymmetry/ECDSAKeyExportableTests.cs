using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

/// <summary>
/// Tests for ECDSA key export and import.
/// </summary>
/// <param name="fixture"></param>
/// <param name="output"></param>
public class ECDSAKeyExportableTests(
    ECDSAKeyFixture fixture,
    ITestOutputHelper output)
    : IClassFixture<ECDSAKeyFixture>
{
    [Fact]
    public void When_ExportedAndImported_Then_PrivateKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl ec -in private-ecdsa.key -out private-ecdsa.out.der -outform DER
        // ```

        ECDsa original = fixture.KeyPair;

        var exported = original.ExportECPrivateKey();

        using var imported = ECDsa.Create();
        imported.ImportECPrivateKey(exported, out var readCount);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(exported, imported.ExportECPrivateKey());
    }

    [Fact]
    public void When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl ec -in private-ecdsa.key -out private-ecdsa.out.pem -outform PEM
        // ```

        ECDsa original = fixture.KeyPair;

        var pem = original.ExportECPrivateKeyPem();
        output.WriteLine($"{pem}");
        //File.WriteAllText(@"private-ecdsa.key", pem);

        using var imported = ECDsa.Create();
        imported.ImportFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.Multiple(
            () => Assert.StartsWith("-----BEGIN EC PRIVATE KEY-----", pem),
            () => Assert.EndsWith("-----END EC PRIVATE KEY-----", pem)
        );

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(pem, imported.ExportECPrivateKeyPem());
    }

}
