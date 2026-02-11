using System.Security.Cryptography;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetric.Ecdsa;

/// <summary>
/// Tests for ECDSA key export and import.
/// </summary>
/// <param name="fixture"></param>
public class EcdsaKeyExportableTests(EcdsaKeyFixture fixture) : IClassFixture<EcdsaKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    /// <summary>
    /// Asserts that two ECDsa instances have the same key.
    /// </summary>
    /// <param name="original"></param>
    /// <param name="imported"></param>
    /// <param name="includePrivateParameters"></param>
    private void AssertSameKey(ECDsa original, ECDsa imported, bool includePrivateParameters = false)
    {
        // 1. It's not overriding, so it's not working as expected.
        Assert.NotEqual(original, imported);

        // 2. If the public keys are the same, then they are the same.
        Assert.Equal(
            original.ExportSubjectPublicKeyInfo(),
            imported.ExportSubjectPublicKeyInfo());

        // 3. Strictly speaking, the parameters, including the private key, are the same.
        Assert.True(original.EqualsParameters(imported, includePrivateParameters: includePrivateParameters));
    }

    [Fact]
    public void When_ExportedAndImported_Then_PrivateKeyIsRestored()
    {
        ECDsa original = fixture.KeyPair;

        /* With OpenSSL use the following command:
        ```shell
        openssl ec -in ecdsa-private.key -out ecdsa-private.key.der -outform DER
        ```
        */
        var exported = original.ExportECPrivateKey();

        using var imported = ECDsa.Create();
        imported.ImportECPrivateKey(exported, out var readCount);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The key is the same.
        AssertSameKey(original, imported, includePrivateParameters: true);
    }


    [Fact]
    public async Task When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        ECDsa original = fixture.KeyPair;

        /* With OpenSSL use the following command:
        ```shell
        openssl ec -in ecdsa-private.key -out ecdsa-private.key.pem -outform PEM
        ```
        */
        var pem = original.ExportECPrivateKeyPem();
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync(@"ecdsa-private.key.pem", pem, TestContext.Current.CancellationToken);

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

        // The key is the same.
        AssertSameKey(original, imported, includePrivateParameters: true);
    }

}
