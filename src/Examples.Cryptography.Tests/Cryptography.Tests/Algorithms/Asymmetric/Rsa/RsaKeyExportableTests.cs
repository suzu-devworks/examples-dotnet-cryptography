using System.Security.Cryptography;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetric.Rsa;

/// <summary>
/// Tests for RSA key export and import.
/// </summary>
/// <param name="fixture"></param>
public class RsaKeyExportableTests(RsaKeyFixture fixture) : IClassFixture<RsaKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    /// <summary>
    /// Asserts that two RSA instances have the same key.
    /// </summary>
    /// <param name="original"></param>
    /// <param name="imported"></param>
    /// <param name="includePrivateParameters"></param>
    private void AssertSameKey(RSA original, RSA imported, bool includePrivateParameters = false)
    {
        // 1. It's not overriding, so it's not working as expected.
        Assert.NotEqual(original, imported);

        // 2. If the public keys are the same, then they are the same.
        Assert.Equal(
            original.ExportRSAPublicKey(),
            imported.ExportRSAPublicKey());

        // 3. Strictly speaking, the parameters, including the private key, are the same.
        Assert.True(original.EqualsParameters(imported, includePrivateParameters));
    }

    [Fact]
    public void When_ExportedAndImported_Then_PrivateKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        /* With OpenSSL use the following command:
        ```shell
        openssl rsa -in rsa-private.key -out rsa-private.key.der -outform DER
        ```
        */
        var exported = original.ExportRSAPrivateKey();

        using var imported = RSA.Create();
        // spell-checker: words readcount
        imported.ImportRSAPrivateKey(exported, out var readcount);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The key is the same.
        AssertSameKey(original, imported, includePrivateParameters: true);
    }

    [Fact]
    public async Task When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        /* With OpenSSL use the following command:
        ```shell
        openssl rsa -in rsa-private.key -out rsa-private.key.pem -outform PEM
        ```
        */
        var pem = original.ExportRSAPrivateKeyPem();
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync(@"rsa-private.key.pem", pem, TestContext.Current.CancellationToken);

        using var imported = RSA.Create();
        imported.ImportFromPem(pem);

        // PEM label as expected.
        Assert.Multiple(
            () => Assert.StartsWith("-----BEGIN RSA PRIVATE KEY-----", pem),
            () => Assert.EndsWith("-----END RSA PRIVATE KEY-----", pem)
        );

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The key is the same.
        AssertSameKey(original, imported, includePrivateParameters: true);
    }

    [Fact]
    public void When_PublicKeyExportedAndImported_Then_OnlyPublicKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        /* With OpenSSL use the following command:
        ```shell
        openssl rsa -in rsa-private.key -pubout -out rsa-public.key.der -outform DER
        ```
        */
        var exported = original.ExportRSAPublicKey();

        using var imported = RSA.Create();
        imported.ImportRSAPublicKey(exported, out var readCount);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The key is the same.
        AssertSameKey(original, imported);

        // Exporting the private key will fail because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
                imported.ExportRSAPrivateKey());
    }

    [Fact]
    public async Task When_PublicKeyExportedToPemAndImported_Then_OnlyPublicKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        /* With OpenSSL use the following command:
        ```shell
        openssl rsa -in rsa-private.key -pubout -out rsa-public.key.pem -outform PEM
        ```
        */
        var pem = original.ExportRSAPublicKeyPem();
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync(@"rsa-public.key.pem", pem, TestContext.Current.CancellationToken);

        using var imported = RSA.Create();
        imported.ImportFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.Multiple(
            () => Assert.StartsWith("-----BEGIN RSA PUBLIC KEY-----", pem),
            () => Assert.EndsWith("-----END RSA PUBLIC KEY-----", pem)
        );

        // They are different instances.
        Assert.NotSame(original, imported);

        // The key is the same.
        AssertSameKey(original, imported);

        // Exporting the private key will fail because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
            imported.ExportRSAPrivateKey());
    }

    [Fact]
    public async Task When_ExportedToXmlAndImported_Then_PrivateKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        var xml = original.ToXmlString(includePrivateParameters: true);
        Output?.WriteLine($"{xml}");
        await FileOutput.WriteFileAsync(@"rsa-private.key.xml", xml, TestContext.Current.CancellationToken);

        using var imported = RSA.Create();
        imported.FromXmlString(xml);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The key is the same.
        AssertSameKey(original, imported, includePrivateParameters: true);

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(xml, imported.ToXmlString(includePrivateParameters: true));
    }

    [Fact]
    public async Task When_PublicKeyExportedToXmlAndImported_Then_OnlyPublicKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        var xml = original.ToXmlString(includePrivateParameters: false);
        Output?.WriteLine($"{xml}");
        await FileOutput.WriteFileAsync(@"rsa-public.key.xml", xml, TestContext.Current.CancellationToken);

        using var imported = RSA.Create();
        imported.FromXmlString(xml);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The key is the same.
        AssertSameKey(original, imported);

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(xml, imported.ToXmlString(includePrivateParameters: false));

        // Exporting the private key will fail because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
                imported.ToXmlString(includePrivateParameters: true));
    }

}
