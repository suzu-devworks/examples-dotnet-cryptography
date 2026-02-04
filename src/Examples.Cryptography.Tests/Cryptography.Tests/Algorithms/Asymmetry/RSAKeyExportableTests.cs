using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

/// <summary>
/// Tests for RSA key export and import.
/// </summary>
/// <param name="fixture"></param>
public class RSAKeyExportableTests(RSAKeyFixture fixture) : IClassFixture<RSAKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_ExportedAndImported_Then_PrivateKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl rsa -in private-rsa.key -out private-rsa.out.der -outform DER
        // ```

        RSA original = fixture.KeyPair;

        var exported = original.ExportRSAPrivateKey();

        using var imported = RSA.Create();
        // spell-checker: words readcount
        imported.ImportRSAPrivateKey(exported, out var readcount);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(exported, imported.ExportRSAPrivateKey());
    }

    [Fact]
    public void When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl rsa -in private-rsa.key -out private-rsa.out.pem -outform PEM
        // ```

        RSA original = fixture.KeyPair;

        var pem = original.ExportRSAPrivateKeyPem();
        Output?.WriteLine($"{pem}");
        //File.WriteAllText(@"private-rsa.key", pem);

        using var imported = RSA.Create();
        imported.ImportFromPem(pem);

        // PEM label as expected.
        Assert.Multiple(
            () => Assert.StartsWith("-----BEGIN RSA PRIVATE KEY-----", pem),
            () => Assert.EndsWith("-----END RSA PRIVATE KEY-----", pem)
        );

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(pem, imported.ExportRSAPrivateKeyPem());
    }

    [Fact]
    public void When_PublicKeyExportedAndImported_Then_OnlyPublicKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl rsa -in private-rsa.key -pubout -out private-rsa.out.der -outform DER
        // ```

        RSA original = fixture.KeyPair;

        var exported = original.ExportRSAPublicKey();

        using var imported = RSA.Create();
        imported.ImportRSAPublicKey(exported, out var readCount);

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(exported, imported.ExportRSAPublicKey());

        // Exporting the private key will fail
        // because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
                imported.ExportRSAPrivateKey());
    }

    [Fact]
    public void When_PublicKeyExportedToPemAndImported_Then_OnlyPublicKeyIsRestored()
    {
        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl rsa -in private-rsa.key -pubout -out public-rsa.out.pem --outform PEM
        // ```

        RSA original = fixture.KeyPair;

        var pem = original.ExportRSAPublicKeyPem();
        Output?.WriteLine($"{pem}");
        //File.WriteAllText(@"public-rsa.key", pem);

        using var imported = RSA.Create();
        imported.ImportFromPem(pem);

        // PEM label as expected.
        Assert.Multiple(
            () => Assert.StartsWith("-----BEGIN RSA PUBLIC KEY-----", pem),
            () => Assert.EndsWith("-----END RSA PUBLIC KEY-----", pem)
        );

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(pem, imported.ExportRSAPublicKeyPem());

        // Exporting the private key will fail
        // because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
                imported.ExportRSAPrivateKeyPem());
    }

    [Fact]
    public void When_ExportedToXmlAndImported_Then_PrivateKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        var xml = original.ToXmlString(includePrivateParameters: true);
        Output?.WriteLine($"{xml}");
        //File.WriteAllText(@"private-rsa.key.xml", xml);

        using var imported = RSA.Create();
        imported.FromXmlString(xml);

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(xml, imported.ToXmlString(includePrivateParameters: true));
    }

    [Fact]
    public void When_PublicKeyExportedToXmlAndImported_Then_OnlyPublicKeyIsRestored()
    {
        RSA original = fixture.KeyPair;

        var xml = original.ToXmlString(includePrivateParameters: false);
        Output?.WriteLine($"{xml}");
        //File.WriteAllText(@"public-rsa.key.xml", xml);

        using var imported = RSA.Create();
        imported.FromXmlString(xml);

        // They are different instances.
        Assert.NotSame(original, imported);
        Assert.NotEqual(original, imported); // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(xml, imported.ToXmlString(includePrivateParameters: false));

        // Exporting the private key will fail
        // because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
                imported.ToXmlString(includePrivateParameters: true));
    }

}
