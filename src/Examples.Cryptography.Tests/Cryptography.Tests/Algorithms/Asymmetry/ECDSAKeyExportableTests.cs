using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class ECDSAKeyExportableTests(
    ECDSAKeyExportableTests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<ECDSAKeyExportableTests.Fixture>
{
    public class Fixture : IDisposable
    {
        // Naming elliptic curves used in cryptography:
        //
        // spell-checker: disable
        // | Curve name | Bits in p | SECG      | ANSI X9.62 |
        // |------------|-----------|-----------|------------|
        // | NIST P-224 | 224       | secp224r1 |            |
        // | NIST P-256 | 256       | secp256r1 | prime256v1 |
        // | NIST P-384 | 384       | secp384r1 |            |
        // | NIST P-521 | 521       | secp521r1 |            |
        // spell-checker: enable

        // With OpenSSL use the following command:
        //
        // ```shell
        // openssl ecparam -genkey -name prime256v1 -noout -out private-ecdsa.key
        // ```

        public void Dispose()
        {
            KeyPair?.Dispose();
            GC.SuppressFinalize(this);
        }

        public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

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

        using ECDsa original = ECDsa.Create(ECCurve.NamedCurves.nistP256);

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
