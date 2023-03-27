using System.Security.Cryptography;

namespace Examples.Cryptography.AsymmetricKey.Ecdsa;

public class ECDSAKeyPairTests
{
    private readonly ITestOutputHelper _output;

    public ECDSAKeyPairTests(ITestOutputHelper output)
    {
        _output = output;
    }

    // Naming elliptic curves used in cryptography
    // Curve name   Bits in p   SECG / ANSI X9.62
    // NIST P-224   224         secp224r1
    // NIST P-256   256         secp256r1 / prime256v1
    // NIST P-384   384         secp384r1

    [Fact]
    public void WhenExportAndImportECPrivateKey()
    {
        // ```sh
        // $ openssl ecparam -genkey -name prime256v1 -noout -out ecdsa-p256-private.key
        // ```

        // Arrange.
        using var provider = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Act.
        var exported = provider.ExportECPrivateKey();

        using var otherProvider = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        otherProvider.ImportECPrivateKey(exported, out var readcount);
        var other = otherProvider.ExportECPrivateKey();

        // Assert.
        other.Is(exported);
        other.Length.Is(readcount);

        return;
    }


    [Fact]
    public void WhenExportAndImportECPrivateKeyPem()
    {
        // ```sh
        // $ openssl ecparam -genkey -name prime256v1 -noout -out ecdsa-p256-private.key
        // ```

        // Arrange.
        using var provider = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Act.
        var pem = provider.ExportECPrivateKeyPem();

        //File.WriteAllText(@"ecdsa-p256-private.key", pem);
        _output.WriteLine($"\n{pem}");

        using var otherProvider = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        otherProvider.ImportFromPem(pem);
        var other = otherProvider.ExportECPrivateKeyPem();

        // Assert.
        other.Is(pem);
        pem.Is(x => x.StartsWith("-----BEGIN EC PRIVATE KEY-----")
                    && x.EndsWith("-----END EC PRIVATE KEY-----"));

        return;
    }

}

