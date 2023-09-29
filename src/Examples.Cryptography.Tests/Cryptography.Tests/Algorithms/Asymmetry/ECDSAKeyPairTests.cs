using System.Diagnostics;
using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class ECDSAKeyPairTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly ECDsa _keyPair;

    public ECDSAKeyPairTests(ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        _keyPair = GenerateKeyPair();
    }

    public void Dispose()
    {
        _keyPair?.Dispose();
        GC.SuppressFinalize(this);
    }


    private ECDsa GenerateKeyPair()
    {
        // ```shell
        // $ openssl ecparam -genkey -name prime256v1 -noout -out ecdsa-p256-private.key
        // ```

        // Naming elliptic curves used in cryptography

        // | Curve name | Bits in p | SECG      | ANSI X9.62 |
        // |------------|-----------|-----------|------------|
        // | NIST P-224 | 224       | secp224r1 |            |
        // | NIST P-256 | 256       | secp256r1 | prime256v1 |
        // | NIST P-384 | 384       | secp384r1 |            |
        // | NIST P-521 | 521       | secp521r1 |            |

        var sw = Stopwatch.StartNew();

        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        sw.Stop();
        _output.WriteLine($"ECDsa generate time {sw.Elapsed}");

        return key;
    }


    [Fact]
    public void WhenImportingFromExportECPrivateKey_ReturnsToBeforeExport()
    {
        // ```shell
        // $ openssl ecparam -genkey -name prime256v1 -noout -out ecdsa-p256-private.key
        // ```

        // ### Arrange. ###
        var keyPair = _keyPair!;

        // ### Act. ###
        var exported = keyPair.ExportECPrivateKey();

        using var actual = ECDsa.Create();
        actual.ImportECPrivateKey(exported, out var readcount);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ExportECPrivateKey();
        other.Is(exported);
        other.Length.Is(readcount);

        return;
    }


    [Fact]
    public void WhenImportingFromExportECPrivateKeyPem_ReturnsToBeforeExport()
    {
        // ```shell
        // ```

        // ### Arrange. ###
        var keyPair = _keyPair!;

        // ### Act. ###
        var pem = keyPair.ExportECPrivateKeyPem();

        using var actual = ECDsa.Create();
        actual.ImportFromPem(pem);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ExportECPrivateKeyPem();
        other.Is(pem);

        // PEM assertions
        pem.Is(x => x.StartsWith("-----BEGIN EC PRIVATE KEY-----")
                    && x.EndsWith("-----END EC PRIVATE KEY-----"));

        _output.WriteLine($"{pem}");
        //File.WriteAllText(@"ecdsa-p256-private.key", pem);

        return;
    }

}

