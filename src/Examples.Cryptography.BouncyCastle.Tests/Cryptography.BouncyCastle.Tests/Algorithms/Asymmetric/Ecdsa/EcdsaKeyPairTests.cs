using System.Diagnostics;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Asymmetry;

public class EcdsaKeyPairTests(EcdsaKeyPairTests.Fixture fixture)
    : IClassFixture<EcdsaKeyPairTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public ValueTask InitializeAsync()
        {
            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }

        public AsymmetricCipherKeyPair KeyPair { get; } = GenerateKeyPair();

        private static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            // There seem to be several ways to create X9ECParameters.

            // X9ECParameters.Curve is {Org.BouncyCastle.Math.EC.FpCurve}
            // ```cs
            // var curve = NistNamedCurves.GetByName("P-256");
            // var curve = ECNamedCurveTable.GetByName("P-256");
            // ```

            // X9ECParameters.Curve is {Org.BouncyCastle.Math.EC.Custom.Sec.SecP256R1Curve}
            // ```cs
            // var curve = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
            // var curve = CustomNamedCurves.GetByName("P-256");
            // ```

            var sw = Stopwatch.StartNew();

            var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
                 .ConfigureECParameter(CustomNamedCurves.GetByName("P-256"))
                 .GenerateKeyPair();

            sw.Stop();
            TestContext.Current.TestOutputHelper?.WriteLine($"ECDSA key pair generate time {sw.Elapsed}");

            return keyPair;
        }
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public void When_ExportedAndImported_Then_KeyPairIsRestored()
    {
        var keyPair = fixture.KeyPair;

        var exported = keyPair.ExportECPrivateKey();

        var imported = AsymmetricCipherKeyPairAgent.CreateECPrivateKeyFrom(exported);

        // Assert:

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }

    [Fact]
    public async Task When_ExportedToPemAndImported_Then_KeyPairIsRestored()
    {
        var keyPair = fixture.KeyPair;

        var pem = keyPair.ExportPrivateKeyPem();
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync("bc-ecdsa-p256-private.key", pem, TestContext.Current.CancellationToken);

        var imported = AsymmetricCipherKeyPairAgent.CreateFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN EC PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END EC PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }

    [Fact]
    public void When_ConvertingKeyPairFromMicrosoft_Then_ExportedResultsIsMatch()
    {
        // generate System.Security.Cryptography.ECDsa KeyPair.
        using var msKeyPair = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        var bcKeyPair = DotNetUtilities.GetECDsaKeyPair(msKeyPair);

        // Assert:

        // They are different instances.
        Assert.NotSame(msKeyPair, bcKeyPair);

        // I expected DER(BER) and PEM to be the same,
        // but that doesn't seem to be the case.
        // Is that what it is?

        var msDer = msKeyPair.ExportECPrivateKey();
        var bcDer = bcKeyPair.ExportECPrivateKey();
        Assert.Equal(msDer, bcDer);

        var msPem = msKeyPair.ExportECPrivateKeyPem();
        var bcPem = bcKeyPair.ExportECPrivateKeyPem();
        Assert.Equal(msPem, bcPem);
    }
}
