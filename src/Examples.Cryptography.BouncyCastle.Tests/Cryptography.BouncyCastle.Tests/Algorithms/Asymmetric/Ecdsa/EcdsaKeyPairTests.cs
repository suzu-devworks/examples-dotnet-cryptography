using System.Diagnostics;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Asymmetry.Ecdsa;

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

        var imported = AsymmetricCipherKeyPairLoader.LoadECPrivateKeyFrom(exported);

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

        var imported = AsymmetricCipherKeyPairLoader.LoadFromPem(pem);

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
    public void When_ConvertingKeyPairFromMicrosoft_WithCustomMethod_Then_ExportedResultsIsMatch()
    {
        // generate System.Security.Cryptography.ECDsa KeyPair.
        using var msKeyPair = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        var bcKeyPair = DotNetUtilities.GetECDsaKeyPair(msKeyPair);

        // Assert:

        // They are different instances.
        Assert.NotSame(msKeyPair, bcKeyPair);

        var msDer = msKeyPair.ExportECPrivateKey();
        var bcDer = bcKeyPair.ExportECPrivateKey();
        Assert.Equal(msDer, bcDer);

        var msPem = msKeyPair.ExportECPrivateKeyPem();
        var bcPem = bcKeyPair.ExportECPrivateKeyPem();
        Assert.Equal(msPem, bcPem);
    }

    [Fact]
    public void When_ConvertingKeyPairFromMicrosoft_Then_ReturnsDifferentOutputForTheSameKey()
    {
        // generate System.Security.Cryptography.ECDsa KeyPair.
        using var msKeyPair = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        var bcKeyPair = DotNetUtilities.GetECDsaKeyPair(msKeyPair);

        var msDer = msKeyPair.ExportECPrivateKey();
        var bcDer = bcKeyPair.ExportPrivateKey();

        // Assert:

        Assert.NotEqual(msDer, bcDer);

        // The DER-encoded ECPrivateKey structure is the same for both keys.
        var msStructure = ECPrivateKeyStructure.GetInstance(msDer);
        var bcStructure = ECPrivateKeyStructure.GetInstance(bcDer);

        // The version, private key, and public key are the same, but the parameters field is different.
        Assert.Equal(msStructure.Version, bcStructure.Version);
        Assert.Equal(msStructure.PrivateKey, bcStructure.PrivateKey);
        Assert.NotEqual(msStructure.Parameters, bcStructure.Parameters);
        Assert.Equal(msStructure.PublicKey, bcStructure.PublicKey);

        // The parameters field in the Microsoft key uses named curve parameters, while the BouncyCastle key uses explicit curve parameters.
        var msParam = X962Parameters.GetInstance(msStructure.Parameters);
        var bcParam = X962Parameters.GetInstance(bcStructure.Parameters);

        // The Microsoft key uses named curve parameters.
        Assert.True(msParam.IsNamedCurve);
        Assert.False(msParam.IsImplicitlyCA);
        Assert.Equal(X9ObjectIdentifiers.Prime256v1, msParam.NamedCurve);

        // The BouncyCastle key uses explicit curve parameters.
        Assert.False(bcParam.IsNamedCurve);
        Assert.False(bcParam.IsImplicitlyCA);
        var bcX9 = X9ECParameters.GetInstance(bcParam.Parameters);
        var p256 = CustomNamedCurves.GetByName("P-256");
        Assert.Equal(p256, bcX9);
    }
}
