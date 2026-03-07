using System.Diagnostics;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Asymmetry.Rsa;

public class RSAKeyPairTests(RSAKeyPairTests.Fixture fixture)
    : IClassFixture<RSAKeyPairTests.Fixture>
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
            var sw = Stopwatch.StartNew();

            var keyPair = GeneratorUtilities.GetKeyPairGenerator("RSA")
                .ConfigureRSAParameter(strength: 2048, certainty: 112)
                .GenerateKeyPair();

            sw.Stop();
            TestContext.Current.TestOutputHelper?.WriteLine($"RSA key pair generate time {sw.Elapsed}");

            return keyPair;
        }
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public void When_ExportedAndImported_Then_KeyPairIsRestored()
    {
        var keyPair = fixture.KeyPair;

        var exported = keyPair.ExportRSAPrivateKey();

        var imported = AsymmetricCipherKeyPairAgent.LoadRSAPrivateKeyFrom(exported);

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
        await FileOutput.WriteFileAsync(@"rsa-private.key", pem, TestContext.Current.CancellationToken);

        var imported = AsymmetricCipherKeyPairAgent.LoadFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN RSA PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END RSA PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }

    [Fact]
    public void When_ConvertingKeyPairFromMicrosoft_Then_ExportedResultsIsMatch()
    {
        // generate System.Security.Cryptography.RSA KeyPair.
        using var msKeyPair = System.Security.Cryptography.RSA.Create(2048);

        var bcKeyPair = DotNetUtilities.GetRsaKeyPair(msKeyPair);

        // Assert:

        // They are different instances.
        Assert.NotSame(msKeyPair, bcKeyPair);

        // I expected DER(BER) and PEM to be the same.
        var msDer = msKeyPair.ExportRSAPrivateKey();
        var bcDer = bcKeyPair.ExportRSAPrivateKey();
        Assert.Equal(msDer, bcDer);

        var msPem = msKeyPair.ExportRSAPrivateKeyPem();
        var bcPem = bcKeyPair.ExportPrivateKeyPem();
        Assert.Equal(msPem, bcPem);
    }
}
