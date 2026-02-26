using System.Diagnostics;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Asymmetry.Dsa;

public class DsaKeyPairTests(DsaKeyPairTests.Fixture fixture)
    : IClassFixture<DsaKeyPairTests.Fixture>
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

            var keyPair = GeneratorUtilities.GetKeyPairGenerator("DSA")
                .ConfigureDSAParameter()
                .GenerateKeyPair();

            sw.Stop();
            TestContext.Current.TestOutputHelper?.WriteLine($"DSA key pair generate time {sw.Elapsed}");

            return keyPair;
        }
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public void When_ExportedAndImported_Then_KeyPairIsRestored()
    {
        var keyPair = fixture.KeyPair;

        var exported = keyPair.ExportDSAPrivateKey();

        var imported = AsymmetricCipherKeyPairAgent.CreateDSAPrivateKeyFrom(exported);

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
        await FileOutput.WriteFileAsync(@"bc-dsa-private.key.pem", pem, TestContext.Current.CancellationToken);

        var imported = AsymmetricCipherKeyPairAgent.CreateFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN DSA PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END DSA PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }
}
