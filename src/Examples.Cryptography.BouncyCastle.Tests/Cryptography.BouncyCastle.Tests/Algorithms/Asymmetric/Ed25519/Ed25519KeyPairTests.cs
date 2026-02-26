using System.Diagnostics;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Asymmetry;

public class Ed25519KeyPairTests(Ed25519KeyPairTests.Fixture fixture)
    : IClassFixture<Ed25519KeyPairTests.Fixture>
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

            var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
                .ConfigureEd25519Key()
                .GenerateKeyPair();

            sw.Stop();
            TestContext.Current.TestOutputHelper?.WriteLine($"Ed25519 key pair generate time {sw.Elapsed}");

            return keyPair;
        }
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public void When_ExportedAndImported_Then_KeyPairIsRestored()
    {
        var keyPair = fixture.KeyPair;

        var exported = keyPair.ExportPrivateKey();

        var imported = AsymmetricCipherKeyPairAgent.CreateFrom(exported);

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
        await FileOutput.WriteFileAsync(@"bc-ed25519-private.key", pem, TestContext.Current.CancellationToken);

        var imported = AsymmetricCipherKeyPairAgent.CreateFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }
}
