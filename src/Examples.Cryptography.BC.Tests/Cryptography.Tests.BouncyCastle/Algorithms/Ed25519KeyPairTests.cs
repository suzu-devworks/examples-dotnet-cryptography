using Examples.Cryptography.BouncyCastle;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms;

public class Ed25519KeyPairTests
{
    private static readonly SecureRandom Random = new();
    private readonly ITestOutputHelper _output;

    public Ed25519KeyPairTests(ITestOutputHelper output)
    {
        _output = output;
    }


    [Fact]
    public void WhenExportAndImportPrivateKey()
    {
        // Arrange.
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
            .Configure(g => g.Init(new Ed25519KeyGenerationParameters(Random)))
            .GenerateKeyPair();

        // Act.
        var der = keyPair.ExportPrivateKey();

        File.WriteAllBytes(@"ed25519-private.der", der);

        //var otherKeyPair = AsymmetricCipherKeyPairAgent.ImportPrivateKeyPem(pem);

        // Assert.
        // keyPair.Private.Is(otherKeyPair.Private);
        // keyPair.Public.Is(otherKeyPair.Public);
        return;
    }


    [Fact]
    public void WhenExportAndImportPrivateKeyPem()
    {
        // Arrange.
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
            .Configure(g => g.Init(new Ed25519KeyGenerationParameters(Random)))
            .GenerateKeyPair();

        // Act.
        var pem = keyPair.ExportPrivateKeyPem();

        //File.WriteAllText(@"ed25519-private.key", pem);
        _output.WriteLine($"\n{pem}");

        var otherKeyPair = AsymmetricCipherKeyPairAgent.ImportPrivateKeyPem(pem);
        var otherPem = otherKeyPair.ExportPrivateKeyPem();

        // Assert.
        keyPair.Private.Is(otherKeyPair.Private);
        keyPair.Public.Is(otherKeyPair.Public);
        pem.Is(otherPem);
        pem.Is(x => x.StartsWith("-----BEGIN PRIVATE KEY-----")
                    && x.EndsWith("-----END PRIVATE KEY-----"));
        return;
    }

}
