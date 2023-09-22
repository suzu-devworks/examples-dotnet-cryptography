using Examples.Cryptography.BouncyCastle;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms;

public class RSAKeyPairTests
{
    private static readonly SecureRandom Random = new();
    private readonly ITestOutputHelper _output;

    public RSAKeyPairTests(ITestOutputHelper output)
    {
        _output = output;
    }


    [Fact]
    public void WhenExportAndImportPrivateKeyPem()
    {
        // Arrange.
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("RSA")
            .Configure(g => g.Init(
                new RsaKeyGenerationParameters(
                    publicExponent: BigInteger.ValueOf(0x10001), // should be a Fermat number.
                    Random,
                    strength: 2048,
                    certainty: 25
                    )))
            .GenerateKeyPair();

        // Act.
        var pem = keyPair.ExportPrivateKeyPem();

        //File.WriteAllText(@"rsa-private.key", pem);
        _output.WriteLine($"\n{pem}");

        var otherKeyPair = AsymmetricCipherKeyPairAgent.ImportPrivateKeyPem(pem);
        var otherPem = otherKeyPair.ExportPrivateKeyPem();

        // Assert.
        keyPair.Private.Is(otherKeyPair.Private);
        keyPair.Public.Is(otherKeyPair.Public);
        pem.Is(otherPem);
        pem.Is(x => x.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                    && x.EndsWith("-----END RSA PRIVATE KEY-----"));
        return;
    }
}
