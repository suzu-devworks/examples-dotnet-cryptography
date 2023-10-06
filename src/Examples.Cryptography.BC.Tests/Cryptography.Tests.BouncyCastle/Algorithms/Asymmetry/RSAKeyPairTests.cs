using Examples.Cryptography.BouncyCastle;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms.Asymmetry;

public class RSAKeyPairTests
{
    private readonly ITestOutputHelper _output;
    private readonly AsymmetricCipherKeyPair _keyPair;

    public RSAKeyPairTests(ITestOutputHelper output)
    {
        // ```
        // dotnet test --logger "console;verbosity=detailed"
        // ```
        _output = output;
        _keyPair = GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("RSA")
            .Configure(g => g.Init(
                // ## Since the default value is given, it is the same as commenting it out. ##
                // new KeyGenerationParameters(
                //     random: new SecureRandom(),
                //     strength: 2048,
                // )
                new RsaKeyGenerationParameters(
                    publicExponent: BigInteger.ValueOf(0x10001), // (default)should be a Fermat number.
                    random: new SecureRandom(),
                    strength: 2048, // 4096 bytes is too late.
                    certainty: 100 // (default) Affects prime numbers?
                    )))
            .GenerateKeyPair();

        return keyPair;
    }

    [Fact]
    public void WhenImportingFromExportPrivateKey_ReturnsGoBackBeforeExporting()
    {
        // ### Arrange. ###
        // Prepare the generated key pair..
        var keyPair = _keyPair;

        // ### Act. ###
        var der = keyPair.ExportRsaPrivateKey();
        var actual = AsymmetricCipherKeyPairAgent.ImportRSAPrivateKey(der);

        // ### Assert. ###
        // It's back to normal.
        actual.Private.Is(keyPair.Private);
        actual.Public.Is(keyPair.Public);

        return;
    }


    [Fact]
    public void WhenImportingFromExportPrivateKeyPem_ReturnsGoBackBeforeExporting()
    {
        // ### Arrange. ###
        // Prepare the generated key pair..
        var keyPair = _keyPair;

        // ### Act. ###
        var pem = keyPair.ExportPrivateKeyPem();
        var actual = AsymmetricCipherKeyPairAgent.ImportPrivateKeyPem(pem);

        // ### Assert. ###
        // It's back to normal
        actual.Private.Is(keyPair.Private);
        actual.Public.Is(keyPair.Public);

        // PEM assertions
        // File.WriteAllText(@"rsa-private.key", pem);
        _output.WriteLine($"{pem}");
        pem.Is(x => x.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                    && x.EndsWith("-----END RSA PRIVATE KEY-----"));
        return;
    }


    [Fact]
    public void WhenConverrtingPrivateKeyFromMicrofot_DoExportedResulesIsMatch()
    {
        // ### Arrange. ###
        // generate System.Security.Cryptography.ECDsa KeyPair.
        using var msKeyPair = System.Security.Cryptography.RSA.Create(2048);

        // ### Act. ###
        var bcKeyPair = DotNetUtilities.GetRsaKeyPair(msKeyPair);

        // ### Assert. ###
        // I expected DER(BER) and PEM to be the same.
        var msDer = msKeyPair.ExportRSAPrivateKey();
        var bcDer = bcKeyPair.ExportECPrivateKey();
        msDer.Is(bcDer);

        var msPem = msKeyPair.ExportRSAPrivateKeyPem();
        var bcPem = bcKeyPair.ExportPrivateKeyPem();
        msPem.Is(bcPem);

        return;
    }
}
