using System.Diagnostics;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Asymmetry;

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

    private AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var sw = Stopwatch.StartNew();

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("RSA")
            // ## Since the default value is given, it is the same as commenting it out. ##
            //.Configure(g => g.Init(
            // new KeyGenerationParameters(
            //     random: new SecureRandom(),
            //     strength: 2048,
            //     )))
            //.Configure(g => g.Init(
            // new RsaKeyGenerationParameters(
            //     publicExponent: BigInteger.ValueOf(0x10001), // (default)should be a Fermat number.
            //     random: new SecureRandom(),
            //     strength: 2048, // 4096 bytes is too late.
            //     certainty: 100 // (default) Affects prime numbers
            //     )))
            .ConfigureDefault()
            .GenerateKeyPair();

        sw.Stop();
        _output.WriteLine($"RSA key pair generate time {sw.Elapsed}");

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
        var actual = AsymmetricCipherKeyPairAgent.CreateRSAPrivateKeyFrom(der);

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
        var actual = AsymmetricCipherKeyPairAgent.CreateFromPem(pem);

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
    public void WhenConvertingPrivateKeyFromMicrosoft_DoExportedResultsIsMatch()
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
