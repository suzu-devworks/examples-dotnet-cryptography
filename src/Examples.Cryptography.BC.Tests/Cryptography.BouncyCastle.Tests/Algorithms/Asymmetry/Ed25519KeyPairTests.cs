using System.Diagnostics;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Asymmetry;

public class Ed25519KeyPairTests
{
    private readonly ITestOutputHelper _output;
    private readonly AsymmetricCipherKeyPair _keyPair;

    public Ed25519KeyPairTests(ITestOutputHelper output)
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

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
            //.Configure(g => g.Init(new Ed25519KeyGenerationParameters(new SecureRandom())))
            .ConfigureEd25519Key()
            .GenerateKeyPair();

        sw.Stop();
        _output.WriteLine($"Ed25519 key pair generate time {sw.Elapsed}");

        return keyPair;
    }

    [Fact]
    public void WhenImportingFromExportPrivateKey_ReturnsGoBackBeforeExporting()
    {
        // ### Arrange. ###
        // Prepare the generated key pair..
        var keyPair = _keyPair;

        // ### Act. ###
        var der = keyPair.ExportPrivateKey();
        var actual = AsymmetricCipherKeyPairAgent.CreateFrom(der);

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
        //File.WriteAllText(@"ed25519-private.key", pem);
        _output.WriteLine($"{pem}");
        pem.Is(x => x.StartsWith("-----BEGIN PRIVATE KEY-----")
            && x.EndsWith("-----END PRIVATE KEY-----"));

        return;
    }

}
