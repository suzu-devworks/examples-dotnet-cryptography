using Examples.Cryptography.BouncyCastle.Algorithms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms.Asymmetry;

public class DSAKeyPairTests
{
    private readonly ITestOutputHelper _output;
    private readonly AsymmetricCipherKeyPair _keyPair;

    public DSAKeyPairTests(ITestOutputHelper output)
    {
        // ```
        // dotnet test --logger "console;verbosity=detailed"
        // ```
        _output = output;
        _keyPair = GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("DSA")
            // .Configure(g =>
            // {
            //     var random = new SecureRandom();
            //     var paramGen = new DsaParametersGenerator();
            //     paramGen.Init(size: 1024, certainty: 80, random);
            //     g.Init(new DsaKeyGenerationParameters(random, paramGen.GenerateParameters()));
            // })
            .ConfigureDefault()
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
        var der = keyPair.ExportDSAPrivateKey();
        var actual = AsymmetricCipherKeyPairAgent.CreateDSAPrivateKeyFrom(der);

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
        //File.WriteAllText(@"dsa-private.key", pem);
        _output.WriteLine($"{pem}");
        pem.Is(x => x.StartsWith("-----BEGIN DSA PRIVATE KEY-----")
            && x.EndsWith("-----END DSA PRIVATE KEY-----"));

        return;
    }

}

