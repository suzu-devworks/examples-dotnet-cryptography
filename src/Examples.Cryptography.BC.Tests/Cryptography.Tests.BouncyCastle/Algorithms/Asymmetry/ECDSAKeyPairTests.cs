using Examples.Cryptography.BouncyCastle;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms.Asymmetry;

public class ECDSAKeyPairTests
{
    private readonly ITestOutputHelper _output;
    private readonly AsymmetricCipherKeyPair _keyPair;

    public ECDSAKeyPairTests(ITestOutputHelper output)
    {
        // ```
        // dotnet test --logger "console;verbosity=detailed"
        // ```
        _output = output;
        _keyPair = GenerateKeyPair();
    }

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

        X9ECParameters? curve = CustomNamedCurves.GetByName("P-256");
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
             .SetECKeyParameters(curve)
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
        var der = keyPair.ExportECPrivateKey();
        var actual = AsymmetricCipherKeyPairAgent.ImportECPrivateKey(der);

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
        //File.WriteAllText(@"ecdsa-p256-private.key", pem);
        _output.WriteLine($"{pem}");
        pem.Is(x => x.StartsWith("-----BEGIN EC PRIVATE KEY-----")
                    && x.EndsWith("-----END EC PRIVATE KEY-----"));

        return;
    }

    [Fact]
    public void WhenConverrtingPrivateKeyFromMicrofot_DoExportedResulesIsMatch()
    {
        // ### Arrange. ###
        // generate System.Security.Cryptography.ECDsa KeyPair.
        using var msKeyPair = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        // ### Act. ###
        var bcKeyPair = DotNetUtilities.GetECDsaKeyPair(msKeyPair);

        // ### Assert. ###
        // I expected DER(BER) and PEM to be the same,
        // but that doesn't seem to be the case.
        // Is that what it is?

        var msDer = msKeyPair.ExportECPrivateKey();
        var bcDer = bcKeyPair.ExportECPrivateKey();
        //msDer.Is(bcDer);
        msDer.IsNot(bcDer);

        var msPem = msKeyPair.ExportECPrivateKeyPem();
        var bcPem = bcKeyPair.ExportPrivateKeyPem();
        //msPem.Is(bcPem);
        msPem.IsNot(bcPem);

        return;
    }

}
