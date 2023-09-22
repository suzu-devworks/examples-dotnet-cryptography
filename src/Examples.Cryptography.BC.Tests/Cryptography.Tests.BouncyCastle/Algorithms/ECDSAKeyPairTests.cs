using System.Security.Cryptography;
using Examples.Cryptography.BouncyCastle;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms;

public class ECDSAKeyPairTests
{
    private static readonly SecureRandom Random = new();
    private readonly ITestOutputHelper _output;

    public ECDSAKeyPairTests(ITestOutputHelper output)
    {
        _output = output;
    }

    // https://tex2e.github.io/rfc-translater/html/rfc5915.html#3--Elliptic-Curve-Private-Key-Format
    //
    // ECPrivateKey ::= SEQUENCE {
    //   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    //   privateKey     OCTET STRING,
    //   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //   publicKey  [1] BIT STRING OPTIONAL
    // }

    //https://tex2e.github.io/rfc-translater/html/rfc5480.html#2-1-1--Unrestricted-Algorithm-Identifier-and-Parameters
    // only the namedCurve CHOICE is permitted
    //
    // ECParameters ::= CHOICE {
    //   namedCurve         OBJECT IDENTIFIER
    //   -- implicitCurve   NULL
    //   -- specifiedCurve  SpecifiedECDomain
    // }

    [Fact]
    public void WhenExportAndImportPrivateKey()
    {
        // Arrange.

        // X9ECParameters.Curve is {Org.BouncyCastle.Math.EC.FpCurve}
        // ```cs
        // var curve = NistNamedCurves.GetByName("P-256");
        // var curve = ECNamedCurveTable.GetByName("P-256");
        // ```

        // X9ECParameters.Curve is {Org.BouncyCastle.Math.EC.Custom.Sec.SecP256R1Curve}
        // ```cs
        // var curve = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
        var curve = CustomNamedCurves.GetByName("P-256");
        // ```

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
             .SetECKeyParameters(curve, Random)
             .GenerateKeyPair();

        // Act.
        var der = keyPair.ExportPrivateKey();

        //File.WriteAllBytes(@"ecdsa-p256-private.der", der);
        _output.WriteLine($"\nExportPrivateKey: length = {der.Length}");

        var otherKeyPair = AsymmetricCipherKeyPairAgent.ImportPrivateKey(der);
        var otherDer = otherKeyPair.ExportPrivateKey();

        // Assert.
        ECPrivateKeyStructure.GetInstance(Asn1Sequence.FromByteArray(der)).IsNotNull();

        der.Is(otherDer);
        keyPair.Private.Is(otherKeyPair.Private);
        keyPair.Public.Is(otherKeyPair.Public);

        return;
    }


    [Fact]
    public void WhenExportAndImportPrivateKeyPem()
    {
        // Arrange.
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
            .SetECKeyParameters(X9ObjectIdentifiers.Prime256v1, Random)
            .GenerateKeyPair();

        // Act.
        var pem = keyPair.ExportPrivateKeyPem();

        //File.WriteAllText(@"ecdsa-p256-private.key", pem);
        _output.WriteLine($"\n{pem}");

        var otherKeyPair = AsymmetricCipherKeyPairAgent.ImportPrivateKeyPem(pem);
        var otherPem = otherKeyPair.ExportPrivateKeyPem();

        // Assert.
        keyPair.Private.Is(otherKeyPair.Private);
        keyPair.Public.Is(otherKeyPair.Public);
        pem.Is(otherPem);
        pem.Is(x => x.StartsWith("-----BEGIN EC PRIVATE KEY-----")
                    && x.EndsWith("-----END EC PRIVATE KEY-----"));
        return;
    }


    [Fact]
    public void WhenExportPrivateKeyPem_WithSystemSecurity()
    {
        using var msEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPair = DotNetUtilities.GetECDsaKeyPair(msEcdsa);

        // Act.
        var mspem = msEcdsa.ExportECPrivateKeyPem();
        var pem = keyPair.ExportPrivateKeyPem();

        //File.WriteAllText(@"ecdsa-p256-ms-private.key", pem);
        _output.WriteLine($"\n{mspem}");
        _output.WriteLine($"\n{pem}");

        // //var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(ecdsa.Private);
        // // _ = privateInfo.HasPublicKey;
        // // var keyPair2 = privateInfo.GetDerEncoded();
        // // var keyPair3 = privateInfo.ToAsn1Object().GetDerEncoded();
        // using var msecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    }
}
