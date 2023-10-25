using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.PKCS;

public class PKCSDataFixture : IDisposable
{
    public PKCSDataFixture()
    {
        // ... lazy initialize data ...
        var notBefore = DateTimeOffset.Now.AddSeconds(-50);

        _rootCaSet = new(() => InitializeRootCaSets(notBefore));
        _interCaSet = new(() => InitializeIntermediateCaSets(notBefore));
        _endEntitySet = new(() => InitializeEESets(notBefore));

        _keyPair = new(() => CreateKeyPair());
    }

    public (AsymmetricCipherKeyPair, X509Certificate) RootCaSet => _rootCaSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _rootCaSet;

    public (AsymmetricCipherKeyPair, X509Certificate) IntermediateCaSet => _interCaSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _interCaSet;

    public (AsymmetricCipherKeyPair, X509Certificate) EndEntitySet => _endEntitySet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _endEntitySet;

    public AsymmetricCipherKeyPair KeyPair => _keyPair.Value;
    private readonly Lazy<AsymmetricCipherKeyPair> _keyPair;

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }


    private static (AsymmetricCipherKeyPair, X509Certificate) InitializeRootCaSets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
          .ConfigureDefault()
          .GenerateKeyPair();

        var cert = new X509V3CertificateGenerator()
            .WithRootCA(
                keyPair.Public,
                new X509Name("C=JP,CN=Test CA root for PKCS"))
            .SetValidity(notBefore.UtcDateTime, days)
            .Generate(keyPair.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }


    private (AsymmetricCipherKeyPair, X509Certificate) InitializeIntermediateCaSets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var (issuerKeyPair, issuerCert) = RootCaSet;

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
          .ConfigureDefault()
          .GenerateKeyPair();

        var cert = new X509V3CertificateGenerator()
          .WithIntermidiateCA(
                keyPair.Public,
                new X509Name($"C=JP,CN=Test CA for PKCS"),
                issuerCert,
                serial: BigInteger.One,
                pathLenConstraint: 1)
          .SetValidity(notBefore.UtcDateTime, days)
          .Generate(issuerKeyPair.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }


    private (AsymmetricCipherKeyPair, X509Certificate) InitializeEESets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var (issuerKeyPair, issuerCert) = IntermediateCaSet;

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
          .ConfigureDefault()
          .GenerateKeyPair();

        var random = new SecureRandom();
        var serial = BigInteger.ValueOf(random.NextInt64(100L, int.MaxValue));

        var cert = new X509V3CertificateGenerator()
            .WithEndEntity(
                keyPair.Public,
                subject: new X509Name("C=JP,CN=Test PKCS"),
                issuerCert,
                serial)
            .SetValidity(notBefore.UtcDateTime, days)
            .Configure(gen => gen.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(KeyUsage.DigitalSignature)))
            .Generate(issuerKeyPair.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }


    private static AsymmetricCipherKeyPair CreateKeyPair()
    {
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("RSA")
            .ConfigureDefault()
            .GenerateKeyPair();

        return keyPair;
    }

}
