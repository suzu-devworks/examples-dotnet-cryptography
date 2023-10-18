using Examples.Cryptography.Tests.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.Tests.BouncyCastle.PKCS;

public class PKCSFixture : IDisposable
{
    public PKCSFixture()
    {
        // ... lazy initialize data ...
        var notBefore = DateTimeOffset.Now.AddSeconds(-50);

        _rootCaSet = new(() => InitializeRootCaSets(notBefore));
        _interCaSet = new(() => InitializeIntermediateCaSets(notBefore));
        _endEntitySet = new(() => InitializeEESets(notBefore));
    }

    public (AsymmetricCipherKeyPair, X509Certificate) RootCaSet => _rootCaSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _rootCaSet;

    public (AsymmetricCipherKeyPair, X509Certificate) IntermediateCaSet => _interCaSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _interCaSet;

    public (AsymmetricCipherKeyPair, X509Certificate) EndEntitySet => _endEntitySet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _endEntitySet;

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }

    private static (AsymmetricCipherKeyPair, X509Certificate) InitializeRootCaSets(DateTimeOffset notBefore)
    {
        var rootKeyPair = X509CertificateTestDataGenerator.GenerateKeyPair("ECDSA");
        var rootCert = X509CertificateTestDataGenerator.GenerateRootCACertificate(
                   rootKeyPair,
                   new X509Name("C=JP,CN=Test CA root for PKCS"),
                   notBefore);

        return (rootKeyPair, rootCert);
    }

    private (AsymmetricCipherKeyPair, X509Certificate) InitializeIntermediateCaSets(DateTimeOffset notBefore)
    {
        var (caKeyPair, caCert) = RootCaSet;

        var intermediateKeyPair = X509CertificateTestDataGenerator.GenerateKeyPair("ECDSA");
        var intermediateCert = X509CertificateTestDataGenerator.GenerateCACertificate(
            intermediateKeyPair,
             new X509Name($"C=JP,CN=Test CA for PKCS"),
             caKeyPair,
             caCert,
             BigInteger.One,
             notBefore,
             pathlength: 1
        );

        return (intermediateKeyPair, intermediateCert);
    }
    private (AsymmetricCipherKeyPair, X509Certificate) InitializeEESets(DateTimeOffset notBefore)
    {
        var random = new SecureRandom();
        var (caKeyPair, caCert) = IntermediateCaSet;

        var keyPair = X509CertificateTestDataGenerator.GenerateKeyPair("ECDSA");
        var cert = X509CertificateTestDataGenerator.GenerateCertificate(
            keyPair,
            new X509Name("C=JP,CN=Test PKCS"),
            caKeyPair,
            caCert,
            BigInteger.ValueOf(random.NextInt64(100L, int.MaxValue)),
            notBefore,
            configure: gen => gen.AddExtension(X509Extensions.KeyUsage, critical: true,
                    new KeyUsage(KeyUsage.DigitalSignature)));

        return (keyPair, cert);
    }

}
