using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.X509;

public class X509DataFixture : IDisposable
{
    public X509DataFixture()
    {
        // ... lazy initialize data ...
        var notBefore = DateTimeOffset.Now.AddSeconds(-50);

        _rootCaSet = new(() => InitializeRootCaSets(notBefore));
        _interCaSets = new(() => InitializeIntermediateCaSets(notBefore, numOfCerts: 4));
        _endEntitySet = new(() => InitializeEESets(notBefore));
    }

    public (AsymmetricCipherKeyPair, X509Certificate) RootCaSet => _rootCaSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _rootCaSet;

    public IEnumerable<(AsymmetricCipherKeyPair, X509Certificate)> IntermediateCaSets => _interCaSets.Value;
    private readonly Lazy<IEnumerable<(AsymmetricCipherKeyPair, X509Certificate)>> _interCaSets;

    public (AsymmetricCipherKeyPair, X509Certificate) EndEntitySet => _endEntitySet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _endEntitySet;

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }

    public IEnumerable<X509Certificate> Certificates
    {
        get
        {
            yield return RootCaSet.Item2;

            foreach (var sers in IntermediateCaSets)
            {
                yield return sers.Item2;
            }

            yield return EndEntitySet.Item2;
        }
    }


    private static (AsymmetricCipherKeyPair, X509Certificate) InitializeRootCaSets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("RSA")
            .ConfigureDefault()
            .GenerateKeyPair();

        var cert = new X509V3CertificateGenerator()
            .WithRootCA(
                keyPair.Public,
                new X509Name("C=JP,CN=Test CA root"))
            .SetValidity(notBefore.UtcDateTime, days)
            .Generate(keyPair.Private.CreateDefaultSignature());

        cert.Verify(keyPair.Public);

        return (keyPair, cert);
    }

    private IEnumerable<(AsymmetricCipherKeyPair, X509Certificate)> InitializeIntermediateCaSets(
        DateTimeOffset notBefore,
        int days = 365,
        int numOfCerts = 3)
    {
        var (issuerKeyPair, issuerCert) = RootCaSet;

        var results = new List<(AsymmetricCipherKeyPair, X509Certificate)>();

        foreach (var i in Enumerable.Range(1, numOfCerts - 2))
        {
            var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
               .ConfigureDefault()
               .GenerateKeyPair();

            var cert = new X509V3CertificateGenerator()
                .WithIntermidiateCA(
                    keyPair.Public,
                    new X509Name($"C=JP,CN=Test CA-{i:0000}"),
                    issuerCert,
                    serial: BigInteger.One,
                    pathLenConstraint: (numOfCerts - 2 - i))
                .SetValidity(notBefore.UtcDateTime, days)
                .Generate(issuerKeyPair.Private.CreateDefaultSignature());

            cert.Verify(issuerKeyPair.Public);

            results.Add((keyPair, cert));

            issuerKeyPair = keyPair;
            issuerCert = cert;
        }

        return results;
    }

    private (AsymmetricCipherKeyPair, X509Certificate) InitializeEESets(
        DateTimeOffset notBefore,
         int days = 365)
    {
        var (issuerKeyPair, issuerCert) = IntermediateCaSets.Last();

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
            .ConfigureDefault()
            .GenerateKeyPair();

        var cert = new X509V3CertificateGenerator()
               .WithEndEntity(
                    keyPair.Public,
                    subject: new X509Name("C=JP,CN=localhost"),
                    issuerCert,
                    serial: BigInteger.One)
               .SetValidity(notBefore.UtcDateTime, days)
               .Configure(gen => gen.AddExtension(X509Extensions.KeyUsage,
                   critical: true,
                   new KeyUsage(KeyUsage.DigitalSignature)))
               .Generate(issuerKeyPair.Private.CreateDefaultSignature());

        cert.Verify(issuerKeyPair.Public);

        return (keyPair, cert);
    }

}

