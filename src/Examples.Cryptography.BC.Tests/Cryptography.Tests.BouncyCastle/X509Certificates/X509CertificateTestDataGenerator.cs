using Examples.Cryptography.BouncyCastle;
using Examples.Cryptography.BouncyCastle.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.Tests.BouncyCastle.X509Certificates;

internal static class X509CertificateTestDataGenerator
{
    public static AsymmetricCipherKeyPair GenerateKeyPair(string algorithm)
    {
        var keyPair = algorithm switch
        {
            "RSA" => GenRSA(),
            "ECDSA" => GenECDSA(),
            "Ed25519" => GenEd25519(),
            _ => throw new NotSupportedException(),
        };

        return keyPair;

        static AsymmetricCipherKeyPair GenRSA()
        {
            var keyPair = GeneratorUtilities.GetKeyPairGenerator("RSA")
             .Configure(g => g.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001),
                 new SecureRandom(),
                 strength: 2048,
                 certainty: 25)))
             .GenerateKeyPair();

            return keyPair;
        }

        static AsymmetricCipherKeyPair GenECDSA()
        {
            var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
                .SetECKeyParameters(CustomNamedCurves.GetByName("P-256"), null)
                .GenerateKeyPair();

            return keyPair;
        }

        static AsymmetricCipherKeyPair GenEd25519()
        {
            var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
                .Configure(g => g.Init(new Ed25519KeyGenerationParameters(new SecureRandom())))
                .GenerateKeyPair();

            return keyPair;
        }
    }

    public static X509Certificate GenerateRootCACertificate(
        AsymmetricCipherKeyPair keyPair,
        X509Name subject,
        DateTimeOffset now,
        int days = 365
        )
    {
        var cert = new X509V3CertificateGenerator()
            .WithRootCA(keyPair, subject)
            .SetValidity(now.UtcDateTime, days)
            .Generate(CreateSignatureFactory(keyPair.Private));

        return cert;
    }

    public static X509Certificate GenerateCACertificate(
        AsymmetricCipherKeyPair keyPair,
        X509Name subject,
        AsymmetricCipherKeyPair issuerKeyPair,
        X509Certificate issuerCert,
        BigInteger serial,
        DateTimeOffset now,
        int days = 365,
        int pathlength = 0
        )
    {
        var cert = new X509V3CertificateGenerator()
            .WithIntermidiateCA(keyPair, subject, issuerCert, serial, pathlength)
            .SetValidity(now.UtcDateTime, days)
            .Generate(CreateSignatureFactory(issuerKeyPair.Private));

        return cert;
    }

    public static X509Certificate GenerateCertificate(
         AsymmetricCipherKeyPair keyPair,
         X509Name subject,
         AsymmetricCipherKeyPair issuerKeyPair,
         X509Certificate issuerCert,
         BigInteger serial,
         DateTimeOffset now,
         int days = 365,
         Action<X509V3CertificateGenerator>? configure = null
         )
    {
        var cert = new X509V3CertificateGenerator()
            .WithEndEntity(keyPair, subject, issuerCert, serial)
            .SetValidity(now.UtcDateTime, days)
            .Configure(gen => configure?.Invoke(gen))
            .Generate(CreateSignatureFactory(issuerKeyPair.Private));

        return cert;
    }

    public static IEnumerable<(AsymmetricCipherKeyPair, X509Certificate)> CreateChainCertificates(
        int numOfCerts,
        DateTimeOffset now,
        X509Name eeSubject,
        Action<X509V3CertificateGenerator>? eeConfigureAction = null
        )
    {
        var notBefore = now.AddSeconds(-50);

        var rootKeyPair = X509CertificateTestDataGenerator.GenerateKeyPair("RSA");
        var rootCert = X509CertificateTestDataGenerator.GenerateRootCACertificate(
            rootKeyPair,
            new X509Name("C=JP,CN=Test CA root"),
            notBefore);

        yield return (rootKeyPair, rootCert);

        // CA
        AsymmetricCipherKeyPair caKeyPair = rootKeyPair;
        X509Certificate caCert = rootCert;

        foreach (var i in Enumerable.Range(1, numOfCerts - 2))
        {
            var intermediateKeyPair = X509CertificateTestDataGenerator.GenerateKeyPair("ECDSA");
            var intermediateCert = X509CertificateTestDataGenerator.GenerateCACertificate(
                intermediateKeyPair,
                 new X509Name($"C=JP,CN=Test CA-{i:0000}"),
                 caKeyPair,
                 caCert,
                 BigInteger.One,
                 notBefore,
                 pathlength: (numOfCerts - 2 - i)
            );

            yield return (intermediateKeyPair, intermediateCert);

            caKeyPair = intermediateKeyPair;
            caCert = intermediateCert;
        }

        // End Entity
        var eeKeyPair = X509CertificateTestDataGenerator.GenerateKeyPair("Ed25519");
        var eeCert = X509CertificateTestDataGenerator.GenerateCertificate(
            eeKeyPair,
            eeSubject,
            caKeyPair,
            caCert,
            BigInteger.One,
            notBefore,
            configure: eeConfigureAction
        );

        yield return (eeKeyPair, eeCert);

    }

    public static X509Crl GenerateCRL(
        AsymmetricCipherKeyPair issuerKeyPair,
        X509Certificate issuer,
        BigInteger crlNumber,
        DateTimeOffset updateAt,
        Action<X509V2CrlGenerator>? configureAction = null
        )
    {
        var nextUpdateAt = updateAt.AddDays(2);

        var crl = new X509V2CrlGenerator()
            .Configure(gen =>
            {
                gen.SetIssuerDN(PrincipalUtilities.GetSubjectX509Principal(issuer));
                gen.SetThisUpdate(updateAt.UtcDateTime);
                gen.SetNextUpdate(nextUpdateAt.UtcDateTime);

                gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                    new AuthorityKeyIdentifierStructure(issuer));
                gen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(crlNumber));
                gen.AddExtension(X509Extensions.IssuingDistributionPoint, critical: false,
                    new IssuingDistributionPoint(
                        distributionPoint: new DistributionPointName(
                            new GeneralNames(new GeneralName(issuer.SubjectDN))
                        ),
                        // only include end entity public key cerrtificates.
                        onlyContainsAttributeCerts: false,
                        // only include CA cerrtificates.
                        onlyContainsCACerts: false,
                        onlySomeReasons: null,
                        // only include certificates issued by the CRL issuer.
                        indirectCRL: true,
                        onlyContainsUserCerts: false
                    ));

                configureAction?.Invoke(gen);
            })
            .Generate(CreateSignatureFactory(issuerKeyPair.Private));

        return crl;
    }


    private static ISignatureFactory CreateSignatureFactory(AsymmetricKeyParameter key)
    {
        return key switch
        {
            RsaKeyParameters _ => new Asn1SignatureFactory("SHA256WithRSA", key),
            ECKeyParameters _ => new Asn1SignatureFactory("SHA256WithECDSA", key),
            Ed25519PrivateKeyParameters => new Asn1SignatureFactory("Ed25519", key),
            _ => throw new NotSupportedException($"{key}"),
        };
    }

}
