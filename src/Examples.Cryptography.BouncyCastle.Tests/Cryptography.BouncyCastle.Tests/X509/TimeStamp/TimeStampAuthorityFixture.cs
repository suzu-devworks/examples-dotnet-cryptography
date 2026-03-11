using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Tests.X509.TimeStamp;

public class TimeStampAuthorityFixture : IAsyncLifetime
{
    public TimeStampAuthorityFixture()
    {
        // ... lazy initialize data ...
        var notBefore = DateTimeOffset.UtcNow.AddSeconds(-50);

        (TsaSignerPrivateKey, TsaSignerCertificate) = InitializeSigner(notBefore);
        (TsaPrivateKey, TsaCertificate) = InitializeTsa(notBefore);
        TsaSignerCrl = InitializeCrl(DateTimeOffset.UtcNow);
    }

    public ValueTask InitializeAsync()
    {
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public AsymmetricCipherKeyPair TsaSignerPrivateKey { get; internal set; }
    public X509Certificate TsaSignerCertificate { get; internal set; }
    public AsymmetricCipherKeyPair TsaPrivateKey { get; internal set; }
    public X509Certificate TsaCertificate { get; internal set; }
    public X509Crl TsaSignerCrl { get; internal set; }

    private static (AsymmetricCipherKeyPair, X509Certificate) InitializeSigner(
        DateTimeOffset notBefore,
        int days = 1)
    {
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
          .ConfigureEd25519Key()
          .GenerateKeyPair();

        var cert = new X509V3CertificateGenerator()
            .Configure(gen =>
            {
                gen.SetSerialNumber(BigInteger.One);
                gen.SetNotBefore(notBefore.UtcDateTime);
                gen.SetNotAfter(notBefore.AddDays(days).UtcDateTime);

                var subject = new X509Name("C=JP,CN=Test CA root for TSA");
                gen.SetIssuerDN(subject);
                gen.SetSubjectDN(subject);
                gen.SetPublicKey(keyPair.Public);

                gen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                    critical: false,
                    X509ExtensionUtilities.CreateAuthorityKeyIdentifier(keyPair.Public));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier,
                    critical: false,
                    X509ExtensionUtilities.CreateSubjectKeyIdentifier(keyPair.Public));
                gen.AddExtension(X509Extensions.BasicConstraints,
                    critical: true,
                    new BasicConstraints(cA: true));
            })
            .Generate(keyPair.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }

    private (AsymmetricCipherKeyPair, X509Certificate) InitializeTsa(
         DateTimeOffset notBefore,
        int days = 1)
    {
        var issuerCert = TsaSignerCertificate;
        var issuerKey = TsaSignerPrivateKey;

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
          .ConfigureECParameter(CustomNamedCurves.GetByName("P-256"))
          .GenerateKeyPair();

        var cert = new X509V3CertificateGenerator()
            .Configure(gen =>
            {
                var random = new SecureRandom();
                var serial = BigInteger.ValueOf(random.NextInt64(100L, int.MaxValue));

                gen.SetSerialNumber(serial);
                gen.SetNotBefore(notBefore.UtcDateTime);
                gen.SetNotAfter(notBefore.AddDays(days).UtcDateTime);

                gen.SetIssuerDN(issuerCert.SubjectDN);
                gen.SetSubjectDN(new X509Name("C=JP,CN=Test TSA"));
                gen.SetPublicKey(keyPair.Public);

                gen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                    critical: false,
                    X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuerCert.GetPublicKey()));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier,
                    critical: false,
                    X509ExtensionUtilities.CreateSubjectKeyIdentifier(keyPair.Public));
                gen.AddExtension(X509Extensions.BasicConstraints,
                    critical: true,
                    new BasicConstraints(cA: false));
                gen.AddExtension(X509Extensions.KeyUsage,
                    critical: true,
                    new KeyUsage(KeyUsage.DigitalSignature));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage,
                    critical: true,
                    new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
                gen.AddExtension(X509Extensions.AuthorityInfoAccess,
                    critical: false,
                    new AuthorityInformationAccess(
                        new AccessDescription[] {
                            new(AccessDescription.IdADCAIssuers,
                                new GeneralName(
                                    GeneralName.UniformResourceIdentifier,
                                    "https://localhost:1234/ca.crt")),
                            new(AccessDescription.IdADOcsp,
                                new GeneralName(
                                    GeneralName.UniformResourceIdentifier,
                                    "https://localhost:1234/ocsp"))
                         }));
                gen.AddExtension(X509Extensions.CrlDistributionPoints,
                    critical: false,
                    new CrlDistPoint(
                        new DistributionPoint[] {
                            new(new DistributionPointName(
                                new GeneralNames(
                                    new GeneralName(
                                        GeneralName.UniformResourceIdentifier,
                                        "https://localhost:1234/ca.crl")
                                )), reasons: null, crlIssuer: null),
                        }));
            })
            .Generate(issuerKey.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }

    private X509Crl InitializeCrl(
        DateTimeOffset updateAt,
        int days = 1)
    {
        var issuerCert = TsaSignerCertificate;
        var issuerKey = TsaSignerPrivateKey;

        var nextUpdateAt = updateAt.AddDays(days);
        var crlNumber = BigInteger.One;

        var crl = new X509V2CrlGenerator()
            .Configure(gen =>
            {
                gen.SetIssuerDN(issuerCert.SubjectDN);
                gen.SetThisUpdate(updateAt.UtcDateTime);
                gen.SetNextUpdate(nextUpdateAt.UtcDateTime);

                gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                    X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuerCert));
                gen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(crlNumber));
                gen.AddExtension(X509Extensions.IssuingDistributionPoint, critical: false,
                    new IssuingDistributionPoint(
                        distributionPoint: new DistributionPointName(
                            new GeneralNames(new GeneralName(issuerCert.SubjectDN))
                        ),
                        // only include end entity public key certificates.
                        onlyContainsAttributeCerts: false,
                        // only include CA certificates.
                        onlyContainsCACerts: false,
                        onlySomeReasons: null,
                        // only include certificates issued by the CRL issuer.
                        indirectCRL: true,
                        onlyContainsUserCerts: false
                    ));

                gen.AddCrlEntry(BigInteger.One, updateAt.UtcDateTime, CrlReason.KeyCompromise);
                gen.AddCrlEntry(BigInteger.Two, updateAt.UtcDateTime, CrlReason.PrivilegeWithdrawn);
            })
            .Generate(issuerKey.Private.CreateDefaultSignature());

        return crl;
    }
}

