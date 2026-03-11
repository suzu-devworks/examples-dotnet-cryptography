using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Tests.X509.Revocations;

/// <summary>
/// Tests for creating X509 CRL (Certificate Revocation List).
/// </summary>
/// <param name="fixture"></param>
public class X509CrlTests(
    X509CrlTests.Fixture fixture
    ) : IClassFixture<X509CrlTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await _ca.InitializeAsync();
            (_, RevocationCert) = InitializeCert(IssuerCert, IssuerKey, DateTimeOffset.UtcNow);
        }

        public async ValueTask DisposeAsync()
        {
            await _ca.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        private readonly CaCertificatesOpenSslFixture _ca = new(includePrivateKeys: true);

        public X509Certificate IssuerCert => _ca.IntermediateCaCertificate;
        public AsymmetricCipherKeyPair IssuerKey => _ca.IntermediateCaPrivateKey!;

        public X509Certificate RevocationCert { get; private set; } = default!;

        private (AsymmetricCipherKeyPair, X509Certificate) InitializeCert(
            X509Certificate issuerCert,
            AsymmetricCipherKeyPair issuerKey,
            DateTimeOffset notBefore,
            int days = 1)
        {
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
                    gen.SetSubjectDN(new X509Name("C=JP,CN=Test Certificate for CRL"));
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
                })
                .Generate(issuerKey.Private.CreateDefaultSignature());

            return (keyPair, cert);
        }
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private X509Crl CreateCrl(
        X509Certificate revocationCert,
        X509Certificate issuerCert,
        AsymmetricCipherKeyPair issuerKey,
        DateTimeOffset updateAt,
        int days = 1)
    {
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

                gen.AddCrlEntry(revocationCert.SerialNumber, updateAt.UtcDateTime, CrlReason.CessationOfOperation);
            })
            .Generate(issuerKey.Private.CreateDefaultSignature());

        return crl;
    }

    [Fact]
    public void When_CreatingCrl_Then_ContainsRevokedCertificatesAndValidSignature()
    {
        var now = DateTimeOffset.UtcNow;
        var revocationCert = fixture.RevocationCert;
        var issuerCert = fixture.IssuerCert;
        var issuerKey = fixture.IssuerKey;

        X509Crl crl = CreateCrl(revocationCert, issuerCert, issuerKey, now);
        Output?.WriteLine($"CRL:\n{crl}");

        // The CRL is signed by the issuer.
        crl.Verify(issuerKey.Public);
        var isValid = crl.IsSignatureValid(issuerKey.Public);

        // The CRL contains the revoked certificate.
        var revoked = crl.IsRevoked(revocationCert);
        var nonRevoked = crl.IsRevoked(issuerCert);

        // Assert:

        Assert.True(isValid);
        Assert.True(revoked);
        Assert.False(nonRevoked);

        Assert.Equal(2, crl.Version);
        Assert.Equal(issuerCert.SubjectDN.ToString(), crl.IssuerDN.ToString());
        Assert.Equal(now.DateTime.Date, crl.ThisUpdate.Date);
        Assert.Equal(now.AddDays(1).DateTime.Date, crl.NextUpdate?.Date);

        Assert.Equal("SHA-256withECDSA", crl.SigAlgName);
        Assert.Equal("1.2.840.10045.4.3.2", crl.SigAlgOid);
        Assert.Equal("1.2.840.10045.4.3.2", crl.SignatureAlgorithm.Algorithm.Id);

        Assert.Empty(crl.GetCriticalExtensionOids());
        Assert.Collection(crl.GetNonCriticalExtensionOids(),
            oid => Assert.Equal(X509Extensions.AuthorityKeyIdentifier.Id, oid),
            oid => Assert.Equal(X509Extensions.CrlNumber.Id, oid),
            oid => Assert.Equal(X509Extensions.IssuingDistributionPoint.Id, oid)
        );
        var number = Assert.IsType<DerInteger>(
            crl.GetExtensionParsedValue(X509Extensions.CrlNumber));
        Assert.Equal(BigInteger.One, number.Value);

        Assert.Collection(crl.GetRevokedCertificates(),
            entry =>
            {
                Assert.Equal(BigInteger.One, entry.SerialNumber);
                var reasonCode = DerEnumerated.GetInstance(entry.GetExtensionParsedValue(X509Extensions.ReasonCode));
                Assert.Equal(CrlReason.KeyCompromise, reasonCode.IntValueExact);
            },
            entry =>
            {
                Assert.Equal(BigInteger.Two, entry.SerialNumber);
                var reasonCode = DerEnumerated.GetInstance(entry.GetExtensionParsedValue(X509Extensions.ReasonCode));
                Assert.Equal(CrlReason.PrivilegeWithdrawn, reasonCode.IntValueExact);
            },
            entry =>
            {
                Assert.Equal(revocationCert.SerialNumber, entry.SerialNumber);
                var reasonCode = DerEnumerated.GetInstance(entry.GetExtensionParsedValue(X509Extensions.ReasonCode));
                Assert.Equal(CrlReason.CessationOfOperation, reasonCode.IntValueExact);
            }
        );
    }

}
