using System.Text;
using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.PKIX;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Tests.PKIX;

public class TimeStampDataFixture : IDisposable
{
    public TimeStampDataFixture()
    {
        // ... lazy initialize data ...
        var notBefore = DateTimeOffset.Now.AddSeconds(-50);

        _caSet = new(() => InitializeCaSets(notBefore));
        _tsaSet = new(() => InitializeTsaSets(notBefore));
        _ocspSignerSet = new(() => InitializeOCSPSignerSets(notBefore));

        _caCrl = new(() => InitializeCaCrl(DateTimeOffset.Now));
        _caOcspResp = new(() => InitializeOcspResp(DateTimeOffset.Now));
        _timeStampResponse = new(() => InitializeTimeStampResponse(DateTimeOffset.Now.AddSeconds(10)));
    }

    public (AsymmetricCipherKeyPair, X509Certificate) CaSet => _caSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _caSet;

    public (AsymmetricCipherKeyPair, X509Certificate) TsaSet => _tsaSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _tsaSet;

    public (AsymmetricCipherKeyPair, X509Certificate) OcspSignerSet => _ocspSignerSet.Value;
    private readonly Lazy<(AsymmetricCipherKeyPair, X509Certificate)> _ocspSignerSet;

    public TimeStampResponse TimeStampResponse => _timeStampResponse.Value;
    private readonly Lazy<TimeStampResponse> _timeStampResponse;

    public X509Crl CaCrl => _caCrl.Value;
    private readonly Lazy<X509Crl> _caCrl;

    public OcspResp CaOcspResp => _caOcspResp.Value;
    private readonly Lazy<OcspResp> _caOcspResp;


    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }


    private static (AsymmetricCipherKeyPair, X509Certificate) InitializeCaSets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var keyPair = GeneratorUtilities.GetKeyPairGenerator("Ed25519")
          .ConfigureDefault()
          .GenerateKeyPair();

        var cert = new X509V3CertificateGenerator()
            .WithRootCA(
                keyPair.Public,
                new X509Name("C=JP,CN=Test CA root for TSA"))
            .SetValidity(notBefore.UtcDateTime, days)
            .Generate(keyPair.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }


    private (AsymmetricCipherKeyPair, X509Certificate) InitializeTsaSets(
         DateTimeOffset notBefore,
        int days = 365)
    {
        var (issuerKeyPair, issuerCert) = CaSet;

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
          .ConfigureDefault()
          .GenerateKeyPair();

        var random = new SecureRandom();
        var serial = BigInteger.ValueOf(random.NextInt64(100L, int.MaxValue));

        var cert = new X509V3CertificateGenerator()
            .WithEndEntity(
                keyPair.Public,
                subject: new X509Name("C=JP,CN=Test TSA"),
                issuerCert,
                serial)
            .SetValidity(notBefore.UtcDateTime, days)
            .Configure(gen =>
            {
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
            .Generate(issuerKeyPair.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }


    private (AsymmetricCipherKeyPair, X509Certificate) InitializeOCSPSignerSets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var (issuerKeyPair, issuerCert) = CaSet;

        var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
          .ConfigureDefault()
          .GenerateKeyPair();

        var random = new SecureRandom();
        var serial = BigInteger.ValueOf(random.NextInt64(200L, int.MaxValue));

        var cert = new X509V3CertificateGenerator()
            .WithEndEntity(
                keyPair.Public,
                subject: new X509Name("C=JP,CN=Test TSA"),
                issuerCert,
                serial)
            .SetValidity(notBefore.UtcDateTime, days)
            .Configure(gen =>
            {
                gen.AddExtension(X509Extensions.KeyUsage,
                    critical: true,
                    new KeyUsage(KeyUsage.DigitalSignature));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage,
                    critical: true,
                    new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
            })
           .Generate(issuerKeyPair.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }


    private X509Crl InitializeCaCrl(
        DateTimeOffset updateAt,
        int days = 2)
    {
        var (issuerKeyPair, issuerCert) = CaSet;

        var nextUpdateAt = updateAt.AddDays(days);
        var crlNumber = BigInteger.One;

        var crl = new X509V2CrlGenerator()
            .Configure(gen =>
            {
                gen.SetIssuerDN(PrincipalUtilities.GetSubjectX509Principal(issuerCert));
                gen.SetThisUpdate(updateAt.UtcDateTime);
                gen.SetNextUpdate(nextUpdateAt.UtcDateTime);

                gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                    new AuthorityKeyIdentifierStructure(issuerCert));
                gen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(crlNumber));
                gen.AddExtension(X509Extensions.IssuingDistributionPoint, critical: false,
                    new IssuingDistributionPoint(
                        distributionPoint: new DistributionPointName(
                            new GeneralNames(new GeneralName(issuerCert.SubjectDN))
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

                gen.AddCrlEntry(BigInteger.One, updateAt.UtcDateTime, CrlReason.KeyCompromise);
                gen.AddCrlEntry(BigInteger.Two, updateAt.UtcDateTime, CrlReason.PrivilegeWithdrawn);
            })
            .Generate(issuerKeyPair.Private.CreateDefaultSignature());

        return crl;
    }


    private OcspResp InitializeOcspResp(DateTimeOffset now)
    {
        var (_, caCert) = CaSet;
        var (_, tsaCert) = TsaSet;
        var (signerKeyPair, signerCert) = OcspSignerSet;

        var id = new CertificateID(CertificateID.HashSha1, caCert, tsaCert.SerialNumber);
        var nonceValue = new DerOctetString(
            new DerOctetString(BigInteger.One.ToByteArray()));
        var values = new Dictionary<DerObjectIdentifier, X509Extension>
            {
                { OcspObjectIdentifiers.PkixOcspNonce, new X509Extension(critical: false, nonceValue) }
            };

        var respGen = new BasicOcspRespGenerator(new RespID(signerCert.SubjectDN));
        respGen.AddResponse(id, CertificateStatus.Good);
        respGen.SetResponseExtensions(new X509Extensions(values));

        var basic = respGen.Generate("SHA512withECDSA",
            signerKeyPair.Private,
            chain: new[] { signerCert },
            thisUpdate: now.UtcDateTime);

        var generator = new OCSPRespGenerator();
        var response = generator.Generate(OCSPRespGenerator.Successful, basic);

        return response;
    }


    private TimeStampResponse InitializeTimeStampResponse(DateTimeOffset now)
    {
        var (_, caCert) = CaSet;
        var (tsaKeyPair, tsaCert) = TsaSet;

        var data = Encoding.UTF8.GetBytes("TEST MESSAGE PHRASE");
        var algorithm = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
        var digest = DigestUtilities.CalculateDigest(algorithm.Algorithm, data);
        var message = new MessageImprint(algorithm, digest);

        var generator = new TimeStampTokenGenerator(
                key: tsaKeyPair.Private,
                cert: tsaCert,
                digestOID: NistObjectIdentifiers.IdSha512.Id,
                tsaPolicyOID: "1.2.3.4.5")
            .Configure(gen =>
            {
                var store = CollectionUtilities.CreateStore(new[] { tsaCert, caCert });
                gen.SetCertificates(store);
            });

        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(true);
        var request = requestGenerator.Generate(
            digestAlgorithmOid: message.HashAlgorithm.Algorithm.Id,
            digest: message.GetHashedMessage(),
            nonce: BigInteger.One);

        var responseGenerator = new TimeStampResponseGenerator(generator, TspAlgorithms.Allowed);
        var response = responseGenerator.Generate(request, BigInteger.One, genTime: now.UtcDateTime);

        return response;
    }


}

