using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Tests.X509.Revocations;

public class OcspFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        await _certs.InitializeAsync();
        (SignerKeyPair, SignerCert) = InitializeCert(_certs.IntermediateCaCertificate,
                _certs.IntermediateCaKeyPair!, DateTimeOffset.UtcNow);
    }

    public async ValueTask DisposeAsync()
    {
        await _certs.DisposeAsync();
        GC.SuppressFinalize(this);
    }

    private readonly EcdsaCertificateChainOpenSslFixture _certs = new(includePrivateKeys: true);
    public X509Certificate IssuerCert => _certs.IntermediateCaCertificate;
    public AsymmetricCipherKeyPair IssuerKeyPair => _certs.IntermediateCaKeyPair!;
    public X509Certificate TargetCert => _certs.EndEntityCertificate;
    public AsymmetricCipherKeyPair SignerKeyPair { get; private set; } = default!;
    public X509Certificate SignerCert { get; private set; } = default!;

    public byte[] CreateOcspRequest() => CreateUnsignedOcspRequest(IssuerCert, TargetCert).GetEncoded();

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
                gen.SetSubjectDN(new X509Name("C=JP,CN=Test Certificate for OCSP"));
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
                     critical: false,
                     new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
                gen.AddExtension(X509Extensions.CrlDistributionPoints,
                    critical: true,
                    new KeyUsage(KeyUsage.DigitalSignature));
            })
            .Generate(issuerKey.Private.CreateDefaultSignature());

        return (keyPair, cert);
    }

    private static OcspReq CreateUnsignedOcspRequest(X509Certificate issuerCert, X509Certificate targetCert)
    {
        CertificateID id = new(CertificateID.DigestSha1, issuerCert, targetCert.SerialNumber);

        OcspReqGenerator gen = new OcspReqGenerator();
        gen.AddRequest(id);

        byte[] nonce = new byte[16];
        new Random().NextBytes(nonce);
        gen.AddNonce(nonce);

        return gen.Generate();
    }
}
