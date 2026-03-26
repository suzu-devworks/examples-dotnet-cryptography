using Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Store;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Examples.Cryptography.BouncyCastle.Tests.X509;

/// <summary>
/// Tests for building a certificate path (chain) from an end-entity certificate to a trust anchor (root CA) using BouncyCastle's PKIX implementation.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280"/>
public class X509ChainTests(
    X509ChainTests.Fixture fixture
    ) : IClassFixture<X509ChainTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await CertChain.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await CertChain.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        private EcdsaCertificateChainOpenSslFixture CertChain { get; } = new(includePrivateKeys: true);

        public X509Certificate RootCaCertificate => CertChain.RootCaCertificate;
        public X509Certificate IntermediateCaCertificate => CertChain.IntermediateCaCertificate;
        public X509Certificate EndEntityCertificate => CertChain.EndEntityCertificate;
    }

    [Fact]
    public void When_BuildingCertificatePath_Then_ReachingTheTrustAnchor()
    {
        var root = fixture.RootCaCertificate;
        var ca = fixture.IntermediateCaCertificate;
        var target = fixture.EndEntityCertificate;

        // Prepare a chain with multiple intermediate CAs
        var certs = new[] { root, ca, target };

        // Search for the target certificate by subject of ee.
        var selector = new X509CertStoreSelector
        {
            Subject = target.SubjectDN
        };

        // Set the trust anchor (root CA).
        var trustAnchors = new HashSet<TrustAnchor>
        {
            new(root, null)
        };

        IStore<X509Certificate> x509CertStore = CollectionUtilities.CreateStore(certs);

        var parameters = new PkixBuilderParameters(trustAnchors, selector)
        {
            IsRevocationEnabled = false
        };
        parameters.AddStoreCert(x509CertStore);

        var builder = new PkixCertPathBuilder();

        PkixCertPathBuilderResult result = builder.Build(parameters);

        // Assert:

        // `CertPath` stores the certificates included in the chain from target certificate to root CA.
        //  However, root (TrustAnchor) is not included.
        Assert.NotNull(result);
        Assert.NotNull(result.CertPath);
        Assert.Collection(result.CertPath.Certificates,
            cert =>
            {
                Assert.Equal(target.SubjectDN, cert.SubjectDN);
            },
            cert =>
            {
                Assert.Equal(ca.SubjectDN, cert.SubjectDN);
            });
        Assert.Null(result.PolicyTree);
        Assert.Equal(target.GetPublicKey(), result.SubjectPublicKey);
        Assert.Equal(root, result.TrustAnchor.TrustedCert);
    }
}
