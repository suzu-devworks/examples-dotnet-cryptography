using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Store;

using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Examples.Cryptography.Tests.BouncyCastle.X509Certificates;

public class X509ChainTests
{
    private readonly ITestOutputHelper _output;

    public X509ChainTests(ITestOutputHelper output)
    {
        /// ```
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;
    }

    // https://datatracker.ietf.org/doc/html/rfc5280

    [Fact]
    public void WhenCallingBuild_ReturnsNestedPath()
    {
        // ### Arrange. ###
        // Prepare a chain with multiple intermediate CAs
        var certs = X509CertificateTestDataGenerator.CreateChainCertificates(
                numOfCerts: 4,
                DateTimeOffset.UtcNow,
                new X509Name("C=JP,CN=localhost")
                ).ToArray();
        var (_, root) = certs.FirstOrDefault();
        var (_, ee) = certs.LastOrDefault();

        // Search for the target certificate by subject of ee.
        var selector = new X509CertStoreSelector
        {
            Subject = ee.SubjectDN
        };

        var trustanchors = new HashSet<TrustAnchor>
        {
            new(root, null)
        };

        IStore<X509Certificate> x509CertStore
            = CollectionUtilities.CreateStore(certs.Select(x => x.Item2));

        // ### Act. ###
        var parameters = new PkixBuilderParameters(trustanchors, selector)
        {
            IsRevocationEnabled = false
        };
        parameters.AddStoreCert(x509CertStore);

        var builder = new PkixCertPathBuilder();

        PkixCertPathBuilderResult result = builder.Build(parameters);

        // ### Assert. ###
        // `CertPath` stores the certificates included in the chain from ee to root CA.
        //  However, root (TrustAnchor) is not included.
        result.CertPath.Certificates.Count.Is(4 - 1);
        result.CertPath.Certificates[0].SubjectDN.ToString().Is("C=JP,CN=localhost");
        result.CertPath.Certificates[1].SubjectDN.ToString().Is("C=JP,CN=Test CA-0002");
        result.CertPath.Certificates[2].SubjectDN.ToString().Is("C=JP,CN=Test CA-0001");
        result.PolicyTree.IsNull();
        result.SubjectPublicKey.Is(ee.GetPublicKey());
        result.TrustAnchor.TrustedCert.Is(root);

        // dump certificates.
        foreach (var (cert, i) in result.CertPath.Certificates.Select((x, i) => (x, i)))
        {
            _output.WriteLine($"# CertPath.Certificates[{i}]:");
            _output.WriteLine(cert.ToString());
        }

        return;
    }


}
