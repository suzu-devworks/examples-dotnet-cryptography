using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Examples.Cryptography.Xml.Tests.Fixtures.OpenSsl;

namespace Examples.Cryptography.Xml.Tests.XAdES.Fixtures;

/// <summary>
/// Shared fixture for XAdES tests.
/// Loads the RSA signer certificate and its CA chain from OpenSSL-generated files,
/// and provides helper data for building XAdES-C/X-L/A level signatures.
/// </summary>
public sealed class XAdESFixture : IAsyncLifetime
{
    private readonly RsaSignerCertificateChainOpenSslFixture _rsaChainFixture =
        new(includePrivateKeys: true);

    /// <summary>Gets the RSA signer certificate (with private key).</summary>
    public X509Certificate2 Signer => _rsaChainFixture.SinnerCertificate;

    /// <summary>Gets the intermediate CA certificate.</summary>
    public X509Certificate2 IntermediateCa => _rsaChainFixture.IntermediateCaCertificate;

    /// <summary>Gets the root CA certificate.</summary>
    public X509Certificate2 RootCa => _rsaChainFixture.RootCaCertificate;

    /// <summary>
    /// Gets the CA certificate chain (intermediate + root) used in XAdES-C and above.
    /// The signer's own certificate is excluded because it is already referenced
    /// in the SignedProperties/SigningCertificateV2 element.
    /// </summary>
    public X509Certificate2Collection CertChain
    {
        get
        {
            var chain = new X509Certificate2Collection();
            chain.Add(IntermediateCa);
            chain.Add(RootCa);
            return chain;
        }
    }

    /// <summary>
    /// Gets a mock TSA client that returns a fake timestamp token.
    /// Suitable for structural tests that do not validate the TSP response content.
    /// </summary>
    public MockTsaClient TsaClient { get; } = new MockTsaClient();

    /// <summary>
    /// Gets mock CRL data (minimal DER-encoded CRL bytes) for XAdES-C / X-L tests.
    /// Real implementations would obtain actual CRLs from the CA's distribution point.
    /// </summary>
    public IReadOnlyList<(byte[] CrlData, string Issuer, DateTime IssueTime)> RevocationRefs =>
    [
        // Mock CRL for the intermediate CA
        (
            CrlData: new byte[] { 0x30, 0x00 },
            Issuer: IntermediateCa.Issuer,
            IssueTime: DateTime.UtcNow.AddDays(-1)
        ),
        // Mock CRL for the root CA
        (
            CrlData: new byte[] { 0x30, 0x00 },
            Issuer: RootCa.Issuer,
            IssueTime: DateTime.UtcNow.AddDays(-1)
        ),
    ];

    /// <summary>
    /// Gets mock CRL DER values for XAdES-X-L tests.
    /// </summary>
    public IReadOnlyList<byte[]> RevocationValues =>
    [
        new byte[] { 0x30, 0x00 }, // Mock CRL for intermediate CA
        new byte[] { 0x30, 0x00 }, // Mock CRL for root CA
    ];

    /// <summary>
    /// Creates a sample XML document to be signed in tests.
    /// </summary>
    public static XmlDocument CreateSampleDocument()
    {
        var xdom = new XElement("Document",
            new XElement("Branch",
                new XElement("Leaf",
                    new XAttribute("Id", "id-target"),
                    new XText("Example text to be signed.")
                ),
                new XElement("Leaf",
                    new XAttribute("Id", "id-non-target"),
                    new XText("Don't sign here.")
                )
            )
        );

        var document = new XmlDocument() { PreserveWhitespace = false };
        document.LoadXml(xdom.ToString());
        return document;
    }

    /// <inheritdoc/>
    public async ValueTask InitializeAsync()
    {
        await _rsaChainFixture.InitializeAsync();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _rsaChainFixture.DisposeAsync();
        GC.SuppressFinalize(this);
    }
}
