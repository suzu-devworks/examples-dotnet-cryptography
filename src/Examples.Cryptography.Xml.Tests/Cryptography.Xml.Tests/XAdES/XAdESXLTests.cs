using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.Tests.XAdES.Fixtures;
using Examples.Cryptography.Xml.XAdES.SchemaBased;

namespace Examples.Cryptography.Tests.Xml.XAdES;

/// <summary>
/// Demonstrates creation and verification of XAdES-X-L signatures.
/// XAdES-X-L (eXtended Long-term) extends XAdES-X by embedding the actual
/// certificate DER values and revocation data (CRLs / OCSP responses) directly
/// into CertificateValues and RevocationValues in UnsignedSignatureProperties.
/// This makes the signature self-contained for long-term verification.
/// </summary>
public class XAdESXLTests(XAdESFixture fixture)
    : IClassFixture<XAdESFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private readonly DateTime _signingTime = DateTime.UtcNow;

    [Fact]
    public void When_CreatingXAdesXL_Then_CertificateValuesAndRevocationValuesAdded()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        // Build XAdES-X-L: T + C (refs) + X (SigAndRefs) + X-L (values)
        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient)
            .WithRevocationValues(fixture.RevocationValues)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}{signed.ToFormattedString()}{Environment.NewLine}");

        // Verify XML signature
        var signatureValid = signed.VerifySignature(signer);

        // Assert:
        Assert.True(signatureValid, "XAdES-X-L signature must be valid.");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // XAdES-C elements must be present
        var certRefsNode = signed.SelectSingleNode("//xa:CompleteCertificateRefs", nsManager);
        Assert.NotNull(certRefsNode);

        var revRefsNode = signed.SelectSingleNode("//xa:CompleteRevocationRefs", nsManager);
        Assert.NotNull(revRefsNode);

        // XAdES-X-L: CertificateValues must be present with embedded X.509 DER data
        var certValuesNode = signed.SelectSingleNode("//xa:CertificateValues", nsManager);
        Assert.NotNull(certValuesNode);

        var encapsulatedCerts = signed.SelectNodes(
            "//xa:CertificateValues/xa:EncapsulatedX509Certificate", nsManager);
        Assert.NotNull(encapsulatedCerts);
        Assert.True(encapsulatedCerts.Count >= 1,
            "CertificateValues must contain at least one EncapsulatedX509Certificate.");

        // XAdES-X-L: RevocationValues must be present with embedded CRL data
        var revValuesNode = signed.SelectSingleNode("//xa:RevocationValues", nsManager);
        Assert.NotNull(revValuesNode);

        var encapsulatedCrls = signed.SelectNodes(
            "//xa:RevocationValues/xa:CRLValues/xa:EncapsulatedCRLValue", nsManager);
        Assert.NotNull(encapsulatedCrls);
        Assert.True(encapsulatedCrls.Count >= 1,
            "RevocationValues must contain at least one EncapsulatedCRLValue.");
    }

    [Fact]
    public void When_CreatingXAdesXL_Then_EmbeddedCertValueMatchesCertChain()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient)
            .WithRevocationValues(fixture.RevocationValues)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // The number of EncapsulatedX509Certificate entries should match the chain length
        var encapsulatedCerts = signed.SelectNodes(
            "//xa:CertificateValues/xa:EncapsulatedX509Certificate", nsManager);
        Assert.NotNull(encapsulatedCerts);
        Assert.Equal(fixture.CertChain.Count, encapsulatedCerts.Count);

        // Each entry must contain base64-encoded DER data
        foreach (XmlNode certNode in encapsulatedCerts)
        {
            var base64 = certNode.InnerText.Trim();
            Assert.NotEmpty(base64);
            var decoded = Convert.FromBase64String(base64);
            Assert.NotEmpty(decoded);
        }
    }

    /// <summary>
    /// XAdES-X-L verification (self-contained): the DER bytes in CertificateValues must
    /// be parseable as X.509 certificates, and their SHA-256 digests must match the
    /// corresponding values in CompleteCertificateRefs.
    /// <para>
    /// This cross-check demonstrates the defining property of XAdES-X-L: the signature
    /// carries everything needed for certificate path validation internally, so a verifier
    /// does not need to contact external LDAP directories or HTTP certificate stores.
    /// </para>
    /// </summary>
    [Fact]
    public void When_VerifyingXAdesXL_Then_EmbeddedCertsAreValidAndMatchCertRefs()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient)
            .WithRevocationValues(fixture.RevocationValues)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");
        nsManager.AddNamespace("ds", System.Security.Cryptography.Xml.SignedXml.XmlDsigNamespaceUrl);

        // Step 1: Extract cert ref digests from CompleteCertificateRefs (C-level).
        var certRefNodes = signed.SelectNodes(
            "//xa:CompleteCertificateRefs/xa:CertRefs/xa:Cert", nsManager);
        Assert.NotNull(certRefNodes);

        var expectedDigests = certRefNodes.Cast<XmlNode>()
            .Select(n =>
            {
                var dv = n.SelectSingleNode("xa:CertDigest/ds:DigestValue", nsManager);
                Assert.NotNull(dv);
                return Convert.FromBase64String(dv.InnerText.Trim());
            })
            .ToList();

        // Step 2: Extract embedded certificate DER bytes from CertificateValues (X-L level).
        var certValueNodes = signed.SelectNodes(
            "//xa:CertificateValues/xa:EncapsulatedX509Certificate", nsManager);
        Assert.NotNull(certValueNodes);
        Assert.Equal(expectedDigests.Count, certValueNodes.Count);

        // Step 3: For each embedded certificate, compute its SHA-256 digest and
        // verify it matches the corresponding reference from CompleteCertificateRefs.
        // This cross-check confirms the X-L data is self-consistent and that a verifier
        // can reconstruct the complete certificate chain purely from the embedded data.
        for (int i = 0; i < certValueNodes.Count; i++)
        {
            var certValueNode = certValueNodes[i];
            Assert.NotNull(certValueNode);
            var base64 = certValueNode.InnerText.Trim();
            var derBytes = Convert.FromBase64String(base64);

            // The DER bytes must be parseable as a valid X.509 certificate.
            using var embeddedCert = X509CertificateLoader.LoadCertificate(derBytes);
            Assert.NotNull(embeddedCert.Subject);

            // The embedded cert's digest must match the C-level certificate reference.
            var embeddedDigest = embeddedCert.GetCertHash(HashAlgorithmName.SHA256);
            Assert.Equal(expectedDigests[i], embeddedDigest);
        }
    }

    /// <summary>
    /// XAdES-X-L verification: the RevocationValues element must contain DER-encoded
    /// CRL data. In a production scenario, each CRL would be parsed to verify the
    /// signing certificate has not been revoked at the time of signing.
    /// The presence of embedded CRL data ensures offline revocation checking is possible.
    /// </summary>
    [Fact]
    public void When_VerifyingXAdesXL_Then_RevocationValuesAreEmbeddedForOfflineCheck()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient)
            .WithRevocationValues(fixture.RevocationValues)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // RevocationValues must contain the same number of CRLs as RevocationRefs.
        var crlValueNodes = signed.SelectNodes(
            "//xa:RevocationValues/xa:CRLValues/xa:EncapsulatedCRLValue", nsManager);
        Assert.NotNull(crlValueNodes);
        Assert.Equal(fixture.RevocationValues.Count, crlValueNodes.Count);

        // Each embedded CRL must be non-empty DER data that can be base64-decoded.
        // (Real CRLs would be verified with X509Crl; here only structural presence is checked.)
        foreach (XmlNode crlNode in crlValueNodes)
        {
            var base64 = crlNode.InnerText.Trim();
            Assert.NotEmpty(base64);
            var derBytes = Convert.FromBase64String(base64);
            Assert.NotEmpty(derBytes);
        }
    }
}
