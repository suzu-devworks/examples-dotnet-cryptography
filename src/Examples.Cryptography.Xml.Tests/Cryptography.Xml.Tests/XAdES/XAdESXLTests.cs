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
}
