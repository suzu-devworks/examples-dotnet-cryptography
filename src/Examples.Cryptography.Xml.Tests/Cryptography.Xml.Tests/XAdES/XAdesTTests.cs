using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.Tests.XAdES.Fixtures;
using Examples.Cryptography.Xml.XAdES.SchemaBased;

namespace Examples.Cryptography.Tests.Xml.XAdES;

/// <summary>
/// Demonstrates creation and verification of XAdES-T signatures.
/// XAdES-T (Electronic Signature with Time) extends XAdES-BES by adding
/// a SignatureTimeStamp in UnsignedSignatureProperties, proving the time
/// of signing via a trusted timestamp authority (TSA).
/// </summary>
public class XAdesTTests(XAdESFixture fixture)
    : IClassFixture<XAdESFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private readonly DateTime _signingTime = DateTime.UtcNow;

    [Fact]
    public void When_CreatingXAdesT_Then_SignatureTimeStampAddedToUnsignedProperties()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        // Build XAdES-T: BES + SignatureTimeStamp
        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}{signed.ToFormattedString()}{Environment.NewLine}");

        // Verify XML signature (must remain valid even with UnsignedProperties added)
        var signatureValid = signed.VerifySignature(signer);
        Assert.True(signatureValid, "XAdES-T signature must be valid.");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // UnsignedProperties must be present
        var unsignedPropsNode = signed.SelectSingleNode("//xa:UnsignedProperties", nsManager);
        Assert.NotNull(unsignedPropsNode);

        // UnsignedSignatureProperties must contain SignatureTimeStamp
        var tsList = signed.SelectNodes("//xa:UnsignedSignatureProperties/xa:SignatureTimeStamp", nsManager);
        Assert.NotNull(tsList);
        Assert.True(tsList.Count >= 1, "At least one SignatureTimeStamp must be present.");

        // Each SignatureTimeStamp must contain an EncapsulatedTimeStamp
        var encapsulatedTs = signed.SelectSingleNode(
            "//xa:SignatureTimeStamp/xa:EncapsulatedTimeStamp", nsManager);
        Assert.NotNull(encapsulatedTs);
        Assert.NotEmpty(encapsulatedTs.InnerText);
    }

    [Fact]
    public void When_CreatingXAdesT_Then_SignedPropertiesArePreserved()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // SignedProperties (from BES) must still be present
        var signingTimeNode = signed.SelectSingleNode("//xa:SigningTime", nsManager);
        Assert.NotNull(signingTimeNode);

        var signingCertNode = signed.SelectSingleNode("//xa:SigningCertificateV2", nsManager);
        Assert.NotNull(signingCertNode);
    }
}
