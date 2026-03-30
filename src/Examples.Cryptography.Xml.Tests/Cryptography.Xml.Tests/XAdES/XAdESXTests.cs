using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.Tests.XAdES.Fixtures;
using Examples.Cryptography.Xml.XAdES.SchemaBased;

namespace Examples.Cryptography.Tests.Xml.XAdES;

/// <summary>
/// Demonstrates creation and verification of XAdES-X signatures.
/// XAdES-X (eXtended Electronic Signature) extends XAdES-C by adding an additional
/// timestamp over the references, protecting the long-term integrity of XAdES-C data.
/// Two types are defined:
/// <list type="bullet">
///   <item>
///     <description>
///       Type 1: <c>SigAndRefsTimeStamp</c> — timestamps the SignatureValue together
///       with the complete-refs elements.
///     </description>
///   </item>
///   <item>
///     <description>
///       Type 2: <c>RefsOnlyTimeStamp</c> — timestamps only the complete-refs elements.
///     </description>
///   </item>
/// </list>
/// </summary>
public class XAdESXTests(XAdESFixture fixture)
    : IClassFixture<XAdESFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private readonly DateTime _signingTime = DateTime.UtcNow;

    [Fact]
    public void When_CreatingXAdesX_Type1_Then_SigAndRefsTimeStampAdded()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        // Build XAdES-X Type 1: T + C + SigAndRefsTimeStamp
        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient, refsOnly: false)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}{signed.ToFormattedString()}{Environment.NewLine}");

        // Verify XML signature
        var signatureValid = signed.VerifySignature(signer);
        Assert.True(signatureValid, "XAdES-X Type 1 signature must be valid.");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // XAdES-T: SignatureTimeStamp must be present
        var sigTs = signed.SelectSingleNode("//xa:SignatureTimeStamp", nsManager);
        Assert.NotNull(sigTs);

        // XAdES-C: CompleteCertificateRefs and CompleteRevocationRefs must be present
        var certRefsNode = signed.SelectSingleNode("//xa:CompleteCertificateRefs", nsManager);
        Assert.NotNull(certRefsNode);

        var revRefsNode = signed.SelectSingleNode("//xa:CompleteRevocationRefs", nsManager);
        Assert.NotNull(revRefsNode);

        // XAdES-X Type 1: SigAndRefsTimeStamp must be present
        var sigAndRefsTs = signed.SelectNodes("//xa:SigAndRefsTimeStamp", nsManager);
        Assert.NotNull(sigAndRefsTs);
        Assert.True(sigAndRefsTs.Count >= 1, "At least one SigAndRefsTimeStamp must be present.");

        var encapsulatedTs = signed.SelectSingleNode(
            "//xa:SigAndRefsTimeStamp/xa:EncapsulatedTimeStamp", nsManager);
        Assert.NotNull(encapsulatedTs);
        var tsBase64 = encapsulatedTs.InnerText.Trim();
        Assert.NotEmpty(tsBase64);
        Assert.NotEmpty(Convert.FromBase64String(tsBase64));

        // RefsOnlyTimeStamp must NOT be present for Type 1
        var refsOnlyTs = signed.SelectSingleNode("//xa:RefsOnlyTimeStamp", nsManager);
        Assert.Null(refsOnlyTs);
    }

    [Fact]
    public void When_CreatingXAdesX_Type2_Then_RefsOnlyTimeStampAdded()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        // Build XAdES-X Type 2: T + C + RefsOnlyTimeStamp
        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient, refsOnly: true)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}{signed.ToFormattedString()}{Environment.NewLine}");

        // Verify XML signature
        var signatureValid = signed.VerifySignature(signer);
        Assert.True(signatureValid, "XAdES-X Type 2 signature must be valid.");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // XAdES-X Type 2: RefsOnlyTimeStamp must be present
        var refsOnlyTs = signed.SelectNodes("//xa:RefsOnlyTimeStamp", nsManager);
        Assert.NotNull(refsOnlyTs);
        Assert.True(refsOnlyTs.Count >= 1, "At least one RefsOnlyTimeStamp must be present.");

        var encapsulatedTs = signed.SelectSingleNode(
            "//xa:RefsOnlyTimeStamp/xa:EncapsulatedTimeStamp", nsManager);
        Assert.NotNull(encapsulatedTs);
        var tsBase64 = encapsulatedTs.InnerText.Trim();
        Assert.NotEmpty(tsBase64);
        Assert.NotEmpty(Convert.FromBase64String(tsBase64));

        // SigAndRefsTimeStamp must NOT be present for Type 2
        var sigAndRefsTs = signed.SelectSingleNode("//xa:SigAndRefsTimeStamp", nsManager);
        Assert.Null(sigAndRefsTs);
    }

    [Fact]
    public void When_CreatingXAdesX_Type1_Then_UnsignedPropertiesOrderIsCorrect()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient, refsOnly: false)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        var unsignedSigPropsNode = signed.SelectSingleNode(
            "//xa:UnsignedProperties/xa:UnsignedSignatureProperties", nsManager);
        Assert.NotNull(unsignedSigPropsNode);

        var childNames = unsignedSigPropsNode.ChildNodes
            .Cast<XmlNode>()
            .Select(n => n.LocalName)
            .ToList();

        // XAdES-X expected order: T → C → X
        Assert.Contains("SignatureTimeStamp", childNames);
        Assert.Contains("CompleteCertificateRefs", childNames);
        Assert.Contains("CompleteRevocationRefs", childNames);
        Assert.Contains("SigAndRefsTimeStamp", childNames);

        // SigAndRefsTimeStamp should come after the C-level refs
        var certRefsIdx = childNames.IndexOf("CompleteCertificateRefs");
        var revRefsIdx = childNames.IndexOf("CompleteRevocationRefs");
        var sigAndRefsIdx = childNames.IndexOf("SigAndRefsTimeStamp");

        Assert.True(sigAndRefsIdx > certRefsIdx,
            "SigAndRefsTimeStamp must follow CompleteCertificateRefs.");
        Assert.True(sigAndRefsIdx > revRefsIdx,
            "SigAndRefsTimeStamp must follow CompleteRevocationRefs.");
    }
}
