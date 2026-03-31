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

        // Assert:
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

        // Assert:
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

    /// <summary>
    /// XAdES-X verification: the SigAndRefsTimeStamp element must appear after all
    /// C-level reference elements in the document, confirming it was issued after
    /// both the signature and the complete-refs were present. This document order
    /// relationship demonstrates that the X-level timestamp covers the C-level data.
    /// </summary>
    [Fact]
    public void When_VerifyingXAdesX_Type1_Then_SigAndRefsTimestampAppearsAfterCLevelRefs()
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

        // Collect ordered element names from UnsignedSignatureProperties.
        var unsignedSigPropsNode = signed.SelectSingleNode(
            "//xa:UnsignedProperties/xa:UnsignedSignatureProperties", nsManager);
        Assert.NotNull(unsignedSigPropsNode);

        var childNames = unsignedSigPropsNode.ChildNodes
            .Cast<XmlNode>()
            .Select(n => n.LocalName)
            .ToList();

        // All four elements must be present.
        Assert.Contains("SignatureTimeStamp", childNames);
        Assert.Contains("CompleteCertificateRefs", childNames);
        Assert.Contains("CompleteRevocationRefs", childNames);
        Assert.Contains("SigAndRefsTimeStamp", childNames);

        // Verify the expected processing order: T → C-cert-refs → C-rev-refs → X.
        var sigTsIdx = childNames.IndexOf("SignatureTimeStamp");
        var certRefsIdx = childNames.IndexOf("CompleteCertificateRefs");
        var revRefsIdx = childNames.IndexOf("CompleteRevocationRefs");
        var sigAndRefsIdx = childNames.IndexOf("SigAndRefsTimeStamp");

        Assert.True(certRefsIdx > sigTsIdx,
            "CompleteCertificateRefs (C) must follow SignatureTimeStamp (T).");
        Assert.True(revRefsIdx > sigTsIdx,
            "CompleteRevocationRefs (C) must follow SignatureTimeStamp (T).");
        Assert.True(sigAndRefsIdx > certRefsIdx,
            "SigAndRefsTimeStamp (X) must follow CompleteCertificateRefs (C).");
        Assert.True(sigAndRefsIdx > revRefsIdx,
            "SigAndRefsTimeStamp (X) must follow CompleteRevocationRefs (C).");

        // The XML signature must remain valid.
        var valid = signed.VerifySignature(signer);
        Assert.True(valid, "XAdES-X Type 1 signature must remain valid.");
    }
}
