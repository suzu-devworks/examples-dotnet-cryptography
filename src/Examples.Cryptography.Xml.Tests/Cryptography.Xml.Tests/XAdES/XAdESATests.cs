using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.Tests.XAdES.Fixtures;
using Examples.Cryptography.Xml.XAdES.SchemaBased;

namespace Examples.Cryptography.Tests.Xml.XAdES;

/// <summary>
/// Demonstrates creation and verification of XAdES-A signatures.
/// XAdES-A (Archival Electronic Signature) extends XAdES-X-L by adding
/// an ArchiveTimeStamp in UnsignedSignatureProperties.
/// The archive timestamp covers the entire signed document structure to guarantee
/// long-term verifiability even after cryptographic algorithms become obsolete.
/// </summary>
public class XAdESATests(XAdESFixture fixture)
    : IClassFixture<XAdESFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private readonly DateTime _signingTime = DateTime.UtcNow;

    [Fact]
    public void When_CreatingXAdesA_Then_ArchiveTimeStampAddedToUnsignedProperties()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        // Build XAdES-A: T + C (refs) + X-L (values) + ArchiveTimeStamp
        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithRevocationValues(fixture.RevocationValues)
            .WithArchiveTimestamp(fixture.TsaClient)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}{signed.ToFormattedString()}{Environment.NewLine}");

        // Verify XML signature
        var signatureValid = signed.VerifySignature(signer);
        Assert.True(signatureValid, "XAdES-A signature must be valid.");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // XAdES-T: SignatureTimeStamp must be present
        var sigTs = signed.SelectSingleNode("//xa:SignatureTimeStamp", nsManager);
        Assert.NotNull(sigTs);

        // XAdES-C: references must be present
        var certRefsNode = signed.SelectSingleNode("//xa:CompleteCertificateRefs", nsManager);
        Assert.NotNull(certRefsNode);

        var revRefsNode = signed.SelectSingleNode("//xa:CompleteRevocationRefs", nsManager);
        Assert.NotNull(revRefsNode);

        // XAdES-X-L: values must be present
        var certValuesNode = signed.SelectSingleNode("//xa:CertificateValues", nsManager);
        Assert.NotNull(certValuesNode);

        var revValuesNode = signed.SelectSingleNode("//xa:RevocationValues", nsManager);
        Assert.NotNull(revValuesNode);

        // XAdES-A: ArchiveTimeStamp must be present
        var archiveTsList = signed.SelectNodes("//xa:ArchiveTimeStamp", nsManager);
        Assert.NotNull(archiveTsList);
        Assert.True(archiveTsList.Count >= 1, "At least one ArchiveTimeStamp must be present.");

        // ArchiveTimeStamp must contain an EncapsulatedTimeStamp
        var encapsulatedAts = signed.SelectSingleNode(
            "//xa:ArchiveTimeStamp/xa:EncapsulatedTimeStamp", nsManager);
        Assert.NotNull(encapsulatedAts);
        Assert.NotEmpty(encapsulatedAts.InnerText);
    }

    [Fact]
    public void When_CreatingXAdesA_Then_UnsignedPropertiesOrderIsCorrect()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithRevocationValues(fixture.RevocationValues)
            .WithArchiveTimestamp(fixture.TsaClient)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // Collect the element names inside UnsignedSignatureProperties in order
        var unsignedSigPropsNode = signed.SelectSingleNode(
            "//xa:UnsignedProperties/xa:UnsignedSignatureProperties", nsManager);
        Assert.NotNull(unsignedSigPropsNode);

        var childNames = unsignedSigPropsNode.ChildNodes
            .Cast<XmlNode>()
            .Select(n => n.LocalName)
            .ToList();

        // XAdES-A expected order: T → C → X-L → A
        Assert.Contains("SignatureTimeStamp", childNames);
        Assert.Contains("CompleteCertificateRefs", childNames);
        Assert.Contains("CompleteRevocationRefs", childNames);
        Assert.Contains("CertificateValues", childNames);
        Assert.Contains("RevocationValues", childNames);
        Assert.Contains("ArchiveTimeStamp", childNames);

        // ArchiveTimeStamp should come last
        Assert.Equal("ArchiveTimeStamp", childNames.Last());
    }
}
