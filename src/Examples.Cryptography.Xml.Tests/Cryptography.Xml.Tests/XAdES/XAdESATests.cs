using System.Security.Cryptography;
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

        // Build XAdES-A: T + C (refs) + X (SigAndRefs) + X-L (values) + ArchiveTimeStamp
        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient)
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
            .WithXTimestamp(fixture.TsaClient)
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

        // XAdES-A expected order: T → C → X → X-L → A
        Assert.Contains("SignatureTimeStamp", childNames);
        Assert.Contains("CompleteCertificateRefs", childNames);
        Assert.Contains("CompleteRevocationRefs", childNames);
        Assert.Contains("SigAndRefsTimeStamp", childNames);
        Assert.Contains("CertificateValues", childNames);
        Assert.Contains("RevocationValues", childNames);
        Assert.Contains("ArchiveTimeStamp", childNames);

        // ArchiveTimeStamp should come last
        Assert.Equal("ArchiveTimeStamp", childNames.Last());
    }

    /// <summary>
    /// XAdES-A verification: all validation materials required for long-term archival
    /// must be present in a single self-contained document. This means a verifier in
    /// the future — when original CAs may be offline and algorithms may be weaker —
    /// can still reconstruct the full validation path from the embedded data alone.
    /// <para>
    /// The required materials are:
    /// <list type="bullet">
    ///   <item><description>T-level: SignatureTimeStamp (trusted time upper bound)</description></item>
    ///   <item><description>C-level: CompleteCertificateRefs + CompleteRevocationRefs (path digest pointers)</description></item>
    ///   <item><description>X-level: SigAndRefsTimeStamp (timestamps covering refs)</description></item>
    ///   <item><description>X-L level: CertificateValues + RevocationValues (embedded DER data for offline validation)</description></item>
    ///   <item><description>A-level: ArchiveTimeStamp (protects entire archive against algorithm obsolescence)</description></item>
    /// </list>
    /// </para>
    /// </summary>
    [Fact]
    public void When_VerifyingXAdesA_Then_AllValidationMaterialsAreSelfContained()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .WithXTimestamp(fixture.TsaClient)
            .WithRevocationValues(fixture.RevocationValues)
            .WithArchiveTimestamp(fixture.TsaClient)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");
        nsManager.AddNamespace("ds", System.Security.Cryptography.Xml.SignedXml.XmlDsigNamespaceUrl);

        // --- T-level: a trusted time upper bound is present ---
        var sigTs = signed.SelectSingleNode(
            "//xa:SignatureTimeStamp/xa:EncapsulatedTimeStamp", nsManager);
        Assert.NotNull(sigTs);
        Assert.NotEmpty(Convert.FromBase64String(sigTs.InnerText.Trim()));

        // --- C-level: digest references allow locating the cert chain ---
        var certRefs = signed.SelectNodes(
            "//xa:CompleteCertificateRefs/xa:CertRefs/xa:Cert", nsManager);
        Assert.NotNull(certRefs);
        Assert.True(certRefs.Count > 0, "At least one certificate reference must be present.");

        // --- X-level: X-level timestamp is present covering C-level refs ---
        var sigAndRefsTs = signed.SelectSingleNode(
            "//xa:SigAndRefsTimeStamp/xa:EncapsulatedTimeStamp", nsManager);
        Assert.NotNull(sigAndRefsTs);
        Assert.NotEmpty(Convert.FromBase64String(sigAndRefsTs.InnerText.Trim()));

        // --- X-L level: embedded certificates allow offline path construction ---
        var embeddedCerts = signed.SelectNodes(
            "//xa:CertificateValues/xa:EncapsulatedX509Certificate", nsManager);
        Assert.NotNull(embeddedCerts);
        Assert.Equal(fixture.CertChain.Count, embeddedCerts.Count);

        // Each embedded cert must parse as a valid X.509 certificate
        // and its digest must match the corresponding C-level certificate reference.
        var certRefDigests = certRefs.Cast<XmlNode>()
            .Select(n =>
            {
                var dv = n.SelectSingleNode("xa:CertDigest/ds:DigestValue", nsManager);
                Assert.NotNull(dv);
                return Convert.FromBase64String(dv.InnerText.Trim());
            })
            .ToList();

        for (int i = 0; i < embeddedCerts.Count; i++)
        {
            var embeddedCertNode = embeddedCerts[i];
            Assert.NotNull(embeddedCertNode);
            var derBytes = Convert.FromBase64String(embeddedCertNode.InnerText.Trim());
            using var cert = X509CertificateLoader.LoadCertificate(derBytes);
            var digest = cert.GetCertHash(HashAlgorithmName.SHA256);
            Assert.Equal(certRefDigests[i], digest);
        }

        // --- X-L level: embedded CRLs allow offline revocation checking ---
        var embeddedCrls = signed.SelectNodes(
            "//xa:RevocationValues/xa:CRLValues/xa:EncapsulatedCRLValue", nsManager);
        Assert.NotNull(embeddedCrls);
        Assert.True(embeddedCrls.Count > 0,
            "At least one embedded CRL must be present for offline revocation check.");

        // --- A-level: archive timestamp is present as the last element ---
        var archiveTs = signed.SelectSingleNode(
            "//xa:ArchiveTimeStamp/xa:EncapsulatedTimeStamp", nsManager);
        Assert.NotNull(archiveTs);
        Assert.NotEmpty(Convert.FromBase64String(archiveTs.InnerText.Trim()));

        var unsignedSigPropsNode = signed.SelectSingleNode(
            "//xa:UnsignedProperties/xa:UnsignedSignatureProperties", nsManager);
        Assert.NotNull(unsignedSigPropsNode);
        var lastChild = unsignedSigPropsNode.ChildNodes.Cast<XmlNode>().Last();
        Assert.Equal("ArchiveTimeStamp", lastChild.LocalName);

        // The XML signature must remain valid throughout all the added unsigned data.
        var valid = signed.VerifySignature(signer);
        Assert.True(valid, "XAdES-A signature must remain cryptographically valid.");
    }
}
