using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.Tests.XAdES.Fixtures;
using Examples.Cryptography.Xml.XAdES.SchemaBased;

namespace Examples.Cryptography.Tests.Xml.XAdES;

/// <summary>
/// Demonstrates creation and verification of XAdES-C signatures.
/// XAdES-C (Electronic Signature with Complete validation data) extends XAdES-T by
/// adding CompleteCertificateRefs and CompleteRevocationRefs in UnsignedSignatureProperties.
/// These provide digest references to all certificates and revocation information
/// needed for later validation.
/// </summary>
public class XAdesCTests(XAdESFixture fixture)
    : IClassFixture<XAdESFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private readonly DateTime _signingTime = DateTime.UtcNow;

    [Fact]
    public void When_CreatingXAdesC_Then_CertificateRefsAndRevocationRefsAdded()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        // Build XAdES-C: T + CompleteCertificateRefs + CompleteRevocationRefs
        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}{signed.ToFormattedString()}{Environment.NewLine}");

        // Verify XML signature
        var signatureValid = signed.VerifySignature(signer);

        // Assert:
        Assert.True(signatureValid, "XAdES-C signature must be valid.");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // SignatureTimeStamp (from T) must be present
        var tsList = signed.SelectNodes("//xa:SignatureTimeStamp", nsManager);
        Assert.NotNull(tsList);
        Assert.True(tsList.Count >= 1, "SignatureTimeStamp must be present.");

        // CompleteCertificateRefs must be present
        var certRefsNode = signed.SelectSingleNode("//xa:CompleteCertificateRefs", nsManager);
        Assert.NotNull(certRefsNode);

        // CertRefs must contain entries for the CA chain
        var certRefItems = signed.SelectNodes("//xa:CompleteCertificateRefs/xa:CertRefs/xa:Cert", nsManager);
        Assert.NotNull(certRefItems);
        Assert.True(certRefItems.Count >= 1, "At least one CertRef must exist for the CA chain.");

        // CompleteRevocationRefs must be present
        var revRefsNode = signed.SelectSingleNode("//xa:CompleteRevocationRefs", nsManager);
        Assert.NotNull(revRefsNode);

        // CRLRefs must contain entries
        var crlRefItems = signed.SelectNodes("//xa:CompleteRevocationRefs/xa:CRLRefs/xa:CRLRef", nsManager);
        Assert.NotNull(crlRefItems);
        Assert.True(crlRefItems.Count >= 1, "At least one CRLRef must exist.");
    }

    [Fact]
    public void When_CreatingXAdesC_Then_CertRefContainsCertDigest()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");
        nsManager.AddNamespace("ds", System.Security.Cryptography.Xml.SignedXml.XmlDsigNamespaceUrl);

        // Each CertRef must contain a DigestAlgAndValue/DigestValue
        var firstCertRef = signed.SelectSingleNode(
            "//xa:CompleteCertificateRefs/xa:CertRefs/xa:Cert", nsManager);
        Assert.NotNull(firstCertRef);

        var digestValue = firstCertRef.SelectSingleNode(
            "xa:CertDigest/ds:DigestValue", nsManager);
        Assert.NotNull(digestValue);
        Assert.NotEmpty(digestValue.InnerText);

        // Each CertRef must contain IssuerSerial
        var issuerSerial = firstCertRef.SelectSingleNode("xa:IssuerSerial", nsManager);
        Assert.NotNull(issuerSerial);
    }

    /// <summary>
    /// XAdES-C verification: each digest value in CompleteCertificateRefs must match
    /// the SHA-256 hash of the corresponding certificate in the chain.
    /// This integrity check confirms the certificate refs have not been tampered with,
    /// and that a verifier can locate the exact certificates needed for path validation.
    /// Unlike XAdES-X-L, the actual certificates must be fetched externally.
    /// </summary>
    [Fact]
    public void When_VerifyingXAdesC_Then_CertRefDigestsMatchActualCertChain()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .WithSignatureTimestamp(fixture.TsaClient)
            .WithCertificateChain(fixture.CertChain)
            .WithRevocationRefs(fixture.RevocationRefs)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");
        nsManager.AddNamespace("ds", System.Security.Cryptography.Xml.SignedXml.XmlDsigNamespaceUrl);

        // Collect all embedded cert ref digest values from CompleteCertificateRefs.
        var certRefNodes = signed.SelectNodes(
            "//xa:CompleteCertificateRefs/xa:CertRefs/xa:Cert", nsManager);
        Assert.NotNull(certRefNodes);
        Assert.Equal(fixture.CertChain.Count, certRefNodes.Count);

        // Each embedded digest must match the actual SHA-256 hash of the corresponding
        // certificate in the chain. This is the C-level integrity verification step.
        var certChainArray = fixture.CertChain.Cast<X509Certificate2>().ToList();
        for (int i = 0; i < certRefNodes.Count; i++)
        {
            var certRefNode = certRefNodes[i];
            Assert.NotNull(certRefNode);
            var digestValueNode = certRefNode.SelectSingleNode(
                "xa:CertDigest/ds:DigestValue", nsManager);
            Assert.NotNull(digestValueNode);

            var embeddedDigest = Convert.FromBase64String(digestValueNode.InnerText.Trim());
            var actualDigest = certChainArray[i].GetCertHash(HashAlgorithmName.SHA256);

            Assert.Equal(actualDigest, embeddedDigest);
        }
    }
}
