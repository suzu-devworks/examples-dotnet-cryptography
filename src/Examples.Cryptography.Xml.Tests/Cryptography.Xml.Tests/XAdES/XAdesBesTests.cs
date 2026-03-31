using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.Tests.XAdES.Fixtures;
using Examples.Cryptography.Xml.XAdES.SchemaBased;

namespace Examples.Cryptography.Tests.Xml.XAdES;

/// <summary>
/// Demonstrates creation and verification of XAdES-BES signatures.
/// XAdES-BES (Basic Electronic Signature) extends XML-DSig by adding
/// SignedProperties containing SigningTime and SigningCertificateV2.
/// </summary>
public class XAdesBesTests(XAdESFixture fixture)
    : IClassFixture<XAdESFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private readonly DateTime _signingTime = DateTime.UtcNow;

    [Fact]
    public void When_CreatingXAdesBes_Then_SignedPropertiesContainSigningTimeAndCert()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        // Build XAdES-BES (no unsigned properties)
        var signed = new XAdESBuilder(signer)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}{signed.ToFormattedString()}{Environment.NewLine}");

        // Verify XML signature
        var signatureValid = signed.VerifySignature(signer);
        Assert.True(signatureValid, "XAdES-BES signature must be valid.");

        // Verify SignedProperties structure
        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        var signingTimeNode = signed.SelectSingleNode("//xa:SigningTime", nsManager);
        Assert.NotNull(signingTimeNode);

        var signingCertNode = signed.SelectSingleNode("//xa:SigningCertificateV2", nsManager);
        Assert.NotNull(signingCertNode);

        // Verify that UnsignedProperties is absent (BES has no UnsignedProperties)
        var unsignedPropsNode = signed.SelectSingleNode("//xa:UnsignedProperties", nsManager);
        Assert.Null(unsignedPropsNode);
    }

    [Fact]
    public void When_CreatingXAdesBes_Then_QualifyingPropertiesContainSignedProperties()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // QualifyingProperties must exist inside ds:Object
        var qpNode = signed.SelectSingleNode("//ds:Object/xa:QualifyingProperties", nsManager);
        Assert.NotNull(qpNode);

        // SignedProperties must be inside QualifyingProperties
        var spNode = qpNode.SelectSingleNode("xa:SignedProperties", nsManager);
        Assert.NotNull(spNode);

        // SignedSignatureProperties must contain SigningTime
        var sspNode = spNode.SelectSingleNode("xa:SignedSignatureProperties", nsManager);
        Assert.NotNull(sspNode);

        var signingTimeNode = sspNode.SelectSingleNode("xa:SigningTime", nsManager);
        Assert.NotNull(signingTimeNode);
        Assert.NotEmpty(signingTimeNode.InnerText);
    }

    /// <summary>
    /// XAdES-BES verification: the digest stored in SigningCertificateV2 must match
    /// the actual signer certificate's SHA-256 hash, binding the certificate identity
    /// to the signed data.
    /// </summary>
    [Fact]
    public void When_VerifyingXAdesBes_Then_SignerCertDigestMatchesSigningCertificateV2()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .Build(original, _signingTime, "id-target");

        var nsManager = new XmlNamespaceManager(signed.NameTable);
        nsManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        // Extract the DigestValue embedded in SigningCertificateV2
        var digestValueNode = signed.SelectSingleNode(
            "//xa:SigningCertificateV2/xa:Cert/xa:CertDigest/ds:DigestValue", nsManager);
        Assert.NotNull(digestValueNode);

        var embeddedDigest = Convert.FromBase64String(digestValueNode.InnerText.Trim());

        // The embedded digest must match the actual signer certificate's SHA-256 hash.
        // This binding allows a verifier to confirm the correct certificate was used.
        var expectedDigest = signer.GetCertHash(HashAlgorithmName.SHA256);
        Assert.Equal(expectedDigest, embeddedDigest);
    }

    /// <summary>
    /// XAdES-BES verification: the XML signature must remain valid after serializing
    /// and re-parsing, simulating how an external verifier would process the document.
    /// </summary>
    [Fact]
    public void When_VerifyingXAdesBes_Then_SignatureRemainsValidAfterRoundTrip()
    {
        X509Certificate2 signer = fixture.Signer;
        var original = XAdESFixture.CreateSampleDocument();

        var signed = new XAdESBuilder(signer)
            .Build(original, _signingTime, "id-target");

        // Serialize the signed document to a string, then re-parse it.
        // This simulates transmitting the document to an external verifier.
        var xml = signed.OuterXml;
        var reloaded = new XmlDocument { PreserveWhitespace = false };
        reloaded.LoadXml(xml);

        // The signature must still be valid in the re-loaded document.
        var valid = reloaded.VerifySignature(signer);
        Assert.True(valid, "XAdES-BES signature must remain valid after round-trip serialization.");

        // The SigningTime must be parseable as a UTC timestamp.
        var nsManager = new XmlNamespaceManager(reloaded.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        var signingTimeNode = reloaded.SelectSingleNode("//xa:SigningTime", nsManager);
        Assert.NotNull(signingTimeNode);
        var signingTime = DateTime.Parse(
            signingTimeNode.InnerText, null, DateTimeStyles.RoundtripKind);
        Assert.True(signingTime <= DateTime.UtcNow,
            "SigningTime must not be in the future.");
    }
}
