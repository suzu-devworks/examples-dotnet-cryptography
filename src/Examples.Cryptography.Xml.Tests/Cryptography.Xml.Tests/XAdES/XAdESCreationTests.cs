using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Examples.Cryptography.Xml;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.Xml.XAdES;

namespace Examples.Cryptography.Tests.Xml.XAdES;

using SchemaBased = Examples.Cryptography.Xml.XAdES.SchemaBased;

public class XAdESCreationTests(XAdESCreationTests.Fixture fixture)
    : IClassFixture<XAdESCreationTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await RsaChainFixture.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await RsaChainFixture.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        private static readonly RsaSignerCertificateChainOpenSslFixture RsaChainFixture = new(includePrivateKeys: true);

        public X509Certificate2 RSASigner => RsaChainFixture.SinnerCertificate;
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private readonly DateTime _signingTime = DateTime.UtcNow;

    [Fact]
    public void When_CreatingXAdES_WithSignedXml_Then_VerificationSuccessful()
    {
        X509Certificate2 signer = fixture.RSASigner;

        var original = CreateSomeXml();
        Output?.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original.ToFormattedString()}{Environment.NewLine}");

        // ===== Without prefix =====
        var signed = new XAdESBuilder(signer)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}" +
            $"{signed.ToFormattedString()}{Environment.NewLine}");

        var result = signed.VerifySignature(signer);
        Assert.True(result, "The XML signature is not valid.");
    }

    [Fact]
    public void When_CreatingXAdES_WithPrefixedSignedXml_Then_VerificationSuccessful()
    {
        X509Certificate2 signer = fixture.RSASigner;

        var original = CreateSomeXml();
        Output?.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original.ToFormattedString()}{Environment.NewLine}");

        // ===== Use Custom SignedXML =====
        var signed = new XAdESBuilder(signer)
            .WithCustomSignedXml(doc => new PrefixedSignedXml(doc, "ds"))
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}" +
            $"{signed.ToFormattedString()}{Environment.NewLine}");

        var result = signed.VerifySignature(signer);
        Assert.True(result, "The XML signature is not valid.");
    }

    [Fact]
    public void When_CreatingXAdES_WithXmlDsigDocument_Then_VerificationSuccessful()
    {
        X509Certificate2 signer = fixture.RSASigner;

        var original = CreateSomeXml();
        Output?.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original.ToFormattedString()}{Environment.NewLine}");

        // ===== Use Custom XmlDocument  =====
        // However, the presence of the "ds" prefix within "SignedInfo"
        // and its descendants causes the signing to fail.
        var signed = new XAdESBuilder(signer)
            .WithCustomXmlDocument(() => new XmlDsigDocument())
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}" +
            $"{signed.ToFormattedString()}{Environment.NewLine}");

        var result = signed.VerifySignature(signer);
        Assert.True(result, "The XML signature is not valid.");
    }

    [Fact]
    public void When_CreatingXAdES_WithXsdGeneratedClass_Then_VerificationSuccessful()
    {
        X509Certificate2 signer = fixture.RSASigner;

        var original = CreateSomeXml();
        Output?.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original.ToFormattedString()}{Environment.NewLine}");

        // ===== Use Generated classes  =====
        // However, the presence of the "ds" prefix within "SignedInfo"
        // and its descendants causes the signing to fail.
        var signed = new SchemaBased.XAdESBuilder(signer)
            .Build(original, _signingTime, "id-target");

        Output?.WriteLine($"[Signed XML]:{Environment.NewLine}" +
            $"{signed.ToFormattedString()}{Environment.NewLine}");

        var result = signed.VerifySignature(signer);
        Assert.True(result, "The XML signature is not valid.");
    }

    private static XmlDocument CreateSomeXml()
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

}
