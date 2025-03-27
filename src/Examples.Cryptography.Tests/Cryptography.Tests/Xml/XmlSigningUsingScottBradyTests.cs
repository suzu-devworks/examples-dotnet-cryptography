using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Examples.Cryptography.Xml;

namespace Examples.Cryptography.Tests.Xml;

public class XmlSigningUsingScottBradyTests : IClassFixture<XmlDataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly XmlDataFixture _fixture;

    public XmlSigningUsingScottBradyTests(XmlDataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;
        _fixture = fixture;
    }

    [Fact]
    public void WhenSigningXMLDSig_UsingECDSA_WorksAsExpected()
    {
        // see.
        // https://www.scottbrady91.com/c-sharp/ecdsa-xml-dotnet

        const string INPUT_TEXT = "<message><content>Just remember ALL CAPS when you spell the man name</content></message>";
        var xml = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        xml.LoadXml(INPUT_TEXT);

        // in-memory key and certificate - not suitable for production
        X509Certificate2 cert = _fixture.ECDsaSigner;
        cert.HasPrivateKey.IsTrue();

        // set your signing key, signing algorithm, and canonicalization method
        var signedXml = new SignedXml(xml.DocumentElement!) { SigningKey = cert.GetECDsaPrivateKey() };
        signedXml.SignedInfo!.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
        // signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

        // sign whole document using "SAML style" transforms
        var reference = new Reference { Uri = string.Empty };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        // create signature
        // `SignatureDescription could not be created for the signature algorithm supplied.`
        CryptoConfig.AddAlgorithm(
            typeof(ECDsa256SignatureDescription),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
        signedXml.ComputeSignature();

        // get signature XML element and add it as a child of the root element
        //signedXml.GetXml();
        xml.DocumentElement?.AppendChild(signedXml.GetXml());

        _output.WriteLine($"xml:{Environment.NewLine}{xml.ToFormattedOuterXml()}");

        Verify(xml, cert.GetECDsaPublicKey()!).IsTrue();


    }


    [Fact]
    public void WhenSigningXMLDSig_UsingRSA_WorksAsExpected()
    {
        // see.
        // https://www.scottbrady91.com/c-sharp/xml-signing-dotnet

        const string INPUT_TEXT = "<message><content>Just remember ALL CAPS when you spell the man name</content></message>";
        var xml = new XmlDocument { PreserveWhitespace = true };

        using var stringReader = new StringReader(INPUT_TEXT);
        using var xmlReader = XmlReader.Create(stringReader);
        xml.Load(xmlReader);

        // in-memory key and certificate - not suitable for production
        X509Certificate2 cert = _fixture.RSASigner;
        cert.HasPrivateKey.IsTrue();

        // set key, signing algorithm, and canonicalization method
        var signedXml = new SignedXml(xml.DocumentElement!) { SigningKey = cert.GetRSAPrivateKey() };
        // signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        // signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

        // sign whole document using "SAML style" transforms
        var reference = new Reference { Uri = string.Empty };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        // OPTIONAL: embed the public key in the XML.
        // This MUST NOT be trusted during validation (used for debugging only)
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));
        signedXml.KeyInfo = keyInfo;

        // compute signature
        signedXml.ComputeSignature();

        // get signature XML element and add it as a child of the root element
        signedXml.GetXml();
        xml.DocumentElement?.AppendChild(signedXml.GetXml());

        _output.WriteLine($"xml:{Environment.NewLine}{xml.ToFormattedOuterXml()}");

        Verify(xml, cert.GetRSAPublicKey()!).IsTrue();


    }

    private static bool Verify(XmlDocument xml, AsymmetricAlgorithm key)
    {
        // double-check the schema
        // usually we would validate using XPath
        var signatureElement = xml.GetElementsByTagName("Signature");
        if (signatureElement.Count != 1)
            throw new InvalidOperationException("Too many signatures!");

        var signedXml = new SignedXml(xml);
        signedXml.LoadXml((XmlElement)signatureElement[0]!);

        // validate references here!
        if ((signedXml.SignedInfo!.References[0] as Reference)?.Uri != "")
            throw new InvalidOperationException("Check your references!");

        bool isValid = signedXml.CheckSignature(key);

        return isValid;
    }

}
