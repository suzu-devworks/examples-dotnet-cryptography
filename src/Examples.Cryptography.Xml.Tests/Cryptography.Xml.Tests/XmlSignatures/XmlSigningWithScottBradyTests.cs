using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Examples.Cryptography.Xml;

namespace Examples.Cryptography.Tests.Xml;

public class XmlSigningWithScottBradyTests
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    /// <summary>
    /// ECDSA and Custom XML Signatures in .NET - Scott Brady
    /// </summary>
    /// <seealso href="https://www.scottbrady91.com/c-sharp/ecdsa-xml-dotnet" />
    [Fact]
    public void When_XmlSigningUsingECDSA_Then_SignatureIsValid()
    {
        const string text = "<message><content>Just remember ALL CAPS when you spell the man name</content></message>";

        var xml = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        xml.LoadXml(text);

        // in-memory key and certificate - not suitable for production
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = new CertificateRequest("CN=test", ecdsa, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-2));

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

        // `SignatureDescription could not be created for the signature algorithm supplied.`
        CryptoConfig.AddAlgorithm(
            typeof(ECDsa256SignatureDescription),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");

        // create signature
        signedXml.ComputeSignature();

        // get signature XML element and add it as a child of the root element
        //signedXml.GetXml();
        xml.DocumentElement?.AppendChild(signedXml.GetXml());

        Output?.WriteLine(xml.ToFormattedString());

        var result = Verify(xml, cert.GetECDsaPublicKey()!);
        Assert.True(result);
    }

    /// <summary>
    /// How to sign XML using RSA in .NET - Scott Brady
    /// </summary>
    /// <seealso href="https://www.scottbrady91.com/c-sharp/xml-signing-dotnet" />
    [Fact]
    public void When_XmlSigningUsingRSA_Then_SignatureIsValid()
    {
        const string text = "<message><content>Just remember ALL CAPS when you spell the man name</content></message>";

        var xml = new XmlDocument { PreserveWhitespace = true };
        using var stringReader = new StringReader(text);
        using var xmlReader = XmlReader.Create(stringReader);
        xml.Load(xmlReader);

        // in-memory key and certificate - not suitable for production
        using var rsa = RSA.Create(/* 3072 */);
        using X509Certificate2 cert = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-2));

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

        Output?.WriteLine(xml.ToFormattedString());

        var result = Verify(xml, cert.GetRSAPublicKey()!);
        Assert.True(result);
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

        return signedXml.CheckSignature(key);
    }

}
