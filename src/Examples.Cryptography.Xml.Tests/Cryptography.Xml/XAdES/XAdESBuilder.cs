using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Xml.Extensions;

namespace Examples.Cryptography.Xml.XAdES;

public sealed class XAdESBuilder(X509Certificate2 signer)
{
    private static readonly XmlSerializerNamespaces XmlNs = InitializeNamespaces();

    private static XmlSerializerNamespaces InitializeNamespaces()
    {
        var ns = new XmlSerializerNamespaces();
        ns.Add("ds", SignedXml.XmlDsigNamespaceUrl);
        ns.Add("xa", "http://uri.etsi.org/01903/v1.3.2#");
        ns.Add("xa141", "http://uri.etsi.org/01903/v1.4.1#");
        return ns;
    }

    private readonly X509Certificate2 _signer = signer;
    private readonly string _keyInfoId = "id-keyInfo";
    private readonly string _qualifyingPropertiesId = "id-QualifyingProperties";
    private readonly string _signedPropertiesId = "id-SignedProperties";

    public XmlDocument Build(XmlDocument original, DateTime signingTime, string uri)
    {
        // Once to sign the target.
        var temporary = SignXml(original, signingTime, uri, signKeyInfoAndProperties: false);

        // Process twice to sign KeyInfo and SignedProperties.
        var signed = SignXml(temporary, signingTime, uri, signKeyInfoAndProperties: true);

        return signed;
    }

    private XmlDocument SignXml(XmlDocument original, DateTime signingTime, string uri, bool signKeyInfoAndProperties = false)
    {
        var doc = CreateNewXmlDocument();
        doc.PreserveWhitespace = false;
        doc.LoadXml(original.OuterXml);

        // Add a Signature.
        SignedXml signedXml = CreateNewSignedXml(doc);
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SigningKey = _signer.GetRSAPrivateKey();

        // Add a KeyInfo.
        var keyInfo = new KeyInfo() { Id = _keyInfoId };
        keyInfo.AddClause(new KeyInfoX509Data(_signer, X509IncludeOption.EndCertOnly));
        signedXml.KeyInfo = keyInfo;

        // Add a Object.
        XmlElement qpElem = CreateQualifyingProperties(signingTime, uri);
        var dataObject = new DataObject
        {
            Data = qpElem.ChildNodes
        };
        signedXml.AddObject(dataObject);

        // Add References.

        // First pass: only sign the document target.
        // Second pass: also sign KeyInfo and SignedProperties.
        var elementsToSign = signKeyInfoAndProperties
            ? new[] { uri, _keyInfoId, _signedPropertiesId }
            : new[] { uri };

        foreach (var refId in elementsToSign)
        {
            // Create a reference to be signed.
            var reference = new Reference(uri: $"#{refId}")
            {
                DigestMethod = SignedXml.XmlDsigSHA256Url,
            };

            // Only apply EnvelopedSignatureTransform to the document target reference
            if (refId == uri)
            {
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            }

            reference.AddTransform(new XmlDsigExcC14NTransform());

            if (refId == _signedPropertiesId)
            {
                reference.Type = "http://uri.etsi.org/01903#SignedProperties";
            }

            signedXml.AddReference(reference);
        }

        // Compute the signature.
        signedXml.ComputeSignature();

        // Get the XML representation of the signature and save
        // it to an XmlElement object.
        XmlElement newSignature = signedXml.GetXml();

        doc.ReplaceSignature(newSignature);

        return doc;
    }

    private XmlElement CreateQualifyingProperties(DateTime signingTimestamp, string uri)
    {
        var manager = XmlNs.ToNamespaceManager();
        var prefix = "xa";
        var ns = manager.LookupNamespace(prefix);

        var doc = new XmlDocument();

        var qualifyingProperties = doc.CreateElement(prefix, "QualifyingProperties", ns);
        qualifyingProperties.SetAttribute("Id", _qualifyingPropertiesId);
        qualifyingProperties.SetAttribute("Target", $"#{uri}");

        var signedProperties = doc.CreateElement(prefix, "SignedProperties", ns);
        signedProperties.SetAttribute("Id", _signedPropertiesId);
        qualifyingProperties.AppendChild(signedProperties);

        var signedSignatureProperties = doc.CreateElement(prefix, "SignedSignatureProperties", ns);
        signedProperties.AppendChild(signedSignatureProperties);

        var signingTime = doc.CreateElement(prefix, "SigningTime", ns);
        signingTime.InnerText = XmlConvert.ToString(signingTimestamp, XmlDateTimeSerializationMode.Utc);
        signedSignatureProperties.AppendChild(signingTime);

        var signingCertificate = doc.CreateElement(prefix, "SigningCertificateV2", ns);
        signingCertificate.SetAttribute("Uri", $"#{_keyInfoId}");
        signedSignatureProperties.AppendChild(signingCertificate);

        var certDigest = doc.CreateElement(prefix, "CertDigest", ns);
        signingCertificate.AppendChild(certDigest);

        var digestMethod = doc.CreateElement(prefix, "DigestMethod", ns);
        digestMethod.SetAttribute("Algorithm", SignedXml.XmlDsigSHA256Url);
        certDigest.AppendChild(digestMethod);

        var digestValue = doc.CreateElement(prefix, "DigestValue", ns);
        digestValue.InnerText = _signer.GetCertHash(HashAlgorithmName.SHA256).ToBase64String();
        certDigest.AppendChild(digestValue);

        return qualifyingProperties.CloneNode(deep: true) as XmlElement
            ?? throw new InvalidOperationException("Failed to create QualifyingProperties element.");
    }

    private SignedXml CreateNewSignedXml(XmlDocument doc)
    {
        return _createSignedXml?.Invoke(doc) ?? new SignedXml(doc);
    }

    private XmlDocument CreateNewXmlDocument()
    {
        return _createXmlDocument?.Invoke() ?? new XmlDocument();
    }

    public XAdESBuilder WithCustomSignedXml(Func<XmlDocument, SignedXml> generator)
    {
        _createSignedXml = generator;

        return this;
    }
    private Func<XmlDocument, SignedXml>? _createSignedXml;

    public XAdESBuilder WithCustomXmlDocument(Func<XmlDocument> generator)
    {
        _createXmlDocument = generator;

        return this;
    }
    private Func<XmlDocument>? _createXmlDocument;
}
