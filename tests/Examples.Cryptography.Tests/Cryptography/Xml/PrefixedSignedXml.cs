using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Examples.Cryptography.Xml;

public class PrefixedSignedXml : SignedXml
{
    private readonly string _prefix;

    public PrefixedSignedXml(XmlDocument document, string prefix)
        : this(document.DocumentElement!, prefix)
    {
    }

    public PrefixedSignedXml(XmlElement element, string prefix)
        : base(element)
    {
        _prefix = prefix;
    }

    public PrefixedSignedXml(string prefix)
        : base()
    {
        _prefix = prefix;
    }

    public new void ComputeSignature()
    {
        BuildDigestedReferences();

        AsymmetricAlgorithm signingKey = this.SigningKey
             ?? throw new CryptographicException("@:Signing key is not loaded.");

        if (SignedInfo?.SignatureMethod is null)
        {
            if ((SignedInfo is not null) && (signingKey is DSA))
            {
                SignedInfo!.SignatureMethod = SignedXml.XmlDsigDSAUrl;
            }
            else if ((SignedInfo is not null) && (signingKey is RSA))
            {
                SignedInfo.SignatureMethod ??= SignedXml.XmlDsigRSASHA256Url;
            }
            else
            {
                throw new CryptographicException("@:Failed to create signing key.");
            }
        }

        SignatureDescription signatureDescription = CryptoHelpers.CreateNonTransformFromName<SignatureDescription>(SignedInfo.SignatureMethod)
            ?? throw new CryptographicException("@:SignatureDescription could not be created for the signature algorithm supplied.");

        HashAlgorithm? hashAlg = signatureDescription.CreateDigest()
            ?? throw new CryptographicException("@:Could not create hash algorithm object. If the application has been trimmed, ensure the required algorithm implementations are preserved.");

        GetC14NDigest(hashAlg, _prefix);

        AsymmetricSignatureFormatter asymmetricSignatureFormatter = signatureDescription.CreateFormatter(signingKey);
        m_signature.SignatureValue = asymmetricSignatureFormatter.CreateSignature(hashAlg);

        return;
    }

    public new XmlElement GetXml()
    {
        XmlElement elem = base.GetXml();
        SetPrefix(_prefix, elem);
        return elem;
    }

    private void BuildDigestedReferences()
    {
        var type = typeof(SignedXml);
        var method = type.GetMethod("BuildDigestedReferences",
                BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new CryptographicException("@:BuildDigestedReferences method not found.");

        method.Invoke(this, Array.Empty<object>());
    }

    private byte[] GetC14NDigest(HashAlgorithm hash, string prefix)
    {
        //bool isKeyedHashAlgorithm = hash is KeyedHashAlgorithm;
        // if (isKeyedHashAlgorithm || !_bCacheValid || !SignedInfo!.CacheValid)
        if (SignedInfo is not null)
        {
            // string? baseUri = _containingDocument?.BaseURI;
            // XmlResolver? resolver = (baseResolverSet ? _xmlResolver : XmlResolverHelper.GetThrowingResolver());
            // XmlDocument doc = Utils.PreProcessElementInput(SignedInfo!.GetXml(), resolver!, baseUri);
            XmlElement elem = SignedInfo.GetXml();
            XmlDocument doc = new()
            {
                PreserveWhitespace = true
            };
            doc.AppendChild(doc.ImportNode(elem, true));

            SetPrefix(prefix, doc.DocumentElement!);

            // // Add non default namespaces in scope
            // CanonicalXmlNodeList? namespaces = (_context == null ? null : Utils.GetPropagatedAttributes(_context));
            // //SignedXmlDebugLog.LogNamespacePropagation(this, namespaces);
            // Utils.AddNamespaces(doc.DocumentElement!, namespaces);

            Transform c14nMethodTransform = SignedInfo.CanonicalizationMethodObject;
            // c14nMethodTransform.Resolver = resolver;
            // c14nMethodTransform.BaseURI = baseUri;

            // SignedXmlDebugLog.LogBeginCanonicalization(this, c14nMethodTransform);
            c14nMethodTransform.LoadInput(doc);
            // SignedXmlDebugLog.LogCanonicalizedOutput(this, c14nMethodTransform);
            _digestedSignedInfo = c14nMethodTransform.GetDigestedOutput(hash);

            //_bCacheValid = !isKeyedHashAlgorithm;
        }
        return _digestedSignedInfo!;
    }

    private byte[]? _digestedSignedInfo;

    private void SetPrefix(string prefix, XmlNode node)
    {
        foreach (XmlNode n in node.ChildNodes)
        {
            SetPrefix(prefix, n);
        }

        if (node.NamespaceURI == SignedXml.XmlDsigNamespaceUrl)
        {
            node.Prefix = prefix;
        }
    }

    private static class CryptoHelpers
    {
        public static T? CreateNonTransformFromName<T>(string? name) where T : class
        {
            var result = (CryptoConfig.CreateFromName(name!) ?? CreateFromKnownName(name!)) as T;
            return result;
        }

        private static object? CreateFromKnownName(string name)
        {
            var type = Type.GetType("System.Security.Cryptography.Xml.CryptoHelpers, System.Security.Cryptography.Xml")
                ?? throw new CryptographicException("@:CryptoHelpers type not defined.");
            var method = type.GetMethod("CreateFromKnownName",
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                ?? throw new CryptographicException("@:CreateFromKnownName method not found.");

            var result = method.Invoke(null, new object[] { name });

            return result;
        }

    }
}
