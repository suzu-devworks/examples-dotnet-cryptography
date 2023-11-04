using System.Security.Cryptography.Xml;
using System.Xml;

namespace Examples.Cryptography.Xml;

public class XmlDsigDocument : XmlDocument
{
    /// <inheritdoc />
    public override XmlElement CreateElement(string? prefix, string localName, string? namespaceURI)
    {
        // CAntonio. If this is a Digital signature security element, add the prefix.
        if (string.IsNullOrEmpty(prefix))
        {
            // !!! Note: If you comment this line, you'll get a valid signed file! (but without ds prefix)
            // !!! Note: If you uncomment this line, you'll get an invalid signed file! (with ds prefix within 'Signature' object)
            //prefix = GetPrefix(namespaceURI);

            // The only way to get a valid signed file is to prevent 'Prefix' on 'SignedInfo' and descendants.
            var signedInfoAndDescendants = new List<string>
            {
                "SignedInfo",
                "CanonicalizationMethod",
                "InclusiveNamespaces",
                "SignatureMethod",
                "Reference",
                "Transforms",
                "Transform",
                "InclusiveNamespaces",
                "DigestMethod",
                "DigestValue"
            };

            if (!signedInfoAndDescendants.Contains(localName))
            {
                prefix = GetPrefix(namespaceURI);
            }
        }

        return base.CreateElement(prefix, localName, namespaceURI);
    }

    private static string GetPrefix(string? namespaceURI)
    {
        if (namespaceURI == "http://www.w3.org/2001/10/xml-exc-c14n#")
            return "ec";
        else if (namespaceURI == SignedXml.XmlDsigNamespaceUrl)
            return "ds";

        return string.Empty;
    }

}
