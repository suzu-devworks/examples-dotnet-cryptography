using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Examples.Cryptography.Xml.Extensions;

/// <summary>
/// Extension methods for Signed <see cref="XmlDocument" />.
/// </summary>
public static class SignedXmlDocumentExtensions
{
    /// <summary>
    /// Verifies the signature of a signed <see cref="XmlDocument" />
    /// using the provided <see cref="X509Certificate2"/>.
    /// </summary>
    /// <param name="signed">The signed XML document.</param>
    /// <param name="signer">The certificate used to verify the signature.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public static bool VerifySignature(this XmlDocument signed, X509Certificate2 signer)
    {
        var document = new XmlDocument() { PreserveWhitespace = false };
        document.LoadXml(signed.OuterXml);

        var signature = SelectSignatureNode(document);
        if (signature is null)
        {
            return false;
        }

        var signedXml = new SignedXml(document);
        signedXml.LoadXml((XmlElement)signature);

        if (signedXml.CheckSignature(signer, verifySignatureOnly: false))
        {
            throw new VerificationException("Invalid signature.");
        }

        return signedXml.CheckSignature();
    }

    /// <summary>
    /// Selects the first &lt;ds:Signature&gt; node from the provided <see cref="XmlDocument"/>.
    /// </summary>
    /// <param name="document">The XML document to search for the signature node.</param>
    /// <returns>The first &lt;ds:Signature&gt; node if found; otherwise, null.</returns>
    public static XmlNode? SelectSignatureNode(this XmlDocument document)
    {
        var nsManager = new XmlNamespaceManager(document.NameTable);
        nsManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

        var node = document.SelectNodes("//ds:Signature", nsManager)
            ?.Cast<XmlNode>()
            .FirstOrDefault();

        return node;
    }

    /// <summary>
    /// Replaces the existing &lt;ds:Signature&gt; node in the provided <see cref="XmlDocument"/>
    /// with the specified new signature element. If no existing signature is found, the new signature
    /// is appended to the document's root element.
    /// </summary>
    /// <param name="doc"></param>
    /// <param name="newSignature"></param>
    public static void ReplaceSignature(this XmlDocument doc, XmlElement newSignature)
    {
        var oldSignature = SelectSignatureNode(doc);
        if (oldSignature is not null)
        {
            var parent = oldSignature?.ParentNode ?? doc.DocumentElement;
            parent?.RemoveChild(oldSignature!);
        }
        doc.DocumentElement!.AppendChild(doc.ImportNode(newSignature, true));
    }

}
