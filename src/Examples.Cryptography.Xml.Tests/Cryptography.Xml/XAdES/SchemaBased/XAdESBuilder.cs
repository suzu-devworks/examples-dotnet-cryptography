using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.XAdES.XAdES132;
using Examples.Cryptography.Xml.XAdES.XmlDsig;

namespace Examples.Cryptography.Xml.XAdES.SchemaBased;

public sealed class XAdESBuilder(X509Certificate2 signer)
{
    private static readonly XmlSerializerNamespaces Xmlns = InitializeNamespaces();

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
        XmlDocument signed = SignXmlWithGenerated(original, signingTime, uri);
        return signed;
    }

    private XmlDocument SignXmlWithGenerated(XmlDocument original, DateTime signingTime, string uri)
    {
        var doc = new XmlDocument() { PreserveWhitespace = false };
        doc.LoadXml(original.OuterXml);

        // Add a Signature.
        var signature = new SignatureType()
        {
            SignedInfo = new()
            {
                CanonicalizationMethod = new()
                {
                    Algorithm = SignedXml.XmlDsigCanonicalizationUrl,
                },
                SignatureMethod = new()
                {
                    Algorithm = SignedXml.XmlDsigRSASHA256Url,
                },
            },
            SignatureValue = new() { Value = Array.Empty<byte>() }, //dummy.
        };

        // Add a KeyInfo.
        var keyInfo = new KeyInfoType() { Id = _keyInfoId }
            .AddX509Data(new X509DataType().AddX509Certificate(_signer));

        signature.KeyInfo = keyInfo;

        // Add a Object.
        var qp = new QualifyingPropertiesType()
        {
            Target = $"#{uri}",
            Id = _qualifyingPropertiesId,
            SignedProperties = new()
            {
                Id = _signedPropertiesId,
                SignedSignatureProperties = new SignedSignaturePropertiesType()
                {
                    SigningTime = signingTime
                }
                .AddSigningCertificateV2(new()
                {
                    Uri = $"#{keyInfo.Id}",
                    CertDigest = new()
                    {
                        DigestMethod = new()
                        {
                            Algorithm = SignedXml.XmlDsigSHA256Url
                        },
                        DigestValue = _signer.GetCertHash(HashAlgorithmName.SHA256),
                    }
                })
            }
        };

        var qpElem = new XmlSerializer(typeof(QualifyingPropertiesType))
            .ToXmlElement(qp, Xmlns);

        var dataObject = new ObjectType();
        dataObject.Any.Add(qpElem);

        signature.Object.Add(dataObject);

        // Add References.
        var elementsToSign = new[] { uri, keyInfo.Id, qp.SignedProperties.Id };
        foreach (var refId in elementsToSign)
        {
            // Create a reference to be signed.
            var reference = new ReferenceType
            {
                Uri = $"#{refId}",
                DigestMethod = new() { Algorithm = SignedXml.XmlDsigSHA256Url },
                DigestValue = Array.Empty<byte>() // dummy
            };

            // Only apply EnvelopedSignatureTransform to the document target reference
            if (refId == uri)
            {
                reference.Transforms.Add(new()
                {
                    Algorithm = SignedXml.XmlDsigEnvelopedSignatureTransformUrl
                });
            }

            reference.Transforms.Add(new()
            {
                Algorithm = SignedXml.XmlDsigExcC14NTransformUrl
            });

            if (refId == _signedPropertiesId)
            {
                reference.Type = "http://uri.etsi.org/01903#SignedProperties";
            }

            signature.SignedInfo.Reference.Add(reference);
        }

        var signatureElem = new XmlSerializer(typeof(SignatureType))
            .ToXmlElement(signature);

        doc.DocumentElement!.AppendChild(doc.ImportNode(signatureElem!, true));

        var signedXml = new SignedXml(doc)
        {
            SigningKey = _signer.GetRSAPrivateKey(),
        };

        signedXml.LoadXml(signatureElem!);

        // Compute the signature.
        signedXml.ComputeSignature();

        var newSignature = signedXml.GetXml();

        doc.ReplaceSignature(newSignature);

        return doc;
    }
}
