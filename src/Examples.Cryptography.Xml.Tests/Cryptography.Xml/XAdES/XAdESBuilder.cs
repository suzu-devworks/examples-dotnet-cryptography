using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.XAdES.XAdES132;
using Examples.Cryptography.Xml.XAdES.XmlDsig;

namespace Examples.Cryptography.Xml.XAdES;

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

    public XmlDocument Build(XmlDocument original, DateTime signingTime, string uri)
    {
        XmlDocument signed;
        if (_useGenerateClasses)
        {
            signed = SignXmlWithGenerated(original, signingTime, uri);
        }
        else
        {
            // Once to sign the target.
            var temporary = SignXml(original, signingTime, uri);

            // Process twice to sign KeyInfo and SignedProperties.
            signed = SignXml(temporary, signingTime, uri);
        }

        return signed;
    }

    private XmlDocument SignXml(XmlDocument original, DateTime signingTime, string uri)
    {
        var doc = CreateNewXmlDocument();
        doc.PreserveWhitespace = false;
        doc.LoadXml(original.OuterXml);

        // Add a Signature.
        SignedXml signedXml = CreateNewSignedXml(doc);
        // signedXml.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.SigningKey = _signer.GetRSAPrivateKey();

        // Add a KeyInfo.
        var keyInfo = new KeyInfo() { Id = "id-keyInfo" };
        keyInfo.AddClause(new KeyInfoX509Data(_signer, X509IncludeOption.EndCertOnly));

        signedXml.KeyInfo = keyInfo;

        // Add a Object.
        var qp = new QualifyingPropertiesType()
        {
            Id = "id-QualifyingProperties",
            Target = $"#{uri}",
            SignedProperties = new()
            {
                Id = "id-SignedProperties",
                SignedSignatureProperties = new SignedSignaturePropertiesType()
                {
                    SigningTime = signingTime,
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

        var dataObject = new DataObject
        {
            // remove XmlDeclaration
            Data = qpElem?.SelectNodes(".")!,
        };

        signedXml.AddObject(dataObject);

        // Add References.
        var idKeyUInfo = doc.SelectSingleNode($"//*[@Id='{keyInfo.Id}']")?.Attributes?["Id"]?.Value;
        var idSignedProperties = doc.SelectSingleNode($"//*[@Id='{qp.SignedProperties.Id}']")?.Attributes?["Id"]?.Value;

        var elementsToSign = new[] { uri, idKeyUInfo, idSignedProperties }.Where(x => x is not null);
        foreach (var refId in elementsToSign)
        {
            // Create a reference to be signed.
            var reference = new Reference(uri: $"#{refId}")
            {
                DigestMethod = SignedXml.XmlDsigSHA256Url,
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            if (refId == idSignedProperties)
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

    private SignedXml CreateNewSignedXml(XmlDocument doc)
    {
        return _createSignedXml?.Invoke(doc) ?? new SignedXml(doc);
    }

    private XmlDocument CreateNewXmlDocument()
    {
        return _createXmlDocument?.Invoke() ?? new XmlDocument();
    }

    private XmlDocument SignXmlWithGenerated(XmlDocument original, DateTime signingTime, string uri)
    {
        var doc = new XmlDocument()
        {
            PreserveWhitespace = false,
        };
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
        var keyInfo = new KeyInfoType() { Id = "id-keyInfo" }
            .AddX509Data(new X509DataType().AddX509Certificate(_signer));

        signature.KeyInfo = keyInfo;

        // Add a Object.
        var qp = new QualifyingPropertiesType()
        {
            Target = $"#{uri}",
            Id = "id-QualifyingProperties",
            SignedProperties = new()
            {
                Id = "id-SignedProperties",
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

            reference.Transforms.Add(new()
            {
                Algorithm = SignedXml.XmlDsigEnvelopedSignatureTransformUrl
            });

            reference.Transforms.Add(new()
            {
                Algorithm = SignedXml.XmlDsigExcC14NTransformUrl
            });

            if (refId == "id-SignedProperties")
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

    public XAdESBuilder UseGeneratedClasses(bool enabled = true)
    {
        _useGenerateClasses = enabled;

        return this;
    }
    private bool _useGenerateClasses;
}
