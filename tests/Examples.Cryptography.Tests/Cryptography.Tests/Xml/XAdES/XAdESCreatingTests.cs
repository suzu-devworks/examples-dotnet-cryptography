using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using Examples.Cryptography.Generics;
using Examples.Cryptography.Xml;
using Examples.Cryptography.Xml.XAdES.XAdES132;
using Examples.Cryptography.Xml.XAdES.XmlDsig;
using Xunit.Sdk;

namespace Examples.Cryptography.Tests.Xml.XAdES;

public class XAdESCreatingTests : IClassFixture<XmlDataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly XmlDataFixture _fixture;

    private readonly DateTime _signedTime;

    public XAdESCreatingTests(XmlDataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;
        _fixture = fixture;

        // _signedTime = DateTime.Parse("2023-12-01T12:34:56").ToUniversalTime();
        _signedTime = DateTime.UtcNow;
    }


    [Fact]
    public void WhenCreatingXAdES_ReturnsAsExpected()
    {
        X509Certificate2 signer = _fixture.RSASigner;

        var original = CreateSomeXml();
        _output.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original!.ToFormattedOuterXml()}{Environment.NewLine}");

        // ===== Without prefix =====
        var signed = new Builder(signer, _output)
            .Build(original, _signedTime, "id-target");

        _output.WriteLine($@"[Signed XML]:{Environment.NewLine}" +
            $"{signed!.ToFormattedOuterXml()}{Environment.NewLine}");

        var result = VerifySignature(signed, signer);
        result.IsTrue("The XML signature is not valid.");

        return;
    }


    [Fact]
    public void WhenCreatingXAdES_WithPrefixedSignedXml_ReturnsAsExpected()
    {
        X509Certificate2 signer = _fixture.RSASigner;

        var original = CreateSomeXml();
        _output.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original!.ToFormattedOuterXml()}{Environment.NewLine}");

        // ===== Use Custom SignedXML =====
        var signed = new Builder(signer, _output)
            .WithCustomSignedXml(doc => new PrefixedSignedXml(doc, "ds"))
            .Build(original, _signedTime, "id-target");

        _output.WriteLine($@"[Signed XML]:{Environment.NewLine}" +
            $"{signed!.ToFormattedOuterXml()}{Environment.NewLine}");

        var result = VerifySignature(signed, signer);
        result.IsTrue("The XML signature is not valid.");

        return;
    }


    [Fact]
    public void WhenCreatingXAdES_WithXmlDsigDocument_ReturnsAsExpected()
    {
        X509Certificate2 signer = _fixture.RSASigner;

        var original = CreateSomeXml();
        _output.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original!.ToFormattedOuterXml()}{Environment.NewLine}");

        // ===== Use Custom XmlDocument  =====
        // However, the presence of the "ds" prefix within "SignedInfo"
        // and its descendants causes the signing to fail.
        var signed = new Builder(signer, _output)
            .WithCustomXmlDocument(() => new XmlDsigDocument())
            .Build(original, _signedTime, "id-target");

        _output.WriteLine($@"[Signed XML]:{Environment.NewLine}" +
            $"{signed!.ToFormattedOuterXml()}{Environment.NewLine}");

        var result = VerifySignature(signed, signer);
        result.IsTrue("The XML signature is not valid.");

        return;
    }


    [Fact]
    public void WhenCreatingXAdES_WithXsdGeneratedClass_ReturnsAsExpected()
    {
        X509Certificate2 signer = _fixture.RSASigner;

        var original = CreateSomeXml();
        _output.WriteLine($"[Original XML]:{Environment.NewLine}" +
            $"{original!.ToFormattedOuterXml()}{Environment.NewLine}");

        // ===== Use Generated classes  =====
        // However, the presence of the "ds" prefix within "SignedInfo"
        // and its descendants causes the signing to fail.
        var signed = new Builder(signer, _output)
            .UseGeneratedClasses()
            .Build(original, _signedTime, "id-target");

        _output.WriteLine($@"[Signed XML]:{Environment.NewLine}" +
            $"{signed!.ToFormattedOuterXml()}{Environment.NewLine}");

        var result = VerifySignature(signed, signer);
        result.IsTrue("The XML signature is not valid.");

        return;


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

        var document = new XmlDocument().Configure(doc =>
        {
            doc.PreserveWhitespace = false;
            doc.LoadXml(xdom.ToString());
        });

        return document;
    }


    private static bool VerifySignature(XmlDocument signed, X509Certificate2 signer)
    {
        var document = new XmlDocument()
        {
            PreserveWhitespace = false,
        };
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
            throw new XunitException("Invalid signature.");
        }

        return signedXml.CheckSignature();
    }


    private static XmlNode? SelectSignatureNode(XmlDocument document)
    {
        var nsManager = new XmlNamespaceManager(document.NameTable);
        nsManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

        var node = document.SelectNodes("//ds:Signature", nsManager)
            ?.Cast<XmlNode>()
            .FirstOrDefault();

        return node;
    }

    private static void ReplaceSignature(XmlDocument doc, XmlElement newSignature)
    {
        var oldSignature = SelectSignatureNode(doc);
        if (oldSignature is not null)
        {
            var parent = oldSignature?.ParentNode ?? doc.DocumentElement;
            parent!.RemoveChild(oldSignature!);
        }
        doc.DocumentElement!.AppendChild(doc.ImportNode(newSignature, true));
    }


    private sealed class Builder
    {
        private readonly ITestOutputHelper _output;
        private readonly X509Certificate2 _signer;
        private readonly XmlSerializerNamespaces _xmlns;

        public Builder(X509Certificate2 signer, ITestOutputHelper output)
        {
            _output = output;
            _signer = signer;

            var ns = new XmlSerializerNamespaces();
            ns.Add("ds", SignedXml.XmlDsigNamespaceUrl);
            ns.Add("xa", "http://uri.etsi.org/01903/v1.3.2#");
            ns.Add("xa141", "http://uri.etsi.org/01903/v1.4.1#");
            _xmlns = ns;
        }

        public XmlDocument Build(XmlDocument original, DateTime signingTime, string uri)
        {
            XmlDocument signed;
            if (_useGenerateClasses)
            {
                signed = SignXmlWithGenerated(original, signingTime, uri);
            }
            else
            {
                // Process twice to sign KeyInfo and SignedProperties.
                var temporary = SignXml(original, signingTime, uri);

                // _output.WriteLine($"Temporary:{Environment.NewLine}" +
                //     $"{temporary!.ToFormattedOuterXml()}{Environment.NewLine}");

                signed = SignXml(temporary, signingTime, uri);

            }

            return signed;
        }

        private XmlDocument SignXml(XmlDocument original, DateTime signingTime, string uri)
        {
            var doc = _createXmlDocument?.Invoke() ?? new XmlDocument()
            {
                PreserveWhitespace = false,
            };
            doc.LoadXml(original.OuterXml);

            var signer = _signer;

            // Add a Signature.
            dynamic signedXml = _createSignedXml?.Invoke(doc) ?? new SignedXml(doc);
            // signedXml.CanonicalizationMethod = SignedXml.XmlDsigCanonicalizationUrl;
            // signedXml.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
            signedXml.SigningKey = signer.GetRSAPrivateKey();

            // Add a KeyInfo.
            var keyInfo = new KeyInfo() { Id = "id-keyInfo" };
            keyInfo.AddClause(new KeyInfoX509Data(signer, X509IncludeOption.EndCertOnly));

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
                            DigestValue = signer.GetCertHash(HashAlgorithmName.SHA256),
                        }
                    })
                }
            };

            var qpElem = new XmlSerializer(typeof(QualifyingPropertiesType))
                .ToXmlElement(qp, _xmlns);

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

                if (refId == "id-SignedProperties")
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

            ReplaceSignature(doc, newSignature);

            return doc;
        }

        private XmlDocument SignXmlWithGenerated(XmlDocument original, DateTime signingTime, string uri)
        {
            var doc = new XmlDocument()
            {
                PreserveWhitespace = false,
            };
            doc.LoadXml(original.OuterXml);

            var signer = _signer;

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
                .AddX509Data(new X509DataType().AddX509Certificate(signer));

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
                            DigestValue = signer.GetCertHash(HashAlgorithmName.SHA256),
                        }
                    })
                }
            };

            var qpElem = new XmlSerializer(typeof(QualifyingPropertiesType))
                .ToXmlElement(qp, _xmlns);

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
                SigningKey = signer.GetRSAPrivateKey(),
            };

            signedXml.LoadXml(signatureElem!);

            // Compute the signature.
            signedXml.ComputeSignature();

            var newSignature = signedXml.GetXml();

            ReplaceSignature(doc, newSignature);

            return doc;
        }

        public Builder WithCustomSignedXml(Func<XmlDocument, SignedXml> generator)
        {
            _createSignedXml = generator;

            return this;
        }
        private Func<XmlDocument, SignedXml>? _createSignedXml;

        public Builder WithCustomXmlDocument(Func<XmlDocument> generator)
        {
            _createXmlDocument = generator;

            return this;
        }
        private Func<XmlDocument>? _createXmlDocument;

        public Builder UseGeneratedClasses(bool enabled = true)
        {
            _useGenerateClasses = enabled;

            return this;
        }
        private bool _useGenerateClasses;
    }


}

