using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;
using Examples.Cryptography.Xml.Extensions;
using Examples.Cryptography.Xml.XAdES.XAdES132;
using Examples.Cryptography.Xml.XAdES.XmlDsig;

namespace Examples.Cryptography.Xml.XAdES.SchemaBased;

/// <summary>
/// Builds XAdES signatures using XSD schema-generated types.
/// Supports XAdES-BES, XAdES-T, XAdES-C, XAdES-X, XAdES-X-L, and XAdES-A levels.
/// </summary>
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

    // XAdES-T: signature timestamp
    private ITsaClient? _signatureTsaClient;
    private HashAlgorithmName _signatureTsaHashAlgorithm = HashAlgorithmName.SHA256;

    // XAdES-C: certificate chain and revocation refs (digests only)
    private X509Certificate2Collection? _certChain;
    private IReadOnlyList<(byte[] CrlData, string Issuer, DateTime IssueTime)>? _revocationRefs;

    // XAdES-X: extended timestamp (SigAndRefsTimeStamp or RefsOnlyTimeStamp)
    private ITsaClient? _xTsaClient;
    private HashAlgorithmName _xTsaHashAlgorithm = HashAlgorithmName.SHA256;
    private bool _xUseRefsOnly;

    // XAdES-X-L: revocation values (embedded DER data)
    private IReadOnlyList<byte[]>? _revocationValues;

    // XAdES-A: archive timestamp
    private ITsaClient? _archiveTsaClient;
    private HashAlgorithmName _archiveTsaHashAlgorithm = HashAlgorithmName.SHA256;

    /// <summary>
    /// Configures a TSA client for XAdES-T (adds SignatureTimeStamp to UnsignedProperties).
    /// </summary>
    public XAdESBuilder WithSignatureTimestamp(
        ITsaClient tsaClient,
        HashAlgorithmName hashAlgorithm = default)
    {
        _signatureTsaClient = tsaClient;
        if (hashAlgorithm != default)
        {
            _signatureTsaHashAlgorithm = hashAlgorithm;
        }

        return this;
    }

    /// <summary>
    /// Configures the CA certificate chain for XAdES-C (adds CompleteCertificateRefs).
    /// Provide intermediate and root CA certificates; the signer cert is handled separately.
    /// </summary>
    public XAdESBuilder WithCertificateChain(X509Certificate2Collection chain)
    {
        _certChain = chain;
        return this;
    }

    /// <summary>
    /// Configures CRL data references for XAdES-C (adds CompleteRevocationRefs).
    /// Each entry contains the raw CRL DER bytes plus issuer and issue time for identification.
    /// </summary>
    public XAdESBuilder WithRevocationRefs(
        IReadOnlyList<(byte[] CrlData, string Issuer, DateTime IssueTime)> crlInfos)
    {
        _revocationRefs = crlInfos;
        return this;
    }

    /// <summary>
    /// Configures a TSA client for XAdES-X (adds an extended timestamp to UnsignedProperties).
    /// <para>
    /// XAdES-X Type 1 (default, <paramref name="refsOnly"/> = false) adds <c>SigAndRefsTimeStamp</c>,
    /// which timestamps the SignatureValue together with the complete-refs elements.
    /// XAdES-X Type 2 (<paramref name="refsOnly"/> = true) adds <c>RefsOnlyTimeStamp</c>,
    /// which timestamps only the complete-refs elements.
    /// </para>
    /// </summary>
    public XAdESBuilder WithXTimestamp(
        ITsaClient tsaClient,
        HashAlgorithmName hashAlgorithm = default,
        bool refsOnly = false)
    {
        _xTsaClient = tsaClient;
        if (hashAlgorithm != default)
        {
            _xTsaHashAlgorithm = hashAlgorithm;
        }

        _xUseRefsOnly = refsOnly;
        return this;
    }

    /// <summary>
    /// Configures embedded CRL values for XAdES-X-L (adds RevocationValues).
    /// </summary>
    public XAdESBuilder WithRevocationValues(IReadOnlyList<byte[]> crlDataList)
    {
        _revocationValues = crlDataList;
        return this;
    }

    /// <summary>
    /// Configures a TSA client for XAdES-A (adds ArchiveTimeStamp to UnsignedProperties).
    /// </summary>
    public XAdESBuilder WithArchiveTimestamp(
        ITsaClient tsaClient,
        HashAlgorithmName hashAlgorithm = default)
    {
        _archiveTsaClient = tsaClient;
        if (hashAlgorithm != default)
        {
            _archiveTsaHashAlgorithm = hashAlgorithm;
        }

        return this;
    }

    /// <summary>
    /// Builds the XAdES-signed document, optionally adding XAdES-T/C/X/X-L/A properties.
    /// </summary>
    public XmlDocument Build(XmlDocument original, DateTime signingTime, string uri)
    {
        // Step 1: Build XAdES-BES (core signature with SignedProperties)
        var doc = BuildBes(original, signingTime, uri);

        // Step 2 onwards: build UnsignedProperties if any upgrade is requested
        bool hasUnsigned = _signatureTsaClient is not null
            || _certChain is not null
            || _revocationRefs is not null
            || _xTsaClient is not null
            || _revocationValues is not null
            || _archiveTsaClient is not null;

        if (!hasUnsigned)
        {
            return doc;
        }

        var unsignedSigProps = new UnsignedSignaturePropertiesType();

        // XAdES-T: add SignatureTimeStamp
        if (_signatureTsaClient is not null)
        {
            var sigValueBytes = GetSignatureValueBytes(doc);
            var hash = ComputeHash(sigValueBytes, _signatureTsaHashAlgorithm);
            var token = _signatureTsaClient.GetTimestampToken(hash, _signatureTsaHashAlgorithm);
            unsignedSigProps.AddSignatureTimeStamp(token);
        }

        // XAdES-C: add CompleteCertificateRefs
        if (_certChain is not null)
        {
            unsignedSigProps.AddCompleteCertificateRefs(
                _certChain.Cast<X509Certificate2>(),
                HashAlgorithmName.SHA256);
        }

        // XAdES-C: add CompleteRevocationRefs
        if (_revocationRefs is not null)
        {
            unsignedSigProps.AddCompleteRevocationRefs(
                _revocationRefs,
                HashAlgorithmName.SHA256);
        }

        // XAdES-X: add SigAndRefsTimeStamp (Type 1) or RefsOnlyTimeStamp (Type 2)
        // NOTE: Per ETSI TS 101 903, a conforming implementation should hash only the
        // canonicalized SignatureValue + CompleteCertificateRefs + CompleteRevocationRefs
        // elements (Type 1), or just the refs (Type 2). Here, the entire document is used
        // as input for simplicity, which is sufficient for structural / learning tests
        // using a mock TSA that does not validate the hash imprint.
        if (_xTsaClient is not null)
        {
            var docBytes = System.Text.Encoding.UTF8.GetBytes(doc.OuterXml);
            var hash = ComputeHash(docBytes, _xTsaHashAlgorithm);
            var token = _xTsaClient.GetTimestampToken(hash, _xTsaHashAlgorithm);
            if (_xUseRefsOnly)
            {
                unsignedSigProps.AddRefsOnlyTimeStamp(token);
            }
            else
            {
                unsignedSigProps.AddSigAndRefsTimeStamp(token);
            }
        }

        // XAdES-X-L: add CertificateValues
        if (_certChain is not null)
        {
            unsignedSigProps.AddCertificateValues(_certChain.Cast<X509Certificate2>());
        }

        // XAdES-X-L: add RevocationValues
        if (_revocationValues is not null)
        {
            unsignedSigProps.AddRevocationValues(_revocationValues);
        }

        // XAdES-A: add ArchiveTimeStamp
        if (_archiveTsaClient is not null)
        {
            var docBytes = System.Text.Encoding.UTF8.GetBytes(doc.OuterXml);
            var hash = ComputeHash(docBytes, _archiveTsaHashAlgorithm);
            var token = _archiveTsaClient.GetTimestampToken(hash, _archiveTsaHashAlgorithm);
            unsignedSigProps.AddArchiveTimeStamp(token);
        }

        AppendUnsignedProperties(doc, unsignedSigProps);

        return doc;
    }

    /// <summary>
    /// Builds the XAdES-BES (Basic Electronic Signature) core document.
    /// Produces a W3C XML-DSig signature containing SignedProperties with
    /// SigningTime and SigningCertificateV2, which together constitute the BES level.
    /// </summary>
    private XmlDocument BuildBes(XmlDocument original, DateTime signingTime, string uri)
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

    private static byte[] GetSignatureValueBytes(XmlDocument doc)
    {
        var nsManager = new XmlNamespaceManager(doc.NameTable);
        nsManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

        var sigValueNode = doc.SelectSingleNode("//ds:SignatureValue", nsManager)
            ?? throw new InvalidOperationException("SignatureValue element not found.");

        return Convert.FromBase64String(sigValueNode.InnerText.Trim());
    }

    private static byte[] ComputeHash(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => SHA256.HashData(data),
        };
    }

    private void AppendUnsignedProperties(
        XmlDocument doc,
        UnsignedSignaturePropertiesType unsignedSigProps)
    {
        var nsManager = new XmlNamespaceManager(doc.NameTable);
        nsManager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");

        var qpNode = doc.SelectSingleNode($"//xa:QualifyingProperties[@Id='{_qualifyingPropertiesId}']", nsManager)
            ?? throw new InvalidOperationException("QualifyingProperties element not found.");

        var unsignedProps = new UnsignedPropertiesType
        {
            UnsignedSignatureProperties = unsignedSigProps
        };

        var upElem = new XmlSerializer(typeof(UnsignedPropertiesType))
            .ToXmlElement(unsignedProps, Xmlns);

        qpNode.AppendChild(doc.ImportNode(upElem!, true));
    }
}
