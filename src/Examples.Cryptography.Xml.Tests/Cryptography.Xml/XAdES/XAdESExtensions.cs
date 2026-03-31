
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Xml.XAdES.XAdES132;
using Examples.Cryptography.Xml.XAdES.XmlDsig;

namespace Examples.Cryptography.Xml.XAdES;

internal static class XAdESExtensions
{
    public static SignedSignaturePropertiesType AddSigningCertificateV2(this SignedSignaturePropertiesType source,
        CertIdTypeV2 certIdv2)
    {
        source.SigningCertificateV2.Add(certIdv2);

        return source;
    }

    public static KeyInfoType AddX509Data(this KeyInfoType source,
        X509DataType x509data)
    {
        source.X509Data.Add(x509data);

        return source;
    }

    public static X509DataType AddX509Certificate(this X509DataType source,
        X509Certificate2 cert)
    {
        source.X509Certificate.Add(cert.RawData);

        return source;
    }

    public static UnsignedSignaturePropertiesType AddSignatureTimeStamp(
        this UnsignedSignaturePropertiesType source, byte[] timestampToken)
    {
        source.SignatureTimeStamp.Add(new XAdEsTimeStampType
        {
            EncapsulatedTimeStamp = { new EncapsulatedPkiDataType { Value = timestampToken } }
        });

        return source;
    }

    public static UnsignedSignaturePropertiesType AddCompleteCertificateRefs(
        this UnsignedSignaturePropertiesType source,
        IEnumerable<X509Certificate2> chainCerts,
        HashAlgorithmName hashAlgorithm)
    {
        var certRefs = new CompleteCertificateRefsType();
        foreach (var cert in chainCerts)
        {
            certRefs.CertRefs.Add(new CertIdType
            {
                CertDigest = new DigestAlgAndValueType
                {
                    DigestMethod = new DigestMethodType
                    {
                        Algorithm = HashAlgorithmNameToXmlDsigUrl(hashAlgorithm)
                    },
                    DigestValue = cert.GetCertHash(hashAlgorithm),
                },
                IssuerSerial = new X509IssuerSerialType
                {
                    X509IssuerName = cert.Issuer,
                    X509SerialNumber = BigInteger.Parse("0" + cert.SerialNumber, NumberStyles.HexNumber).ToString(),
                }
            });
        }

        source.CompleteCertificateRefs.Add(certRefs);

        return source;
    }

    public static UnsignedSignaturePropertiesType AddCompleteRevocationRefs(
        this UnsignedSignaturePropertiesType source,
        IEnumerable<(byte[] CrlData, string Issuer, DateTime IssueTime)> crlInfos,
        HashAlgorithmName hashAlgorithm)
    {
        var revRefs = new CompleteRevocationRefsType();
        foreach (var (crlData, issuer, issueTime) in crlInfos)
        {
            revRefs.CrlRefs.Add(new CrlRefType
            {
                DigestAlgAndValue = new DigestAlgAndValueType
                {
                    DigestMethod = new DigestMethodType
                    {
                        Algorithm = HashAlgorithmNameToXmlDsigUrl(hashAlgorithm)
                    },
                    DigestValue = ComputeHash(crlData, hashAlgorithm),
                },
                CrlIdentifier = new CrlIdentifierType
                {
                    Issuer = issuer,
                    IssueTime = issueTime,
                }
            });
        }

        source.CompleteRevocationRefs.Add(revRefs);

        return source;
    }

    public static UnsignedSignaturePropertiesType AddCertificateValues(
        this UnsignedSignaturePropertiesType source,
        IEnumerable<X509Certificate2> certs)
    {
        var certValues = new CertificateValuesType();
        foreach (var cert in certs)
        {
            certValues.EncapsulatedX509Certificate.Add(new EncapsulatedPkiDataType
            {
                Value = cert.RawData
            });
        }

        source.CertificateValues.Add(certValues);

        return source;
    }

    public static UnsignedSignaturePropertiesType AddRevocationValues(
        this UnsignedSignaturePropertiesType source,
        IEnumerable<byte[]> crlDataList)
    {
        var revValues = new RevocationValuesType();
        foreach (var crlData in crlDataList)
        {
            revValues.CrlValues.Add(new EncapsulatedPkiDataType
            {
                Value = crlData
            });
        }

        source.RevocationValues.Add(revValues);

        return source;
    }

    public static UnsignedSignaturePropertiesType AddArchiveTimeStamp(
        this UnsignedSignaturePropertiesType source, byte[] timestampToken)
    {
        source.ArchiveTimeStamp.Add(new XAdEsTimeStampType
        {
            EncapsulatedTimeStamp = { new EncapsulatedPkiDataType { Value = timestampToken } }
        });

        return source;
    }

    public static UnsignedSignaturePropertiesType AddSigAndRefsTimeStamp(
        this UnsignedSignaturePropertiesType source, byte[] timestampToken)
    {
        source.SigAndRefsTimeStamp.Add(new XAdEsTimeStampType
        {
            EncapsulatedTimeStamp = { new EncapsulatedPkiDataType { Value = timestampToken } }
        });

        return source;
    }

    public static UnsignedSignaturePropertiesType AddRefsOnlyTimeStamp(
        this UnsignedSignaturePropertiesType source, byte[] timestampToken)
    {
        source.RefsOnlyTimeStamp.Add(new XAdEsTimeStampType
        {
            EncapsulatedTimeStamp = { new EncapsulatedPkiDataType { Value = timestampToken } }
        });

        return source;
    }

    private static string HashAlgorithmNameToXmlDsigUrl(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            "SHA256" => System.Security.Cryptography.Xml.SignedXml.XmlDsigSHA256Url,
            "SHA384" => System.Security.Cryptography.Xml.SignedXml.XmlDsigSHA384Url,
            "SHA512" => System.Security.Cryptography.Xml.SignedXml.XmlDsigSHA512Url,
            _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported."),
        };
    }

    private static byte[] ComputeHash(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported."),
        };
    }

}
