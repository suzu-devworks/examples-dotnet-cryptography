using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Xml.XAdES.XAdES132;
using Examples.Cryptography.Xml.XAdES.XmlDsig;

namespace Examples.Cryptography.Xml;

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

}
