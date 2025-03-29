using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Generics;

namespace Examples.Cryptography.Tests.Xml;

public class XmlFixture : IDisposable
{
    public XmlFixture()
    {
        var notBefore = DateTimeOffset.Now.AddDays(-2);

        _rsaSignerSet = new(() => InitializeRSASigner(notBefore));
        _ecdsaSignerSet = new(() => InitializeECDsaSigner(notBefore));
    }

    public X509Certificate2 RSASigner => _rsaSignerSet.Value;
    private readonly Lazy<X509Certificate2> _rsaSignerSet;

    public X509Certificate2 ECDsaSigner => _ecdsaSignerSet.Value;
    private readonly Lazy<X509Certificate2> _ecdsaSignerSet;


    public void Dispose()
    {
        _rsaSignerSet.DisposeIfValueCreated();
        _ecdsaSignerSet.DisposeIfValueCreated();
        GC.SuppressFinalize(this);
    }

    private static X509Certificate2 InitializeRSASigner(
      DateTimeOffset notBefore,
      int days = 365)
    {
        var notAfter = notBefore.AddDays(days);

        // X509Certificate2 has a private key.
        using var rsa = RSA.Create(3072);

        X509Certificate2 cert = new CertificateRequest(
                subjectName: "CN=test",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(notBefore, notAfter);

        return cert;
    }

    private static X509Certificate2 InitializeECDsaSigner(
      DateTimeOffset notBefore,
      int days = 365)
    {
        var notAfter = notBefore.AddDays(days);

        // X509Certificate2 has a private key.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        X509Certificate2 cert = new CertificateRequest(
                subjectName: "CN=test",
                ecdsa,
                HashAlgorithmName.SHA256)
            .CreateSelfSigned(notBefore, notAfter);

        return cert;
    }

}
