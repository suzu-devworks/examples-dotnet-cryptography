using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;

namespace Examples.Cryptography.Tests.Helpers;

/// <summary>
/// Helper for creating test certificates.
/// </summary>
public static class TestCertificateFactory
{
    public static X509Certificate2 CreateSelfSigned(
        X500DistinguishedName subject,
        DateTime notBefore,
        int days = 1)
    {
        var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var req = new CertificateRequest(
            subject,
            keyPair,
            HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension();

        var notAfter = notBefore.AddDays(days);

        // Self signed X509Certificate2 has a private key.
        return req.CreateSelfSigned(notBefore, notAfter);
    }
}
