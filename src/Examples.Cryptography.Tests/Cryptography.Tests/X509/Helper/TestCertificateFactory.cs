using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509.Helper;

public static class TestCertificateFactory
{
    public static X509Certificate2 CreateSelfSignedEntity(X500DistinguishedName subject, DateTime notBefore, int days = 1)
    {
        var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var req = new CertificateRequest(
            subject,
            keyPair,
            HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension()
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity());

        var notAfter = notBefore.AddDays(days);

        // Self signed X509Certificate2 has a private key.
        return req.CreateSelfSigned(notBefore, notAfter);
    }

    public static X509Certificate2 GetStatic()
    {
        // spell-checker: disable
        const string FROM_OPENSSL_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIBhjCCASugAwIBAgIUS8FIrjsJFGzqL1i8GhrJAapcW8UwCgYIKoZIzj0EAwIw
            GDEWMBQGA1UEAwwNeDUwOS5leGFtcGxlczAeFw0yNTA2MTgxMzEwNDJaFw0yNjA2
            MTgxMzEwNDJaMBgxFjAUBgNVBAMMDXg1MDkuZXhhbXBsZXMwWTATBgcqhkjOPQIB
            BggqhkjOPQMBBwNCAAQX2e9lenpiHxnYKGbRy1ooBDoOogp2bTudFwXCQMzyuexf
            1FfvL2zdgPXgIALDAOiqKT/SXkp1GVFREf1cKkBRo1MwUTAdBgNVHQ4EFgQU3iRe
            fDTG87ENA6TthL+PxU0nO9MwHwYDVR0jBBgwFoAU3iRefDTG87ENA6TthL+PxU0n
            O9MwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA6DOwFSGs2ltC
            U2T1pcVK3nU85AwKclt+Pr8QIKIUm/wCIQDyEYGAzH3Huk3V2Qq3asRBQr+zF2+4
            18Z9ErXD+Xh37Q==
            -----END CERTIFICATE-----
            """;
        // spell-checker: enable

        var loaded = X509Certificate2.CreateFromPem(FROM_OPENSSL_PEM);

        Assert.Equal("CEB765689BE077B587666897ADBB4E92A88FA0AE", loaded.Thumbprint);

        return loaded;
    }
}
