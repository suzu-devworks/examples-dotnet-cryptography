using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates;

public static class CertificateRequestExtensions
{
    public static X509Certificate2 Create(this CertificateRequest request,
        X500DistinguishedName issuerName,
        AsymmetricAlgorithm issuerKeyPair,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        byte[] serialNumber)
    {
        var generator = (issuerKeyPair is ECDsa dsa)
            ? X509SignatureGenerator.CreateForECDsa(dsa)
            : X509SignatureGenerator.CreateForRSA((RSA)issuerKeyPair, RSASignaturePadding.Pkcs1);

        var newCertificate = request.Create(issuerName, generator,
            notBefore, notAfter, serialNumber);

        return newCertificate;
    }

    public static CertificateRequest AddExtension(this CertificateRequest req,
        X509Extension extension)
    {
        req.CertificateExtensions.Add(extension);

        return req;
    }

    /// <summary>
    /// RFC 5280 4.2.1.1. Authority Key Identifier
    /// </summary>
    /// <param name="req"></param>
    /// <param name="issuer"></param>
    /// <param name="includeKeyIdentifier"></param>
    /// <param name="includeIssuerAndSerial"></param>
    /// <returns></returns>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-1-1--Authority-Key-Identifier" />
    public static CertificateRequest AddAuthorityKeyIdentifierExtension(this CertificateRequest req,
        X509Certificate2 issuer,
        bool includeKeyIdentifier = true,
        bool includeIssuerAndSerial = true)
    {
        // authorityKeyIdentifier   = keyid, issuer

        return req.AddExtension(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                issuer, includeKeyIdentifier, includeIssuerAndSerial));
    }

    /// <summary>
    /// RFC 5280 4.2.1.2. Subject Key Identifier
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-1-2--Subject-Key-Identifier" />
    public static CertificateRequest AddSubjectKeyIdentifierExtension(this CertificateRequest req)
    {
        // subjectKeyIdentifier     = hash

        return req.AddExtension(
            new X509SubjectKeyIdentifierExtension(
                key: req.PublicKey,
                algorithm: X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                critical: false));
    }

    /// <summary>
    /// RFC 5280 4.2.1.3. Key Usage
    /// </summary>
    /// <param name="req"></param>
    /// <param name="critical"></param>
    /// <param name="flags"></param>
    /// <returns></returns>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-1-3--Key-Usage" />
    public static CertificateRequest AddKeyUsageExtension(this CertificateRequest req,
        bool critical,
        X509KeyUsageFlags flags = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)
    {
        // keyUsage                = critical, keyCertSign, cRLSign

        return req.AddExtension(
            new X509KeyUsageExtension(flags, critical));
    }

    /// <summary>
    /// RFC 5280 4.2.1.6. Subject Alternative Name
    /// </summary>
    /// <param name="req"></param>
    /// <param name="action"></param>
    /// <returns></returns>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-1-6--Subject-Alternative-Name" />
    public static CertificateRequest AddSubjectAlternativeName(this CertificateRequest req,
        Action<SubjectAlternativeNameBuilder> action)
    {
        // subjectAltName           = @alt_names
        //
        // [ alt_names ]
        // DNS.1 = www.local-server.jp
        // DNS.2 = localserver.jp

        var builder = new SubjectAlternativeNameBuilder();
        action?.Invoke(builder);
        return req.AddExtension(builder.Build());
    }

    /// <summary>
    /// RFC 5280 4.2.1.9. Basic Constraints
    /// </summary>
    /// <param name="req"></param>
    /// <param name="critical"></param>
    /// <param name="isCa"></param>
    /// <param name="pathLengthConstraint"></param>
    /// <returns></returns>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-1-9--Basic-Constraints" />
    [Obsolete(message: "Use req.AddExtension() with X509BasicConstraintsExtension static factories.")]
    public static CertificateRequest AddBasicConstraintsExtension(this CertificateRequest req,
        bool critical = false,
        bool isCa = true,
        int? pathLengthConstraint = null)
    {
        // basicConstraints         = critical, CA:true

        return req.AddExtension(
            new X509BasicConstraintsExtension(
                isCa,
                pathLengthConstraint != null,
                pathLengthConstraint ?? 0,
                critical
            ));
    }

    /// <summary>
    /// RFC 5280 4.2.1.12. Extended Key Usage
    /// </summary>
    /// <param name="req"></param>
    /// <param name="action"></param>
    /// <returns></returns>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-1-12--Extended-Key-Usage" />
    public static CertificateRequest AddExtendedKeyUsageExtension(this CertificateRequest req,
        bool critical,
        Action<OidCollection> action)
    {
        // extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection

        var exKeyUsages = new OidCollection();
        action?.Invoke(exKeyUsages);

        return req.AddExtension(
            new X509EnhancedKeyUsageExtension(exKeyUsages, critical));
    }

    /// <summary>
    /// RFC 5280 4.2.1.13. CRL Distribution Points
    /// </summary>
    /// <param name="req"></param>
    /// <param name="action"></param>
    /// <returns></returns>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-1-13--CRL-Distribution-Points" />
    public static CertificateRequest AddCRLDistributionPointsExtension(this CertificateRequest req,
        Action<object> action)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// RFC 5280 4.2.2.1. Authority Information Access
    /// </summary>
    /// <param name="req"></param>
    /// <value></value>
    /// <seealso href="https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-2-2-1--Authority-Information-Access" />
    public static CertificateRequest AddAuthorityInformationAccessExtension(this CertificateRequest req)
    {
        throw new NotImplementedException();
    }

}
