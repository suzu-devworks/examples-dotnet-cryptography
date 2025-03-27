using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Extension methods for <see cref="CertificateRequest" />.
/// </summary>
public static class CertificateRequestExtensions
{
    /// <summary>
    /// Creates <see cref="X509Certificate2" /> instance from <see cref="CertificateRequest" />.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="issuerName">The <see cref="X500DistinguishedName" /> for the issuer.</param>
    /// <param name="issuerKeyPair">The issuer key pair.</param>
    /// <param name="notBefore">The oldest date and time when this certificate is considered valid.</param>
    /// <param name="notAfter">The date and time when this certificate is no longer considered valid.</param>
    /// <param name="serialNumber">The serial number to use for the new certificate.</param>
    /// <returns>A <see cref="X509Certificate2" /> instance.</returns>
    public static X509Certificate2 CreateCertificate(this CertificateRequest request,
        X500DistinguishedName issuerName,
        AsymmetricAlgorithm issuerKeyPair,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        byte[] serialNumber)
    {
        var generator = issuerKeyPair switch
        {
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            _ => throw new NotSupportedException($"not supported {issuerKeyPair?.GetType().ToString()
                ?? "issuerKeyPair is null"}."),
        };

        var newCertificate = request.Create(issuerName, generator,
            notBefore, notAfter, serialNumber);

        return newCertificate;
    }

    /// <summary>
    /// Adds X.509 v3 extensions to <see cref="CertificateRequest" />.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="extension">The <see cref="X509Extension" /> instance.</param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    public static CertificateRequest AddExtension(this CertificateRequest request,
        X509Extension extension)
    {
        request.CertificateExtensions.Add(extension);

        return request;
    }

    /// <summary>
    /// Gets X.509 v3 extensions from <see cref="CertificateRequest" />.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <typeparam name="T">The derived class of <see cref="X509Extension" />.</typeparam>
    /// <returns>An extension entry.</returns>
    public static T? GetExtension<T>(this CertificateRequest request)
        where T : X509Extension
    {
        return request.CertificateExtensions.FirstOrDefault(x => x is T) as T;
    }

    /// <summary>
    /// Adds RFC 5280 4.2.1.1. Authority Key Identifier.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="issuer">The issuer certificate.</param>
    /// <param name="includeKeyIdentifier">True to include the Subject Key Identifier value from the certificate
    ///     as the key identifier value in this extension; otherwise, false.</param>
    /// <param name="includeIssuerAndSerial">True to include the certificate's issuer name and serial number
    ///     in this extension; otherwise, false.</param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1" />
    public static CertificateRequest AddAuthorityKeyIdentifierExtension(this CertificateRequest request,
        X509Certificate2? issuer = null,
        bool includeKeyIdentifier = true,
        bool includeIssuerAndSerial = false)
    {
        // ```openssl.conf
        // authorityKeyIdentifier   = keyid, issuer
        // ```
        // spell-checker: words keyid

        if (issuer is null)
        {
            var subject = request.GetExtension<X509SubjectKeyIdentifierExtension>()
                ?? throw new InvalidOperationException("X509SubjectKeyIdentifierExtension is required first.");

            return request.AddExtension(
                X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subject!.SubjectKeyIdentifierBytes.Span)
                );
        }

        return request.AddExtension(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                issuer!, includeKeyIdentifier, includeIssuerAndSerial));
    }

    /// <summary>
    /// Adds RFC 5280 4.2.1.2. Subject Key Identifier.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2" />
    public static CertificateRequest AddSubjectKeyIdentifierExtension(this CertificateRequest request)
    {
        // ```openssl.conf
        // subjectKeyIdentifier     = hash
        // ```

        return request.AddExtension(
            new X509SubjectKeyIdentifierExtension(
                key: request.PublicKey,
                algorithm: X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                critical: false));
    }

    /// <summary>
    /// Adds RFC 5280 4.2.1.3. Key Usage.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="critical">True if the extension is critical; otherwise, false.</param>
    /// <param name="flags">One of the <see cref="X509KeyUsageFlags" /> values.</param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3" />
    public static CertificateRequest AddKeyUsageExtension(this CertificateRequest request,
        bool critical,
        X509KeyUsageFlags flags = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)
    {
        // ```openssl.conf
        // keyUsage                = critical, keyCertSign, cRLSign
        // ```

        return request.AddExtension(
            new X509KeyUsageExtension(flags, critical));
    }

    /// <summary>
    /// Adds RFC 5280 4.2.1.6. Subject Alternative Name.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="action">The delegate method for configuration.</param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6" />
    public static CertificateRequest AddSubjectAlternativeName(this CertificateRequest request,
        Action<SubjectAlternativeNameBuilder> action)
    {
        // ```openssl.conf
        // subjectAltName           = @alt_names
        //
        // [ alt_names ]
        // DNS.1 = www.local-server.jp
        // DNS.2 = localserver.jp
        // ```
        // spell-checker: words localserver

        var builder = new SubjectAlternativeNameBuilder();
        action?.Invoke(builder);

        return request.AddExtension(builder.Build());
    }

    /// <summary>
    /// Adds RFC 5280 4.2.1.9. Basic Constraints.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="critical"></param>
    /// <param name="isCa"></param>
    /// <param name="pathLengthConstraint"></param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9" />
    [Obsolete(message: "Use req.AddExtension() with X509BasicConstraintsExtension static factories.")]
    public static CertificateRequest AddBasicConstraintsExtension(this CertificateRequest request,
        bool critical = false,
        bool isCa = true,
        int? pathLengthConstraint = null)
    {
        // ```openssl.conf
        // basicConstraints         = critical, CA:true
        // ```

        return request.AddExtension(
            new X509BasicConstraintsExtension(
                isCa,
                pathLengthConstraint != null,
                pathLengthConstraint ?? 0,
                critical
            ));
    }

    /// <summary>
    /// Adds RFC 5280 4.2.1.12. Extended Key Usage.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="action">The delegate method for configuration.</param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12" />
    public static CertificateRequest AddExtendedKeyUsageExtension(this CertificateRequest request,
        bool critical,
        Action<OidCollection> action)
    {
        // ```openssl.conf
        // extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
        // ```

        var extendedKeyUsages = new OidCollection();
        action?.Invoke(extendedKeyUsages);

        return request.AddExtension(
            new X509EnhancedKeyUsageExtension(extendedKeyUsages, critical));
    }

    /// <summary>
    /// Adds RFC 5280 4.2.1.13. CRL Distribution Points.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <param name="action"></param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13" />
    public static CertificateRequest AddCRLDistributionPointsExtension(this CertificateRequest request,
        Action<object> action)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Adds RFC 5280 4.2.2.1. Authority Information Access.
    /// </summary>
    /// <param name="request">The <see cref="CertificateRequest" /> instance.</param>
    /// <returns>An extended <see cref="CertificateRequest" /> instance.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1" />
    public static CertificateRequest AddAuthorityInformationAccessExtension(this CertificateRequest req)
    {
        throw new NotImplementedException();
    }

}
