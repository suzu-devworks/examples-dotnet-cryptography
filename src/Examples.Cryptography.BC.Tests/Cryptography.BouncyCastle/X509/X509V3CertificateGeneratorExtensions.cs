using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="X509V3CertificateGenerator" />.
/// </summary>
public static class X509V3CertificateGeneratorExtensions
{
    /// <summary>
    /// Sets expiration date to <see cref="X509V3CertificateGenerator" />.
    /// </summary>
    /// <param name="generator">The <see cref="X509V3CertificateGenerator" /> instance.</param>
    /// <param name="now">The expiration start date. This will be <c>NotBefore</c>.</param>
    /// <param name="days">The number of valid days. Adding this value will result in <c>NotAfter</c>.</param>
    /// <returns>The <see cref="X509V3CertificateGenerator" /> Instances for daisy chaining</returns>
    public static X509V3CertificateGenerator SetValidityPeriod(this X509V3CertificateGenerator generator,
        DateTime now,
        int days)
    {
        generator.SetNotBefore(now.ToUniversalTime());
        generator.SetNotAfter(now.AddDays(days).ToUniversalTime());

        return generator;
    }

    /// <summary>
    /// Configure basic settings for root CA.
    /// </summary>
    /// <param name="generator">The <see cref="X509V3CertificateGenerator" /> instance.</param>
    /// <param name="publicKey">The root CA public key.</param>
    /// <param name="subject">The root CA subject.</param>
    /// <returns>The <see cref="X509V3CertificateGenerator" /> Instances for daisy chaining</returns>
    public static X509V3CertificateGenerator WithRootCA(this X509V3CertificateGenerator generator,
        AsymmetricKeyParameter publicKey,
        X509Name subject
        )
    {
        generator.SetIssuerDN(subject);
        generator.SetSerialNumber(BigInteger.One);
        generator.SetSubjectDN(subject);
        generator.SetPublicKey(publicKey);

        generator.AddExtension(X509Extensions.AuthorityKeyIdentifier,
            critical: false,
            new AuthorityKeyIdentifierStructure(publicKey));
        generator.AddExtension(X509Extensions.SubjectKeyIdentifier,
            critical: false,
            new SubjectKeyIdentifierStructure(publicKey));
        generator.AddExtension(X509Extensions.BasicConstraints,
            critical: true,
            new BasicConstraints(cA: true));

        return generator;
    }

    /// <summary>
    /// Configure basic settings for intermediate CA.
    /// </summary>
    /// <param name="generator">The <see cref="X509V3CertificateGenerator" /> instance.</param>
    /// <param name="publicKey">The intermediate CA public key.</param>
    /// <param name="subject">The intermediate CA subject.</param>
    /// <param name="issuerCert">The issuer certificate.</param>
    /// <param name="serial">A Serial number issued by issuer.</param>
    /// <param name="pathLenConstraint">PathLength value to set in BasicConstraints.
    /// Without this, you cannot chain.</param>
    /// <returns>The <see cref="X509V3CertificateGenerator" /> Instances for daisy chaining</returns>
    public static X509V3CertificateGenerator WithIntermediateCA(this X509V3CertificateGenerator generator,
        AsymmetricKeyParameter publicKey,
        X509Name subject,
        X509Certificate issuerCert,
        BigInteger serial,
        int pathLenConstraint = 0
        )
    {
        generator.SetIssuerDN(issuerCert.SubjectDN);
        generator.SetSerialNumber(serial);
        generator.SetSubjectDN(subject);
        generator.SetPublicKey(publicKey);

        generator.AddExtension(X509Extensions.AuthorityKeyIdentifier,
            critical: false,
            new AuthorityKeyIdentifierStructure(issuerCert));
        generator.AddExtension(X509Extensions.SubjectKeyIdentifier,
            critical: false,
            new SubjectKeyIdentifierStructure(publicKey));
        generator.AddExtension(X509Extensions.BasicConstraints,
            critical: true,
            new BasicConstraints(pathLenConstraint));
        generator.AddExtension(X509Extensions.KeyUsage,
            critical: true,
            new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign));

        return generator;
    }

    /// <summary>
    /// Configure basic settings for end entity certificate.
    /// </summary>
    /// <param name="generator">The <see cref="X509V3CertificateGenerator" /> instance.</param>
    /// <param name="publicKey">The end entity public key.</param>
    /// <param name="subject">The end entity subject.</param>
    /// <param name="issuerCert">The issuer certificate.</param>
    /// <param name="serial">A Serial number issued by issuer.</param>
    /// <returns>The <see cref="X509V3CertificateGenerator" /> Instances for daisy chaining</returns>
    public static X509V3CertificateGenerator WithEndEntity(this X509V3CertificateGenerator generator,
        AsymmetricKeyParameter publicKey,
        X509Name subject,
        X509Certificate issuerCert,
        BigInteger serial
        )
    {
        generator.SetIssuerDN(issuerCert.SubjectDN);
        generator.SetSerialNumber(serial);
        generator.SetSubjectDN(subject);
        generator.SetPublicKey(publicKey);

        generator.AddExtension(X509Extensions.AuthorityKeyIdentifier,
            critical: false,
            new AuthorityKeyIdentifierStructure(issuerCert));
        generator.AddExtension(X509Extensions.SubjectKeyIdentifier,
            critical: false,
            new SubjectKeyIdentifierStructure(publicKey));
        generator.AddExtension(X509Extensions.BasicConstraints,
            critical: true,
            new BasicConstraints(cA: false));

        return generator;
    }

}
