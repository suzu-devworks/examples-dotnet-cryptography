using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Extensions;

/// <summary>
/// Extension methods for <see cref="X509Certificate2" />.
/// </summary>
public static class X509Certificate2Extensions
{
    /// <summary>
    /// Gets X.509 v3 extensions from <see cref="X509Certificate2" />.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2" /> instance.</param>
    /// <typeparam name="T">The derived class of <see cref="X509Extension" />.</typeparam>
    /// <returns>An extension entry.</returns>
    public static T? GetExtension<T>(this X509Certificate2 certificate)
        where T : X509Extension
    {
        return certificate.Extensions.OfType<T>().FirstOrDefault();
    }

    /// <summary>
    /// Indicates whether the certificate is a Certificate Authority (CA).
    /// </summary>
    /// <param name="certificate">The certificate instance.</param>
    /// <returns>True if the certificate is a CA; otherwise, false.</returns>
    public static bool IsCertificateAuthority(this X509Certificate2 certificate)
        => certificate.GetExtension<X509BasicConstraintsExtension>()
            ?.CertificateAuthority ?? false;

    /// <summary>
    /// Gets the public key as an <see cref="AsymmetricAlgorithm" />.
    /// </summary>
    /// <param name="certificate">The certificate instance.</param>
    /// <returns>The public key as an <see cref="AsymmetricAlgorithm" />.</returns>
    /// <exception cref="NotSupportedException">The public key algorithm is not supported.</exception>
    public static AsymmetricAlgorithm GetAnyPublicKey(this X509Certificate2 certificate)
    {
        return (AsymmetricAlgorithm?)certificate.GetRSAPublicKey()
            ?? certificate.GetECDsaPublicKey()
            ?? throw new NotSupportedException("The AsymmetricAlgorithm in this certificate is not supported.");
    }

}
