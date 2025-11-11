using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates;

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
    ///
    /// </summary>
    /// <param name="certificate"></param>
    /// <returns></returns>
    public static bool IsCertificateAuthority(this X509Certificate2 certificate)
        => certificate.GetExtension<X509BasicConstraintsExtension>()
            ?.CertificateAuthority ?? false;

    /// <summary>
    ///
    /// </summary>
    /// <param name="certificate"></param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException"></exception>
    public static AsymmetricAlgorithm GetAnyPublicKey(this X509Certificate2 certificate)
    {
        return (AsymmetricAlgorithm?)certificate.GetRSAPublicKey()
            ?? certificate.GetECDsaPublicKey()
            ?? throw new NotSupportedException("The AsymmetricAlgorithm in this certificate is not supported.");
    }

}
