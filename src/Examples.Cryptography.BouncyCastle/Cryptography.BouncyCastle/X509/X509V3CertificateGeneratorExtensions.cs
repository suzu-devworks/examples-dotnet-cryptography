using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="X509V3CertificateGenerator" />.
/// </summary>
public static class X509V3CertificateGeneratorExtensions
{
    /// <summary>
    /// Configures <see cref="X509V3CertificateGenerator" /> using the provided action.
    /// This is useful for daisy chaining multiple configuration methods.
    /// </summary>
    /// <param name="generator">The certificate generator to configure.</param>
    /// <param name="configure">The action to perform on the certificate generator.</param>
    /// <returns>The configured certificate generator.</returns>
    public static X509V3CertificateGenerator Configure(this X509V3CertificateGenerator generator,
        Action<X509V3CertificateGenerator> configure)
    {
        configure.Invoke(generator);
        return generator;
    }
}
