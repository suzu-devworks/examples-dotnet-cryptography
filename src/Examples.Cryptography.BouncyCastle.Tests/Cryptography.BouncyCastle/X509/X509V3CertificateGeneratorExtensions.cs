using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="X509V3CertificateGenerator" />.
/// </summary>
public static class X509V3CertificateGeneratorExtensions
{
    /// <summary>
    /// Configures <see cref="X509V3CertificateGenerator" /> using the provided action. This is useful for daisy chaining multiple configuration methods.
    /// </summary>
    /// <param name="generator"></param>
    /// <param name="action"></param>
    /// <returns></returns>
    public static X509V3CertificateGenerator Configure(this X509V3CertificateGenerator generator,
        Action<X509V3CertificateGenerator> action)
    {
        action.Invoke(generator);
        return generator;
    }

    /// <summary>
    /// Sets expiration date to <see cref="X509V3CertificateGenerator" />.
    /// </summary>
    /// <param name="generator">The <see cref="X509V3CertificateGenerator" /> instance.</param>
    /// <param name="notBefore">The expiration start date. This will be <c>NotBefore</c>.</param>
    /// <param name="days">The number of valid days. Adding this value will result in <c>NotAfter</c>.</param>
    /// <returns>The <see cref="X509V3CertificateGenerator" /> Instances for daisy chaining</returns>
    public static X509V3CertificateGenerator WithValidityPeriod(this X509V3CertificateGenerator generator,
        DateTimeOffset notBefore,
        int days)
    {
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notBefore.AddDays(days).UtcDateTime);

        return generator;
    }
}
