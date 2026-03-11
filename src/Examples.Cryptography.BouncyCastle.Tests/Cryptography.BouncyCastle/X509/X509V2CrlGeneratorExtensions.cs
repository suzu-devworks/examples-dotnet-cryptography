using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="X509V2CrlGenerator" />.
/// </summary>
public static class X509V2CrlGeneratorExtensions
{
    /// <summary>
    /// Configures <see cref="X509V2CrlGenerator" /> using the provided action.
    /// This is useful for daisy chaining multiple configuration methods.
    /// </summary>
    /// <param name="generator">The CRL generator to configure.</param>
    /// <param name="configure">The action to perform on the CRL generator.</param>
    /// <returns>The configured CRL generator.</returns>
    public static X509V2CrlGenerator Configure(this X509V2CrlGenerator generator,
        Action<X509V2CrlGenerator> configure)
    {
        configure(generator);
        return generator;
    }
}
