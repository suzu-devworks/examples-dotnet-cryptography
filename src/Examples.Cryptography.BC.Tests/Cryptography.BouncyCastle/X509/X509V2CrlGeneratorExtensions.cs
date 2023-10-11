using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="X509V2CrlGenerator" />.
/// </summary>
public static class X509V2CrlGeneratorExtensions
{
    /// <summary>
    /// Call delegate to confine the settings to <see cref="X509V2CrlGenerator" /> to the function scope.
    /// </summary>
    /// <param name="generator">The <see cref="X509V2CrlGenerator" /> instance.</param>
    /// <param name="configureAction">A delegate for setting.</param>
    /// <returns>The <see cref="X509V2CrlGenerator" /> Instances for daisy chaining</returns>
    public static X509V2CrlGenerator Configure(this X509V2CrlGenerator generator,
        Action<X509V2CrlGenerator> configureAction)
    {
        configureAction.Invoke(generator);

        return generator;
    }
}
