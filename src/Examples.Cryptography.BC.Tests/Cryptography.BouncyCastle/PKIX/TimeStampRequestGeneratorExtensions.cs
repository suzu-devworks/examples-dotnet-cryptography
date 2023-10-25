using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.PKIX;

/// <summary>
/// Extension methods for <see cref="TimeStampRequestGenerator" />.
/// </summary>
public static class TimeStampRequestGeneratorExtensions
{
    /// <summary>
    /// Call delegate to confine the settings to <see cref="TimeStampRequestGenerator" /> to the function scope.
    /// </summary>
    /// <param name="generator">The <see cref="TimeStampRequestGenerator" /> instance.</param>
    /// <param name="configureAction">A delegate for setting.</param>
    /// <returns>The <see cref="TimeStampRequestGenerator" /> Instances for daisy chaining</returns>
    public static TimeStampRequestGenerator Configure(this TimeStampRequestGenerator generator,
             Action<TimeStampRequestGenerator> configureAction)
    {
        configureAction.Invoke(generator);

        return generator;
    }

}
