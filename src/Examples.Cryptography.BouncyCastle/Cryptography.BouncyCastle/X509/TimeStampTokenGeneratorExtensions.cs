using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="TimeStampTokenGenerator" />.
/// </summary>
public static class TimeStampTokenGeneratorExtensions
{
    /// <summary>
    /// Configures <see cref="TimeStampTokenGenerator" /> using the provided action.
    /// This is useful for daisy chaining multiple configuration methods.
    /// </summary>
    /// <param name="generator">The time stamp token generator to configure.</param>
    /// <param name="configure">The action to perform on the time stamp token generator.</param>
    /// <returns>The configured time stamp token generator.</returns>
    public static TimeStampTokenGenerator Configure(this TimeStampTokenGenerator generator,
        Action<TimeStampTokenGenerator> configure)
    {
        configure(generator);
        return generator;
    }
}
