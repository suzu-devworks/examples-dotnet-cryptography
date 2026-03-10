using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.X509;

public static class TimeStampTokenGeneratorExtensions
{
    public static TimeStampTokenGenerator Configure(this TimeStampTokenGenerator generator,
        Action<TimeStampTokenGenerator> configure)
    {
        configure(generator);
        return generator;
    }
}
