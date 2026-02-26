using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

/// <summary>
/// Extension methods for <see cref="IAsymmetricCipherKeyPairGenerator"/> to configure parameters for various algorithms.
/// </summary>
public static class AsymmetricCipherKeyPairGeneratorExtensions
{
    /// <summary>
    /// Configures the <see cref="IAsymmetricCipherKeyPairGenerator"/> for RSA key generation with specified parameters.
    /// </summary>
    /// <param name="generator">The key pair generator to configure.</param>
    /// <param name="strength">The strength of the RSA key in bits.</param>
    /// <param name="certainty">The certainty for the prime number generation.</param>
    /// <param name="random">The secure random number generator.</param>
    /// <returns>The configured key pair generator.</returns>
    public static IAsymmetricCipherKeyPairGenerator ConfigureRSAParameter(this IAsymmetricCipherKeyPairGenerator generator,
        int strength = 4096,
        int certainty = 80,
        SecureRandom? random = null)
    {
        random ??= new();

        /*
         * publicExponent:
         *
         * This value should be a Fermat number. 0x10001 (F4) is current recommended value.
         * Windows does not tolerate public exponents which do not fit in a 32-bit unsigned integer.
         * Using e=3 or e=65537 works "everywhere".
         */

        /*
         * certainty:
         *
         * probability of 1 - (1/2)**certainty.
         * <p>From Knuth Vol 2, pg 395.</p>
         *
         * C.3.1 Miller-Rabin Probabilistic primality test.
         * https://csrc.nist.gov/files/pubs/fips/186-3/final/docs/fips_186-3.pdf
         */
        /* spell-checker: words primality */

        var publicExponent = BigInteger.ValueOf(0x10001);
        var param = new RsaKeyGenerationParameters(publicExponent, random, strength, certainty);
        generator.Init(param);

        return generator;
    }

    /// <summary>
    /// Configures the <see cref="IAsymmetricCipherKeyPairGenerator"/> for DSA key generation with specified parameters.
    /// </summary>
    /// <param name="generator">The key pair generator to configure.</param>
    /// <param name="size">The size of the DSA key in bits.</param>
    /// <param name="certainty">The certainty for the prime number generation.</param>
    /// <param name="random">The secure random number generator.</param>
    /// <returns>The configured key pair generator.</returns>
    public static IAsymmetricCipherKeyPairGenerator ConfigureDSAParameter(this IAsymmetricCipherKeyPairGenerator generator,
        int size = 1024,
        int certainty = 64,
        SecureRandom? random = null)
    {
        random ??= new();

        var paramGen = new DsaParametersGenerator();
        paramGen.Init(size, certainty, random);

        var param = new DsaKeyGenerationParameters(random, paramGen.GenerateParameters());
        generator.Init(param);

        return generator;
    }

    /// <summary>
    /// Configures the <see cref="IAsymmetricCipherKeyPairGenerator"/> for EC key generation with specified curve parameters.
    /// </summary>
    /// <param name="generator">The key pair generator to configure.</param>
    /// <param name="curve">The elliptic curve parameters.</param>
    /// <param name="random">The secure random number generator.</param>
    /// <returns>The configured key pair generator.</returns>
    public static IAsymmetricCipherKeyPairGenerator ConfigureECParameter(this IAsymmetricCipherKeyPairGenerator generator,
        X9ECParameters curve,
        SecureRandom? random = null)
    {
        random ??= new();

        var domain = new ECDomainParameters(curve);
        var param = new ECKeyGenerationParameters(domain, random);
        generator.Init(param);

        return generator;
    }

    /// <summary>
    /// Configures the <see cref="IAsymmetricCipherKeyPairGenerator"/> for EC key generation with specified named curve parameters.
    /// </summary>
    /// <param name="generator">The key pair generator to configure.</param>
    /// <param name="namedCurve">The named curve identifier.</param>
    /// <param name="random">The secure random number generator.</param>
    /// <returns>The configured key pair generator.</returns>
    public static IAsymmetricCipherKeyPairGenerator ConfigureECParameter(this IAsymmetricCipherKeyPairGenerator generator,
        DerObjectIdentifier namedCurve,
        SecureRandom? random = null)
    {
        random ??= new();

        var param = new ECKeyGenerationParameters(namedCurve, random);
        generator.Init(param);

        return generator;
    }

    /// <summary>
    /// Configures the <see cref="IAsymmetricCipherKeyPairGenerator"/> for Ed25519 key generation.
    /// </summary>
    /// <param name="generator">The key pair generator to configure.</param>
    /// <param name="random">The secure random number generator.</param>
    /// <returns>The configured key pair generator.</returns>
    public static IAsymmetricCipherKeyPairGenerator ConfigureEd25519Key(this IAsymmetricCipherKeyPairGenerator generator,
        SecureRandom? random = null)
    {
        random ??= new();

        var param = new Ed25519KeyGenerationParameters(random);
        generator.Init(param);

        return generator;
    }

}
