using Examples.Cryptography.Generics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

public static class AsymmetricCipherKeyPairGeneratorExtensions
{
    public static IAsymmetricCipherKeyPairGenerator ConfigureDefault(this IAsymmetricCipherKeyPairGenerator generator,
        SecureRandom? random = null)
    {
        random ??= new();

        return generator switch
        {
            RsaKeyPairGenerator g => g.ConfigureRsaKey(strength: 2048, certainty: 112, random: random),
            DsaKeyPairGenerator g => g.ConfigureDSAKey(random: random),
            ECKeyPairGenerator g => g.ConfigureECKey(CustomNamedCurves.GetByName("P-256"), random: random),
            Ed25519KeyPairGenerator g => g.ConfigureEd25519Key(random: random),
            _ => throw new NotSupportedException($"not supported generator {generator.GetType()}"),
        };
    }


    public static IAsymmetricCipherKeyPairGenerator ConfigureRsaKey(this IAsymmetricCipherKeyPairGenerator generator,
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

        var publicExponent = BigInteger.ValueOf(0x10001);
        var param = new RsaKeyGenerationParameters(publicExponent, random, strength, certainty);

        return generator.Configure(g => g.Init(param));
    }


    public static IAsymmetricCipherKeyPairGenerator ConfigureDSAKey(this IAsymmetricCipherKeyPairGenerator generator,
        int size = 1024,
        int certainty = 64,
        SecureRandom? random = null)
    {
        random ??= new();

        var paramGen = new DsaParametersGenerator();
        paramGen.Init(size, certainty, random);
        var param = new DsaKeyGenerationParameters(random, paramGen.GenerateParameters());

        return generator.Configure(g => g.Init(param));
    }


    public static IAsymmetricCipherKeyPairGenerator ConfigureECKey(this IAsymmetricCipherKeyPairGenerator generator,
        X9ECParameters curve,
        SecureRandom? random = null)
    {
        random ??= new();

        var domain = new ECDomainParameters(curve);
        var param = new ECKeyGenerationParameters(domain, random);

        return generator.Configure(g => g.Init(param));
    }

    public static IAsymmetricCipherKeyPairGenerator ConfigureECKey(this IAsymmetricCipherKeyPairGenerator generator,
        DerObjectIdentifier namedCurve,
        SecureRandom? random = null)
    {
        random ??= new();

        var param = new ECKeyGenerationParameters(namedCurve, random);

        return generator.Configure(g => g.Init(param));
    }

    public static IAsymmetricCipherKeyPairGenerator ConfigureEd25519Key(this IAsymmetricCipherKeyPairGenerator generator,
        SecureRandom? random = null)
    {
        random ??= new();

        var param = new Ed25519KeyGenerationParameters(random);

        return generator.Configure(g => g.Init(param));
    }

}
