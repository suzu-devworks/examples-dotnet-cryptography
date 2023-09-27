using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle;

public static class AsymmetricCipherKeyPairGeneratorExtensions
{
    public static IAsymmetricCipherKeyPairGenerator SetECKeyParameters(this IAsymmetricCipherKeyPairGenerator generator,
        X9ECParameters curve,
        SecureRandom? random = null)
    {
        random ??= new();

        var domain = new ECDomainParameters(curve);
        var param = new ECKeyGenerationParameters(domain, random);

        return generator.Configure(g => g.Init(param));
    }

    public static IAsymmetricCipherKeyPairGenerator SetECKeyParameters(this IAsymmetricCipherKeyPairGenerator generator,
        DerObjectIdentifier namedCurve,
        SecureRandom? random = null)
    {
        random ??= new();

        var param = new ECKeyGenerationParameters(namedCurve, random);

        return generator.Configure(g => g.Init(param));
    }


    public static IAsymmetricCipherKeyPairGenerator Configure(this IAsymmetricCipherKeyPairGenerator generator,
        Action<IAsymmetricCipherKeyPairGenerator> action)
    {
        action?.Invoke(generator);

        return generator;
    }


}
