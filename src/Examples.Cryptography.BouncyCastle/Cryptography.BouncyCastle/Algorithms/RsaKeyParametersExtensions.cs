using Org.BouncyCastle.Crypto.Parameters;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

/// <summary>
/// Extension methods for <see cref="RsaKeyParameters"/>.
/// </summary>
public static class RsaKeyParametersExtensions
{
    public static RsaKeyParameters GeneratePublicKey(this RsaKeyParameters privateKey)
    {
        return new RsaKeyParameters(false, privateKey.Modulus, privateKey.Exponent);
    }
}
