using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

/// <summary>
/// Extension methods for <see cref="AsymmetricKeyParameter"/>.
/// </summary>
public static class AsymmetricKeyParameterExtensions
{
    /// <summary>
    /// Gets the public key from the given private key. Supported types are RSA, EC and Ed25519.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException"></exception>
    public static AsymmetricKeyParameter GetPublicKey(this AsymmetricKeyParameter privateKey)
    {
        return privateKey switch
        {
            RsaKeyParameters rsa => rsa.GeneratePublicKey(),
            ECPrivateKeyParameters ec => ec.GeneratePublicKey(),
            Ed25519PrivateKeyParameters ed25519 => ed25519.GeneratePublicKey(),
            _ => throw new NotSupportedException($"type is {privateKey.GetType().Name}"),
        };
    }

    /// <summary>
    /// Creates a default signature factory for the given private key. Supported types are RSA, EC and Ed25519.
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException"></exception>
    public static ISignatureFactory CreateDefaultSignature(this AsymmetricKeyParameter key)
    {
        return key switch
        {
            RsaKeyParameters => new Asn1SignatureFactory("SHA256WithRSA", key),
            ECKeyParameters => new Asn1SignatureFactory("SHA256WithECDSA", key),
            Ed25519PrivateKeyParameters => new Asn1SignatureFactory("Ed25519", key),
            _ => throw new NotSupportedException($"not supported {key.GetType()}"),
        };
    }

}
