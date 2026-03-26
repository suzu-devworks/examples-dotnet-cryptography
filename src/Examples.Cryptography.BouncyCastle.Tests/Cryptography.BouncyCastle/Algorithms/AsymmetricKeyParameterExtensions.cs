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
        return new Asn1SignatureFactory(key.GetSignatureAlgorithmName(), key);
    }

    /// <summary>
    /// Gets the default signature algorithm name for the given key. Supported types are RSA, EC and Ed25519.
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException"></exception>
    public static string GetSignatureAlgorithmName(this AsymmetricKeyParameter key)
    {
        return (key) switch
        {
            RsaKeyParameters => "SHA256withRSA",
            ECKeyParameters => "SHA256withECDSA",
            Ed25519PrivateKeyParameters => "Ed25519",
            _ => throw new NotSupportedException($"not supported {key.GetType()}"),
        };
    }
}
