using Org.BouncyCastle.Crypto.Parameters;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

/// <summary>
/// Extension methods for <see cref="ECPrivateKeyParameters"/>.
/// </summary>
public static class ECPrivateKeyParametersExtensions
{
    /// <summary>
    /// Creates Public key as <see cref="ECPublicKeyParameters"/> from the given <see cref="ECPrivateKeyParameters"/>.
    /// </summary>
    /// <param name="privateKey">The EC private key parameters used to generate the public key.</param>
    /// <returns>The corresponding EC public key parameters derived from the specified private key.</returns>
    public static ECPublicKeyParameters GeneratePublicKey(this ECPrivateKeyParameters privateKey)
    {
        // 1. Get the private key value as D
        var d = privateKey.D;

        // 2. Get the base point (G) from the curve parameters
        // and calculate the public key (Q = dG)
        var q = privateKey.Parameters.G.Multiply(d);

        // 3. Create public key parameters using the calculated Q
        return new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
    }
}
