using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

public static partial class AsymmetricCipherKeyPairAgent
{
    /// <summary>
    /// Export the current key in DSAPrivateKey format.
    /// </summary>
    /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair" /> type key pair.</param>
    /// <returns>A byte array containing the DSAPrivateKey representation of this key.</returns>
    public static byte[] ExportDSAPrivateKey(this AsymmetricCipherKeyPair keyPair)
        => keyPair.ExportPrivateKey();

    /// <summary>
    /// Creates a new <see cref="AsymmetricCipherKeyPair" /> from the DSAPrivateKey structure.
    /// </summary>
    /// <param name="der">The bytes of an DSAPrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair CreateDSAPrivateKeyFrom(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(der);
        if (seq.Count != 6)
        {
            throw new ArgumentException("Invalid byte sequence.");
        }

        // ??
        _ = (DerInteger)seq[0];
        var p = (DerInteger)seq[1];
        var q = (DerInteger)seq[2];
        var g = (DerInteger)seq[3];
        var y = (DerInteger)seq[4];
        var x = (DerInteger)seq[5];

        var parameters = new DsaParameters(p.Value, q.Value, g.Value);
        var privateKey = new DsaPrivateKeyParameters(x.Value, parameters);
        var publicKey = new DsaPublicKeyParameters(y.Value, parameters);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

}
