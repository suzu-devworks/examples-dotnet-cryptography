using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;

namespace Examples.Cryptography.BouncyCastle.Symmetric;

public static class BlockCipherExtensions
{
    public static DerObjectIdentifier GetAesAlgorithm(this BlockCipherModes mode, int keySize)
    {
        return (mode, keySize) switch
        {
            (BlockCipherModes.Ecb, 16) => NistObjectIdentifiers.IdAes128Ecb,
            (BlockCipherModes.Ecb, 24) => NistObjectIdentifiers.IdAes192Ecb,
            (BlockCipherModes.Ecb, 32) => NistObjectIdentifiers.IdAes256Ecb,

            (BlockCipherModes.Cbc, 16) => NistObjectIdentifiers.IdAes128Cbc,
            (BlockCipherModes.Cbc, 24) => NistObjectIdentifiers.IdAes192Cbc,
            (BlockCipherModes.Cbc, 32) => NistObjectIdentifiers.IdAes256Cbc,

            (BlockCipherModes.Cfb, 16) => NistObjectIdentifiers.IdAes128Cfb,
            (BlockCipherModes.Cfb, 24) => NistObjectIdentifiers.IdAes192Cfb,
            (BlockCipherModes.Cfb, 32) => NistObjectIdentifiers.IdAes256Cfb,

            (BlockCipherModes.Ofb, 16) => NistObjectIdentifiers.IdAes128Ofb,
            (BlockCipherModes.Ofb, 24) => NistObjectIdentifiers.IdAes192Ofb,
            (BlockCipherModes.Ofb, 32) => NistObjectIdentifiers.IdAes256Ofb,

            (BlockCipherModes.Ccm, 16) => NistObjectIdentifiers.IdAes128Ccm,
            (BlockCipherModes.Ccm, 24) => NistObjectIdentifiers.IdAes192Ccm,
            (BlockCipherModes.Ccm, 32) => NistObjectIdentifiers.IdAes256Ccm,

            (BlockCipherModes.Gcm, 16) => NistObjectIdentifiers.IdAes128Gcm,
            (BlockCipherModes.Gcm, 24) => NistObjectIdentifiers.IdAes192Gcm,
            (BlockCipherModes.Gcm, 32) => NistObjectIdentifiers.IdAes256Gcm,

            _ => throw new ArgumentException("Invalid mode or key size.")
        };
    }

}
