using System.ComponentModel;

namespace Examples.Cryptography.BouncyCastle.Symmetric;

public enum BlockCipherModes
{
    None = 0,

    /// <summary>
    /// Electronic Codebook (ECB) is a mode of operation for block ciphers where each block of plaintext is encrypted independently.
    /// </summary>
    [Description("Electronic Codebook")]
    Ecb,

    /// <summary>
    /// Cipher Block Chaining (CBC) is a mode of operation for block ciphers that provides confidentiality by chaining together blocks of plaintext and ciphertext.
    /// </summary>
    [Description("Cipher Block Chaining")]
    Cbc,

    /// <summary>
    /// Cipher Feedback (CFB) is a mode of operation for block ciphers that allows encryption of data in units smaller than the block size.
    /// </summary>
    [Description("Cipher Feedback")]
    Cfb,

    /// <summary>
    /// Output Feedback (OFB) is a mode of operation for block ciphers that turns a block cipher into a synchronous stream cipher.
    /// </summary>
    [Description("Output Feedback")]
    Ofb,

    /// <summary>
    /// Counter with CBC-MAC (CCM) is a mode of operation for block ciphers that provides both confidentiality and authenticity.
    /// </summary>
    [Description("Counter with CBC-MAC")]
    Ccm,

    /// <summary>
    /// Galois/Counter Mode (GCM) is a mode of operation for block ciphers that provides both confidentiality and authenticity.
    /// </summary>
    [Description("Galois/Counter Mode")]
    Gcm,
}
