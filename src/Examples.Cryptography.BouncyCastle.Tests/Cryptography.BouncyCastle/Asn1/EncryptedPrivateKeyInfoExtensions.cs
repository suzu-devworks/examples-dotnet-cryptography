using Org.BouncyCastle.Asn1.Pkcs;

namespace Examples.Cryptography.BouncyCastle.Asn1;

public static class EncryptedPrivateKeyInfoExtensions
{
    /// <summary>
    /// Writes the structure of the <see cref="EncryptedPrivateKeyInfo"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="encryptedPrivateKeyInfo">The <see cref="EncryptedPrivateKeyInfo"/> instance to write.</param>
    /// <param name="output">The <see cref="TextWriter"/> to write the structure to.</param>
    /// <param name="indent">The character to use for indentation.</param>
    public static void WriteStructure(this EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, TextWriter output, char indent = '\t')
    {
        // RFC 5958 - Asymmetric Key Packages
        // 3.  Encrypted Private Key Info
        // https://datatracker.ietf.org/doc/html/rfc5958#section-3

        // ```asn.1
        // EncryptedPrivateKeyInfo ::= SEQUENCE {
        //      encryptionAlgorithm  EncryptionAlgorithmIdentifier,
        //      encryptedData        EncryptedData }
        //
        // EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
        //                                    { CONTENT-ENCRYPTION,
        //                                      { KeyEncryptionAlgorithms } }
        //
        // EncryptedData ::= OCTET STRING
        // ```

        output.WriteLine("EncryptedPrivateKeyInfo : {");
        output.WriteLine($"{indent}encryptionAlgorithm : {encryptedPrivateKeyInfo.EncryptionAlgorithm.Algorithm}");
        output.WriteLine($"{indent}encryptedData      : {encryptedPrivateKeyInfo.EncryptedData}");
        output.WriteLine("}");
    }
}
