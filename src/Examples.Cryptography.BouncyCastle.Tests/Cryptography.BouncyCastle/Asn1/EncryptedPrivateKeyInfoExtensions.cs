using Org.BouncyCastle.Asn1.Pkcs;

namespace Examples.Cryptography.BouncyCastle.Asn1;

/// <summary>
/// Extension methods for ASN1 parsing for <see cref="EncryptedPrivateKeyInfo"/>.
/// </summary>
public static class EncryptedPrivateKeyInfoExtensions
{
    /// <summary>
    /// Returns a string representation of the structure of the <see cref="EncryptedPrivateKeyInfo"/> instance.
    /// </summary>
    /// <param name="encryptedPrivateKeyInfo">The <see cref="EncryptedPrivateKeyInfo"/> instance.</param>
    /// <returns>A string representation of the structure.  </returns>
    public static string ToStructureString(this EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
    {
        using var writer = new StringWriter();
        encryptedPrivateKeyInfo.WriteStructure(writer);
        return writer.ToString();
    }

    /// <summary>
    /// Writes the structure of the <see cref="EncryptedPrivateKeyInfo"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="encryptedPrivateKeyInfo">The <see cref="EncryptedPrivateKeyInfo"/> instance to write.</param>
    /// <param name="output">The <see cref="TextWriter"/> to write the structure to.</param>
    public static void WriteStructure(this EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, TextWriter output)
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

        output.WriteLine("EncryptedPrivateKeyInfo ::= {");
        output.WriteLine($" encryptionAlgorithm : {encryptedPrivateKeyInfo.EncryptionAlgorithm.Algorithm}");
        output.WriteLine($"       encryptedData : {encryptedPrivateKeyInfo.EncryptedData}");
        output.WriteLine("}");
    }
}
