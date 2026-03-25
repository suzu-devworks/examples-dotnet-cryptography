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
        WriteStructure(writer, encryptedPrivateKeyInfo);
        return writer.ToString();
    }

    /// <summary>
    /// Writes the structure of the <see cref="EncryptedPrivateKeyInfo"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="writer">The <see cref="TextWriter"/> to write the structure to.</param>
    /// <param name="encryptedPrivateKeyInfo">The <see cref="EncryptedPrivateKeyInfo"/> instance to write.</param>
    public static void WriteStructure(TextWriter writer, EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
    {
        // RFC 5958 - Asymmetric Key Packages
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

        writer.WriteLine($"EncryptedPrivateKeyInfo ::= {{");
        writer.WriteLine($"     encryptionAlgorithm: {encryptedPrivateKeyInfo.EncryptionAlgorithm.Algorithm}");
        writer.WriteLine($"           encryptedData: {encryptedPrivateKeyInfo.EncryptedData}");
        writer.WriteLine($"}}");
    }
}
