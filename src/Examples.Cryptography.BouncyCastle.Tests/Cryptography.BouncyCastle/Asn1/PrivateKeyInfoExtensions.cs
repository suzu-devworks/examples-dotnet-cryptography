
using Org.BouncyCastle.Asn1.Pkcs;

namespace Examples.Cryptography.BouncyCastle.Asn1;

/// <summary>
/// Extension methods for ASN1 parsing for <see cref="PrivateKeyInfo"/>.
/// </summary>
public static class PrivateKeyInfoExtensions
{
    /// <summary>
    /// Returns a string representation of the structure of the <see cref="PrivateKeyInfo"/> instance.
    /// </summary>
    /// <param name="privateKeyInfo">The <see cref="PrivateKeyInfo"/> instance.</param>
    /// <returns>A string representation of the structure.</returns>
    public static string ToStructureString(this PrivateKeyInfo privateKeyInfo)
    {
        using var writer = new StringWriter();
        privateKeyInfo.WriteStructure(writer);
        return writer.ToString();
    }

    /// <summary>
    /// Writes the structure of the <see cref="PrivateKeyInfo"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="privateKeyInfo">The <see cref="PrivateKeyInfo"/> instance to write.</param>
    /// <param name="output">The <see cref="TextWriter"/> to write the structure to.</param>
    public static void WriteStructure(this PrivateKeyInfo privateKeyInfo, TextWriter output)
    {
        // RFC 5958 - Asymmetric Key Packages
        // 2. Asymmetric Key Package CMS Content Type
        // https://datatracker.ietf.org/doc/html/rfc5958#section-2

        // ```asn.1
        // OneAsymmetricKey ::= SEQUENCE {
        //   version                   Version,
        //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        //   privateKey                PrivateKey,
        //   attributes           [0]  IMPLICIT Attributes OPTIONAL,
        //   ...,
        //   [[2: publicKey       [1] IMPLICIT PublicKey OPTIONAL ]],
        //   ...
        // }
        //
        // PrivateKeyInfo ::= OneAsymmetricKey
        //
        // Version::= INTEGER { v1(0), v2(1) }(v1, ..., v2)
        //
        // PrivateKeyAlgorithmIdentifier::= AlgorithmIdentifier
        //                                   { PUBLIC-KEY,
        //                                     { PrivateKeyAlgorithms }}
        //
        // PrivateKey::= OCTET STRING
        //                    -- Content varies based on type of key.The
        //                    -- algorithm identifier dictates the format of
        //                    --the key.
        //
        // PublicKey ::= BIT STRING
        //                    -- Content varies based on type of key.The
        //                    -- algorithm identifier dictates the format of
        //                    --the key.
        //
        // Attributes ::= SET OF Attribute { { OneAsymmetricKeyAttributes } }
        // ```

        output.WriteLine("PrivateKeyInfo ::= {");
        output.WriteLine($"             version : {privateKeyInfo.Version}");
        output.WriteLine($" privateKeyAlgorithm : {privateKeyInfo.PrivateKeyAlgorithm.Algorithm}");
        output.WriteLine($"          privateKey : {privateKeyInfo.PrivateKey}");
        output.WriteLine($"      attributes [0] : {privateKeyInfo.Attributes}");
        output.WriteLine($"       publicKey [1] : {privateKeyInfo.ParsePublicKey()}");
        output.WriteLine("}");
    }
}
