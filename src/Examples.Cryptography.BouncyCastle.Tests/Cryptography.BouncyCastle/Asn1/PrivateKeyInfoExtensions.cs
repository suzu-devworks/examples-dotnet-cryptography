
using Org.BouncyCastle.Asn1.Pkcs;

namespace Examples.Cryptography.BouncyCastle.Asn1;

public static class PrivateKeyInfoExtensions
{
    /// <summary>
    /// Writes the structure of the <see cref="PrivateKeyInfo"/> to the provided <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="privateKeyInfo">The <see cref="PrivateKeyInfo"/> instance to write.</param>
    /// <param name="output"></param>
    /// <param name="indent">The character to use for indentation.</param>
    public static void WriteStructure(this PrivateKeyInfo privateKeyInfo, TextWriter output, char indent = '\t')
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
        output.WriteLine("PrivateKeyInfo(OneAsymmetricKey) : {");
        output.WriteLine($"{indent}version             : {privateKeyInfo.Version}");
        output.WriteLine($"{indent}privateKeyAlgorithm : {privateKeyInfo.PrivateKeyAlgorithm.Algorithm}");
        output.WriteLine($"{indent}privateKey          : {privateKeyInfo.ParsePrivateKey()}");
        output.WriteLine($"{indent}attributes [0]      : {privateKeyInfo.Attributes}");
        output.WriteLine($"{indent}publicKey  [1]      : {privateKeyInfo.ParsePublicKey()}");
        output.WriteLine("}");

    }
}
