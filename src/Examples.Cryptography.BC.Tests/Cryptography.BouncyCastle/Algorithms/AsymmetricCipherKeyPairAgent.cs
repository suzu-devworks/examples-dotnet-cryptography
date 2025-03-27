using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

/// <summary>
/// The <see cref="AsymmetricCipherKeyPair" /> importer and extension methods for export.
/// </summary>
public static partial class AsymmetricCipherKeyPairAgent
{
    /// <summary>
    /// Export the current key  PrivateKeyInfo format.
    /// </summary>
    /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair" /> type key pair.</param>
    /// <returns>A byte array containing the PrivateKeyInfo representation of this key.</returns>
    public static byte[] ExportPrivateKey(this AsymmetricCipherKeyPair keyPair)
    {
        var misc = new MiscPemGenerator(keyPair).Generate();
        return misc.Content;
    }

    /// <summary>
    /// Creates a new <see cref="AsymmetricCipherKeyPair" /> from the PrivateKey structure.
    /// </summary>
    /// <param name="der">The bytes of an PrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair CreateFrom(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(der);
        if (seq.Count != 4)
        {
            throw new ArgumentException("Invalid byte sequence.");
        }

        // RFC 5208 - Public-Key Cryptography Standards (PKCS) #8
        // https://datatracker.ietf.org/doc/html/rfc5208#appendix-A

        // Appendix A.  ASN.1 Syntax
        //
        // ```asn.1
        // PrivateKeyInfo::= SEQUENCE {
        //      version             Version,
        //      privateKeyAlgorithm AlgorithmIdentifier { { PrivateKeyAlgorithms} },
        //      privateKey          PrivateKey,
        //      attributes[0]       Attributes OPTIONAL
        // }
        // Version::= INTEGER { v1(0)} (v1, ...)
        // PrivateKey::= OCTET STRING
        // Attributes ::= SET OF Attribute
        // ```
        var privateKeyInfo = PrivateKeyInfo.GetInstance(seq);
        var privateKey = PrivateKeyFactory.CreateKey(privateKeyInfo);

        // RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
        // https://datatracker.ietf.org/doc/html/rfc5480#section-2

        // 2.  Subject Public Key Information Fields
        //
        // ```asn.1
        // SubjectPublicKeyInfo::= SEQUENCE  {
        //      algorithm           AlgorithmIdentifier,
        //      subjectPublicKey    BIT STRING
        // }
        //```
        var publicKey = GetPublicKey(privateKey);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /// <summary>
    /// Exports the current key in the PrivateKey format, PEM encoded.
    /// </summary>
    /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair" /> type key pair.</param>
    /// <returns>A string containing the PEM-encoded PrivateKey.</returns>
    public static string ExportPrivateKeyPem(this AsymmetricCipherKeyPair keyPair)
    {
        var builder = new StringBuilder();
        //using var memory = new MemoryStream();
        //using (var writer = new PemWriter(new StreamWriter(memory, Encoding.ASCII)))
        using (var writer = new PemWriter(new StringWriter(builder)))
        {
            writer.WriteObject(keyPair);
        }
        //var pem = Encoding.ASCII.GetString(memory.ToArray()).TrimEnd();
        var pem = builder.ToString().TrimEnd();

        return pem;
    }

    /// <summary>
    /// Creates a new <see cref="AsymmetricCipherKeyPair" /> from RFC 7468 PEM-encoded private key.
    /// </summary>
    /// <param name="pem">The PEM-encoded private key.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair CreateFromPem(string pem)
    {
        using var reader = new PemReader(new StringReader(pem));
        var loaded = reader.ReadObject();

        if (loaded is AsymmetricCipherKeyPair pair)
        {
            return pair;
        }

        if (loaded is AsymmetricKeyParameter privateKey)
        {
            var publicKey = GetPublicKey(privateKey);
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        throw new NotSupportedException($"type is {loaded.GetType().Name}");
    }


    private static AsymmetricKeyParameter GetPublicKey(AsymmetricKeyParameter privateKey)
    {
        return privateKey switch
        {
            Ed25519PrivateKeyParameters ed25519 => ed25519.GeneratePublicKey(),
            _ => throw new NotSupportedException($"type is {privateKey.GetType().Name}"),
        };
    }

}
