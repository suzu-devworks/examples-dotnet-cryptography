using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

public static partial class AsymmetricCipherKeyPairAgent
{
    /// <summary>
    /// Exports the current key in the ECPrivateKey format.
    /// </summary>
    /// <param name="keyPair"></param>
    /// <returns>A byte array containing the ECPrivateKey representation of this key.</returns>
    public static byte[] ExportECPrivateKey(this AsymmetricCipherKeyPair keyPair)
        => keyPair.ExportPrivateKey();

    /// <summary>
    /// Creates a new <see cref="AsymmetricCipherKeyPair" /> from the ECPrivateKey structure.
    /// </summary>
    /// <param name="der">The bytes of an ECPrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair CreateECPrivateKeyFrom(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(der);
        if (seq.Count != 4)
        {
            throw new ArgumentException("Invalid byte sequence.");
        }

        // RFC 5915 - Elliptic Curve Private Key Structure
        // https://datatracker.ietf.org/doc/html/rfc5915#appendix-A


        // Appendix A.  ASN.1 Module
        //
        // ```asn.1
        // ECPrivateKey::= SEQUENCE {
        //      version         INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //      privateKey      OCTET STRING,
        //      parameters  [0] ECParameters { { NamedCurve } } OPTIONAL,
        //      publicKey   [1] BIT STRING OPTIONAL
        // }
        // ```
        /* spell-checker: words Privkey */
        var structure = ECPrivateKeyStructure.GetInstance(seq);

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
        //
        // Version::= INTEGER { v1(0)} (v1, ...)
        // PrivateKey::= OCTET STRING
        // Attributes ::= SET OF Attribute
        // ```
        var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, structure.Parameters?.ToAsn1Object());
        var privateKeyInfo = new PrivateKeyInfo(algId, structure.ToAsn1Object());
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
        // ```
        var publicKeyData = structure.PublicKey
            ?? throw new NotSupportedException("publicKey is null.");
        var publicKeyInfo = new SubjectPublicKeyInfo(algId, publicKeyData.GetBytes());
        var publicKey = PublicKeyFactory.CreateKey(publicKeyInfo);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

}
