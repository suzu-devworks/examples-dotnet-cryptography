using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

public static partial class AsymmetricCipherKeyPairLoader
{
    /// <summary>
    /// Loads a new <see cref="AsymmetricCipherKeyPair" /> from the PKCS #1 RSAPrivateKey structure.
    /// </summary>
    /// <param name="der">The bytes of an PKCS #1 RSAPrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair LoadRSAPrivateKeyFrom(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(der);
        if (seq.Count < 9)
        {
            throw new ArgumentException("Invalid byte sequence.");
        }

        // RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2
        // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A

        // ```asn.1
        // RSAPrivateKey::= SEQUENCE {
        //      version         Version,
        //      modulus         INTEGER,    -- n
        //      publicExponent  INTEGER,    -- e
        //      privateExponent INTEGER,    -- d
        //      prime1          INTEGER,    -- p
        //      prime2          INTEGER,    -- q
        //      exponent1       INTEGER,    -- d mod(p - 1)
        //      exponent2       INTEGER,    -- d mod(q - 1)
        //      coefficient     INTEGER,    -- (inverse of q) mod p
        //      otherPrimeInfos OtherPrimeInfos OPTIONAL
        // }
        //
        // Version::= INTEGER { two - prime(0), multi(1) }
        //        (CONSTRAINED BY
        //        { --version must be multi if otherPrimeInfos present--})
        // OtherPrimeInfos::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
        // OtherPrimeInfo::= SEQUENCE {
        //      prime           INTEGER,    -- ri
        //      exponent        INTEGER,    -- di
        //      coefficient     INTEGER     -- ti
        // }
        // ```
        var structure = RsaPrivateKeyStructure.GetInstance(seq);
        var privateKey = new RsaPrivateCrtKeyParameters(structure);

        // A.1.1.  RSA Public Key Syntax
        //
        // ```asn.1
        // RSAPublicKey::= SEQUENCE {
        //      modulus         INTEGER,    -- n
        //      publicExponent  INTEGER     -- e
        // }
        // ```
        var publicKey = new RsaKeyParameters(false,
            structure.Modulus, structure.PublicExponent);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

}
