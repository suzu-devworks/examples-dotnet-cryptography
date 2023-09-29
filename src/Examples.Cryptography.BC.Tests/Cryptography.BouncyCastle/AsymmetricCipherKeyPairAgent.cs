using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle;

/// <summary>
/// The <see cref="AsymmetricCipherKeyPair" /> importer and extension methods for export.
/// </summary>
public static class AsymmetricCipherKeyPairAgent
{
    /// <summary>
    /// Export the current key in PKCS#1 RSAPrivateKey format.
    /// </summary>
    /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair" /> type key pair.</param>
    /// <returns>A byte array containing the RSAPrivateKey representation of this key.</returns>
    public static byte[] ExportRsaPrivateKey(this AsymmetricCipherKeyPair keyPair)
        => keyPair.ExportPrivateKey();

    /// <summary>
    /// Imports the public/private key pair from the PKCS #1 RSAPrivateKey structure
    /// and returns a new <see cref="AsymmetricCipherKeyPair" /> instance.
    /// </summary>
    /// <param name="der">The bytes of an PKCS #1 RSAPrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair ImportRSAPrivateKey(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(der);
        if (seq.Count < 9)
        {
            throw new ArgumentException("Invalid byte sequence.");
        }

        // RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2
        // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A

        // A.1.2.  RSA Private Key Syntax
        //
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
        // Version::= INTEGER { two - prime(0), multi(1) }
        //        (CONSTRAINED BY
        //        { --version must be multi if otherPrimeInfos present--})
        // OtherPrimeInfos::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
        // OtherPrimeInfo::= SEQUENCE {
        //      prime           INTEGER,    -- ri
        //      exponent        INTEGER,    -- di
        //      coefficient     INTEGER     -- ti
        // }
        var structure = RsaPrivateKeyStructure.GetInstance(seq);
        var privateKey = new RsaPrivateCrtKeyParameters(structure);

        // A.1.1.  RSA Public Key Syntax
        //
        // RSAPublicKey::= SEQUENCE {
        //      modulus         INTEGER,    -- n
        //      publicExponent  INTEGER     -- e
        // }
        var publicKey = new RsaKeyParameters(false,
            structure.Modulus, structure.PublicExponent);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /// <summary>
    /// Export the current key in DSAPrivateKey format.
    /// </summary>
    /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair" /> type key pair.</param>
    /// <returns>A byte array containing the DSAPrivateKey representation of this key.</returns>
    public static byte[] ExportDSAPrivateKey(this AsymmetricCipherKeyPair keyPair)
        => keyPair.ExportPrivateKey();

    /// <summary>
    /// Imports the public/private key pair from the DSAPrivateKey structure
    /// and returns a new <see cref="AsymmetricCipherKeyPair" /> instance.
    /// </summary>
    /// <param name="der">The bytes of an DSAPrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair ImportDSAPrivateKey(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(der);
        if (seq.Count != 6)
        {
            throw new ArgumentException("Invalid byte sequence.");
        }

        // ??
        _ = (DerInteger)seq[0];
        var p = (DerInteger)seq[1];
        var q = (DerInteger)seq[2];
        var g = (DerInteger)seq[3];
        var y = (DerInteger)seq[4];
        var x = (DerInteger)seq[5];

        var parameters = new DsaParameters(p.Value, q.Value, g.Value);
        var privateKey = new DsaPrivateKeyParameters(x.Value, parameters);
        var publicKey = new DsaPublicKeyParameters(y.Value, parameters);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /// <summary>
    /// Exports the current key in the ECPrivateKey format.
    /// </summary>
    /// <param name="keyPair"></param>
    /// <returns>A byte array containing the ECPrivateKey representation of this key.</returns>
    public static byte[] ExportECPrivateKey(this AsymmetricCipherKeyPair keyPair)
        => keyPair.ExportPrivateKey();

    /// <summary>
    /// Imports the public/private key pair from the ECPrivateKey structure
    /// and returns a new <see cref="AsymmetricCipherKeyPair" /> instance.
    /// </summary>
    /// <param name="der">The bytes of an ECPrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair ImportECPrivateKey(byte[] der)
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
        // ECPrivateKey::= SEQUENCE {
        //      version         INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //      privateKey      OCTET STRING,
        //      parameters  [0] ECParameters { { NamedCurve } } OPTIONAL,
        //      publicKey   [1] BIT STRING OPTIONAL
        // }
        var structure = ECPrivateKeyStructure.GetInstance(seq);

        // RFC 5208 - Public-Key Cryptography Standards (PKCS) #8
        // https://datatracker.ietf.org/doc/html/rfc5208#appendix-A

        // Appendix A.  ASN.1 Syntax
        //
        // PrivateKeyInfo::= SEQUENCE {
        //      version             Version,
        //      privateKeyAlgorithm AlgorithmIdentifier { { PrivateKeyAlgorithms} },
        //      privateKey          PrivateKey,
        //      attributes[0]       Attributes OPTIONAL
        // }
        // Version::= INTEGER { v1(0)} (v1, ...)
        // PrivateKey::= OCTET STRING
        // Attributes ::= SET OF Attribute
        var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, structure.GetParameters());
        var privateKeyInfo = new PrivateKeyInfo(algId, structure.ToAsn1Object());
        var privateKey = PrivateKeyFactory.CreateKey(privateKeyInfo);

        // RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
        // https://datatracker.ietf.org/doc/html/rfc5480#section-2

        // 2.  Subject Public Key Information Fields
        //
        // SubjectPublicKeyInfo::= SEQUENCE  {
        //      algorithm           AlgorithmIdentifier,
        //      subjectPublicKey    BIT STRING
        // }
        var publicKeyData = structure.GetPublicKey()
            ?? throw new NotSupportedException("publicKey is null.");
        var publicKeyInfo = new SubjectPublicKeyInfo(algId, publicKeyData.GetBytes());
        var publicKey = PublicKeyFactory.CreateKey(publicKeyInfo);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

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
    /// Imports the public/private key pair from the PrivateKey structure
    /// and returns a new <see cref="AsymmetricCipherKeyPair" /> instance.
    /// </summary>
    /// <param name="der">The bytes of an PrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair ImportPrivateKey(byte[] der)
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
        // PrivateKeyInfo::= SEQUENCE {
        //      version             Version,
        //      privateKeyAlgorithm AlgorithmIdentifier { { PrivateKeyAlgorithms} },
        //      privateKey          PrivateKey,
        //      attributes[0]       Attributes OPTIONAL
        // }
        // Version::= INTEGER { v1(0)} (v1, ...)
        // PrivateKey::= OCTET STRING
        // Attributes ::= SET OF Attribute
        var privateKeyInfo = PrivateKeyInfo.GetInstance(seq);
        var privateKey = PrivateKeyFactory.CreateKey(privateKeyInfo);

        // RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
        // https://datatracker.ietf.org/doc/html/rfc5480#section-2

        // 2.  Subject Public Key Information Fields
        //
        // SubjectPublicKeyInfo::= SEQUENCE  {
        //      algorithm           AlgorithmIdentifier,
        //      subjectPublicKey    BIT STRING
        // }
        var publicKey = GetPublicKey(privateKey);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    private static AsymmetricKeyParameter GetPublicKey(AsymmetricKeyParameter privateKey)
    {
        return privateKey switch
        {
            Ed25519PrivateKeyParameters ed25519 => ed25519.GeneratePublicKey(),
            _ => throw new NotSupportedException($"type is {privateKey.GetType().Name}"),
        };
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
    /// Imports the public/private keypair from an PrivateKey structure, replacing the keys for this object.
    /// </summary>
    /// <param name="pem">The PEM text of the key to import.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair ImportPrivateKeyPem(string pem)
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

}
