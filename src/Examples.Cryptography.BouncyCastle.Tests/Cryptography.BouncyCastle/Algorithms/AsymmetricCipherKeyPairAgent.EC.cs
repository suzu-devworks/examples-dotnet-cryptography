using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

public static partial class AsymmetricCipherKeyPairAgent
{
    /// <summary>
    /// Export the current key in RFC 5915 ECPrivateKey format,
    /// using Named Curve OID for the parameters field (same as .NET's ExportECPrivateKey).
    /// </summary>
    /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair" /> type key pair.</param>
    /// <returns>A byte array containing the ECPrivateKey representation of this key.</returns>
    public static byte[] ExportECPrivateKey(this AsymmetricCipherKeyPair keyPair)
    {
        var ecPrivate = (ECPrivateKeyParameters)keyPair.Private;
        var ecPublic = (ECPublicKeyParameters)keyPair.Public;

        // Use the Named Curve OID if available, otherwise look it up from the domain parameters.
        var curveOid = ecPrivate.PublicKeyParamSet
            ?? LookupNamedCurveOid(ecPrivate.Parameters);

        if (curveOid is not null)
        {
            // orderBitLength determines the fixed-size padding of the private key octet string.
            var orderBitLength = ecPrivate.Parameters.N.BitLength;

            // Encode the public key point (uncompressed: 04 || x || y).
            var publicKeyPoint = ecPublic.Q.GetEncoded(compressed: false);

            // RFC 5915 - Elliptic Curve Private Key Structure
            // https://datatracker.ietf.org/doc/html/rfc5915#section-3
            //
            // ```asn.1
            // ECPrivateKey ::= SEQUENCE {
            //      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
            //      privateKey     OCTET STRING,
            //      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
            //      publicKey  [1] BIT STRING OPTIONAL
            // }
            // ```
            var structure = new ECPrivateKeyStructure(
                orderBitLength,
                ecPrivate.D,
                new DerBitString(publicKeyPoint),
                curveOid);

            return structure.GetDerEncoded();
        }

        // Fallback: export with explicit curve parameters via MiscPemGenerator.
        return keyPair.ExportPrivateKey();
    }

    /// <summary>
    /// Exports the current key in the ECPrivateKey format, PEM encoded,
    /// using Named Curve OID for the parameters field (same as .NET's ExportECPrivateKeyPem).
    /// </summary>
    /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair" /> type key pair.</param>
    /// <returns>A string containing the PEM-encoded ECPrivateKey.</returns>
    public static string ExportECPrivateKeyPem(this AsymmetricCipherKeyPair keyPair)
    {
        var der = keyPair.ExportECPrivateKey();
        var pemObject = new PemObject("EC PRIVATE KEY", der);

        var builder = new StringBuilder();
        using (var stringWriter = new StringWriter(builder))
        using (var writer = new PemWriter(stringWriter))
        {
            writer.WriteObject(pemObject);
        }

        return builder.ToString().TrimEnd();
    }

    /// <summary>
    /// Finds the Named Curve OID by matching the curve order against known named curves.
    /// </summary>
    private static DerObjectIdentifier? LookupNamedCurveOid(ECDomainParameters domainParams)
    {
        foreach (string name in ECNamedCurveTable.Names)
        {
            var x9 = ECNamedCurveTable.GetByName(name);
            if (x9 is not null && x9.N.Equals(domainParams.N))
            {
                return ECNamedCurveTable.GetOid(name);
            }
        }

        return null;
    }

    /// <summary>
    /// Loads a new <see cref="AsymmetricCipherKeyPair" /> from the ECPrivateKey structure.
    /// </summary>
    /// <param name="der">The bytes of an ECPrivateKey structure in ASN.1-BER encoding.</param>
    /// <returns>The <see cref="AsymmetricCipherKeyPair" /> instance containing the imported key.</returns>
    public static AsymmetricCipherKeyPair LoadECPrivateKeyFrom(byte[] der)
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
