using System.Runtime.InteropServices;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle;

public static class AsymmetricCipherKeyPairAgent
{
    public static byte[] ExportPrivateKey(this AsymmetricCipherKeyPair keyPair)
    {
        var misc = new MiscPemGenerator(keyPair).Generate();
        return misc.Content;
    }

    public static AsymmetricCipherKeyPair ImportPrivateKey(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(der);

        var keyPair = CreateECKeyPair(seq);
        if (keyPair is not null)
        {
            return keyPair;
        }

        //PKCS #8
        //var privateKey = PrivateKeyFactory.CreateKey(der);

        //RSA
        //var rsa = RsaPrivateKeyStructure.GetInstance(seq);


        throw new NotImplementedException();
    }

    private static AsymmetricCipherKeyPair? CreateECKeyPair(Asn1Sequence seq)
    {
        if (seq.Count != 4)
        {
            return null;
        }
        var structure = ECPrivateKeyStructure.GetInstance(seq);

        var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, structure.GetParameters());
        var privateKeyInfo = new PrivateKeyInfo(algId, structure.ToAsn1Object());
        var privateKey = PrivateKeyFactory.CreateKey(privateKeyInfo);

        var publicKeyData = structure.GetPublicKey()
            ?? throw new NotSupportedException("publicKey is null.");

        var publicKeyInfo = new SubjectPublicKeyInfo(algId, publicKeyData.GetBytes());
        var publicKey = PublicKeyFactory.CreateKey(publicKeyInfo);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

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


    public static AsymmetricCipherKeyPair ImportPrivateKeyPem(string pem)
    {
        using var reader = new PemReader(new StringReader(pem));
        var loaded = reader.ReadObject();

        var keyPair = loaded switch
        {
            AsymmetricCipherKeyPair pair => pair,
            Ed25519PrivateKeyParameters ed25519 =>
                new AsymmetricCipherKeyPair(ed25519.GeneratePublicKey(), ed25519),
            _ => throw new NotSupportedException($"type is {loaded.GetType().Name}"),
        };

        return keyPair;
    }
}
