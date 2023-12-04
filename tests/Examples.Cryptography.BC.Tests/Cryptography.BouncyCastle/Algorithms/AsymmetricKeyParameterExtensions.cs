using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Examples.Cryptography.BouncyCastle.Algorithms;

public static class AsymmetricKeyParameterExtensions
{
    public static ISignatureFactory CreateDefaultSignature(this AsymmetricKeyParameter key)
    {
        return key switch
        {
            RsaKeyParameters _ => new Asn1SignatureFactory("SHA256WithRSA", key),
            ECKeyParameters _ => new Asn1SignatureFactory("SHA256WithECDSA", key),
            Ed25519PrivateKeyParameters => new Asn1SignatureFactory("Ed25519", key),
            _ => throw new NotSupportedException($"not supported {key.GetType()}"),
        };
    }
}
