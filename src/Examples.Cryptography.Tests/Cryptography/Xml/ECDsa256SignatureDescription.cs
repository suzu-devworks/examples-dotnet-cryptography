using System.Security.Cryptography;

namespace Examples.Cryptography.Xml;

/// <summary>
/// Implement <see cref="SignatureDescription" /> for signing with ECDsa SHA256
/// </summary>
public class ECDsa256SignatureDescription : SignatureDescription
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ECDsa256SignatureDescription" /> class.
    /// </summary>
    public ECDsa256SignatureDescription()
    {
        KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
    }

    /// <inheritdoc />
    public override HashAlgorithm CreateDigest() => SHA256.Create();

    /// <inheritdoc />
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        if (key is not ECDsa ecdsa || ecdsa.KeySize != 256)
        {
            throw new InvalidOperationException("Requires EC key using P-256");
        }

        return new ECDsaSignatureFormatter(ecdsa);
    }

    /// <inheritdoc />
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        if (key is not ECDsa ecdsa || ecdsa.KeySize != 256)
        {
            throw new InvalidOperationException("Requires EC key using P-256");
        }

        return new ECDsaSignatureDeformatter(ecdsa);
    }


    private class ECDsaSignatureFormatter : AsymmetricSignatureFormatter
    {
        private ECDsa _key;

        public ECDsaSignatureFormatter(ECDsa key)
            => _key = key;

        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key is ECDsa ecdsa)
            {
                _key = ecdsa;
            }
        }

        public override void SetHashAlgorithm(string strName) { }

        public override byte[] CreateSignature(byte[] rgbHash)
            => _key.SignHash(rgbHash);

    }

    private class ECDsaSignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private ECDsa _key;

        public ECDsaSignatureDeformatter(ECDsa key)
            => _key = key;

        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key is ECDsa ecdsa)
            {
                _key = ecdsa;
            }
        }

        public override void SetHashAlgorithm(string strName) { }

        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
            => _key.VerifyHash(rgbHash, rgbSignature);

    }

}
