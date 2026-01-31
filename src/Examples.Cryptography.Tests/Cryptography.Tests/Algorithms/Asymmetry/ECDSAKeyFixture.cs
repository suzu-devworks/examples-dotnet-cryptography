using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class ECDSAKeyFixture : IDisposable
{
    // Naming elliptic curves used in cryptography:
    //
    // spell-checker: disable
    // | Curve name | Bits in p | SECG      | ANSI X9.62 |
    // |------------|-----------|-----------|------------|
    // | NIST P-224 | 224       | secp224r1 |            |
    // | NIST P-256 | 256       | secp256r1 | prime256v1 |
    // | NIST P-384 | 384       | secp384r1 |            |
    // | NIST P-521 | 521       | secp521r1 |            |
    // spell-checker: enable

    // With OpenSSL use the following command:
    //
    // ```shell
    // openssl ecparam -genkey -name prime256v1 -noout -out private-ecdsa.key
    // ```

    public ECDSAKeyFixture()
    {
        KeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    public ECDsa KeyPair { get; }

    public void Dispose()
    {
        KeyPair?.Dispose();
        GC.SuppressFinalize(this);
    }

}
