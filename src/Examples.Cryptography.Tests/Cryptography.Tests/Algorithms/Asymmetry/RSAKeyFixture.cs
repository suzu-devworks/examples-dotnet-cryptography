using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class RSAKeyFixture : IDisposable
{
    // With OpenSSL use the following command:
    //
    // ```shell
    // openssl genrsa -out private-rsa.key -traditional 4096
    // ```

    public RSAKeyFixture()
    {
        KeyPair = RSA.Create(keySizeInBits: 2048 /* use 4096 or more */);
    }

    public RSA KeyPair { get; }

    public void Dispose()
    {
        KeyPair?.Dispose();
        GC.SuppressFinalize(this);
    }

}
