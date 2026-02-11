using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetric.Rsa;

/// <summary>
/// Fixture for RSA key pair.
/// </summary>
public class RsaKeyFixture : IDisposable
{
    public RsaKeyFixture()
    {
        /* With OpenSSL use the following command:
        ```shell
        openssl genrsa -out private-rsa.key -traditional 4096
        ```
        */
        KeyPair = RSA.Create(keySizeInBits: 2048 /* use 4096 or more */);
    }

    public void Dispose()
    {
        KeyPair?.Dispose();
        GC.SuppressFinalize(this);
    }

    public RSA KeyPair { get; }

}
