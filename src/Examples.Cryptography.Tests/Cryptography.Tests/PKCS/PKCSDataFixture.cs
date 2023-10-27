using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.PKCS;

public class PKCSDataFixture : IDisposable
{
    public PKCSDataFixture()
    {
        _rsaKeyPairProvider = new(() => RSA.Create(2048));
        _ecKeyPairProvider = new(() => ECDsa.Create(ECCurve.NamedCurves.nistP384));
    }

    public RSA RSAKeyProvider => _rsaKeyPairProvider.Value;
    private readonly Lazy<RSA> _rsaKeyPairProvider;

    public ECDsa ECKeyProvider => _ecKeyPairProvider.Value;
    private readonly Lazy<ECDsa> _ecKeyPairProvider;

    public void Dispose()
    {
        if (_rsaKeyPairProvider.IsValueCreated)
        {
            _rsaKeyPairProvider.Value.Dispose();
        }

        if (_ecKeyPairProvider.IsValueCreated)
        {
            _ecKeyPairProvider.Value.Dispose();
        }

        GC.SuppressFinalize(this);
    }


}
