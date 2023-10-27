using System.Security.Cryptography;
using Examples.Cryptography.Generics;

namespace Examples.Cryptography.Tests.PKCS;

public class PKCSDataFixture : IDisposable
{
    public PKCSDataFixture()
    {
        _rsaKeyPairProvider = new(() => RSA.Create(2048));
        _ecdsaKeyPairProvider = new(() => ECDsa.Create(ECCurve.NamedCurves.nistP384));
    }

    public RSA RSAKeyProvider => _rsaKeyPairProvider.Value;
    private readonly Lazy<RSA> _rsaKeyPairProvider;

    public ECDsa ECKeyProvider => _ecdsaKeyPairProvider.Value;
    private readonly Lazy<ECDsa> _ecdsaKeyPairProvider;

    public void Dispose()
    {
        _rsaKeyPairProvider.DisposeIfValueCreated();
        _ecdsaKeyPairProvider.DisposeIfValueCreated();
        GC.SuppressFinalize(this);
    }


}
