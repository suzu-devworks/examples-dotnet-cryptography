using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.PKCS;

public partial class PKCS8AsymmetricKeyPackagesTests
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

            Pem = File.ReadAllText(Path.Combine(dir, "example.ecdsa.pk8"));
            Secret = File.ReadAllText(Path.Combine(dir, ".password"));
        }

        public void Dispose()
        {
            KeyPair?.Dispose();
            GC.SuppressFinalize(this);
        }

        public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public string Pem { get; }
        public string Secret { get; }
    }
}
