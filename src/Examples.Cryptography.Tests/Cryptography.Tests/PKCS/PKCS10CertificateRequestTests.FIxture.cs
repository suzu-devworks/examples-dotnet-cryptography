using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.PKCS;

public partial class PKCS10CertificateRequestTests
{

    public class Fixture : IDisposable
    {
        public Fixture()
        {
            var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

            Pem = File.ReadAllText(Path.Combine(dir, "example.ecdsa.csr"));
        }

        public void Dispose()
        {
            KeyPair.Dispose();
            GC.SuppressFinalize(this);
        }

        public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public string Pem { get; }
    }
}
