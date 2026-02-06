using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

public partial class PKCS12PersonalInformationExchangeTests
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;
            Secret = File.ReadAllText(Path.Combine(dir, ".password"));

            _privateKey = new(() =>
            {
                var key = ECDsa.Create();
                key.ImportFromPem(File.ReadAllText(Path.Combine(dir, "example.ecdsa.key")));
                return key;
            });
            _certificate = new(() => X509CertificateLoader.LoadCertificateFromFile(
                Path.Combine(dir, "example.ecdsa.crt")));
            _pkcs12Bytes = new(() => File.ReadAllBytes(
                Path.Combine(dir, "example.ecdsa.p12")));
        }

        public void Dispose()
        {
            if (_certificate.IsValueCreated)
            {
                _certificate.Value.Dispose();
            }
            if (_privateKey.IsValueCreated)
            {
                _privateKey.Value.Dispose();
            }
            GC.SuppressFinalize(this);
        }

        public ECDsa PrivateKey => _privateKey.Value;
        private readonly Lazy<ECDsa> _privateKey = new(() => ECDsa.Create());

        public X509Certificate2 Certificate => _certificate.Value;
        private readonly Lazy<X509Certificate2> _certificate;

        public byte[] Pkcs12Bytes => _pkcs12Bytes.Value;
        private readonly Lazy<byte[]> _pkcs12Bytes;

        public string Secret { get; }
    }
}
