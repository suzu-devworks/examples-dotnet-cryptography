using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

public partial class PKCS7Certificate2CollectionExportableTests
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

            Pem = File.ReadAllText(Path.Combine(dir, "example.ecdsa.p7b.crt"));

            RootCaCertificate = X509Certificate2.CreateFromPemFile(
                    Path.Combine(dir, "example.ca-root.crt"), Path.Combine(dir, "example.ca-root.key"));
            IntermediateCaCertificate = X509Certificate2.CreateFromPemFile(
                    Path.Combine(dir, "example.ca-intermediate.crt"), Path.Combine(dir, "example.ca-intermediate.key"));
            EndEntityCertificate = X509Certificate2.CreateFromPemFile(
                    Path.Combine(dir, "example.rsa.crt"), Path.Combine(dir, "example.rsa.key"));
        }

        public void Dispose()
        {
            EndEntityCertificate.Dispose();
            IntermediateCaCertificate.Dispose();
            RootCaCertificate.Dispose();
            GC.SuppressFinalize(this);
        }

        public string Pem { get; }
        public X509Certificate2 RootCaCertificate { get; }
        public X509Certificate2 IntermediateCaCertificate { get; }
        public X509Certificate2 EndEntityCertificate { get; }
    }

}
