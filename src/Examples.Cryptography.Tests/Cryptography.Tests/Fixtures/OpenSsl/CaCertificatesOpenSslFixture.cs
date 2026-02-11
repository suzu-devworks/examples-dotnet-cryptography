using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class CaCertificatesOpenSslFixture(bool includePrivateKeys = false) : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        RootCaCertificate = X509CertificateLoader.LoadCertificateFromFile(
                Path.Combine(dir, "example.ca-root.crt"));
        IntermediateCaCertificate = X509CertificateLoader.LoadCertificateFromFile(
                Path.Combine(dir, "example.ca-intermediate.crt"));

        if (includePrivateKeys)
        {
            RootCaCertificate = RootCaCertificate.CopyWithPrivateKey(
                await TestPrivateKeyLoader.LoadECDsaPrivateKey(
                    Path.Combine(dir, "example.ca-root.key"),
                    TestContext.Current.CancellationToken));
            IntermediateCaCertificate = IntermediateCaCertificate.CopyWithPrivateKey(
                await TestPrivateKeyLoader.LoadECDsaPrivateKey(
                    Path.Combine(dir, "example.ca-intermediate.key"),
                    TestContext.Current.CancellationToken));
        }
    }

    public ValueTask DisposeAsync()
    {
        RootCaCertificate.Dispose();
        IntermediateCaCertificate.Dispose();
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public X509Certificate2 RootCaCertificate { get; private set; } = default!;
    public X509Certificate2 IntermediateCaCertificate { get; private set; } = default!;

}
