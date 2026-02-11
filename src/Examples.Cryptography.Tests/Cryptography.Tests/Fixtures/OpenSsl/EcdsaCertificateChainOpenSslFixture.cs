using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class EcdsaCertificateChainOpenSslFixture(bool includePrivateKeys = false) : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        await _caCertificates.InitializeAsync();

        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        EndEntityCertificate = X509CertificateLoader.LoadCertificateFromFile(
                Path.Combine(dir, "example.ecdsa.crt"));

        if (includePrivateKeys)
        {
            EndEntityCertificate = EndEntityCertificate.CopyWithPrivateKey(
                await TestPrivateKeyLoader.LoadECDsaPrivateKey(
                    Path.Combine(dir, "example.ecdsa.key"),
                    TestContext.Current.CancellationToken));
        }

        Certificates = new X509Certificate2Collection
        {
            EndEntityCertificate,
            IntermediateCaCertificate,
            RootCaCertificate
        };
    }

    public async ValueTask DisposeAsync()
    {
        EndEntityCertificate?.Dispose();
        await _caCertificates.DisposeAsync();
        GC.SuppressFinalize(this);
    }

    private readonly CaCertificatesOpenSslFixture _caCertificates = new(includePrivateKeys);

    public X509Certificate2 RootCaCertificate => _caCertificates.RootCaCertificate;
    public X509Certificate2 IntermediateCaCertificate => _caCertificates.IntermediateCaCertificate;
    public X509Certificate2 EndEntityCertificate { get; private set; } = default!;

    public X509Certificate2Collection Certificates { get; private set; } = default!;
}
