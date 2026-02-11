using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class EcdsaCertificateOpenSslFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        var key = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.key"),
                TestContext.Current.CancellationToken);
        PrivateKey.ImportFromPem(key.AsSpan());

        CertificatePem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.crt"),
                TestContext.Current.CancellationToken);

        Certificate = X509CertificateLoader.LoadCertificate(Encoding.UTF8.GetBytes(CertificatePem));
    }

    public ValueTask DisposeAsync()
    {
        Certificate?.Dispose();
        PrivateKey.Dispose();
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public ECDsa PrivateKey { get; } = ECDsa.Create();
    public X509Certificate2 Certificate { get; private set; } = default!;
    public string CertificatePem { get; private set; } = string.Empty;
}
