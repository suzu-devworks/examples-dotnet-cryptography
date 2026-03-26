using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Xml.Tests.Fixtures.OpenSsl;

public class RsaSignerCertificateChainOpenSslFixture(bool includePrivateKeys = false) : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        RootCaCertificate = X509CertificateLoader.LoadCertificateFromFile(
                Path.Combine(dir, "example.ca-root.crt"));
        IntermediateCaCertificate = X509CertificateLoader.LoadCertificateFromFile(
                Path.Combine(dir, "example.ca-intermediate.crt"));
        SinnerCertificate = X509CertificateLoader.LoadCertificateFromFile(
                Path.Combine(dir, "example.rsa.crt"));

        if (includePrivateKeys)
        {
            RootCaCertificate = RootCaCertificate.CopyWithPrivateKey(
                await AsymmetricAlgorithmLoader.LoadECDsaPrivateKeyAsync(
                    Path.Combine(dir, "example.ca-root.key"),
                    TestContext.Current.CancellationToken));
            IntermediateCaCertificate = IntermediateCaCertificate.CopyWithPrivateKey(
                await AsymmetricAlgorithmLoader.LoadECDsaPrivateKeyAsync(
                    Path.Combine(dir, "example.ca-intermediate.key"),
                    TestContext.Current.CancellationToken));
            SinnerCertificate = SinnerCertificate.CopyWithPrivateKey(
                await AsymmetricAlgorithmLoader.LoadRsaPrivateKeyAsync(
                    Path.Combine(dir, "example.rsa.key"),
                    TestContext.Current.CancellationToken));
        }
    }

    public ValueTask DisposeAsync()
    {
        RootCaCertificate.Dispose();
        IntermediateCaCertificate.Dispose();
        SinnerCertificate.Dispose();
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public X509Certificate2 RootCaCertificate { get; private set; } = default!;
    public X509Certificate2 IntermediateCaCertificate { get; private set; } = default!;
    public X509Certificate2 SinnerCertificate { get; private set; } = default!;
}
