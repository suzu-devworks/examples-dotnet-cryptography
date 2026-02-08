namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class Pkcs7OpenSslFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        ContainerPem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.p7b"),
                TestContext.Current.CancellationToken);
        CertificateCollectionPem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.p7b.crt"),
                TestContext.Current.CancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public string ContainerPem { get; private set; } = string.Empty;
    public string CertificateCollectionPem { get; private set; } = string.Empty;
}

