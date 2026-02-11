namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class Pkcs10OpenSslFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        EcdsaCertRequestPem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.csr"),
                TestContext.Current.CancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public string EcdsaCertRequestPem { get; private set; } = string.Empty;
}
