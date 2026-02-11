namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class RsaKeyOpenSslFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        PrivateKeyPem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.rsa.key"),
                TestContext.Current.CancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public string PrivateKeyPem { get; private set; } = string.Empty;
}
