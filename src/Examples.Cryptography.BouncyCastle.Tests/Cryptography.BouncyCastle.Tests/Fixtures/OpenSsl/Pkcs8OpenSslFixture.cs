namespace Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;

public class Pkcs8OpenSslFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        PrivateKeyPem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.p8"),
                TestContext.Current.CancellationToken);
        EncryptedPrivateKeyPem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.p8.enc"),
                TestContext.Current.CancellationToken);
        Secret = await File.ReadAllTextAsync(
                Path.Combine(dir, ".password"),
                TestContext.Current.CancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public string PrivateKeyPem { get; private set; } = string.Empty;
    public string EncryptedPrivateKeyPem { get; private set; } = string.Empty;
    public string Secret { get; private set; } = string.Empty;
}
