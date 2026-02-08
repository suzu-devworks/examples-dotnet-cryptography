namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class Pkcs12OpenSslFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        Pkcs12Bytes = await File.ReadAllBytesAsync(
                Path.Combine(dir, "example.ecdsa.p12"),
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

    public byte[] Pkcs12Bytes { get; private set; } = [];
    public string Secret { get; private set; } = string.Empty;

}
