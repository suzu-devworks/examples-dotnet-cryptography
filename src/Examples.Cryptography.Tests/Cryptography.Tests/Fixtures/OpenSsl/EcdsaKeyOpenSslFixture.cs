using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Fixtures.OpenSsl;

public class EcdsaKeyOpenSslFixture : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        PrivateKeyPem = await File.ReadAllTextAsync(
                Path.Combine(dir, "example.ecdsa.key"),
                TestContext.Current.CancellationToken);

        KeyPair.ImportFromPem(PrivateKeyPem.AsSpan());
    }

    public ValueTask DisposeAsync()
    {
        KeyPair.Dispose();
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public string PrivateKeyPem { get; private set; } = string.Empty;
    public ECDsa KeyPair { get; } = ECDsa.Create();

}
